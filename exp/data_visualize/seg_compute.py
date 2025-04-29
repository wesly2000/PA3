import pyshark
import os
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import argparse
from tqdm import tqdm

from WFlib.tools.visualize import *
from WFlib.tools.capture import *
from WFlib.tools.analyzer import *

custom_parameters=["-C", "Customized", "-2"]

def extract_tcp_stream(pcap_file: Path, sni, keylog_file, custom_parameters, override_prefs):
    """
    Extract the proper TCP stream from the pcap file given the SNIs. If any error occurs, return an empty string.
    """
    try:
        tcp_stream_numbers, _ = h2data_SNI_intersect(pcap_file, [sni], keylog_file=keylog_file, 
                                            custom_parameters=custom_parameters, 
                                            override_prefs=override_prefs)
    except Exception as e:
        print(f"Error in file {pcap_file}: {e}")
        return ""
    tcp_stream_numbers = select_stream(pcap_file=pcap_file, stream_numbers=tcp_stream_numbers, mapper=packet_count, criteria=max)
    tcp_stream_filter = stream_extract_filter(tcp_stream_numbers, [])
    if tcp_stream_filter == "":
        print(f"Error in file {pcap_file}: No TCP stream found")
        return ""
    
    return tcp_stream_filter

def main(root, protocol, host, sni, dry_run=False):
    pcap_dir = f"{root}/{protocol}_capture/{host}"
    keylog_file = f"{pcap_dir}/keylog.txt"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)

    if protocol == 'normal':
        override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)}
    elif protocol == 'vmess':
        override_prefs={'tls.keylog_file': os.path.abspath(keylog_file),
                        'vmess.keylog_file': os.path.abspath(proxy_keylog_file)}


    lines = []
    for file in tqdm(sorted(pcap_dir_path.iterdir())):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            tcp_stream_filter = extract_tcp_stream(file, sni, keylog_file, custom_parameters, override_prefs)
            if tcp_stream_filter == "":
                continue

            if dry_run:
                print(f"File {file.name} TCP filter: {tcp_stream_filter}")
                continue  # No actual computing in dry run mode

            cap = pyshark.FileCapture(input_file=file, display_filter=tcp_stream_filter, 
                                        custom_parameters=custom_parameters,
                                        override_prefs=override_prefs)
            
            lines.append(get_adjacent_protocol_reassemble_info(cap, upper_protocol="http2", lower_protocol="tls"))
            cap.close()

    if not dry_run:
        byte_segments = generate_byte_segment(lines)
        avg_byte_segments = np.mean(np.array(byte_segments), axis=0)
        std_byte_segments = np.std(np.array(byte_segments), axis=0)

        avg_array_path = Path(f"exp/data_visualize/result/avg_{host}_{sni}_{protocol}.npy")
        std_array_path = Path(f"exp/data_visualize/result/std_{host}_{sni}_{protocol}.npy")

        np.save(avg_array_path, avg_byte_segments)
        np.save(std_array_path, std_byte_segments)


if __name__ == '__main__':    
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-p", "--protocol", default="normal", type=str, help="The protocol to analyze")
    parser.add_argument("--host", required=True, type=str, help="The host to analyze")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The SNI to analyze")
    parser.add_argument("-r", "--root", default="exp", type=str, help="The root directory of the capture and keylog")
    parser.add_argument("--dry-run", action='store_true', help="Test the stream filter or other results instead of generating Lines")
    args = parser.parse_args()

    main(args.root, args.protocol, args.host, args.sni, args.dry_run)