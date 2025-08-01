import pyshark
import os
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import argparse
from tqdm import tqdm
import time

from WFlib.tools.visualize import *
from WFlib.tools.capture import *
from WFlib.tools.analyzer import *

from WFlib.utils.config import SUPPORTED_BASE, SUPPORTED_PROTOCOL, default_override_prefs

DEBUG = False

custom_parameters=["-2"]

def extract_tcp_stream(pcap_file: Path, sni, keylog_file, custom_parameters, override_prefs):
    """
    Extract the proper TCP stream from the pcap file given the SNIs. If any error occurs, return an empty string.
    """
    try:
        tcp_stream_numbers = h2data_SNI_intersect(pcap_file, [sni], keylog_file=keylog_file, 
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

def main(input_root, protocol, host, sni, base, output_root, dry_run=False):
    pcap_dir = f"{input_root}/{protocol}_capture/{host}"
    keylog_file = f"{pcap_dir}/keylog.txt"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)

    override_prefs = default_override_prefs(protocol, os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))

    lines = []
    limit = 30
    for file in tqdm(sorted(pcap_dir_path.iterdir())[:limit]):
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
            
            if DEBUG:
                cap.set_debug()
            
            protocol_stack = ['http2', 'tls']
            if base == 'tcp':
                if protocol == 'normal':
                    protocol_stack.append('tcp')
                elif protocol == 'vmess':
                    protocol_stack.append('vmess')
                    protocol_stack.append('tcp')

            try:
                lines.append(get_reassemble_info(cap, protocol_stack=protocol_stack))
            except Exception as e:
                print(f"Error in file {file.name}: {e}")
            try:
                cap.close()
            except Exception as e:
                print(f"Error in file {file.name}: {e}")

    if not dry_run:
        byte_segments = generate_byte_segment(lines)
        avg_byte_segments = np.mean(np.array(byte_segments), axis=0)
        std_byte_segments = np.std(np.array(byte_segments), axis=0)

        avg_array_path = Path(f"{output_root}/seg_compute/{base}/{protocol}/avg_{host}_{sni}.npy")
        std_array_path = Path(f"{output_root}/seg_compute/{base}/{protocol}/std_{host}_{sni}.npy")

        Path(avg_array_path).parent.mkdir(parents=True, exist_ok=True)
        Path(std_array_path).parent.mkdir(parents=True, exist_ok=True)

        np.save(avg_array_path, avg_byte_segments)
        np.save(std_array_path, std_byte_segments)


if __name__ == '__main__':    
    """
    Compute the byte segment of the given protocol, host, and SNI. Users should strictly follow the directory structure for convenient file management. See INPUT_CAPTURE in README.md for more details.

    The output root is the root directory of the output, since VisualSeg would output many kind of results, e.g., the byte segment array, byte segment diagram, some statistics, etc., each method would have its own output directory under the SAME root.

    For example, for seg_compute.py with protocol="normal", base="tls", the output directory is:
    output_root/
        seg_compute/
            tls/
                normal/
                    avg_host_sni.npy
                    std_host_sni.npy
    """
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-p", "--protocol", default="normal", type=str, help="The protocol to analyze")
    parser.add_argument("--host", required=True, type=str, help="The host to analyze")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The SNI to analyze")
    parser.add_argument("-b", "--base", default="tls", type=str, help="The lowest layer protocol as the segment index")
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--dry-run", action='store_true', help="Test the stream filter or other results instead of generating Lines")
    args = parser.parse_args()

    if args.base not in SUPPORTED_BASE:
        raise ValueError(f"Unsupported base: {args.base}. Supported bases: {SUPPORTED_BASE}")
    if args.protocol not in SUPPORTED_PROTOCOL:
        raise ValueError(f"Unsupported protocol: {args.protocol}. Supported protocols: {SUPPORTED_PROTOCOL}")

    main(args.input_root, args.protocol, args.host, args.sni, args.base, args.output_root, args.dry_run)