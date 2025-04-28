import pyshark
import os
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import argparse

from WFlib.tools.visualize import *
from WFlib.tools.capture import *
from WFlib.tools.analyzer import *

def draw_byte_segment(avg_byte_segments: np.ndarray, std_byte_segments: np.ndarray, output_path: str):
    """
    Draw the byte segment array. The array is a list of segment index. The length of the list is the cutoff.
    """
    plt.figure(figsize=(12, 6))
    plt.plot(avg_byte_segments, '-', linewidth=1, color='blue', label='Average')
    plt.plot(std_byte_segments, '-', linewidth=1, color='red', label='Standard Deviation')
    
    plt.xlabel('Byte Index')
    plt.ylabel('Stream Relative Segment Index')
    plt.title('Byte Segment Map')
    fig_format = output_path.split('.')[-1]
    plt.savefig(output_path, dpi=300, format=fig_format, bbox_inches='tight')
    plt.close()

custom_parameters=["-C", "Customized", "-2"]

def main():
    def dry_run():
        for file in sorted(pcap_dir.iterdir()):
            if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
                try:
                    tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, 
                                                        custom_parameters=custom_parameters, 
                                                        override_prefs=override_prefs)
                except Exception as e:
                    print(f"Error in file {file}: {e}")
                    continue
                tcp_stream_filter = stream_extract_filter(tcp_stream, [])
                if tcp_stream_filter == "":
                    continue

                print(f"File {file.name} TCP filter: {tcp_stream_filter}")

    def run():
        if avg_array_path.exists() and std_array_path.exists():
                print("The array has already been computed, use the stored value")
                avg_byte_segments = np.load(avg_array_path)
                std_byte_segments = np.load(std_array_path)
        else:
            lines = []
            for file in sorted(pcap_dir.iterdir()):
                if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
                    try:
                        tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, 
                                                            custom_parameters=custom_parameters, 
                                                            override_prefs=override_prefs)
                    except Exception as e:
                        print(f"Error in file {file}: {e}")
                        continue
                    tcp_stream_filter = stream_extract_filter(tcp_stream, [])
                    if tcp_stream_filter == "":
                        continue

                    cap = pyshark.FileCapture(input_file=file, display_filter=tcp_stream_filter, 
                                                custom_parameters=custom_parameters,
                                                override_prefs=override_prefs)
                    
                    lines.append(get_adjacent_protocol_reassemble_info(cap, upper_protocol="http2", lower_protocol="tls"))

                    cap.close()

            byte_segments = generate_byte_segment(lines)
            avg_byte_segments = np.mean(np.array(byte_segments), axis=0)
            std_byte_segments = np.std(np.array(byte_segments), axis=0)

            np.save(avg_array_path, avg_byte_segments)
            np.save(std_array_path, std_byte_segments)

        draw_byte_segment(avg_byte_segments, std_byte_segments, f"exp/data_visualize/img/{args.host}_{args.sni}_{args.protocol}.pdf")

    
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-p", "--protocol", default="normal", type=str, help="The protocol to analyze")
    parser.add_argument("--host", required=True, type=str, help="The host to analyze")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The SNI to analyze")
    parser.add_argument("-r", "--root", default="exp", type=str, help="The root directory of the capture and keylog")
    parser.add_argument("--dry-run", action='store_true', help="Test the stream filter or other results instead of generating Lines")
    args = parser.parse_args()

    avg_array_path = Path(f"exp/data_visualize/result/avg_{args.host}_{args.sni}_{args.protocol}.npy")
    std_array_path = Path(f"exp/data_visualize/result/std_{args.host}_{args.sni}_{args.protocol}.npy")

    pcap_dir = Path(f"{args.root}/{args.protocol}_capture/{args.host}")
    keylog_file = f"{args.root}/{args.protocol}_capture/{args.host}/keylog.txt"
    proxy_keylog_file = f"{args.root}/{args.protocol}_capture/{args.host}/proxy_keylog.txt"

    if args.protocol == 'normal':
        override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)}
    elif args.protocol == 'vmess':
        override_prefs={'tls.keylog_file': os.path.abspath(keylog_file),
                        'vmess.keylog_file': os.path.abspath(proxy_keylog_file)}
    SNIs = [args.sni]

    if args.dry_run:
        dry_run()
    else:
        run()

if __name__ == '__main__':    
    main()