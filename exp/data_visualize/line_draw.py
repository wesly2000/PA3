import pyshark
import os
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

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


if __name__ == '__main__':
    pcap_dir = Path("exp/normal_capture/www.apple.com")
    # file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"

    # tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/normal_capture/www.apple.com/keylog.txt"
    SNIs = ["is1-ssl.mzstatic.com"]
    lines = []
    for file in sorted(pcap_dir.iterdir()):
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            tcp_stream, _ = h2data_SNI_intersect(file, SNIs, keylog_file=keylog_file, custom_parameters={"-C": "Customized"})
            tcp_stream_filter = stream_extract_filter(tcp_stream, [])
            display_filter = tcp_stream_filter
            if tcp_stream_filter == "":
                continue

            cap = pyshark.FileCapture(input_file=file, display_filter=tcp_stream_filter, 
                                        custom_parameters=["-C", "Customized", "-2"],
                                        override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
            
            lines.append(get_adjacent_protocol_reassemble_info(cap, upper_protocol="http2", lower_protocol="tls"))

            cap.close()

    byte_segments = generate_byte_segment(lines)
    avg_byte_segments = np.mean(np.array(byte_segments), axis=0)
    std_byte_segments = np.std(np.array(byte_segments), axis=0)

    draw_byte_segment(avg_byte_segments, std_byte_segments, "exp/data_visualize/img/example.pdf")