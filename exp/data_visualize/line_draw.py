
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import os
import argparse
import seg_compute
import logging

logger = logging.getLogger(__name__)

avg_color_map = {"Normal": "blue", "VMess": "green", "Shadowsocks": "red", "Trojan": "orange"}
std_color_map = {"Normal": "yellow", "VMess": "purple", "Shadowsocks": "red", "Trojan": "orange"}

def draw_single_byte_segment(fig: plt.Figure, ax: plt.Axes, avg_byte_segments: np.ndarray, std_byte_segments: np.ndarray, proto: str):
    """
    Draw the byte segment array. The array is a list of segment index. The length of the list is the cutoff.
    """
    ax.plot(avg_byte_segments, '-', linewidth=1, color=avg_color_map[proto], label=f"{proto} Avg")
    ax.plot(std_byte_segments, '-', linewidth=1, color=std_color_map[proto], label=f"{proto} Std")


def draw_byte_segment(input_root: str, host: str, sni: str, base: str, output_root: str):
    """
    Draw the byte segment array. The array is a list of segment index. The length of the list is the cutoff.
    """
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle('Byte Segment Map', fontdict={'size': 16})
    for protocol in avg_color_map:
        avg_array_path = Path(f"{output_root}/seg_compute/{base}/{protocol.lower()}/avg_{host}_{sni}.npy")
        std_array_path = Path(f"{output_root}/seg_compute/{base}/{protocol.lower()}/std_{host}_{sni}.npy")
        if avg_array_path.exists() and std_array_path.exists():
            logger.info("Array exists, use stored array.")
            avg_byte_segments, std_byte_segments = np.load(avg_array_path), np.load(std_array_path)
        else:
            logger.info("Array does not exist, start computing...")
            seg_compute.main(input_root, protocol.lower(), host, sni, base, output_root)

            avg_byte_segments, std_byte_segments = np.load(avg_array_path), np.load(std_array_path)
            
        draw_single_byte_segment(fig, ax, avg_byte_segments, std_byte_segments, protocol)
    
    ax.legend(loc='upper left')
    ax.set_xlabel('Byte Index')
    ax.set_ylabel('Relative Segment Index')
    ax.set_title(f'Host: {host}, SNI: {sni}', fontsize=12)

    output_path = f"{args.output_root}/line_draw/{base}/{args.host}_{args.sni}.pdf"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    fig_format = output_path.split('.')[-1]
    plt.savefig(output_path, dpi=300, format=fig_format, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("-b", "--base", default="tcp", type=str, help="The lowest layer protocol as the segment index")
    parser.add_argument("--host", required=True, type=str, help="The host to analyze")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The SNI to analyze")
    args = parser.parse_args()

    logger.info("Task line_draw started")
    draw_byte_segment(args.input_root, args.host, args.sni, args.base, args.output_root)
    logger.info("Task line_draw completed")