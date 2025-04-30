
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import os
import argparse
import seg_compute

avg_color_map = {"Normal": "blue", "VMess": "green"}
std_color_map = {"Normal": "yellow", "VMess": "purple"}

def draw_single_byte_segment(fig: plt.Axes, ax: plt.Axes, avg_byte_segments: np.ndarray, std_byte_segments: np.ndarray, proto: str):
    """
    Draw the byte segment array. The array is a list of segment index. The length of the list is the cutoff.
    """
    ax.plot(avg_byte_segments, '-', linewidth=1, color=avg_color_map[proto], label=f"{proto} Avg")
    ax.plot(std_byte_segments, '-', linewidth=1, color=std_color_map[proto], label=f"{proto} Std")


def draw_byte_segment(root: str, host: str, SNI: str, output_path: str):
    """
    Draw the byte segment array. The array is a list of segment index. The length of the list is the cutoff.
    """
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle('Byte Segment Map', fontdict={'size': 16})
    for proto in avg_color_map:
        avg_array_path = Path(os.path.join(root, "data_visualize", "result", f"avg_{host}_{SNI}_{proto}.npy"))
        std_array_path = Path(os.path.join(root, "data_visualize", "result", f"std_{host}_{SNI}_{proto}.npy"))
        if avg_array_path.exists() and std_array_path.exists():
            print("Array exists, use stored array.")
            avg_byte_segments, std_byte_segments = np.load(avg_array_path), np.load(std_array_path)
        else:
            print("Array does not exist, start computing...")
            seg_compute.main(root, proto.lower(), host, SNI)

            avg_byte_segments, std_byte_segments = np.load(avg_array_path), np.load(std_array_path)
            
        draw_single_byte_segment(fig, ax, avg_byte_segments, std_byte_segments, proto)
    
    ax.legend(loc='upper left')
    ax.set_xlabel('Byte Index')
    ax.set_ylabel('Relative Segment Index')
    ax.set_title(f'Host: {host}, SNI: {SNI}', fontsize=12)

    fig_format = output_path.split('.')[-1]
    plt.savefig(output_path, dpi=300, format=fig_format, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("--host", required=True, type=str, help="The host to analyze")
    parser.add_argument("-s", "--sni", required=True, type=str, help="The SNI to analyze")
    parser.add_argument("-r", "--root", default="exp", type=str, help="The root directory of the capture and keylog")
    # parser.add_argument("--dry-run", action='store_true', help="Test the stream filter or other results instead of generating Lines")
    parser.add_argument("-o", "--output_path", type=str, help="The output path of the figure")
    args = parser.parse_args()

    if args.output_path is None:
        output_path = f"{args.root}/data_visualize/img/{args.host}_{args.sni}.pdf"
    else:
        output_path = args.output_path

    draw_byte_segment(args.root, args.host, args.sni, output_path)