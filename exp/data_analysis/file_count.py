"""
This file is used to count pcap(ng) files per subdirectory in the base dir.
"""
from pa3.tools.analyzer import file_count
import argparse
import os
from pathlib import Path


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    args = parser.parse_args()

    base_dir = Path(args.dir)
    cnt = file_count(base_dir=base_dir)
    for k, v in cnt.items():
        print(f'{k}: {v} pcap(ng) files')