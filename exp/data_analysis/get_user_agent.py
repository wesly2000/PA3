import pandas as pd
import numpy as np
from typing import List, Set
import pyshark
from pathlib import Path
from tqdm import tqdm
import argparse
import logging

from WFlib.tools.capture import *
from WFlib.utils.statistics import *
from WFlib.utils.config import default_override_prefs, get_tshark_path
from WFlib.tools.analyzer import user_agent_fetch

logger = logging.getLogger(__name__)

custom_parameters=["-2"]
config_path = Path.cwd() / 'config.ini'


def get_user_agent_per_protocol(input_root: str, output_root: str, host: str, protocol: str):
    input_root = Path(f"{input_root}/{protocol}_capture")
    tshark_path=get_tshark_path(config_path, protocol)
    
    if not input_root.exists():
        raise FileNotFoundError(f"Directory {input_root} does not exist")
    
    if not input_root.is_dir():
        raise NotADirectoryError(f"{input_root} is not a directory")

    with open(f'{output_root}/{protocol}.txt', 'w') as f:
        for subdir in input_root.iterdir():
            if subdir.is_dir():
                pcap_dir = subdir
                keylog_file = f"{pcap_dir}/keylog.txt"
                proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"
                
                override_prefs = default_override_prefs(protocol, os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))

                # Select one .pcapng for analysis
                pcap_file = list(filter(lambda x: x.is_file() and x.suffix in ['.pcapng', '.pcap'], Path(pcap_dir).iterdir()))[0]
                cap = pyshark.FileCapture(input_file=pcap_file, display_filter='http2', 
                                        override_prefs=override_prefs, tshark_path=tshark_path)
                
                # Extract browser version
                user_agent = user_agent_fetch(cap)
                f.write(f"{subdir.name}: {user_agent}\n")
            

def main(input_root: str, output_root: str, host: str, protocols: List[str]):
    for protocol in protocols:
        get_user_agent_per_protocol(input_root, output_root, host, protocol)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--host", default="exp/data_analysis/host_list.txt", type=str, help="The host list file")
    parser.add_argument("-p", "--protocols", nargs='+', default=["normal"], type=str, help="The protocols")
    args = parser.parse_args()
    logger.info("Task browser_version started")
    main(args.input_root, args.output_root, args.host, args.protocols)
    logger.info("Task browser_version completed")