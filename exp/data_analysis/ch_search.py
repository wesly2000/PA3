"""
This script is used to compute the frame index of Client Hello packet within a TCP stream.
"""
import os
from typing import List
import pyshark
from pathlib import Path
import logging
import pandas as pd
import argparse

from WFlib.tools.capture import stream_number_extract, read_host_list
from WFlib.tools.analyzer import PROTOCOL_CH_SEARCHER
from WFlib.utils.config import get_tshark_path, default_override_prefs

logger = logging.getLogger(__name__)

custom_parameters=["-2"]
config_path = Path.cwd() / 'config.ini'
PROTOCOLS = ['normal']

def pcap_CH_search(pcap_file: str, protocol: str, tshark_path: str, override_prefs) -> List[int]:
    """
    A .pcap file usually contains multiple TCP streams, thus we perform pcap-level CH search following steps:

    1. Use the protocol as display filter to extract all the TCP stream numbers.
    2. For each stream, generate the capture using the stream number as display filter.
    3. For each capture, perform CH search.
    4. Return the frame index of Client Hello packet within each stream.

    Parameters
    ----------
    pcap_file : str
        The path to the .pcap file.
    protocol : str
    """
    ch_indices = []
    # Extract all the TCP streams (proxied traffic currently does not support UDP, so we ignore UDP streams)
    if protocol == 'normal':
        display_filter = "tls.handshake.type == 1"
    else:
        display_filter = f"{protocol} and tls.handshake.type == 1"
    with pyshark.FileCapture(pcap_file, 
                             display_filter=display_filter, 
                             tshark_path=tshark_path, 
                             override_prefs=override_prefs,
                             custom_parameters=custom_parameters) as cap:
        tcp_stream_numbers, _ = stream_number_extract(cap, lambda _: True)

    for tcp_stream_number in tcp_stream_numbers:
        with pyshark.FileCapture(pcap_file, 
                                 display_filter=f"tcp.stream eq {tcp_stream_number}", 
                                 tshark_path=tshark_path, 
                                 override_prefs=override_prefs,
                                 custom_parameters=custom_parameters) as cap:
            ch_searcher = PROTOCOL_CH_SEARCHER[protocol]
            ch_indices.append(ch_searcher.search(cap))

    return ch_indices


def host_CH_search(root_dir: str, protocol: str, host: str, tshark_path: str) -> List[int]:
    ch_indices = []

    pcap_dir = f"{root_dir}/{protocol}_capture/{host}"
    keylog_file = f"{pcap_dir}/keylog.txt"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        raise FileNotFoundError(f"Directory {pcap_dir} does not exist")
    
    override_prefs = default_override_prefs(protocol, os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))
    limit = 10
    for file in sorted([f for f in pcap_dir_path.iterdir() 
                        if f.is_file() and f.suffix in ['.pcapng', '.pcap']])[:limit]:
        
        logger.info(f"Processing {file}")
        try:
            ch_indices += pcap_CH_search(file, protocol, tshark_path, override_prefs)
        except Exception as e:
            logger.error(f"Error in file {file}: {e}")    
            continue
    return ch_indices

def main(input_root: str, output_root: str, host_list_file: str):
    PADDING = -2
    
    database_file = f"{output_root}/ch_search/database.csv"
    Path(database_file).parent.mkdir(parents=True, exist_ok=True)

    if not Path(database_file).exists():
        logger.info("Client Hello index database does not exist, create a new one")
        df = pd.DataFrame(columns=PROTOCOLS)
        df.to_csv(database_file, index=False)

    host_list = read_host_list(host_list_file)
    for host in host_list:
        ch_indices = {protocol: [] for protocol in PROTOCOLS}
        for protocol in PROTOCOLS:
            tshark_path = get_tshark_path(config_path, protocol)
            try:
                ch_indices[protocol] = host_CH_search(input_root, protocol, host, tshark_path)
            except Exception as e:
                logger.error(f"Error in host: {host}, Protocol: {protocol}: {e}")
                continue

        # Pad each key's array to the largest length
        max_length = max(len(indices) for indices in ch_indices.values())
        for protocol, indices in ch_indices.items():
            ch_indices[protocol] = indices + [PADDING] * (max_length - len(indices))

        df = pd.DataFrame(ch_indices)
        df.to_csv(database_file, mode='a', index=False, header=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--host", default="exp/data_analysis/host_list.txt", type=str, help="The host list file")
    args = parser.parse_args()
    logger.info("Task ch_search started")
    main(args.input_root, args.output_root, args.host)
    logger.info("Task ch_search completed")