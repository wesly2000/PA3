"""
Extract features from a .csv file, and store the features into a database.
"""

import pandas as pd
from typing import Set, List, Union
from pathlib import Path
import os
import argparse
import logging

from WFlib.tools.extractor import *
from WFlib.utils.config import default_override_prefs
from WFlib.utils.config import get_config
from WFlib.tools.capture import read_host_list

logger = logging.getLogger(__name__)

config_path = Path.cwd() / 'config.ini'
if not config_path.exists():
    tshark_path = "tshark"
else:
    config = get_config(config_path)
    tshark_path = config['tshark'].get('tshark_path', fallback="tshark")

src = ["58.206.207.126", "192.168.5.5", "10.4.0.3", "192.168.5.7"]
PROTOCOLS = ['normal', 'vmess']

def extract_csv_db_per_host(root: str, protocol: str, host: str, host_filter: Set[str], display_filter: str='tcp', db: pd.DataFrame=None):
    pcap_dir = f"{root}/{protocol}_capture/{host}"
    keylog_file = f"{pcap_dir}/keylog.txt"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        raise FileNotFoundError(f"Directory {pcap_dir} does not exist")
    
    override_prefs = default_override_prefs(protocol, keylog_file=None, proxy_keylog_file=os.path.abspath(proxy_keylog_file))

    result = multi_pcap_extract(tshark_path, pcap_dir, host_filter, display_filter, protocol, override_prefs, src, db)

    return result


def extract_csv_db(root: str, host_list: Set[str], database_file: str, host_filter: Set[str], display_filter: str='tcp'):
    db = pd.read_csv(database_file)[['host', 'id', 'protocol']].drop_duplicates()

    for host in host_list:
        for protocol in PROTOCOLS:
            logger.info(f"Host: {host}, Protocol: {protocol}")
            result = extract_csv_db_per_host(root, protocol, host, host_filter, display_filter, db)
            df = pd.DataFrame(columns=['host', 'id', 'sni', 'stream', 'transport', 'protocol', 'feature'], data=result)
            df.to_csv(database_file, mode='a', index=False, header=False)
            

def main(input_root: str, output_root: str, host_list_file: str, host_filter_file: str):
    database_file = f"{output_root}/csv_db_extract/database.csv"
    Path(database_file).parent.mkdir(parents=True, exist_ok=True)
    if not Path(database_file).exists():
        logger.info("CSV DB database does not exist, create a new one")
        df = pd.DataFrame(columns=['host', 'id', 'sni', 'stream', 'transport', 'protocol', 'feature'])
        df.to_csv(database_file, index=False)

    host_list = read_host_list(host_list_file)
    host_filter = read_host_list(host_filter_file)

    extract_csv_db(input_root, host_list, database_file, host_filter)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--host", default="exp/data_extract/host_list.txt", type=str, help="The host list file")
    parser.add_argument("-f", "--filter", default="exp/data_extract/filter.txt", help="The host filter file")
    args = parser.parse_args()

    logger.info("Task csv_db_extract started")
    main(args.input_root, args.output_root, args.host, args.filter)
    logger.info("Task csv_db_extract completed")