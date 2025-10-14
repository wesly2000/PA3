"""
Extract features from a .csv file, and store the features into a database.
"""

import pandas as pd
from typing import Set, List, Union, Optional
from pathlib import Path
import os
import argparse
import logging
import multiprocessing as mp
from functools import partial

from WFlib.tools.extractor import *
from WFlib.utils.config import default_override_prefs, get_tshark_path
from WFlib.tools.capture import read_host_list
from WFlib.utils.config import COMMON_SOURCE_IP

logger = logging.getLogger(__name__)

config_path = Path.cwd() / 'config.ini'

src = COMMON_SOURCE_IP
PROTOCOLS = ['vmess', 'shadowsocks', 'trojan']

def extract_csv_db_per_host_per_protocol(root: str, protocol: str, host: str, host_filter: Set[str], display_filter: str='tcp', db: Optional[pd.DataFrame]=None, tshark_path: str='tshark'):
    pcap_dir = f"{root}/{protocol}_capture/{host}"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        raise FileNotFoundError(f"Directory {pcap_dir} does not exist")
    
    override_prefs = default_override_prefs(protocol, keylog_file=None, proxy_keylog_file=os.path.abspath(proxy_keylog_file))

    result = multi_pcap_extract(tshark_path, pcap_dir, host_filter, display_filter, protocol, override_prefs, src, db)

    return result


def extract_csv_db_per_host(host: str, root: str, host_filter: set, 
                         display_filter: str, db: pd.DataFrame, database_file: str, array_dir: str,
                         write_lock) -> None:
    """
    Process a single host-protocol combination and write results to the database file.
    Uses a lock to prevent write conflicts.
    """
    result = []
    for protocol in PROTOCOLS:
        tshark_path = get_tshark_path(config_path, protocol)
        try:
            logger.info(f"Processing Host: {host}, Protocol: {protocol}")
            result.extend(extract_csv_db_per_host_per_protocol(root, protocol, host, host_filter, display_filter, db, tshark_path))
            
        except Exception as e:
            logger.error(f"Error processing Host: {host}, Protocol: {protocol}: {e}")

    for i in range(len(result)):
        array_name = array_path(host, result[i]['id'], result[i]['transport'], result[i]['stream'], result[i]['protocol'])
        np.savez_compressed(f"{array_dir}/{array_name}", direction=result[i]['direction'], timestamp=result[i]['timestamp'], length=result[i]['length'])

    df = pd.DataFrame(columns=['host', 'id', 'sni', 'stream', 'transport', 'protocol'], 
                    data=result)
    
    with write_lock:
        df.to_csv(database_file, mode='a', index=False, header=False)

def main(input_root: str, output_root: str, host_list_file: str, host_filter_file: str, 
         display_filter: Optional[str] = None, n_processes: Optional[int] = None):
    database_file = f"{output_root}/csv_db_extract/database.csv"
    array_dir = f"{output_root}/csv_db_extract/arrays"
    Path(database_file).parent.mkdir(parents=True, exist_ok=True)
    Path(array_dir).mkdir(parents=True, exist_ok=True)
    if not Path(database_file).exists():
        logger.info("CSV database does not exist, create a new one")
        df = pd.DataFrame(columns=['host', 'id', 'sni', 'stream', 'transport', 'protocol'])
        df.to_csv(database_file, index=False)

    host_list = read_host_list(host_list_file)
    host_filter = read_host_list(host_filter_file)
    db = pd.read_csv(database_file)[['host', 'id', 'protocol']] if Path(database_file).exists() else None

    # Create a lock for file writing
    manager = mp.Manager()
    write_lock = manager.Lock()
    
    # Create a process pool
    n_processes = n_processes or mp.cpu_count()
    logger.info(f"Using {n_processes} processes")
    
    # Create tasks for each host-protocol combination
    tasks = [(host, input_root, host_filter, display_filter, db, database_file, array_dir, write_lock) for host in host_list]
    
    # Process tasks in parallel
    with mp.Pool(n_processes) as pool:
        pool.starmap(extract_csv_db_per_host, tasks)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--host", default="exp/data_extract/host_list.txt", type=str, help="The host list file")
    parser.add_argument("-f", "--filter", default="exp/data_extract/filter.txt", help="The host filter file")
    parser.add_argument("-p", "--processes", type=int, help="Number of processes to use (default: CPU count)")
    args = parser.parse_args()
    
    logger.info(f"Task csv_db_extract started, n_processes: {args.processes}")
    main(args.input_root, args.output_root, args.host, args.filter, n_processes=args.processes)
    logger.info("Task csv_db_extract completed")