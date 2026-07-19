import pandas as pd
import numpy as np
from typing import List, Set
import pyshark
from pathlib import Path
from tqdm import tqdm
import argparse
import logging

from pa3.tools.capture import *
from pa3.utils.statistics import *
from pa3.utils.config import default_override_prefs, get_tshark_path

logger = logging.getLogger(__name__)

PROTOCOLS = ['normal', 'vmess', 'shadowsocks', 'trojan']
custom_parameters=["-2"]
config_path = Path.cwd() / 'config.ini'


def h2_stream_analysis_per_sni(file: Path, host_filter: Set[str], custom_parameters = None, override_prefs = None, tshark_path = 'tshark'):
    """
    Count the average number of HTTP/2 streams and available HTTP/2 streams (streams with HTTP/2 DATA frames).
    To make these statistics reusable, store them into .csv files. The key is (host, SNI, protocol).

    Params
    ------
    
    """
    origin_cap = pyshark.FileCapture(input_file=file, 
                                     display_filter="tls.handshake.type == 1",
                                     custom_parameters=custom_parameters, 
                                     override_prefs=override_prefs,
                                     tshark_path=tshark_path
                                     )

    SNIs = SNI_extract(origin_cap)

    origin_cap.close()
    filtered_SNIs = SNIs - host_filter

    for SNI in filtered_SNIs:
        # Fetch the number of all HTTP/2 streams for the same SNI
        tcp_stream_numbers, _ = SNI_stream_extract(file, [SNI], custom_parameters, override_prefs, tshark_path)
        h2_stream_number = len(tcp_stream_numbers)
        # Fetch the number of all available HTTP/2 streams for the same SNI
        try:
            tcp_stream_numbers = h2data_SNI_intersect(file, [SNI], None, custom_parameters, override_prefs, tshark_path)
        except Exception as e:
            logger.error(f"Error in file {file}: {e}")
            continue
        available_h2_stream_number = len(tcp_stream_numbers)

        yield SNI, h2_stream_number, available_h2_stream_number


def h2_stream_analysis_per_host(root: str, protocol: str, host: str, host_filter: Set[str], tshark_path) -> pd.DataFrame:
    """
    Count the average number of HTTP/2 streams and available HTTP/2 streams (streams with HTTP/2 DATA frames).
    To make these statistics reusable, store them into .csv files. The key is (host, SNI, protocol).

    Params
    ------
    root : str
        The root of all capture (.pcap(ng)) files.
    """
    df = pd.DataFrame(columns=['host', 'SNI', 'protocol', 'h2_avg', 'h2_std', 'avail_h2_avg', 'avail_h2_std'])
    pcap_dir = f"{root}/{protocol}_capture/{host}"
    keylog_file = f"{pcap_dir}/keylog.txt"
    proxy_keylog_file = f"{pcap_dir}/proxy_keylog.txt"

    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        raise FileNotFoundError(f"Directory {pcap_dir} does not exist")

    override_prefs = default_override_prefs(protocol, os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))
    
    stats = dict()
    limit = 20
    for file in sorted([f for f in pcap_dir_path.iterdir() 
                        if f.is_file() and f.suffix in ['.pcapng', '.pcap']])[:limit]:
            logger.info(f"Processing {file}")
            for SNI, h2, avail_h2 in h2_stream_analysis_per_sni(file, host_filter,   
                                                                    custom_parameters=custom_parameters, 
                                                                    override_prefs=override_prefs,
                                                                    tshark_path=tshark_path):
                if SNI not in stats:
                    stats[SNI] = {'h2': [h2], 'avail_h2': [avail_h2]}
                else:
                    stats[SNI]['h2'].append(h2)
                    stats[SNI]['avail_h2'].append(avail_h2)

    if len(stats[SNI]['h2']) > 1:  # If there are more than 1 elements, do IQR filter
        lower_bound, upper_bound = IQR_bound(stats[SNI]['avail_h2'])
        stats[SNI]['avail_h2'] = [v for v in stats[SNI]['avail_h2'] if lower_bound <= v <= upper_bound]

        lower_bound, upper_bound = IQR_bound(stats[SNI]['h2'])
        stats[SNI]['h2'] = [v for v in stats[SNI]['h2'] if lower_bound <= v <= upper_bound]

    # Write the result to the database
    for SNI in stats:
        df.loc[len(df)] = [host, SNI, protocol, 
               np.mean(stats[SNI]['h2']), np.std(stats[SNI]['h2']), 
               np.mean(stats[SNI]['avail_h2']), np.std(stats[SNI]['avail_h2'])]
        
    return df
        
def h2_stream_analysis(root: str, host_list: Set[str], database_file: str, host_filter: Set[str]):
    existed_df = pd.read_csv(database_file)[['host', 'protocol']]
    for host in sorted(host_list):
        for protocol in PROTOCOLS:
            tshark_path = get_tshark_path(config_path, protocol)
            logger.info(f"Host: {host}, Protocol: {protocol}")
            # Check if the host with the given protocol has been computed
            if ((existed_df['host'] == host) & (existed_df['protocol'] == protocol)).any():
                logger.info(f"Host: {host}, Protocol: {protocol} has been computed, skip")
                continue
            try:
                df = h2_stream_analysis_per_host(root, protocol, host, host_filter, tshark_path)
            except Exception as e:
                logger.error(f"Error in host: {host}, Protocol: {protocol}: {e}")
                continue
            df.to_csv(database_file, mode='a', index=False, header=False)

def main(input_root: str, output_root: str, host_list_file: str, host_filter_file: str):
    database_file = f"{output_root}/h2_stream_analysis/database.csv"
    Path(database_file).parent.mkdir(parents=True, exist_ok=True)
    if not Path(database_file).exists():
        logger.info("H2 stream database does not exist, create a new one")
        df = pd.DataFrame(columns=['host', 'SNI', 'protocol', 'h2_avg', 'h2_std', 'avail_h2_avg', 'avail_h2_std'])
        df.to_csv(database_file, index=False)
    host_list = read_host_list(host_list_file)
    host_filter = read_host_list(host_filter_file)

    h2_stream_analysis(input_root, host_list, database_file, host_filter)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument("-i", "--input_root", required=True, type=str, help="The root directory of the capture and keylog")
    parser.add_argument("-o", "--output_root", required=True, type=str, help="The root directory of the output")
    parser.add_argument("--host", default="exp/data_analysis/host_list.txt", type=str, help="The host list file")
    parser.add_argument("-f", "--filter", default="exp/data_analysis/filter.txt", help="The host filter file")
    args = parser.parse_args()
    logger.info("Task http2_stream_analysis started")
    main(args.input_root, args.output_root, args.host, args.filter)
    logger.info("Task http2_stream_analysis completed")