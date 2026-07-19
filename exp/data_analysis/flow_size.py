import argparse
import numpy as np
import pandas as pd

from pa3.tools.capture import read_host_list
from pa3.tools.extractor import array_path
import logging
logger = logging.getLogger(__name__)
INTRINSIC_SNIS = ['firefox-settings-attachments.cdn.mozilla.net', 'firefox.settings.services.mozilla.com', 'content-signature-2.cdn.mozilla.net']

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--protocol', default='normal', type=str, help="The protocol considered in the extraction")
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the array and db files")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    args = parser.parse_args()

    if args.protocol not in ['vmess', 'shadowsocks', 'trojan']:
        raise ValueError(f"Invalid protocol: {args.protocol}")
    
    array_dir = f'{args.dir}/arrays'
    db_file = f'{args.dir}/database.csv'
    SNI_filter = None


    db = pd.read_csv(db_file).query(f"protocol == '{args.protocol}'")[['host', 'id', 'stream', 'transport', 'sni']]
    db = db[~db['sni'].isin(INTRINSIC_SNIS)]
    db = db[['host', 'id', 'stream', 'transport']]

    # Fetch all the hosts from the database and sort them alphabetically
    hosts = sorted(db['host'].unique())
    flow_size = []

    for host in hosts:
        logger.info(f"Processing host: {host}, protocol: {args.protocol}")
        for pcap_id in db[db['host'] == host]['id'].unique():
            host_db = db[(db['host'] == host) & (db['id'] == int(pcap_id))]
            paths = host_db.apply(lambda row: f'{array_dir}/{array_path(row["host"], row["id"], row["transport"], row["stream"], args.protocol)}', axis=1)
            for path in paths:
                flow_size.append(np.sum(np.load(path)['length']))

    np.savez_compressed(args.output_file, flow_size=flow_size)
                