"""
This file is used to extract the csv files from the database and related array storage.
"""

import argparse
import numpy as np
from WFlib.tools.formatter import CsvFormatter
from WFlib.tools.extractor import NpzHSDBSExtractor, HSDBSCriterion, NpzDirExtractor, VmessStripper, BSExcludeCriterion
from WFlib.tools.capture import read_host_list

import logging
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the array and db files")
    parser.add_argument('-l', '--length', type=int, default=5000, help="The length of the expect feature vectors")
    parser.add_argument('-k', '--k', type=int, default=0, help="The k value for the HSDBS criterion")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    parser.add_argument('-p', '--protocol', default='normal', type=str, help="The protocol considered in the extraction")
    parser.add_argument('-f', '--filter_file', default=None, type=str, help="The SNI filter file")
    parser.add_argument('--bs_filter', default=False, type=bool, help="The BS filter file")
    args = parser.parse_args()

    normal_filter_file = None

    if args.bs_filter:
        if args.protocol == 'vmess':
            # lower_bounds = np.array([2240000, 6500, 12000, 72000, 84000])   # threshold 0
            # upper_bounds = np.array([2272000, 7500, 12500, 74000, 86000])  
            # lower_bounds = np.array([66000, 79000, 2169000, 5400, 10200])     # threshold 40
            # upper_bounds = np.array([68000, 81000, 2178000, 6000, 10800])
            lower_bounds = np.array([2120000, 5500, 9500,  64000, 76800])     # threshold 60
            upper_bounds = np.array([2146000, 6000, 10000, 66400, 79200])
        elif args.protocol == 'shadowsocks':
            # lower_bounds = np.array([2280000, 7500, 12500, 84000, 105000])  # threshold 0
            # upper_bounds = np.array([2336000, 8000, 13000, 90000, 108000])
            # lower_bounds = np.array([80000, 97000, 2205000, 6000, 10200])   # threshold 40
            # upper_bounds = np.array([81000, 99000, 2214000, 6600, 10800])
            lower_bounds = np.array([2180000, 5600, 10000, 76000, 94000])     # threshold 60
            upper_bounds = np.array([2280000, 6400, 10400, 80000, 96000])
        elif args.protocol == 'normal':
            normal_filter_file = "exp/data_extract/tmp_filter.txt"
        else:
            raise ValueError(f"Invalid protocol: {args.protocol}")

    formatter = CsvFormatter(length=args.length)
    # criterion = HSDBSCriterion(k = args.k)
    criterion = BSExcludeCriterion(lower_bounds=lower_bounds, upper_bounds=upper_bounds, threshold=60) if args.bs_filter and args.protocol != 'normal' else None
    # extractor = NpzHSDBSExtractor(ignore_control_packets=True, criterion=criterion)
    extractor = NpzDirExtractor(criterion=criterion)
    if args.filter_file:
        SNI_filter = read_host_list(args.filter_file)
    elif normal_filter_file:
        SNI_filter = read_host_list(normal_filter_file)
    else:
        SNI_filter = None   

    array_dir = f'{args.dir}/arrays'
    db_file = f'{args.dir}/database.csv'
    logger.info("Task csv_batch_extract started")
    formatter.batch_extract(array_dir, db_file, args.protocol, args.output_file, SNI_filter, extractor)
    logger.info("Task csv_batch_extract completed")