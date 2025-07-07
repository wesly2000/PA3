"""
This file is used to extract the csv files from the database and related array storage.
"""

import argparse
import numpy as np
from WFlib.tools.formatter import CsvFormatter
from WFlib.tools.extractor import NpzHSDBSExtractor, HSDBSCriterion, NpzDirExtractor, VmessStripper, BSExcludeCriterion, LengthExcludeCriterion, make_split_weight_generator, LengthCriterion
from WFlib.tools.capture import read_host_list

TROJAN_RANGES = [(2200000, 2400000), (10400, 11200), (12800, 13600), (15200, 16800), (80000, 120000)]
VMESS_RANGES = [(2240000, 2272000), (6500, 7500), (12000, 12500), (72000, 74000), (84000, 86000)]
SHADOWSOCKS_RANGES = [(2280000, 2336000), (7500, 8000), (12500, 13000), (84000, 90000), (105000, 108000)]

def bound_gen(*ranges: tuple):
    lower_bounds = np.array([r[0] for r in ranges])
    upper_bounds = np.array([r[1] for r in ranges])
    return lower_bounds, upper_bounds

import logging
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the array and db files")
    parser.add_argument('-l', '--length', type=int, default=5000, help="The length of the expect feature vectors")
    parser.add_argument('-k', '--k', type=int, default=1, help="The k value for the HSDBS criterion")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    parser.add_argument('-p', '--protocol', default='normal', type=str, help="The protocol considered in the extraction")
    parser.add_argument('-f', '--filter_file', default=None, type=str, help="The SNI filter file")
    parser.add_argument('--bs_filter', default=False, type=bool, help="The BS filter file")
    args = parser.parse_args()

    normal_filter_file = None

    regenerate = 1
    if args.bs_filter:
        if args.protocol == 'vmess':
            lower_bounds, upper_bounds = bound_gen(*VMESS_RANGES)
            criteria = [
                BSExcludeCriterion(lower_bounds=lower_bounds, upper_bounds=upper_bounds, threshold=0),
                ]
            extractor = NpzDirExtractor(criteria=criteria)
        elif args.protocol == 'shadowsocks':
            lower_bounds, upper_bounds = bound_gen(*SHADOWSOCKS_RANGES)
            criteria = [
                BSExcludeCriterion(lower_bounds=lower_bounds, upper_bounds=upper_bounds, threshold=0), 
                ]
            extractor = NpzDirExtractor(criteria=criteria)
        elif args.protocol == 'trojan':
            lower_bounds, upper_bounds = bound_gen(*TROJAN_RANGES)
            criteria = [
                BSExcludeCriterion(lower_bounds=lower_bounds, upper_bounds=upper_bounds, threshold=0),
                ]
            extractor = NpzDirExtractor(criteria=criteria)
        elif args.protocol == 'normal':
            normal_filter_file = "exp/data_extract/tmp_filter.txt"
            extractor = NpzDirExtractor()
        else:
            raise ValueError(f"Invalid protocol: {args.protocol}")
    if not args.bs_filter:
        extractor = NpzDirExtractor()
    formatter = CsvFormatter(length=args.length)
    if args.filter_file:
        SNI_filter = read_host_list(args.filter_file)
    elif normal_filter_file:
        SNI_filter = read_host_list(normal_filter_file)
    else:
        SNI_filter = None   

    array_dir = f'{args.dir}/arrays'
    db_file = f'{args.dir}/database.csv'
    logger.info("Task csv_batch_extract started")
    formatter.batch_extract(array_dir, db_file, args.protocol, args.output_file, SNI_filter, extractor, regenerate=regenerate)
    logger.info("Task csv_batch_extract completed")