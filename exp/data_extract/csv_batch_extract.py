"""
This file is used to extract the csv files from the database and related array storage.
"""

import argparse
import numpy as np

from WFlib.tools.formatter import CsvFormatter
from WFlib.tools.extractor import NpzDirExtractor, HSDBSExcludeCriterion, NpzRawExtractor
from WFlib.tools.augmentor import SlopeAugmentor
from WFlib.tools.capture import read_host_list
from WFlib.tools.extractor import sni_cover, PROTOCOL_STRIPPER

INTRINSIC_SNIS = ['firefox-settings-attachments.cdn.mozilla.net', 'firefox.settings.services.mozilla.com', 'content-signature-2.cdn.mozilla.net']
STAT_ROOT = "exp/data_extract"

def bound_gen(*ranges: tuple):
    lower_bounds = np.array([r[0] for r in ranges])
    upper_bounds = np.array([r[1] for r in ranges])
    return lower_bounds, upper_bounds

import logging
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the array and db files")
    parser.add_argument('-l', '--length', type=int, default=10000, help="The length of the expect feature vectors")
    parser.add_argument('-k', '--k', type=int, default=1, help="The k value for the HSDBS criterion")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    parser.add_argument('-p', '--protocol', default='normal', type=str, help="The protocol considered in the extraction")
    parser.add_argument('-f', '--filter_file', default=None, type=str, help="The SNI filter file")
    parser.add_argument('--bs_filter', action='store_true', help="The BS filter file")
    parser.add_argument('--coverage', default=0.4, type=float, help="BS coverage to filter")
    parser.add_argument('--strip', action='store_true', help="Strip the handshake packets")
    parser.add_argument('--feature', type=str, default="size", help="Feature type, options=[dir, size, raw]")
    parser.add_argument('--slope', type=str, default=None, help="The slope file")
    args = parser.parse_args()

    if args.slope is not None:
        slope_arr = np.load(args.slope)['slope_ratio']
        augmentor = SlopeAugmentor(slope_arr)
    else:
        augmentor = None

    stripper = None
    criteria = None
    SNI_filter = None
    lower_bounds, upper_bounds = None, None
    regenerate = 1

    if args.protocol.lower() in ['vmess', 'shadowsocks', 'trojan']:
        if args.bs_filter:
            total_cover = []
            for sni in INTRINSIC_SNIS:
                cover, _ = sni_cover(STAT_ROOT, args.protocol, sni, args.coverage)
                total_cover += cover
            lower_bounds, upper_bounds = bound_gen(*total_cover)
            
        if args.strip:
            stripper = PROTOCOL_STRIPPER[args.protocol.lower()]
    elif args.protocol == 'normal':
        # When needed, Normal could always leverage SNI filter
        if args.bs_filter:
            SNI_filter = read_host_list("exp/data_extract/tmp_filter.txt")
    else:
        raise ValueError(f"Invalid protocol: {args.protocol}")
    
    if lower_bounds is not None and upper_bounds is not None:
        criteria = HSDBSExcludeCriterion(lower_bounds=lower_bounds, upper_bounds=upper_bounds, threshold=0)

    if args.feature.lower() in ['size', 'dir']:
        extractor = NpzDirExtractor(criteria=criteria, stripper=stripper)
    elif args.feature.lower() in ['raw']:
        extractor = NpzRawExtractor(features={'direction', 'length', 'timestamp'}, criteria=criteria, stripper=stripper, augmentor=augmentor)
    else:
        raise NotImplementedError
    
    formatter = CsvFormatter(length=args.length)

    if args.filter_file is not None:
        SNI_filter = read_host_list(args.filter_file)

    array_dir = f'{args.dir}/arrays'
    db_file = f'{args.dir}/database.csv'
    logger.info("Task csv_batch_extract started")
    formatter.batch_extract(array_dir, db_file, args.protocol, args.output_file, SNI_filter, extractor, regenerate=regenerate)
    logger.info("Task csv_batch_extract completed")