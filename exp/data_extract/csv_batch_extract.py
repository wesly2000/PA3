"""
This file is used to extract the csv files from the database and related array storage.
"""

import argparse

from WFlib.tools.formatter import CsvFormatter
from WFlib.tools.extractor import NpzHSDBSExtractor, HSDBSCriterion, NpzDirExtractor, VmessStripper

import logging
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the array and db files")
    parser.add_argument('-l', '--length', type=int, default=5000, help="The length of the expect feature vectors")
    parser.add_argument('-k', '--k', type=int, default=120, help="The k value for the HSDBS criterion")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    parser.add_argument('-p', '--protocol', default='normal', type=str, help="The protocol considered in the extraction")
    args = parser.parse_args()

    formatter = CsvFormatter(length=args.length)
    criterion = HSDBSCriterion(k = args.k)
    extractor = NpzHSDBSExtractor(ignore_control_packets=True, criterion=criterion)
    # extractor = NpzDirExtractor(stripper=VmessStripper())

    array_dir = f'{args.dir}/arrays'
    db_file = f'{args.dir}/database.csv'
    logger.info("Task csv_batch_extract started")
    formatter.batch_extract(array_dir, db_file, args.protocol, args.output_file, extractor)
    logger.info("Task csv_batch_extract completed")