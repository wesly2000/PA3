import argparse
import os
import random
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing as mp
from pathlib import Path
from typing import List
from joblib import Parallel, delayed

import numpy as np
import torch
from tqdm import tqdm
from WFlib.tools import data_processor


def process_TSAM(sequence, maximum_load_time, max_matrix_len):
    TSAM = np.zeros((2, max_matrix_len))
    for time, direction, size in sequence:
        if time == -2:
            break
        if direction > 0:
            if time >= maximum_load_time:
                TSAM[0][-1] += size
            else:
                idx = int(time * (max_matrix_len - 1) / maximum_load_time)
                TSAM[0][idx] += size
        if direction < 0:
            if time >= maximum_load_time:
                TSAM[1][-1] += size
            else:
                idx = int(time * (max_matrix_len - 1) / maximum_load_time)
                TSAM[1][idx] += size
    TSAM = TSAM / 1500.0
    return TSAM


def extract_TSAM(sequences, maximum_load_time=80, max_matrix_len=1800, num_workers=100):
    """
    Extract the Traffic Size Analysis Matrix (TSAM) from sequences.

    Parameters:
    sequences (ndarray): Input sequences.

    Returns:
    ndarray: Extracted TSAM features.
    """
    print(f"maximum_load_time: {maximum_load_time}, max_matrix_len: {max_matrix_len}")
    # with mp.Pool(processes=num_workers) as pool:
    #     TSAM = list(tqdm(pool.imap(process_TSAM, sequences), total=len(sequences)))
    TSAM = Parallel(n_jobs=-1)(
        delayed(process_TSAM)(sequence, maximum_load_time, max_matrix_len) for sequence in sequences
    )
    return np.array(TSAM)


# Set a fixed seed for reproducibility
fix_seed = 2024
random.seed(fix_seed)
torch.manual_seed(fix_seed)
np.random.seed(fix_seed)

# Argument parser for command-line options, arguments, and sub-commands
parser = argparse.ArgumentParser(description="Feature extraction")
parser.add_argument("--output_file", "-o", type=str, required=True, help="output file")
parser.add_argument("--input_file", "-i", type=str, required=True, help="input file")
parser.add_argument("-t", type=int, default=80)
parser.add_argument("-l", type=int, default=1800)


# Parse arguments
args = parser.parse_args()

data = np.load(args.input_file, allow_pickle=True)
X = data["raw"]
labels = data["labels"]
hosts = data["hosts"]

# Extract the Traffic Size Aggregation Matrix (TSAM)
tsam = extract_TSAM(X, args.t, args.l)
# Save the processed data into a new .npz file
np.savez(args.output_file, tsam=tsam, labels=labels, hosts=hosts)