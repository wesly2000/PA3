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
    feature_pkts = np.zeros((2, max_matrix_len))
    feature_size = np.zeros((2, max_matrix_len))
    for time, direction, size in sequence:
        if time == -2:
            break
        if direction > 0:
            if time >= maximum_load_time:
                feature_pkts[0][-1] += 1
                feature_size[0][-1] += size
            else:
                idx = int(time * (max_matrix_len - 1) / maximum_load_time)
                feature_pkts[0][idx] += 1
                feature_size[0][idx] += size
        if direction < 0:
            if time >= maximum_load_time:
                feature_pkts[1][-1] += 1
                feature_size[1][-1] += size
            else:
                idx = int(time * (max_matrix_len - 1) / maximum_load_time)
                feature_pkts[1][idx] += 1
                feature_size[1][idx] += size
    feature_size = feature_size / 1500.0
    TSAM = np.array([feature_pkts, feature_size])
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
parser.add_argument("--dataset", "-d", type=str, required=True, default="gpts", help="Dataset name")
parser.add_argument("--in_file", type=str, default="train", help="input file")
parser.add_argument("-t", type=int, default=80)
parser.add_argument("-l", type=int, default=1800)


# Parse arguments
args = parser.parse_args()
in_path = Path("./data/split", args.dataset)
if not in_path.exists():
    raise FileNotFoundError(f"The dataset path does not exist: {in_path.resolve()}")

# Define output file path
if args.t != 80 or args.l != 1800:
    out_file = in_path / f"tsam_{args.t}_{args.l}_{args.in_file}.npz"
else:
    out_file = in_path / f"tsam_{args.in_file}.npz"

# # If the output file does not exist, process the input file
if not os.path.exists(out_file):
    # Load dataset from the specified .npz file
    data = np.load(in_path / f"{args.in_file}.npz", allow_pickle=True)
    X = data["X"]
    y = data["y"]
    p = data["p"]
    # Extract the Traffic Size Aggregation Matrix (TSAM)
    X = extract_TSAM(X, args.t, args.l)
    # Print processing information
    print(f"{args.in_file} process done: X = {X.shape}, y = {y.shape}")
    # Save the processed data into a new .npz file
    np.savez(out_file, X=X, y=y, p=p)
else:
    # Print a message if the output file already exists
    print(f"{out_file} has been generated.")
