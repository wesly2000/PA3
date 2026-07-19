# Generates the transformed traffic features. 
import numpy as np
import os
import argparse
from typing import List
import time
import random
import torch
from tqdm import tqdm
from multiprocessing import Process
from pa3.tools import data_processor

# Set a fixed seed for reproducibility
fix_seed = 2024
random.seed(fix_seed)
torch.manual_seed(fix_seed)
np.random.seed(fix_seed)

parser = argparse.ArgumentParser(description='Feature extraction')
# parser.add_argument("--dataset", type=str, required=True, default="Undefended", help="Dataset name")
parser.add_argument("--seq_len", type=int, default=5000, help="Input sequence length")
parser.add_argument("--input_file", "-i", type=str, help="input file")
parser.add_argument("--output_file", "-o", type=str, required=True, help="output file")
parser.add_argument("--feature", "-f", type=str, required=True, help="The target feature in the output data, option=[TAM, TSAM]")
parser.add_argument("--in_feature", type=str, default="raw", help="The original feature to be transformed")

# Params specific to TAM/TASM
parser.add_argument("-t", type=int, default=80, help="Maximum load time for packets")
parser.add_argument("-l", type=int, default=1800, help="Maximum length of the matrix")
args = parser.parse_args()

if not os.path.exists(args.input_file):
    raise FileNotFoundError(f"The dataset path does not exist: {args.input_file}")

feature = args.feature.lower()

if not os.path.exists(args.output_file):
    data = np.load(args.input_file, allow_pickle=True)
    X = data[args.in_feature]

    # Data alignment
    if args.in_feature == 'raw':
        if X.shape[1] > args.seq_len:  # Truncate along axis 1
            X = X[:,:args.seq_len,:]
        else:
            padding_num = args.seq_len - X.shape[1]
            pad_width = [(0, 0), (0, padding_num), (0, 0)]
            X = np.pad(X, pad_width=pad_width, mode="constant", constant_values=0)  # Pad the sequence with zeros
    else:
        X = data_processor.length_align(X, args.seq_len)

    transformed = {'labels': data["labels"], 'hosts': data["hosts"]}
    
    if feature == 'tam':
        transformed[feature] = data_processor.extract_TAM(X, args.t, args.l)
    elif feature == 'tsam':
        transformed[feature] = data_processor.extract_TSAM(X, args.t, args.l)
    elif feature == 'mtaf':
        transformed[feature] = data_processor.extract_MTAF(X)
    elif feature == 'taf':
        transformed[feature] = data_processor.extract_TAF(X)   
    elif feature == 'tsaf':
        transformed[feature] = data_processor.extract_TAF(X, ignore_size=False)  
    elif feature == 'size':
        transformed[feature] = data_processor.extract_SIZE(X, args.seq_len)  
    elif feature == 'dt':
        transformed[feature] = data_processor.extract_DT(X, args.seq_len)  
    else:
        raise NotImplementedError("Feature not implemented")
    
    np.savez_compressed(args.output_file, **transformed)
else:
    print(f"File {args.output_file} already exists")