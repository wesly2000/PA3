import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import numpy as np
import argparse

from pa3.utils.statistics import compute_outgoing_cdfs
import logging
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description="Extract outgoing burst CDFs from a raw .npz dataset")
parser.add_argument("--input_file", "-i", type=str, required=True,
                    help="Path to input .npz file (must contain 'raw' key)")
parser.add_argument("--output_file", "-o", type=str, required=True,
                    help="Path to output .npz file for the CDFs")
args = parser.parse_args()

if not os.path.exists(args.input_file):
    raise FileNotFoundError(f"Input file does not exist: {args.input_file}")

if os.path.exists(args.output_file):
    logger.info(f"The file {args.output_file} already exists")
    exit(0)

data = np.load(args.input_file, allow_pickle=True)
X = data["raw"]
print(f"Loaded {len(X)} samples from {args.input_file}")

cdfs = compute_outgoing_cdfs(X)

saveable = {k: v for k, v in cdfs.items() if v is not None}
np.savez(args.output_file, **saveable)
print(f"Saved CDFs to {args.output_file}")
for k, v in saveable.items():
    v_arr = np.asarray(v)
    print(f"  {k}: {v_arr.shape} {v_arr.dtype}")
