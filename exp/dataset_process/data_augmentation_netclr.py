import numpy as np
import os
import argparse
import random
from tqdm import tqdm

from pa3.tools.augmentor import NetCLRAugmentor, raw_to_dict, dict_to_raw

parser = argparse.ArgumentParser(description="Data augmentation for raw traffic traces")
parser.add_argument("--input_file", "-i", type=str, required=True, help="Path to input .npz file")
parser.add_argument("--output_file", "-o", type=str, required=True, help="Path to output .npz file")
parser.add_argument("--n_aug", type=int, default=1, help="Number of augmented copies per sample")
parser.add_argument("--inflate_mode", type=str, default="resample", choices=["resample", "interpolate"],
                    help="Inflate strategy for change_content")
parser.add_argument("--merge_timestamp_mode", type=str, default="keep", choices=["keep", "compress"],
                    help="Timestamp strategy for merge_incoming_bursts")
parser.add_argument("--seed", type=int, default=2024, help="Random seed")
parser.add_argument("--cdf_file", type=str, default=None,
                    help="Path to pre-computed CDF .npz file. If not provided, no CDFs are used.")
args = parser.parse_args()

random.seed(args.seed)
np.random.seed(args.seed)

if not os.path.exists(args.input_file):
    raise FileNotFoundError(f"Input file does not exist: {args.input_file}")

if os.path.exists(args.output_file):
    print(f"Output file already exists: {args.output_file}")
else:
    data = np.load(args.input_file, allow_pickle=True)
    X = data["raw"]
    y = data["labels"]
    hosts = data["hosts"]
    seq_len = X.shape[1]

    if args.cdf_file is not None:
        cdf_data = np.load(args.cdf_file, allow_pickle=True)
        cdfs = {}
        for key in cdf_data.files:
            val = cdf_data[key]
            if key in ("outgoing_burst_sizes", "outgoing_packet_sizes"):
                cdfs[key] = val.tolist()
            elif key in ("outgoing_delays",):
                cdfs[key] = val.tolist()
            else:
                cdfs[key] = val
        augmentor = NetCLRAugmentor(**cdfs)
    else:
        augmentor = NetCLRAugmentor()

    X_aug_list = []
    y_aug_list = []

    for i in tqdm(range(len(X)), desc="Augmenting"):
        d = raw_to_dict(X[i])
        if len(d["direction"]) == 0:
            for _ in range(args.n_aug):
                X_aug_list.append(np.zeros((seq_len, 3), dtype=np.float64))
                y_aug_list.append(y[i])
            continue

        for _ in range(args.n_aug):
            d_aug = augmentor.augment(d,
                                      inflate_mode=args.inflate_mode,
                                      merge_timestamp_mode=args.merge_timestamp_mode)
            row_aug = dict_to_raw(d_aug, seq_len)
            X_aug_list.append(row_aug)
            y_aug_list.append(y[i])

    X_aug = np.stack(X_aug_list, axis=0)
    y_aug = np.array(y_aug_list)

    np.savez_compressed(args.output_file, raw=X_aug, labels=y_aug, hosts=hosts)
    print(f"Saved {len(X_aug)} augmented samples to {args.output_file}")