import argparse
import os
import random

import numpy as np
from tqdm import tqdm

from WFlib.tools.augmentor import DyWinAugmentor, raw_to_dict, dict_to_raw


parser = argparse.ArgumentParser(description="DyWin data augmentation for raw traffic traces")
parser.add_argument("--input_file", "-i", type=str, required=True, help="Path to input .npz file")
parser.add_argument("--output_file", "-o", type=str, required=True, help="Path to output .npz file")
parser.add_argument("--n_aug", type=int, default=1, help="Number of augmented copies per sample")
parser.add_argument("--prob", type=float, default=0.3, help="Probability of applying mask/jitter per window")
parser.add_argument("--num_windows", type=int, default=9, help="Number of packet-count windows per trace")
parser.add_argument("--jitter_min", type=float, default=0.2, help="Minimum timestamp offset for jittered packets")
parser.add_argument("--jitter_max", type=float, default=1.0, help="Maximum timestamp offset for jittered packets")
parser.add_argument("--seed", type=int, default=2024, help="Random seed")
args = parser.parse_args()

random.seed(args.seed)
np.random.seed(args.seed)

if not os.path.exists(args.input_file):
    raise FileNotFoundError("Input file does not exist: {}".format(args.input_file))

if os.path.exists(args.output_file):
    print("Output file already exists: {}".format(args.output_file))
else:
    data = np.load(args.input_file, allow_pickle=True)
    X = data["raw"]
    y = data["labels"]
    hosts = data["hosts"]
    seq_len = X.shape[1]

    augmentor = DyWinAugmentor(
        prob=args.prob,
        num_windows=args.num_windows,
        jitter_min=args.jitter_min,
        jitter_max=args.jitter_max,
    )

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
            d_aug = augmentor.augment(d)
            row_aug = dict_to_raw(d_aug, seq_len)
            X_aug_list.append(row_aug)
            y_aug_list.append(y[i])

    X_aug = np.stack(X_aug_list, axis=0)
    y_aug = np.array(y_aug_list)

    np.savez_compressed(args.output_file, raw=X_aug, labels=y_aug, hosts=hosts)
    print("Saved {} augmented samples to {}".format(len(X_aug), args.output_file))
