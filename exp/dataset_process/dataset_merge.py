import numpy as np
from typing import List
from pathlib import Path
import argparse

def merge_npz_files(input_paths, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load all files
    npzs = [np.load(path) for path in input_paths]
    
    # Verify keys match
    keys = set(npzs[0].keys())
    if any(set(npz.keys()) != keys for npz in npzs):
        raise ValueError("NPZ files have different keys")
    
    # Concatenate arrays
    merged = {key: np.concatenate([npz[key] for npz in npzs], axis=0) for key in keys}
    
    # Save
    np.savez_compressed(output_path, **merged)
    return output_path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_file', type=str, nargs='+', help="input datasets")
    parser.add_argument('-o', '--output_file', type=str, help="output merged dataset")
    args = parser.parse_args()

    merge_npz_files(args.input_file, args.output_file)