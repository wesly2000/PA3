from WFlib.tools.analyzer import Line 
from WFlib.utils.statistics import IQR_bound
from WFlib.tools.extractor import NpzExtractor 
from WFlib.tools.formatter import array_path
 
from typing import List, Tuple, Union, Set
import numpy as np
from numpy.typing import ArrayLike
import torch
from torch import nn
import matplotlib.pyplot as plt
import pandas as pd
from numpy.lib.npyio import NpzFile

def generate_byte_stream(segment_byte_map: dict, cutoff: int, abs_lower_frame_numbers: List[int]) -> np.ndarray:
        """
        Generate segment index for a segment-byte map with the cutoff. We illustrate the generate process with 
        an example, where the upper_abs_byte_map is {226: (0, 3), 228: (3, 5), 230: (5, 12)}, and cutoff is 9. 
        Note that the right point of each interval is exclusive. 
        
        The segment index is generated in the relative sense, i.e., 226 is the 0-th segment, 228 is the 
        1-st, 230 is the 2-nd. Therefore, the result is [0, 0, 0, 1, 1, 2, 2, 2, 2].
        """
        rel_lower_frame_numbers = {abs_frame_number: i for i, abs_frame_number in enumerate(abs_lower_frame_numbers)}
        byte_segment = np.array([0] * cutoff)

        for seg_idx in segment_byte_map:
            for cover in segment_byte_map[seg_idx]:
                byte_segment[cover[0] : min(cutoff, cover[1])] = rel_lower_frame_numbers[seg_idx]

        return byte_segment

def generate_byte_segment(lines: List[Line]) -> List[np.ndarray]:
    """
    Generate segment index for each line, then return the byte segment arrays.
    
    Since each line may differ in size, the smallest one is used as a cutoff. To avoid outliers, we
    use IQR to filter out those lines that are too short.
    """
    byte_count_arr = np.array([line.byte_counter for line in lines])
    if byte_count_arr.shape[0] > 1:
        lower_bound, upper_bound = IQR_bound(byte_count_arr)

        # Filter out outliers (lines with byte_counter within the IQR range)
        filtered_lines = [line for line in lines if lower_bound <= line.byte_counter <= upper_bound]

        # Calculate the minimum byte_counter among the filtered lines
    else:
        # No need to do IQR when only 1 elements within (it occurs in some tests)
        filtered_lines = lines

    min_byte_count = min([line.byte_counter for line in filtered_lines])

    result = []
    for i, line in enumerate(filtered_lines):
        try:
            result.append(generate_byte_stream(line.upper_abs_byte_map, min_byte_count, line.lower_abs_frame_numbers)) 
        except Exception as e:
            print(f"Error in Line {i}: {e}")
    return result

def get_activations(model: nn.Module, input_data: torch.Tensor, layer_names: List[str], device: str) -> List[np.ndarray]:

    activation = dict()
    X, y = input_data[0].to(device), input_data[1].to(device)
    def get_activation(name):
        def hook(layer: nn.Module, input, output):
            if name not in activation:
                activation[name] = {'X': [], 'y': []}
            activation[name]['X'].append(output.detach().cpu().numpy())
            activation[name]['y'].append(y.detach().cpu().numpy())

        return hook
    
    for layer_name in layer_names:
        getattr(model, layer_name).register_forward_hook(get_activation(layer_name))
    
    
    model(X)

    return activation

def greedy_mass_covering(arr, bin_size, coverage_threshold):
    # Step 1: Bin the array
    arr = np.array(arr)
    min_val = arr.min()
    max_val = arr.max()
    bin_edges = np.arange(min_val, max_val + bin_size, bin_size)
    hist, edges = np.histogram(arr, bins=bin_edges)
    
    total_mass = hist.sum()
    target_mass = coverage_threshold * total_mass
    n_bins = len(hist)
    
    # Step 2: Create all possible intervals (i, j)
    intervals = []
    for i in range(n_bins):
        mass = 0
        for j in range(i, n_bins):
            mass += hist[j]
            width = edges[j+1] - edges[i]
            if mass > 0:
                density = mass / width
                intervals.append((-density, mass, i, j))  # max-heap with negative density
    
    # Step 3: Greedy selection of non-overlapping intervals
    intervals.sort()
    selected = []
    covered_bins = set()
    collected_mass = 0
    
    for _, mass, i, j in intervals:
        if collected_mass >= target_mass:
            break
        if any(k in covered_bins for k in range(i, j+1)):
            continue
        selected.append((i, j))
        collected_mass += mass
        covered_bins.update(range(i, j+1))
    
    # Step 4: Merge overlapping/adjacent intervals into ranges
    selected.sort()
    merged_ranges = []
    for i, j in selected:
        start = edges[i]
        end = edges[j+1]
        if not merged_ranges:
            merged_ranges.append([start, end])
        else:
            last_start, last_end = merged_ranges[-1]
            if start <= last_end:
                merged_ranges[-1][1] = max(last_end, end)
            else:
                merged_ranges.append([start, end])
    
    # Final actual coverage
    actual_coverage = collected_mass / total_mass
    
    return merged_ranges, actual_coverage


def stream_feature_3D(host: str, SNIs: Union[Set[str], str], base_dir: str, protocol: str, extractor: NpzExtractor, db: pd.DataFrame):
    """
    Extract 3D features for a given host and SNIs. The original data is provided by db.
    """
    if isinstance(SNIs, str):
        SNIs = set(SNIs)
    db = db.query(f"host == {host} and sni in {SNIs} and protocol == {protocol}")
    groups = db.groupby(['id'], sort=True)
    yz_3D = []

    for id, group in groups:
        paths = group.apply(lambda row: f'{base_dir}/{array_path(row["host"], id, row["transport"], row["stream"], protocol)}', axis=1)
        npz_files = [np.load(path) for path in paths]
        yz_2D = stream_feature_2D(npz_files, extractor)
        yz_3D.append(yz_2D)

    return yz_3D


def stream_feature_2D(npz_files: List[NpzFile], extractor: NpzExtractor):
    """
    Stream level feature extraction, one npz_file represents one stream, we require generally the meta information of the stream being (feature_ts, feature) list, and extract the timestamp and feature series for each stream.
    """
    yz_2D = []
    for npz_file in npz_files:
        stream = extractor.single_stream_extract(npz_file)
        timestamp = [s[0] for s in stream]
        feature = [s[1] for s in stream]
        yz_2D.append((timestamp, feature))

    return yz_2D


def stream_feature_3D_draw(host: str, sni: str, feature: str, yz_3D: List[List[Tuple[ArrayLike, ArrayLike]]], bar_width: float=0.3, cmap_name: str='tab10', alpha: float=0.8):
    """
    yz_3D: 
        list of yz_2D, which is a list of (y, z) tuples.
    """

    cmap = plt.cm.get_cmap('tab10', len(yz_3D))

    fig = plt.figure(figsize=(10, 6))
    ax = fig.add_subplot(111, projection='3d')
    for x, yz_2D in enumerate(yz_3D):
        for y, z in yz_2D:
            y = np.array(y)
            z = np.array(z)

            # Create arrays for bar3d
            xs = np.full_like(y, x)  # Same x for the whole group
            ys = y
            zs = np.zeros_like(z)

            ax.bar3d(xs, ys, zs, dx=bar_width, dy=bar_width, dz=z, color=cmap(x), alpha=0.8)


    ax.set_xlabel('capture ID')
    ax.set_ylabel('timestamp')
    ax.set_zlabel('value')
    ax.set_title(f'{feature}, {host}, {sni}')

    plt.tight_layout()
    plt.show()