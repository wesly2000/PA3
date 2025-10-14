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


def stream_feature_3D(host: str, SNIs: Union[Set[str], str], base_dir: str, protocol: str, extractor: NpzExtractor, db: pd.DataFrame):
    """
    Extract 3D features for a given host and SNIs. The original data is provided by db.
    """
    if isinstance(SNIs, str):
        SNIs = set([SNIs])
    db = db.query(f"host == '{host}' and sni in @SNIs and protocol == '{protocol}'")
    groups = db.groupby(['id'], sort=True)
    yz_3D = []

    for id, group in groups:
        paths = group.apply(lambda row: f'{base_dir}/{array_path(row["host"], id[0], row["transport"], row["stream"], protocol)}', axis=1)
        npz_files = [np.load(path) for path in paths]
        yz_2D = stream_feature_2D(npz_files, extractor)
        yz_3D.append(yz_2D)

    return yz_3D


def stream_feature_2D(npz_files: List[NpzFile], extractor: NpzExtractor):
    """
    Stream level feature extraction, one npz_file represents one stream, we require generally the meta information of the stream being (feature_ts, feature) list, and extract the timestamp and feature series for each stream.
    """

    # BIN_RANGE = 50000
    # BIN_STEP = 500
    # BINS = np.arange(-BIN_RANGE, BIN_RANGE + BIN_STEP, BIN_STEP)

    yz_2D = []
    stream_start_times = []
    for npz_file in npz_files:
        stream = extractor.single_stream_extract(npz_file)
        timestamp = np.array([s[0] for s in stream])
        feature = np.array([s[1] for s in stream])
        # Add bins to the feature and clip the feature to the range [lower_bound, upper_bound]
        # Create a mask for non-zero elements
        # non_zero_mask = feature != 0
        # Initialize result array with zeros
        # binned_feature = np.zeros_like(feature)

        # Only apply binning to non-zero elements
        # if np.any(non_zero_mask):
        #     bin_idx = np.digitize(feature[non_zero_mask], BINS) - 1
        #     bin_idx = np.clip(bin_idx, 0, len(BINS) - 2)
        #     binned_feature[non_zero_mask] = (BINS[bin_idx] + BINS[bin_idx + 1]) / 2

        yz_2D.append((timestamp, feature))

        stream_start_times.append(np.min(timestamp))

    start_time = np.min(stream_start_times)
    # yz_2D = [(timestamp - start_time, binned_feature) for timestamp, binned_feature in yz_2D]
    yz_2D = [(timestamp - start_time, feature) for timestamp, feature in yz_2D]

    return yz_2D


def stream_feature_2D_draw(host: str, sni: str, xy: List[List[Tuple[ArrayLike, ArrayLike]]], bar_width: float=0.1, cmap_name: str='tab10', alpha: float=0.8):
    """
    Draw bin graph for feature 2D.
    """
    x_limit = 3
    xy.sort(key=lambda x: len(x[0]), reverse=True)
    cmap = ["#033BE4", "#069404", "#D27000", "#9C0000", "#C602E0", "#028067"]
    fig, ax = plt.subplots(1, 1, figsize=(4, 1.5), constrained_layout=True)

    ax.axhline(y=0, color='black', linestyle='--', lw=.5)
    for c, (x, y) in enumerate(xy):
        x_mask = x < x_limit
        x = x[x_mask]
        y = y[x_mask]

        color = cmap[c]    
        positive_y_mask = y > 0
        positive_y = y[positive_y_mask]
        x_for_positive_y = np.round(x[positive_y_mask], 2)
        unique_x_for_positive_y, indices = np.unique(x_for_positive_y, return_inverse=True)
        positive_sums = np.bincount(indices, weights=positive_y)
        ax.bar(unique_x_for_positive_y, positive_sums, color=color, width=bar_width)
        # ax.plot(unique_x_for_positive_y, positive_sums, color=color)

        negative_y_mask = y < 0
        negative_y = y[negative_y_mask]
        x_for_negative_y = np.round(x[negative_y_mask], 2)
        unique_x_for_negative_y, indices = np.unique(x_for_negative_y, return_inverse=True)
        negative_sums = np.bincount(indices, weights=negative_y)
        # ax.plot(unique_x_for_negative_y, negative_sums, color=color)
        
        # ax.bar(x, y, color=color, alpha=0.8, width=bar_width, linewidth=.5, edgecolor='black')
        ax.bar(unique_x_for_negative_y, negative_sums, color=color, width=bar_width)
        
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Size')
    ax.set_title(f'{host}, {sni}')

    # plt.tight_layout()
    plt.show()

def stream_feature_3D_draw(host: str, sni: str, feature: str, yz_3D: List[List[Tuple[ArrayLike, ArrayLike]]], bar_width: float=0.3, cmap_name: str='tab10', alpha: float=0.8):
    """
    yz_3D: 
        list of yz_2D, which is a list of (y, z) tuples.
    """
    cmap = plt.cm.get_cmap(cmap_name, 10)
    
    fig = plt.figure(figsize=(10, 6))
    ax = fig.add_subplot(111, projection='3d')
    ax.set_box_aspect([1, 5, 1])
    for x, yz_2D in enumerate(yz_3D):
        yz_2D.sort(key=lambda x: max(x[0]), reverse=True)
        for c, (y, z) in enumerate(yz_2D):
            # y = np.array(y)
            # z = np.array(z)
            # mask = y <= 60
            # y = y[mask]

            # if len(y) == 0:
            #     continue
            # z = z[mask]

            # # Create arrays for bar3d
            # xs = np.full_like(y, x)  # Same x for the whole group
            # ys = y
            # zs = np.zeros_like(z)

            # dx = np.ones_like(y) * bar_width
            # dy = np.ones_like(y) * bar_width
            # dz = z

            # color = cmap(c)            
            # ax.bar3d(xs, ys, zs, dx, dy, dz, color=color, alpha=0.8)
            y = np.array(y)
            y = np.clip(y, 0, 20)
            z = np.array(z)

            # Create arrays for bar3d
            xs = np.full_like(y, x)  # Same x for the whole group
            ys = y
            zs = np.zeros_like(z)

            color = cmap(c)            
            ax.plot(xs, y, z, color=color, alpha=0.8)


    ax.set_xlabel('capture ID')
    ax.set_ylabel('timestamp')
    ax.set_zlabel('value')
    ax.set_title(f'{feature}, {host}, {sni}')

    plt.tight_layout()
    plt.show()