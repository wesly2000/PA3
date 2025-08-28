import numpy as np
from typing import Union, List, Iterable
import random

def IQR_bound(array: Union[np.array, List]):
    arr_sorted = np.sort(array)

    lower_half = arr_sorted[:len(arr_sorted)//2]    
    upper_half = arr_sorted[(len(arr_sorted)+1)//2:]

    Q1 = np.median(lower_half)
    Q3 = np.median(upper_half)

    IQR = Q3 - Q1  # Interquartile range (IQR)
    lower_bound = Q1 - 1.5 * IQR  # Lower bound for outliers
    upper_bound = Q3 + 1.5 * IQR  # Upper bound for outliers

    return lower_bound, upper_bound

def sample(iterator, k):
    """
    Samples k elements from an iterable object.

    :param iterator: an object that is iterable
    :param k: the number of items to sample
    """
    # fill the reservoir to start
    result = [next(iterator) for _ in range(k)]

    n = k - 1
    for item in iterator:
        n += 1
        s = random.randint(0, n)
        if s < k:
            result[s] = item

    return result

def jaccard_similarity(set1: Iterable, set2: Iterable):
    """
    Calculate the Jaccard similarity between two sets.
    """
    set1, set2 = set(set1), set(set2)
    return len(set1 & set2) / len(set1 | set2)

def greedy_mass_covering(arr: Union[np.ndarray, List], bin_size: int, coverage_threshold: float) -> Tuple[List[tuple], float]:
    assert coverage_threshold <= 1, "Coverage must not be larger than 1"

    # Step 1: Bin the array (density version)
    arr = np.array(arr)
    min_val = arr.min()
    max_val = arr.max()
    bin_edges = np.arange(min_val, max_val + bin_size, bin_size)
    hist, edges = np.histogram(arr, bins=bin_edges)

    hist = hist.astype(dtype=float)
    hist /= len(arr)

    # Step 2: Sort the array by its density
    sorted_hist = [(i, density) for i, density in enumerate(hist)]
    sorted_hist.sort(key=lambda x: x[1], reverse=True)

    # Step 3: Select those bins by density in descending order.
    selected_bins = []
    accumulate_density = 0

    for index, density in sorted_hist:
        if accumulate_density >= coverage_threshold:
            break 

        selected_bins.append([edges[index], edges[index + 1]])
        accumulate_density += density

    # Step 4: Merge consecutive bins.
    if len(selected_bins) <= 1:
        return selected_bins, accumulate_density
    
    selected_bins.sort(key=lambda x: x[0])  # Sort bins by their starting (left) point
    covers = []
    cover_index = 0
    while cover_index < len(selected_bins):
        cover = [selected_bins[cover_index][0], selected_bins[cover_index][1]]  # Get the starting point of the cover

        if cover_index == len(selected_bins) - 1:  # Last bin.
            covers.append(cover)
            break

        for i in range(cover_index + 1, len(selected_bins)):
            # If the left point of current bin equals the right point of the cover, merge them into a larger cover.
            # For example, the cover is [0, 25] and current bin is [25, 30], the new cover should be [0, 30].
            if selected_bins[i][0] == cover[1]:  
                cover[1] = selected_bins[i][1]
                cover_index += 1
            else:
                # We have already sorted these bins, so if the next bin is not consecutive with current cover, no further search is needed.
                break

        covers.append(cover)
        cover_index += 1 

    return covers, accumulate_density