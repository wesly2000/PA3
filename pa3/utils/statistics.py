import random
import bisect

import numpy as np
from typing import Union, List, Dict, Iterable, Tuple
from abc import ABC, abstractmethod
import sklearn.metrics as metrics


# ---------------------------------------------------------------------------
# Burst detection & CDF utilities
# ---------------------------------------------------------------------------

def find_bursts(direction: np.ndarray) -> List[Tuple[int, int]]:
    """Return burst index ranges from a direction array.

    A burst is a maximal contiguous run of the same non-zero direction
    value.  Zero values (padding) terminate scanning.

    Returns a list of (start, end) tuples where ``direction[start:end]``
    is the burst.
    """
    bursts: List[Tuple[int, int]] = []
    n = len(direction)
    if n == 0 or direction[0] == 0:
        return bursts

    start = 0
    cur_dir = direction[0]
    for i in range(1, n):
        if direction[i] == 0:
            bursts.append((start, i))
            break
        if direction[i] != cur_dir:
            bursts.append((start, i))
            start = i
            cur_dir = direction[i]
    else:
        bursts.append((start, n))
    return bursts


def sample_from_cdf(cdf: np.ndarray, values: list):
    """Sample a single value from an empirical CDF.

    Parameters
    ----------
    cdf : 1-D array of cumulative probabilities (monotonically increasing,
        last element is 1.0).
    values : list of values corresponding to each CDF entry.
    """
    p = random.random()
    idx = bisect.bisect_left(cdf, p)
    idx = min(idx, len(values) - 1)
    return values[idx]


def empirical_cdf(values: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Compute the empirical CDF from a 1-D array of observed values.

    Returns
    -------
    (unique_values, cdf) where *cdf[i]* is the probability that a sample
    is <= *unique_values[i]*.
    """
    unique_vals, counts = np.unique(values, return_counts=True)
    cdf = np.cumsum(counts).astype(np.float64) / counts.sum()
    return unique_vals, cdf


def compute_outgoing_cdfs(X_raw: np.ndarray) -> Dict[str, object]:
    """Compute empirical CDFs for outgoing burst statistics from raw data.

    Parameters
    ----------
    X_raw : ndarray of shape (N, L, 3)
        Each row contains L triplets of ``[timestamp, direction, size]``.
        Trailing all-zero triplets (padding) are ignored.

    Returns
    -------
    dict with keys that can be unpacked directly into
    ``NetCLRAugmentor(**cdfs)``:

    - ``outgoing_burst_sizes`` / ``outgoing_burst_size_cdf``
    - ``outgoing_packet_sizes`` / ``outgoing_packet_size_cdf``
    - ``outgoing_delays`` / ``outgoing_delay_cdf``

    If no outgoing bursts are found, the corresponding values/CDF entries
    are empty list / ``None``.
    """
    burst_size_collector: List[int] = []
    packet_size_collector: List[int] = []
    delay_collector: List[float] = []

    for i in range(len(X_raw)):
        row = X_raw[i]
        mask = ~np.all(row == 0, axis=1)
        active = row[mask]
        if len(active) == 0:
            continue

        timestamp = active[:, 0]
        direction = active[:, 1].astype(np.int64)
        size = active[:, 2].astype(np.int64)

        bursts = find_bursts(direction)
        for start, end in bursts:
            if direction[start] != 1:
                continue
            burst_len = end - start
            burst_size_collector.append(burst_len)
            packet_size_collector.extend(size[start:end].tolist())
            if burst_len >= 2:
                delay_collector.extend(np.diff(timestamp[start:end]).tolist())

    result: Dict[str, object] = {}

    if burst_size_collector:
        vals, cdf = empirical_cdf(np.array(burst_size_collector))
        result["outgoing_burst_sizes"] = vals.tolist()
        result["outgoing_burst_size_cdf"] = cdf
    else:
        result["outgoing_burst_sizes"] = []
        result["outgoing_burst_size_cdf"] = None

    if packet_size_collector:
        vals, cdf = empirical_cdf(np.array(packet_size_collector))
        result["outgoing_packet_sizes"] = vals.tolist()
        result["outgoing_packet_size_cdf"] = cdf
    else:
        result["outgoing_packet_sizes"] = []
        result["outgoing_packet_size_cdf"] = None

    if delay_collector:
        vals, cdf = empirical_cdf(np.array(delay_collector))
        result["outgoing_delays"] = vals.tolist()
        result["outgoing_delay_cdf"] = cdf
    else:
        result["outgoing_delays"] = []
        result["outgoing_delay_cdf"] = None

    return result

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


class MMD(ABC):
    def __init__(self) -> None:
        super().__init__()

    @abstractmethod
    def compute(self, X: np.ndarray, Y: np.ndarray) -> float:
        raise NotImplementedError


class MMDLinear(MMD):
    """MMD using linear kernel (i.e., k(x, y) = <x, y>)."""

    def __init__(self) -> None:
        super().__init__()

    def compute(self, X: np.ndarray, Y: np.ndarray) -> float:
        # This is the reformulated and faster linear MMD expression.
        delta = X.mean(0) - Y.mean(0)
        return delta.dot(delta.T)


class MMDRBF(MMD):
    """MMD using rbf (gaussian) kernel (i.e., k(x, y) = exp(-gamma * ||x-y||^2 / 2))."""

    def __init__(self, gamma: float = 1.0) -> None:
        super().__init__()
        self.gamma = gamma

    def compute(self, X: np.ndarray, Y: np.ndarray) -> float:
        XX = metrics.pairwise.rbf_kernel(X, X, self.gamma)
        YY = metrics.pairwise.rbf_kernel(Y, Y, self.gamma)
        XY = metrics.pairwise.rbf_kernel(X, Y, self.gamma)
        return XX.mean() + YY.mean() - 2 * XY.mean()


class MMDPoly(MMD):
    """MMD using polynomial kernel (i.e., k(x, y) = (gamma <X, Y> + coef0)^degree)."""

    def __init__(self, degree: int = 2, gamma: int = 1, coef0: int = 0) -> None:
        super().__init__()
        self.degree = degree
        self.gamma = gamma
        self.coef0 = coef0

    def compute(self, X: np.ndarray, Y: np.ndarray) -> float:
        XX = metrics.pairwise.polynomial_kernel(X, X, self.degree, self.gamma, self.coef0)
        YY = metrics.pairwise.polynomial_kernel(Y, Y, self.degree, self.gamma, self.coef0)
        XY = metrics.pairwise.polynomial_kernel(X, Y, self.degree, self.gamma, self.coef0)
        return XX.mean() + YY.mean() - 2 * XY.mean()


def classwise_mmd(X_1: np.ndarray, y_1: np.ndarray, X_2: np.ndarray, y_2: np.ndarray, mmd: MMD) -> float:
    """Compute class-wise MMD and sum over all classes.

    For each class label, this function selects class-specific samples from both
    datasets and computes MMD using the provided MMD instance.
    """

    labels_1 = np.unique(y_1)
    labels_2 = np.unique(y_2)
    if set(labels_1.tolist()) != set(labels_2.tolist()):
        raise ValueError("Label spaces of y_1 and y_2 must be identical.")

    total_mmd = 0.0
    for label in labels_1:
        X_1_label = X_1[y_1 == label]
        X_2_label = X_2[y_2 == label]
        total_mmd += mmd.compute(X_1_label, X_2_label)

    return total_mmd