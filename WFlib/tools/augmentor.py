import random
import numpy as np
from typing import Any, List, Dict, Tuple

from WFlib.utils.statistics import find_bursts, sample_from_cdf


# ---------------------------------------------------------------------------
# Raw triplet format <-> dict-of-arrays converters
# ---------------------------------------------------------------------------

def raw_to_dict(row: np.ndarray) -> Dict[str, np.ndarray]:
    """Convert a single raw-format sample to the dict format used by augmentors.

    Parameters
    ----------
    row : ndarray of shape (L, 3)
        Columns are [timestamp, direction, size].  Trailing all-zero rows
        (padding) are stripped before conversion.

    Returns
    -------
    dict with keys ``"timestamp"``, ``"direction"``, ``"size"``, each a 1-D
    ndarray.  ``direction`` and ``size`` are ``int64``; ``timestamp`` is
    ``float64``.
    """
    mask = ~np.all(row == 0, axis=1)
    active = row[mask]
    return {
        "timestamp": active[:, 0].astype(np.float64),
        "direction": active[:, 1].astype(np.int64),
        "size": active[:, 2].astype(np.int64),
    }


def dict_to_raw(d: Dict[str, np.ndarray], length: int) -> np.ndarray:
    """Convert an augmented dict back to a single raw-format row.

    Parameters
    ----------
    d : dict with ``"timestamp"``, ``"direction"``, ``"size"`` arrays.
    length : int
        Target sequence length.  The result is truncated or zero-padded to
        this length.

    Returns
    -------
    ndarray of shape (length, 3) with columns [timestamp, direction, size].
    """
    ts = np.asarray(d["timestamp"], dtype=np.float64)
    dr = np.asarray(d["direction"], dtype=np.float64)
    sz = np.asarray(d["size"], dtype=np.float64)

    n = len(ts)
    if n >= length:
        return np.column_stack([ts[:length], dr[:length], sz[:length]])

    pad = length - n
    out = np.zeros((length, 3), dtype=np.float64)
    out[:n, 0] = ts
    out[:n, 1] = dr
    out[:n, 2] = sz
    return out


class Augmentor(object):
    def __init__(self):
        raise NotImplementedError("Augmentor is an abstract class and cannot be instantiated directly.")

    def augment(self, data: Any) -> Any:
        raise NotImplementedError("Augmentor is an abstract class and cannot be instantiated directly.")


class TrafficAugmentor(Augmentor):
    """
    TrafficAugmentor is the augmentor for traffic data, i.e., a mixture of flows within it.
    """
    def __init__(self):
        super().__init__()

    def augment(self, data: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        raise NotImplementedError("TrafficAugmentor is an abstract class and cannot be instantiated directly.")



class NetCLRAugmentor(TrafficAugmentor):
    """
    Implementation of the NetCLR augmentor, which is described in the paper: Realistic Website Fingerprinting By Augmenting Network Trace. CCS 2023.

    Original paper focused on Tor traffic, which only includes packet direction sequence. We try to add augmentation rules for timestamp and size using simple method. The direction augmentation rules are implemented respecting the original paper.
    """
    def __init__(self,
                 r_up_sample: float = 1.0,
                 r_down_sample: float = 0.5,
                 num_bursts_to_merge: int = 5,
                 merge_burst_rate: float = 0.1,
                 add_outgoing_burst_rate: float = 0.3,
                 outgoing_burst_sizes: List[int] = None,
                 outgoing_burst_size_cdf: np.ndarray = None,
                 outgoing_packet_sizes: List[int] = None,
                 outgoing_packet_size_cdf: np.ndarray = None,
                 outgoing_delays: List[float] = None,
                 outgoing_delay_cdf: np.ndarray = None,
                 large_burst_threshold: int = 10):
        self.r_up_sample = r_up_sample
        self.r_down_sample = r_down_sample
        self.num_bursts_to_merge = num_bursts_to_merge
        self.merge_burst_rate = merge_burst_rate
        self.add_outgoing_burst_rate = add_outgoing_burst_rate
        self.large_burst_threshold = large_burst_threshold

        # CDF for sampling burst-level outgoing burst packet counts (from original NetCLR)
        self.outgoing_burst_sizes = outgoing_burst_sizes or []
        self.outgoing_burst_size_cdf = outgoing_burst_size_cdf

        # CDFs for sampling per-packet attributes of synthetic outgoing packets (Option C)
        self.outgoing_packet_sizes = outgoing_packet_sizes or []
        self.outgoing_packet_size_cdf = outgoing_packet_size_cdf
        self.outgoing_delays = outgoing_delays or []
        self.outgoing_delay_cdf = outgoing_delay_cdf

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(direction: np.ndarray,
                      size: np.ndarray,
                      timestamp: np.ndarray) -> Dict[str, np.ndarray]:
        return {
            "direction": np.asarray(direction, dtype=np.int64),
            "size": np.asarray(size, dtype=np.int64),
            "timestamp": np.asarray(timestamp, dtype=np.float64),
        }

    # ------------------------------------------------------------------
    # Sub-algorithm 1: change_content
    # ------------------------------------------------------------------

    def _deflate_burst(self, direction: np.ndarray, size: np.ndarray,
                       timestamp: np.ndarray, start: int, end: int,
                       new_count: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Shrink a burst by randomly dropping packets."""
        burst_len = end - start
        keep = sorted(random.sample(range(burst_len), new_count))
        indices = [start + k for k in keep]
        return direction[indices], size[indices], timestamp[indices]

    def _inflate_burst_resample(self, direction: np.ndarray, size: np.ndarray,
                                timestamp: np.ndarray, start: int, end: int,
                                new_count: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Enlarge a burst by resampling packets from the same burst.

        New packet sizes are sampled with replacement from existing sizes.
        New timestamps are placed at uniformly random points within randomly
        chosen existing inter-packet gaps.
        """
        burst_dir = direction[start:end]
        burst_size = size[start:end]
        burst_ts = timestamp[start:end]
        burst_len = end - start
        n_add = new_count - burst_len

        new_sizes = np.random.choice(burst_size, size=n_add, replace=True)
        new_dir = np.full(n_add, burst_dir[0])

        if burst_len >= 2:
            gaps = np.diff(burst_ts)
            gap_indices = np.random.choice(len(gaps), size=n_add, replace=True)
            fractions = np.random.uniform(0.0, 1.0, size=n_add)
            new_ts = burst_ts[gap_indices] + fractions * gaps[gap_indices]
        else:
            new_ts = np.full(n_add, burst_ts[0])

        all_dir = np.concatenate([burst_dir, new_dir])
        all_size = np.concatenate([burst_size, new_sizes])
        all_ts = np.concatenate([burst_ts, new_ts])

        order = np.argsort(all_ts, kind="stable")
        return all_dir[order], all_size[order], all_ts[order]

    def _inflate_burst_interpolate(self, direction: np.ndarray, size: np.ndarray,
                                   timestamp: np.ndarray, start: int, end: int,
                                   new_count: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Enlarge a burst by interpolation

        New packet size = average of its two neighbors.
        New timestamp = jittered midpoint within a subdivided gap.
        """
        burst_dir = list(direction[start:end])
        burst_size = list(size[start:end])
        burst_ts = list(timestamp[start:end])
        n_add = new_count - (end - start)

        for _ in range(n_add):
            if len(burst_ts) < 2:
                burst_dir.append(burst_dir[0])
                burst_size.append(burst_size[0])
                burst_ts.append(burst_ts[0])
                continue

            gaps = [burst_ts[j + 1] - burst_ts[j] for j in range(len(burst_ts) - 1)]
            gap_idx = random.choices(range(len(gaps)), weights=gaps if any(g > 0 for g in gaps) else None, k=1)[0]
            frac = random.uniform(0.3, 0.7)
            new_t = burst_ts[gap_idx] + frac * gaps[gap_idx]
            new_s = int(round((burst_size[gap_idx] + burst_size[gap_idx + 1]) / 2.0))
       
            ins = gap_idx + 1
            burst_dir.insert(ins, burst_dir[0])
            burst_size.insert(ins, new_s)
            burst_ts.insert(ins, new_t)

        return np.array(burst_dir), np.array(burst_size), np.array(burst_ts)

    def _change_content(self, data: Dict[str, np.ndarray],
                        inflate_mode: str = "resample") -> Dict[str, np.ndarray]:
        """Augment by inflating or deflating incoming bursts.

        Parameters
        ----------
        data : dict with direction, size, timestamp arrays.
        inflate_mode : ``"resample"`` (Option A) or ``"interpolate"`` (Option D).
        """
        direction = data["direction"].copy()
        size = data["size"].copy()
        timestamp = data["timestamp"].copy()
        bursts = find_bursts(direction)
        trace_len = len(direction)

        if trace_len < 1000:
            do_inflate = True
        elif trace_len > 4000:
            do_inflate = False
        else:
            do_inflate = random.random() >= 0.5

        out_dir, out_size, out_ts = [], [], []
        prev_end = 0

        for start, end in bursts:
            # Emit any gap between previous burst end and this burst start
            if start > prev_end:
                out_dir.append(direction[prev_end:start])
                out_size.append(size[prev_end:start])
                out_ts.append(timestamp[prev_end:start])

            burst_len = end - start
            is_incoming = direction[start] == -1

            if is_incoming and burst_len >= self.large_burst_threshold:
                if do_inflate:
                    rate = random.random() * self.r_up_sample
                    new_count = int(burst_len * (1 + rate))
                else:
                    rate = random.random() * self.r_down_sample
                    new_count = max(1, int(burst_len * (1 - rate)))

                if new_count < burst_len:
                    bd, bs, bt = self._deflate_burst(direction, size, timestamp, start, end, new_count)
                elif new_count > burst_len:
                    if inflate_mode == "interpolate":
                        bd, bs, bt = self._inflate_burst_interpolate(direction, size, timestamp, start, end, new_count)
                    else:
                        bd, bs, bt = self._inflate_burst_resample(direction, size, timestamp, start, end, new_count)
                else:
                    bd, bs, bt = direction[start:end], size[start:end], timestamp[start:end]

                out_dir.append(bd)
                out_size.append(bs)
                out_ts.append(bt)
            else:
                out_dir.append(direction[start:end])
                out_size.append(size[start:end])
                out_ts.append(timestamp[start:end])

            prev_end = end

        if prev_end < len(direction):
            out_dir.append(direction[prev_end:])
            out_size.append(size[prev_end:])
            out_ts.append(timestamp[prev_end:])

        return self._build_result(
            np.concatenate(out_dir) if out_dir else np.array([], dtype=direction.dtype),
            np.concatenate(out_size) if out_size else np.array([], dtype=size.dtype),
            np.concatenate(out_ts) if out_ts else np.array([], dtype=timestamp.dtype),
        )

    # ------------------------------------------------------------------
    # Sub-algorithm 2: merge_incoming_bursts
    # ------------------------------------------------------------------

    def _merge_incoming_bursts(self, data: Dict[str, np.ndarray],
                               merge_timestamp_mode: str = "keep") -> Dict[str, np.ndarray]:
        """Merge consecutive incoming bursts, dropping interleaved outgoing bursts.

        Parameters
        ----------
        merge_timestamp_mode : ``"keep"`` preserves original timestamps;
            ``"compress"`` closes the gaps left by removed outgoing bursts.
        """
        direction = data["direction"]
        size = data["size"]
        timestamp = data["timestamp"]
        bursts = find_bursts(direction)

        burst_sizes = [end - start for start, end in bursts]

        # Skip first ~20 cells (same heuristic as original)
        skip = 0
        cell_count = 0
        while skip < len(bursts) and cell_count < 20:
            cell_count += burst_sizes[skip]
            skip += 1

        out_dir, out_size, out_ts = [], [], []
        # Emit everything before skip boundary (including inter-burst gaps)
        if skip > 0:
            emit_end = bursts[skip - 1][1] if skip <= len(bursts) else len(direction)
            out_dir.append(direction[:emit_end])
            out_size.append(size[:emit_end])
            out_ts.append(timestamp[:emit_end])

        i = skip
        while i < len(bursts) - self.num_bursts_to_merge:
            b_start, b_end = bursts[i]
            is_incoming = direction[b_start] == -1

            if not is_incoming:
                out_dir.append(direction[b_start:b_end])
                out_size.append(size[b_start:b_end])
                out_ts.append(timestamp[b_start:b_end])
                i += 1
                continue

            if random.random() < self.merge_burst_rate:
                num_merges = random.randint(2, self.num_bursts_to_merge)
                merged_dir, merged_size, merged_ts = [], [], []
                merges_done = 0

                while i < len(bursts) and merges_done < num_merges:
                    bs, be = bursts[i]
                    if direction[bs] == -1:
                        merged_dir.append(direction[bs:be])
                        merged_size.append(size[bs:be])
                        merged_ts.append(timestamp[bs:be])
                        merges_done += 1
                    i += 1

                if merge_timestamp_mode == "compress" and len(merged_ts) > 1:
                    compressed_ts = [merged_ts[0]]
                    for k in range(1, len(merged_ts)):
                        prev_last = compressed_ts[-1][-1]
                        cur_deltas = np.diff(merged_ts[k])
                        if len(cur_deltas) > 0:
                            spacing = np.min(cur_deltas[cur_deltas > 0]) if np.any(cur_deltas > 0) else 0.0
                        else:
                            spacing = 0.0
                        shifted = np.empty(len(merged_ts[k]))
                        shifted[0] = prev_last + spacing
                        if len(cur_deltas) > 0:
                            shifted[1:] = shifted[0] + np.cumsum(cur_deltas)
                        compressed_ts.append(shifted)
                    merged_ts = compressed_ts

                out_dir.append(np.concatenate(merged_dir))
                out_size.append(np.concatenate(merged_size))
                out_ts.append(np.concatenate(merged_ts))
            else:
                out_dir.append(direction[b_start:b_end])
                out_size.append(size[b_start:b_end])
                out_ts.append(timestamp[b_start:b_end])
                i += 1

        # Emit remaining bursts that were not considered
        while i < len(bursts):
            b_start, b_end = bursts[i]
            out_dir.append(direction[b_start:b_end])
            out_size.append(size[b_start:b_end])
            out_ts.append(timestamp[b_start:b_end])
            i += 1

        return self._build_result(
            np.concatenate(out_dir) if out_dir else np.array([], dtype=direction.dtype),
            np.concatenate(out_size) if out_size else np.array([], dtype=size.dtype),
            np.concatenate(out_ts) if out_ts else np.array([], dtype=timestamp.dtype),
        )

    # ------------------------------------------------------------------
    # Sub-algorithm 3: add_outgoing_burst
    # ------------------------------------------------------------------

    def _add_outgoing_burst(self, data: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Split large incoming bursts and insert synthetic outgoing bursts."""
        direction = data["direction"]
        size = data["size"]
        timestamp = data["timestamp"]
        bursts = find_bursts(direction)

        # Skip first ~20 cells
        skip = 0
        cell_count = 0
        while skip < len(bursts):
            cell_count += bursts[skip][1] - bursts[skip][0]
            if cell_count >= 20:
                skip += 1
                break
            skip += 1

        out_dir, out_size, out_ts = [], [], []
        if skip > 0:
            emit_end = bursts[skip - 1][1] if skip <= len(bursts) else len(direction)
            out_dir.append(direction[:emit_end])
            out_size.append(size[:emit_end])
            out_ts.append(timestamp[:emit_end])

        for idx in range(skip, len(bursts)):
            b_start, b_end = bursts[idx]
            burst_len = b_end - b_start
            is_incoming = direction[b_start] == -1

            if not is_incoming or burst_len < self.large_burst_threshold:
                out_dir.append(direction[b_start:b_end])
                out_size.append(size[b_start:b_end])
                out_ts.append(timestamp[b_start:b_end])
                continue

            if random.random() >= self.add_outgoing_burst_rate:
                out_dir.append(direction[b_start:b_end])
                out_size.append(size[b_start:b_end])
                out_ts.append(timestamp[b_start:b_end])
                continue

            # Sample outgoing burst packet count from the burst-level CDF
            if self.outgoing_burst_size_cdf is not None and len(self.outgoing_burst_sizes) > 0:
                out_burst_count = sample_from_cdf(self.outgoing_burst_size_cdf, self.outgoing_burst_sizes)
            else:
                out_burst_count = random.randint(1, 5)

            if burst_len <= 6:
                out_dir.append(direction[b_start:b_end])
                out_size.append(size[b_start:b_end])
                out_ts.append(timestamp[b_start:b_end])
                continue

            divide = random.randint(3, burst_len - 3)
            split_point = b_start + divide

            # Part 1: incoming packets before the split
            part1_dir = direction[b_start:split_point]
            part1_size = size[b_start:split_point]
            part1_ts = timestamp[b_start:split_point]

            # Part 2: incoming packets after the split
            part2_dir = direction[split_point:b_end]
            part2_size = size[split_point:b_end]
            part2_ts = timestamp[split_point:b_end]

            # Synthetic outgoing burst
            syn_dir = np.ones(out_burst_count, dtype=direction.dtype)

            if self.outgoing_packet_size_cdf is not None and len(self.outgoing_packet_sizes) > 0:
                syn_size = np.array([sample_from_cdf(self.outgoing_packet_size_cdf,
                                                           self.outgoing_packet_sizes)
                                     for _ in range(out_burst_count)], dtype=np.int64)
            else:
                mean_out_size = int(round(np.mean(size[direction == 1]))) if np.any(direction == 1) else 100
                syn_size = np.full(out_burst_count, mean_out_size, dtype=np.int64)

            t_left = part1_ts[-1]
            t_right = part2_ts[0]
            gap = t_right - t_left

            if self.outgoing_delay_cdf is not None and len(self.outgoing_delays) > 0:
                raw_delays = np.array([sample_from_cdf(self.outgoing_delay_cdf, self.outgoing_delays)
                                       for _ in range(out_burst_count)])
            else:
                if gap > 0 and out_burst_count > 0:
                    raw_delays = np.full(out_burst_count, gap / (out_burst_count + 1))
                else:
                    raw_delays = np.zeros(out_burst_count)

            cumulative = np.cumsum(raw_delays)
            total_delay = cumulative[-1] if len(cumulative) > 0 else 0.0
            if total_delay > gap and total_delay > 0:
                cumulative = cumulative * (gap * 0.9 / total_delay)

            syn_ts = t_left + cumulative

            out_dir.extend([part1_dir, syn_dir, part2_dir])
            out_size.extend([part1_size, syn_size, part2_size])
            out_ts.extend([part1_ts, syn_ts, part2_ts])

        return self._build_result(
            np.concatenate(out_dir) if out_dir else np.array([], dtype=direction.dtype),
            np.concatenate(out_size) if out_size else np.array([], dtype=size.dtype),
            np.concatenate(out_ts) if out_ts else np.array([], dtype=timestamp.dtype),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def augment(self, data: Dict[str, np.ndarray],
                inflate_mode: str = "resample",
                merge_timestamp_mode: str = "keep") -> Dict[str, np.ndarray]:
        """Augment the trace using a randomly chosen augmentation method.

        Parameters
        ----------
        data : dict with keys ``"direction"``, ``"size"``, ``"timestamp"``.
        inflate_mode : ``"resample"`` or ``"interpolate"`` -- forwarded to
            ``_change_content``.
        merge_timestamp_mode : ``"keep"`` or ``"compress"`` -- forwarded to
            ``_merge_incoming_bursts``.
        """
        direction = data["direction"]
        bursts = find_bursts(direction)
        if len(bursts) == 0:
            return data

        choice = random.randint(0, 2)
        if choice == 0:
            return self._change_content(data, inflate_mode=inflate_mode)
        elif choice == 1:
            return self._merge_incoming_bursts(data, merge_timestamp_mode=merge_timestamp_mode)
        else:
            return self._add_outgoing_burst(data)