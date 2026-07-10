import random
import numpy as np
from typing import Any, List, Dict, Tuple

import math
from WFlib.utils.statistics import find_bursts, sample_from_cdf, empirical_cdf


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


class FlowAugmentor(Augmentor):
    """
    FlowAugmentor is the augmentor for flow data, i.e., a single flow.
    """
    def __init__(self):
        super().__init__()

    def augment(self, data: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        raise NotImplementedError("FlowAugmentor is an abstract class and cannot be instantiated directly.")


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


def slope(source_proto: str, target_proto: str) -> Tuple[float, float]:
    slope_dict = {
            ('vmess', 'shadowsocks'): (1.1732, 0.1519),
            ('vmess', 'trojan'): (0.9829, 0.1168),
            ('shadowsocks', 'vmess'): (0.8658, 0.1049),
            ('shadowsocks', 'trojan'): (0.9000, 0.0727),
            ('trojan', 'vmess'): (0.8763, 0.1233),
            ('trojan', 'shadowsocks'): (1.1183, 0.0902),
        }
    
    return slope_dict[(source_proto, target_proto)]

class RosettaAugmentor(FlowAugmentor):
    """
    Raw-flow extension of Rosetta's TCP-aware augmentation.

    The public Rosetta code augments CSV packet-size sequences rather than
    emitting modified pcap/raw traces. This implementation adapts the same
    packet aggregation and packet loss ideas to WFLib flow dictionaries while
    preserving aligned timestamp, direction, and length/size arrays.
    """
    EPSILON = 1e-9

    def __init__(self,
                 loss_rate_max: float = 0.3,
                 max_rtt: float = 0.01,
                 mss: int = 1448,
                 nagle: bool = True,
                 warmup_packets: int = 2):
        self.loss_rate_max = loss_rate_max
        self.max_rtt = max_rtt
        self.mss = mss
        self.nagle = nagle
        self.warmup_packets = warmup_packets

    @staticmethod
    def _length_key(data: Dict[str, np.ndarray]) -> str:
        if "length" in data:
            return "length"
        if "size" in data:
            return "size"
        raise KeyError("RosettaAugmentor requires either 'length' or 'size'.")

    @classmethod
    def _build_result(cls,
                      length_key: str,
                      direction: np.ndarray,
                      length: np.ndarray,
                      timestamp: np.ndarray) -> Dict[str, np.ndarray]:
        timestamp = np.asarray(timestamp, dtype=np.float64)
        timestamp = cls._ensure_monotonic(timestamp)
        return {
            "timestamp": timestamp,
            "direction": np.asarray(direction, dtype=np.int64),
            length_key: np.asarray(length, dtype=np.int64),
        }

    @staticmethod
    def _strip_padding(data: Dict[str, np.ndarray]
                       ) -> Tuple[str, np.ndarray, np.ndarray, np.ndarray]:
        length_key = RosettaAugmentor._length_key(data)
        direction = np.asarray(data["direction"], dtype=np.int64)
        timestamp = np.asarray(data["timestamp"], dtype=np.float64)
        length = np.asarray(data[length_key], dtype=np.int64)

        nonzero = np.nonzero(direction)[0]
        if len(nonzero) == 0:
            empty_int = np.array([], dtype=np.int64)
            empty_float = np.array([], dtype=np.float64)
            return length_key, empty_int, empty_int, empty_float

        active_end = nonzero[-1] + 1
        return (length_key,
                direction[:active_end].copy(),
                length[:active_end].copy(),
                timestamp[:active_end].copy())

    @classmethod
    def _ensure_monotonic(cls, timestamp: np.ndarray) -> np.ndarray:
        timestamp = np.asarray(timestamp, dtype=np.float64).copy()
        for i in range(1, len(timestamp)):
            if timestamp[i] < timestamp[i - 1]:
                timestamp[i] = timestamp[i - 1] + cls.EPSILON
        return timestamp

    def _compute_delay_cdf(self,
                           timestamp: np.ndarray,
                           direction: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        same_dir_delays: List[float] = []
        for i in range(1, len(timestamp)):
            delay = timestamp[i] - timestamp[i - 1]
            if direction[i] == direction[i - 1] and delay > 0:
                same_dir_delays.append(float(delay))

        if same_dir_delays:
            return empirical_cdf(np.array(same_dir_delays, dtype=np.float64))

        all_delays = np.diff(timestamp)
        all_delays = all_delays[all_delays > 0]
        if len(all_delays) > 0:
            return empirical_cdf(all_delays.astype(np.float64))

        fallback = max(float(self.max_rtt), self.EPSILON)
        values = np.array([fallback / 100.0, fallback / 10.0, fallback],
                          dtype=np.float64)
        cdf = np.array([0.33, 0.67, 1.0], dtype=np.float64)
        return values, cdf

    def _sample_delay(self, delay_values: np.ndarray, delay_cdf: np.ndarray) -> float:
        delay = float(sample_from_cdf(delay_cdf, delay_values.tolist()))
        if delay <= 0:
            return self.EPSILON
        return delay

    def _segment_payload(self, payload: int) -> List[int]:
        payload = int(abs(payload))
        if payload <= 0:
            return []

        segments: List[int] = []
        while payload > self.mss:
            segments.append(self.mss)
            payload -= self.mss
        segments.append(payload)
        return segments

    def _timestamps_for_segments(self,
                                 start_timestamp: float,
                                 count: int,
                                 delay_values: np.ndarray,
                                 delay_cdf: np.ndarray) -> List[float]:
        if count <= 0:
            return []

        timestamps = [float(start_timestamp)]
        while len(timestamps) < count:
            timestamps.append(timestamps[-1] +
                              self._sample_delay(delay_values, delay_cdf))
        return timestamps

    def _apply_nagle(self,
                     length_key: str,
                     direction: np.ndarray,
                     length: np.ndarray,
                     timestamp: np.ndarray) -> Dict[str, np.ndarray]:
        if not self.nagle or len(direction) == 0:
            return self._build_result(length_key, direction, length, timestamp)

        delay_values, delay_cdf = self._compute_delay_cdf(timestamp, direction)
        warmup = min(max(int(self.warmup_packets), 0), len(direction))

        out_dir: List[int] = direction[:warmup].astype(np.int64).tolist()
        out_len: List[int] = length[:warmup].astype(np.int64).tolist()
        out_ts: List[float] = timestamp[:warmup].astype(np.float64).tolist()

        i = warmup
        while i < len(direction):
            group_dir = int(direction[i])
            start_ts = float(timestamp[i])
            rtt_budget = random.random() * self.max_rtt
            payload = 0
            consumed = 0

            while i < len(direction) and int(direction[i]) == group_dir:
                payload += int(abs(length[i]))
                i += 1
                consumed += 1

                if i >= len(direction) or int(direction[i]) != group_dir:
                    break

                rtt_budget -= self._sample_delay(delay_values, delay_cdf)
                if consumed > 0 and rtt_budget <= 0:
                    break

            segments = self._segment_payload(payload)
            segment_ts = self._timestamps_for_segments(
                start_ts, len(segments), delay_values, delay_cdf
            )

            out_dir.extend([group_dir] * len(segments))
            out_len.extend(segments)
            out_ts.extend(segment_ts)

        return self._build_result(length_key,
                                  np.array(out_dir, dtype=np.int64),
                                  np.array(out_len, dtype=np.int64),
                                  np.array(out_ts, dtype=np.float64))

    def _apply_packet_loss(self,
                           length_key: str,
                           direction: np.ndarray,
                           length: np.ndarray,
                           timestamp: np.ndarray) -> Dict[str, np.ndarray]:
        if len(direction) <= 1 or self.loss_rate_max <= 0:
            return self._build_result(length_key, direction, length, timestamp)

        loss_rate = random.random() * self.loss_rate_max
        keep_indices = [0]
        for idx in range(1, len(direction)):
            if random.random() > loss_rate:
                keep_indices.append(idx)

        keep = np.array(keep_indices, dtype=np.int64)
        return self._build_result(length_key,
                                  direction[keep],
                                  length[keep],
                                  timestamp[keep])

    def augment(self, data: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Apply Rosetta-style Nagle aggregation followed by packet loss."""
        length_key, direction, length, timestamp = self._strip_padding(data)
        if len(direction) == 0:
            return self._build_result(length_key, direction, length, timestamp)

        aggregated = self._apply_nagle(length_key, direction, length, timestamp)
        return self._apply_packet_loss(
            length_key,
            aggregated["direction"],
            aggregated[length_key],
            aggregated["timestamp"],
        )


class SlopeAugmentor(FlowAugmentor):
    """
    SlopeAugmentor augments a single flow according to an empirical slope
    distribution.  Bursts are defined by TCP segmentation behaviour rather
    than simple direction runs.
    """
    BETA = 0.2

    def __init__(self, slope_arr: np.ndarray,
                 threshold_ack: int = 100,
                 threshold_seg: int = 1400,
                 tcp_header_size: int = 60,
                 tcp_max_size: int = 1460,
                 ack_interval: int = 2):
        self.slope_arr = slope_arr

        self.threshold_ack = threshold_ack
        self.threshold_seg = threshold_seg
        self.tcp_header_size = tcp_header_size
        self.tcp_max_size = tcp_max_size
        self.mss = tcp_max_size - tcp_header_size
        self.ack_interval = ack_interval

    # ------------------------------------------------------------------
    # Burst construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_padding(data: Dict[str, np.ndarray]
                       ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Remove trailing zero-padding from direction/timestamp/length.

        Returns the three stripped arrays (direction, timestamp, length).
        """
        direction = data["direction"]
        timestamp = data["timestamp"]
        length = data["length"]

        nonzero = np.nonzero(direction)[0]
        if len(nonzero) == 0:
            empty_int = np.array([], dtype=np.int64)
            empty_float = np.array([], dtype=np.float64)
            return empty_int, empty_float, empty_int
        active_end = nonzero[-1] + 1
        return (direction[:active_end].copy(),
                timestamp[:active_end].copy(),
                length[:active_end].copy())

    def _classify_packets(self, direction: np.ndarray, length: np.ndarray
                          ) -> Dict[str, np.ndarray]:
        """Classify packet indices into four groups.

        Returns a dict with keys ``"out_ack"``, ``"in_ack"``,
        ``"out_data"``, ``"in_data"``, each mapping to an ``int64``
        index array.
        """
        out_mask = direction == 1
        in_mask = direction == -1
        ack_mask = length < self.threshold_ack
        data_mask = ~ack_mask

        return {
            "out_ack": np.where(out_mask & ack_mask)[0].astype(np.int64),
            "in_ack": np.where(in_mask & ack_mask)[0].astype(np.int64),
            "out_data": np.where(out_mask & data_mask)[0].astype(np.int64),
            "in_data": np.where(in_mask & data_mask)[0].astype(np.int64),
        }

    def _build_data_bursts(self, data_indices: np.ndarray,
                           length: np.ndarray) -> List[np.ndarray]:
        """Group data-view indices into TCP-segmentation-aware bursts.

        A burst is a maximal run of consecutive data-view indices whose
        packet length >= ``threshold_seg``, followed by at most one
        packet with length < ``threshold_seg``.  A standalone packet
        with length < ``threshold_seg`` forms its own single-element
        burst.
        """
        if len(data_indices) == 0:
            return []

        bursts: List[np.ndarray] = []
        current: List[int] = []

        for idx in data_indices:
            pkt_len = length[idx]
            if pkt_len >= self.threshold_seg:
                current.append(idx)
            else:
                current.append(idx)
                bursts.append(np.array(current, dtype=np.int64))
                current = []

        if current:
            bursts.append(np.array(current, dtype=np.int64))

        return bursts

    def _build_burst_view(self, data: Dict[str, np.ndarray]) -> Dict[str, object]:
        """Build the full burst view for a single flow.

        Returns
        -------
        dict with keys:

        - ``"out_ack"``  -- ``np.ndarray`` of outgoing ACK indices
        - ``"in_ack"``   -- ``np.ndarray`` of incoming ACK indices
        - ``"out_data"`` -- ``List[np.ndarray]``, outgoing data bursts
        - ``"in_data"``  -- ``List[np.ndarray]``, incoming data bursts
        - ``"active_length"`` -- number of non-padding packets
        - ``"direction"`` -- stripped direction array
        - ``"timestamp"`` -- stripped timestamp array
        - ``"length"``    -- stripped length array
        """
        direction, timestamp, length = self._strip_padding(data)
        groups = self._classify_packets(direction, length)

        return {
            "out_ack": groups["out_ack"],
            "in_ack": groups["in_ack"],
            "out_data": self._build_data_bursts(groups["out_data"], length),
            "in_data": self._build_data_bursts(groups["in_data"], length),
            "active_length": len(direction),
            "direction": direction,
            "timestamp": timestamp,
            "length": length,
        }

    # ------------------------------------------------------------------
    # Augmentation helpers
    # ------------------------------------------------------------------

    def _compute_flow_delay_cdf(
        self,
        timestamp: np.ndarray,
        direction: np.ndarray,
        length: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Compute empirical inter-packet delay CDF from data packets.

        Only considers consecutive data packets (length >= threshold_ack)
        travelling in the same direction.  Returns ``(values, cdf)`` or
        a small fallback if fewer than 2 qualifying delays exist.
        """
        data_mask = length >= self.threshold_ack
        data_ts = timestamp[data_mask]
        data_dir = direction[data_mask]

        delays: List[float] = []
        for i in range(1, len(data_ts)):
            if data_dir[i] == data_dir[i - 1]:
                d = data_ts[i] - data_ts[i - 1]
                if d > 0:
                    delays.append(d)

        if len(delays) < 2:
            fallback_vals = np.array([0.0001, 0.001, 0.01])
            fallback_cdf = np.array([0.33, 0.67, 1.0])
            return fallback_vals, fallback_cdf

        return empirical_cdf(np.array(delays))

    def _rescale_burst(
        self,
        burst_indices: np.ndarray,
        length: np.ndarray,
        direction: np.ndarray,
        timestamp: np.ndarray,
        slope: float,
        delay_values: np.ndarray,
        delay_cdf: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Rescale a data burst's payload by *slope* and re-segment.

        Returns ``(new_direction, new_length, new_timestamp)`` arrays
        for the rescaled burst (data packets only, no ACKs yet).
        """
        burst_len = length[burst_indices]
        burst_dir = direction[burst_indices[0]]
        t_start = timestamp[burst_indices[0]]

        payload = int(np.sum(burst_len)) - len(burst_indices) * self.tcp_header_size
        if payload <= 0:
            return (
                direction[burst_indices].copy(),
                length[burst_indices].copy(),
                timestamp[burst_indices].copy(),
            )

        extend_payload = math.ceil(payload * slope)
        k_new = math.ceil(extend_payload / self.mss)
        if k_new <= 0:
            k_new = 1

        remainder = extend_payload % self.mss
        new_lengths = np.full(k_new, self.tcp_max_size, dtype=np.int64)
        if remainder != 0:
            new_lengths[-1] = remainder + self.tcp_header_size

        new_dir = np.full(k_new, burst_dir, dtype=np.int64)

        new_ts = np.empty(k_new, dtype=np.float64)
        new_ts[0] = t_start
        for i in range(1, k_new):
            new_ts[i] = new_ts[i - 1] + sample_from_cdf(delay_cdf, delay_values.tolist())

        return new_dir, new_lengths, new_ts

    def _insert_acks(
        self,
        data_dir: np.ndarray,
        data_len: np.ndarray,
        data_ts: np.ndarray,
        delay_values: np.ndarray,
        delay_cdf: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Interleave ACK packets into a rescaled data burst.

        One ACK is inserted every ``ack_interval`` data segments.
        ACK direction is opposite to the burst direction.

        Timestamp rules:
        - ACK between two data packets: uniform random between neighbours.
        - Trailing ACK (after last data packet): last timestamp + sampled delay.
        """
        if len(data_dir) == 0:
            return data_dir.copy(), data_len.copy(), data_ts.copy()

        ack_dir_val = -data_dir[0]
        merged_dir: List[int] = []
        merged_len: List[int] = []
        merged_ts: List[float] = []
        data_count = 0

        for i in range(len(data_dir)):
            merged_dir.append(int(data_dir[i]))
            merged_len.append(int(data_len[i]))
            merged_ts.append(float(data_ts[i]))
            data_count += 1

            if data_count % self.ack_interval == 0:
                if i + 1 < len(data_dir):
                    ack_t = random.uniform(data_ts[i], data_ts[i + 1])
                else:
                    ack_t = data_ts[i] + sample_from_cdf(
                        delay_cdf, delay_values.tolist()
                    )
                merged_dir.append(int(ack_dir_val))
                merged_len.append(self.tcp_header_size)
                merged_ts.append(ack_t)

        return (
            np.array(merged_dir, dtype=np.int64),
            np.array(merged_len, dtype=np.int64),
            np.array(merged_ts, dtype=np.float64),
        )

    def _reassemble_flow(
        self,
        view: Dict[str, object],
        rescaled_bursts: Dict[int, Tuple[np.ndarray, np.ndarray, np.ndarray]],
    ) -> Dict[str, np.ndarray]:
        """Reassemble the flow from original ACKs and rescaled bursts.

        Parameters
        ----------
        view : burst view from ``_build_burst_view``.
        rescaled_bursts : mapping from the *first* original index of each
            burst to its ``(direction, length, timestamp)`` replacement
            (already including inserted ACKs).

        Walks through original indices in order, emitting either the
        original ACK packet (time-shifted) or the rescaled burst block.
        A running ``time_offset`` accumulates overflow from bursts that
        grew longer in time.
        """
        direction = view["direction"]
        timestamp = view["timestamp"]
        length = view["length"]
        n = view["active_length"]

        burst_start_set: Dict[int, Tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
        burst_member_set: set = set()
        for start_idx, replacement in rescaled_bursts.items():
            burst_start_set[start_idx] = replacement

        all_burst_indices: set = set()
        for burst_list in (view["out_data"], view["in_data"]):
            for b in burst_list:
                for idx in b:
                    all_burst_indices.add(int(idx))

        out_dir: List[np.ndarray] = []
        out_len: List[np.ndarray] = []
        out_ts: List[np.ndarray] = []
        time_offset = 0.0
        i = 0

        while i < n:
            if i in burst_start_set:
                burst_indices = None
                for burst_list in (view["out_data"], view["in_data"]):
                    for b in burst_list:
                        if len(b) > 0 and b[0] == i:
                            burst_indices = b
                            break
                    if burst_indices is not None:
                        break

                orig_end_ts = timestamp[burst_indices[-1]]
                rep_dir, rep_len, rep_ts = burst_start_set[i]
                shifted_rep_ts = rep_ts + time_offset
                out_dir.append(rep_dir)
                out_len.append(rep_len)
                out_ts.append(shifted_rep_ts)

                new_end_ts = shifted_rep_ts[-1] if len(shifted_rep_ts) > 0 else orig_end_ts
                overflow = new_end_ts - (orig_end_ts + time_offset)
                if overflow > 0:
                    time_offset += overflow

                i = int(burst_indices[-1]) + 1
            elif i in all_burst_indices:
                i += 1
            else:
                out_dir.append(np.array([direction[i]], dtype=np.int64))
                out_len.append(np.array([length[i]], dtype=np.int64))
                out_ts.append(np.array([timestamp[i] + time_offset], dtype=np.float64))
                i += 1

        if not out_dir:
            return {
                "direction": np.array([], dtype=np.int64),
                "length": np.array([], dtype=np.int64),
                "timestamp": np.array([], dtype=np.float64),
            }

        return {
            "direction": np.concatenate(out_dir).astype(np.int64),
            "length": np.concatenate(out_len).astype(np.int64),
            "timestamp": np.concatenate(out_ts).astype(np.float64),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def augment(self, data: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Augment a flow by rescaling data burst payloads via slope sampling.

        For each data burst (both directions), a random slope is drawn
        from ``slope_arr``.  The burst payload is divided by the slope,
        re-segmented into TCP-sized packets, ACKs are interleaved, and
        timestamps are assigned from the flow's empirical delay CDF.
        Subsequent packets are globally shifted to accommodate any
        time overflow.
        """
        view = self._build_burst_view(data)
        if view["active_length"] == 0:
            return {
                "direction": np.array([], dtype=np.int64),
                "length": np.array([], dtype=np.int64),
                "timestamp": np.array([], dtype=np.float64),
            }

        direction = view["direction"]
        timestamp = view["timestamp"]
        length = view["length"]

        delay_values, delay_cdf = self._compute_flow_delay_cdf(
            timestamp, direction, length
        )

        rescaled_bursts: Dict[int, Tuple[np.ndarray, np.ndarray, np.ndarray]] = {}

        for burst_list in (view["out_data"], view["in_data"]):
            for burst_indices in burst_list:
                if len(burst_indices) == 0:
                    continue
                slope = float(np.random.choice(self.slope_arr))
                d, l, t = self._rescale_burst(
                    burst_indices, length, direction, timestamp,
                    slope, delay_values, delay_cdf,
                )
                d, l, t = self._insert_acks(d, l, t, delay_values, delay_cdf)
                rescaled_bursts[int(burst_indices[0])] = (d, l, t)

        return self._reassemble_flow(view, rescaled_bursts)