"""
Offline NetRandAugment-style augmentation for pa3 raw datasets.

The released NetRandAugment implementation operates on timing and direction
sequences. This script adapts those transformations to pa3 raw triplets by
carrying packet sizes through reorder/drop operations and sampling sizes for
synthetic packets from the current trace.
"""

import argparse
import os
import random
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from tqdm import tqdm

from pa3.tools.augmentor import raw_to_dict, dict_to_raw


Trace = Dict[str, np.ndarray]
PoolEntry = Dict[str, object]


DEFAULT_PARAMS = {
    "swap_ratio": 0.05,
    "upsample_rate": 1.0,
    "downsample_rate": 0.5,
    "shift_bound_a": 10,
    "merge_rate": 0.1,
    "merge_up_limit": 5,
    "shift_bound_m": 10,
    "insert_rate": 0.3,
    "shift_bound_i": 10,
    "inject_ratio": 0.1,
    "remove_ratio": 0.1,
    "overlap_ratio": 0.1,
    "replace_rate": 0.1,
    "interp_rate": 0.5,
}

M_RANGE_MAPPING = {
    "swap_ratio": [(0.05, 0.1), (0.05, 0.15), (0.05, 0.2), (0.05, 0.25), (0.05, 0.3),
                   (0.05, 0.35), (0.05, 0.4)],
    "upsample_rate": [(0.95, 1.05), (0.9, 1.1), (0.85, 1.15), (0.8, 1.2), (0.75, 1.25),
                      (0.7, 1.3), (0.65, 1.35)],
    "downsample_rate": [(0.45, 0.55), (0.4, 0.6), (0.35, 0.65), (0.3, 0.7), (0.25, 0.75),
                        (0.2, 0.8), (0.15, 0.85)],
    "shift_bound_a": [(10, 12), (10, 14), (10, 16), (10, 18), (10, 20),
                      (10, 22), (10, 24)],
    "merge_rate": [(0.05, 0.15), (0.05, 0.2), (0.05, 0.25), (0.05, 0.3), (0.05, 0.35),
                   (0.05, 0.4), (0.05, 0.45)],
    "merge_up_limit": [(3, 4), (3, 5), (3, 6), (3, 7), (3, 8), (3, 9), (3, 10)],
    "shift_bound_m": [(10, 12), (10, 14), (10, 16), (10, 18), (10, 20),
                      (10, 22), (10, 24)],
    "insert_rate": [(0.25, 0.35), (0.2, 0.4), (0.15, 0.45), (0.10, 0.50), (0.05, 0.55),
                    (0.05, 0.6), (0.05, 0.65)],
    "shift_bound_i": [(10, 12), (10, 14), (10, 16), (10, 18), (10, 20),
                      (10, 22), (10, 24)],
    "inject_ratio": [(0.05, 0.2), (0.05, 0.25), (0.05, 0.3), (0.05, 0.35), (0.05, 0.4),
                     (0.05, 0.45), (0.05, 0.5)],
    "remove_ratio": [(0.05, 0.2), (0.05, 0.25), (0.05, 0.3), (0.05, 0.35), (0.05, 0.4),
                     (0.05, 0.45), (0.05, 0.5)],
    "overlap_ratio": [(0.05, 0.2), (0.05, 0.25), (0.05, 0.3), (0.05, 0.35), (0.05, 0.4),
                      (0.05, 0.45), (0.05, 0.5)],
    "replace_rate": [(0.05, 0.2), (0.05, 0.25), (0.05, 0.3), (0.05, 0.35), (0.05, 0.4),
                     (0.05, 0.45), (0.05, 0.5)],
    "interp_rate": [(0.45, 0.55), (0.4, 0.6), (0.35, 0.65), (0.3, 0.7), (0.25, 0.75),
                    (0.2, 0.8), (0.15, 0.85)],
}

METHOD_PARAM_MAPPING = {
    "swap_burst_pairs": [("swap_ratio", float)],
    "alter_incoming_bursts": [("upsample_rate", float), ("downsample_rate", float), ("shift_bound_a", int)],
    "merge_incoming_bursts": [("merge_rate", float), ("merge_up_limit", int), ("shift_bound_m", int)],
    "insert_outgoing_bursts": [("insert_rate", float), ("shift_bound_i", int)],
    "inject_or_remove_packets": [("inject_ratio", float), ("remove_ratio", float)],
    "add_overlapping_segment": [("overlap_ratio", float)],
    "replace_peer_bursts": [("replace_rate", float)],
    "generate_linear_interpolation": [("interp_rate", float)],
}

ALL_METHODS = list(METHOD_PARAM_MAPPING.keys())
PEER_METHODS = {"replace_peer_bursts", "generate_linear_interpolation"}
RANDOM_METHODS = {"add_overlapping_segment"}
OUTGOING_POOL_METHODS = {"insert_outgoing_bursts"}


def _copy_trace(trace: Trace) -> Trace:
    return {k: np.asarray(v).copy() for k, v in trace.items()}


def _empty_trace() -> Trace:
    return {
        "timestamp": np.array([], dtype=np.float64),
        "direction": np.array([], dtype=np.int64),
        "size": np.array([], dtype=np.int64),
    }


def _build_trace(timestamp: Sequence[float], direction: Sequence[int], size: Sequence[int], sort: bool = True) -> Trace:
    ts = np.asarray(timestamp, dtype=np.float64)
    dr = np.asarray(direction, dtype=np.int64)
    sz = np.asarray(size, dtype=np.int64)
    n = min(len(ts), len(dr), len(sz))
    ts, dr, sz = ts[:n], dr[:n], sz[:n]
    active = dr != 0
    ts, dr, sz = ts[active], dr[active], sz[active]
    if len(ts) == 0:
        return _empty_trace()
    if sort:
        order = np.argsort(ts, kind="stable")
        ts, dr, sz = ts[order], dr[order], sz[order]
    for i in range(1, len(ts)):
        if ts[i] < ts[i - 1]:
            ts[i] = ts[i - 1]
    return {"timestamp": ts, "direction": dr, "size": sz}


def _sample_size(trace: Trace) -> int:
    sizes = np.asarray(trace["size"], dtype=np.int64)
    sizes = sizes[sizes > 0]
    if len(sizes) == 0:
        return 1
    return int(np.random.choice(sizes))


def _update_times(times: Sequence[float], old_boot_t: float, new_boot_t: float) -> List[float]:
    return [float(t) - float(old_boot_t) + float(new_boot_t) for t in times]


def _extract_bursts(trace: Trace) -> List[Dict[str, object]]:
    ts = np.asarray(trace["timestamp"], dtype=np.float64)
    dr = np.asarray(trace["direction"], dtype=np.int64)
    sz = np.asarray(trace["size"], dtype=np.int64)
    if len(dr) == 0:
        return []

    bursts: List[Dict[str, object]] = []
    cur_dir = int(dr[0])
    cur_ts = [float(ts[0])]
    cur_sz = [int(sz[0])]
    boot_time = 0.0

    for t, d, s in zip(ts[1:], dr[1:], sz[1:]):
        d = int(d)
        if d == 0:
            break
        if d == cur_dir:
            cur_ts.append(float(t))
            cur_sz.append(int(s))
        else:
            bursts.append({
                "direction": cur_dir,
                "times": cur_ts,
                "sizes": cur_sz,
                "boot_time": boot_time,
            })
            boot_time = cur_ts[-1]
            cur_dir = d
            cur_ts = [float(t)]
            cur_sz = [int(s)]

    bursts.append({
        "direction": cur_dir,
        "times": cur_ts,
        "sizes": cur_sz,
        "boot_time": boot_time,
    })
    return bursts


def _burst_count(burst: Dict[str, object]) -> int:
    return len(burst["times"])


def _burst_to_trace(bursts: List[Dict[str, object]]) -> Trace:
    times: List[float] = []
    directions: List[int] = []
    sizes: List[int] = []
    for burst in bursts:
        count = _burst_count(burst)
        times.extend(burst["times"])
        directions.extend([int(burst["direction"])] * count)
        sizes.extend([int(s) for s in burst["sizes"]])
    return _build_trace(times, directions, sizes, sort=False)


def _retime_burst(burst: Dict[str, object], new_boot_t: float) -> Dict[str, object]:
    return {
        "direction": int(burst["direction"]),
        "times": _update_times(burst["times"], burst["boot_time"], new_boot_t),
        "sizes": [int(s) for s in burst["sizes"]],
        "boot_time": float(new_boot_t),
    }


def _merge_traces(trace_a: Trace, trace_b: Trace) -> Trace:
    ts = np.concatenate([trace_a["timestamp"], trace_b["timestamp"]])
    dr = np.concatenate([trace_a["direction"], trace_b["direction"]])
    sz = np.concatenate([trace_a["size"], trace_b["size"]])
    return _build_trace(ts, dr, sz, sort=True)


def _find_split_idx_by_span(timestamp: np.ndarray, span: float) -> int:
    if len(timestamp) < 2:
        return 0
    target_time = timestamp[-1] - span
    if target_time <= 0:
        return 0
    return int(np.searchsorted(timestamp[:-1], target_time, side="left"))


def _sorted_burst_ids(bursts: List[Dict[str, object]], direction: int) -> List[int]:
    ids = [i for i, burst in enumerate(bursts) if int(burst["direction"]) == direction]
    return sorted(ids, key=lambda i: _burst_count(bursts[i]), reverse=True)


def _counterpart_mapping(ids: List[int], ex_ids: List[int]) -> Dict[int, int]:
    if not ids or not ex_ids:
        return {}
    scale = len(ex_ids) / len(ids)
    return {raw_id: ex_ids[min(int((rank + 1) * scale), len(ex_ids)) - 1]
            for rank, raw_id in enumerate(ids)}


def _resample_burst_counts(bursts: List[Dict[str, object]], raw_len: int, target_len: int) -> List[int]:
    if not bursts or raw_len <= 0:
        return []
    factor = target_len / raw_len
    target_float = [_burst_count(burst) * factor for burst in bursts]
    target_int = [max(1, int(v)) for v in target_float]
    budget = max(len(bursts), target_len) - sum(target_int)
    gaps = [tf - ti for tf, ti in zip(target_float, target_int)]
    for idx in sorted(range(len(bursts)), key=lambda i: gaps[i], reverse=True):
        if budget <= 0:
            break
        target_int[idx] += 1
        budget -= 1
    return target_int


def _align_bursts(bursts: List[Dict[str, object]], target_counts: List[int], size_trace: Trace) -> List[Dict[str, object]]:
    aligned = []
    for burst, target_count in zip(bursts, target_counts):
        new_burst = {
            "direction": int(burst["direction"]),
            "times": list(burst["times"]),
            "sizes": [int(s) for s in burst["sizes"]],
            "boot_time": float(burst["boot_time"]),
        }
        cur_count = _burst_count(new_burst)
        if cur_count < target_count:
            add_num = target_count - cur_count
            positions = (random.sample(range(cur_count), add_num)
                         if add_num <= cur_count else random.choices(range(cur_count), k=add_num))
            for p in sorted(positions, reverse=True):
                if p > 0:
                    new_t = random.uniform(new_burst["times"][p - 1], new_burst["times"][p])
                else:
                    new_t = new_burst["times"][0]
                new_burst["times"].insert(p, new_t)
                new_burst["sizes"].insert(p, _sample_size(size_trace))
        elif cur_count > target_count:
            remove_positions = random.sample(range(cur_count), cur_count - target_count)
            for p in sorted(remove_positions, reverse=True):
                new_burst["times"].pop(p)
                new_burst["sizes"].pop(p)
        aligned.append(new_burst)
    return aligned


def build_pools_from_raw(X: np.ndarray, labels: np.ndarray) -> Tuple[List[PoolEntry], Dict[int, List[int]], List[int], List[Trace]]:
    traces: List[PoolEntry] = []
    same_class_pool: Dict[int, List[int]] = {}
    random_pool: List[int] = []
    outgoing_burst_pool: List[Trace] = []

    for idx in range(len(X)):
        trace = raw_to_dict(X[idx])
        label = int(labels[idx])
        entry = {"index": idx, "label": label, "trace": trace}
        traces.append(entry)
        if len(trace["direction"]) == 0:
            continue
        same_class_pool.setdefault(label, []).append(idx)
        random_pool.append(idx)
        for burst in _extract_bursts(trace):
            if int(burst["direction"]) != 1:
                continue
            times = np.asarray(burst["times"], dtype=np.float64)
            if len(times) == 0:
                continue
            outgoing_burst_pool.append({
                "timestamp": times - times[0],
                "direction": np.ones(len(times), dtype=np.int64),
                "size": np.asarray(burst["sizes"], dtype=np.int64),
            })

    return traces, same_class_pool, random_pool, outgoing_burst_pool


class NetRandAugmentRaw:
    def __init__(self,
                 traces: List[PoolEntry],
                 same_class_pool: Dict[int, List[int]],
                 random_pool: List[int],
                 outgoing_burst_pool: List[Trace],
                 n: int = 1,
                 m: int = 4,
                 methods: Optional[Sequence[str]] = None):
        if not 1 <= int(m) <= 7:
            raise ValueError("M must be in [1, 7].")
        self.traces = traces
        self.same_class_pool = same_class_pool
        self.random_pool = random_pool
        self.outgoing_burst_pool = outgoing_burst_pool
        self.N = int(n)
        self.M = int(m)
        self.methods = list(methods) if methods else list(ALL_METHODS)
        unknown = set(self.methods) - set(ALL_METHODS)
        if unknown:
            raise ValueError(f"Unknown NetRandAugment methods: {sorted(unknown)}")
        for key, value in DEFAULT_PARAMS.items():
            setattr(self, key, value)

    def _sample_magnitude(self, method: str) -> None:
        for param_name, param_type in METHOD_PARAM_MAPPING[method]:
            lo, hi = M_RANGE_MAPPING[param_name][self.M - 1]
            if param_type is int:
                setattr(self, param_name, random.randint(int(lo), int(hi)))
            else:
                setattr(self, param_name, random.uniform(float(lo), float(hi)))

    def _peer_trace(self, index: int, label: int) -> Optional[Trace]:
        candidates = [i for i in self.same_class_pool.get(int(label), []) if i != index]
        if not candidates:
            return None
        return _copy_trace(self.traces[random.choice(candidates)]["trace"])

    def _random_trace(self, index: int) -> Optional[Trace]:
        candidates = [i for i in self.random_pool if i != index]
        if not candidates:
            candidates = list(self.random_pool)
        if not candidates:
            return None
        return _copy_trace(self.traces[random.choice(candidates)]["trace"])

    def _available_methods(self, index: int, label: int, methods: Sequence[str]) -> List[str]:
        available = []
        has_peer = self._peer_trace(index, label) is not None
        has_random = self._random_trace(index) is not None
        has_outgoing = len(self.outgoing_burst_pool) > 0
        for method in methods:
            if method in PEER_METHODS and not has_peer:
                continue
            if method in RANDOM_METHODS and not has_random:
                continue
            if method in OUTGOING_POOL_METHODS and not has_outgoing:
                continue
            available.append(method)
        return available

    def augment(self,
                trace: Trace,
                index: int,
                label: int,
                mode: str = "randaugment",
                methods: Optional[Sequence[str]] = None) -> Trace:
        if len(trace["direction"]) == 0:
            return _copy_trace(trace)
        candidates = list(methods) if methods else list(self.methods)
        candidates = self._available_methods(index, label, candidates)
        if not candidates:
            return _copy_trace(trace)

        if mode.lower() == "randaugment":
            out = _copy_trace(trace)
            for _ in range(self.N):
                method = random.choice(candidates)
                self._sample_magnitude(method)
                out = self._apply(method, out, index, label)
            return out
        if mode.lower() == "random":
            method = random.choice(candidates)
            return self._apply(method, trace, index, label)
        if mode in ALL_METHODS:
            if mode not in candidates:
                return _copy_trace(trace)
            return self._apply(mode, trace, index, label)
        raise ValueError(f"Unsupported mode: {mode}")

    def _apply(self, method: str, trace: Trace, index: int, label: int) -> Trace:
        if method == "add_overlapping_segment":
            return self.add_overlapping_segment(trace, self._random_trace(index))
        if method == "replace_peer_bursts":
            return self.replace_peer_bursts(trace, self._peer_trace(index, label))
        if method == "generate_linear_interpolation":
            return self.generate_linear_interpolation(trace, self._peer_trace(index, label))
        return getattr(self, method)(trace)

    def _netclr_shift(self, trace: Trace, shift_bound: int) -> Trace:
        if len(trace["direction"]) == 0 or shift_bound <= 0:
            return _copy_trace(trace)
        shift = int(np.random.randint(-shift_bound, shift_bound + 1))
        if shift > 0:
            if shift >= len(trace["direction"]):
                return _empty_trace()
            return _build_trace(trace["timestamp"][shift:], trace["direction"][shift:], trace["size"][shift:], sort=False)
        if shift < 0:
            add_num = abs(shift)
            time_bound = trace["timestamp"][add_num] if add_num < len(trace["timestamp"]) else trace["timestamp"][-1]
            prefix_ts = sorted(np.random.uniform(0, max(float(time_bound), 0.0), size=add_num).tolist())
            prefix_dir = np.random.choice([-1, 1], size=add_num).astype(np.int64)
            prefix_size = np.array([_sample_size(trace) for _ in range(add_num)], dtype=np.int64)
            return _build_trace(np.concatenate([prefix_ts, trace["timestamp"]]),
                                np.concatenate([prefix_dir, trace["direction"]]),
                                np.concatenate([prefix_size, trace["size"]]),
                                sort=False)
        return _copy_trace(trace)

    def swap_burst_pairs(self, trace: Trace) -> Trace:
        bursts = _extract_bursts(trace)
        if len(bursts) < 2:
            return _copy_trace(trace)
        swap_num = min(int(len(bursts) * self.swap_ratio), len(bursts) - 1)
        if swap_num < 1:
            return _copy_trace(trace)
        for pos in sorted(random.sample(range(len(bursts) - 1), swap_num)):
            left, right = bursts[pos], bursts[pos + 1]
            new_right_times = _update_times(right["times"], right["boot_time"], left["boot_time"])
            new_left_times = _update_times(left["times"], left["boot_time"], new_right_times[-1])
            bursts[pos] = {"direction": right["direction"], "times": new_right_times,
                           "sizes": list(right["sizes"]), "boot_time": left["boot_time"]}
            bursts[pos + 1] = {"direction": left["direction"], "times": new_left_times,
                               "sizes": list(left["sizes"]), "boot_time": new_right_times[-1]}
        return _burst_to_trace(bursts)

    def alter_incoming_bursts(self, trace: Trace) -> Trace:
        bursts = _extract_bursts(trace)
        if not bursts:
            return _copy_trace(trace)

        def increase() -> None:
            for burst in bursts:
                if int(burst["direction"]) != -1:
                    continue
                count = _burst_count(burst)
                inject_num = int(count * self.upsample_rate * random.random())
                if inject_num <= 0:
                    continue
                positions = (random.sample(range(count), inject_num)
                             if inject_num <= count else random.choices(range(count), k=inject_num))
                for pos in sorted(positions, reverse=True):
                    times = burst["times"]
                    new_t = random.uniform(times[pos - 1], times[pos]) if pos > 0 else times[0]
                    burst["times"].insert(pos, new_t)
                    burst["sizes"].insert(pos, _sample_size(trace))

        def decrease() -> None:
            for burst in bursts:
                if int(burst["direction"]) != -1:
                    continue
                count = _burst_count(burst)
                remove_num = int(count * self.downsample_rate * random.random())
                if remove_num <= 0:
                    continue
                remove_num = min(remove_num, count)
                for pos in sorted(random.sample(range(count), remove_num), reverse=True):
                    burst["times"].pop(pos)
                    burst["sizes"].pop(pos)

        trace_len = len(trace["direction"])
        if trace_len < 1000:
            increase()
        elif trace_len > 4000:
            decrease()
        elif random.random() >= 0.5:
            increase()
        else:
            decrease()
        return self._netclr_shift(_burst_to_trace([b for b in bursts if _burst_count(b) > 0]), self.shift_bound_a)

    def merge_incoming_bursts(self, trace: Trace) -> Trace:
        bursts = _extract_bursts(trace)
        if not bursts:
            return _copy_trace(trace)
        new_bursts = []
        bid = 0
        packet_count = 0
        cur_boot = 0.0
        while bid < len(bursts) and packet_count < 20:
            packet_count += _burst_count(bursts[bid])
            retimed = _retime_burst(bursts[bid], cur_boot)
            cur_boot = retimed["times"][-1]
            new_bursts.append(retimed)
            bid += 1

        while bid < len(bursts):
            burst = bursts[bid]
            if int(burst["direction"]) != -1 or bid >= len(bursts) - self.merge_up_limit:
                retimed = _retime_burst(burst, cur_boot)
                cur_boot = retimed["times"][-1]
                new_bursts.append(retimed)
                bid += 1
                continue
            if random.random() < self.merge_rate:
                num_merges = random.randint(2, self.merge_up_limit)
                merged_times: List[float] = []
                merged_sizes: List[int] = []
                merged_boot = cur_boot
                while bid < len(bursts) and num_merges > 0:
                    if int(bursts[bid]["direction"]) == -1:
                        retimed = _retime_burst(bursts[bid], cur_boot)
                        merged_times.extend(retimed["times"])
                        merged_sizes.extend(retimed["sizes"])
                        cur_boot = merged_times[-1]
                        num_merges -= 1
                    bid += 1
                if merged_times:
                    new_bursts.append({"direction": -1, "times": merged_times,
                                       "sizes": merged_sizes, "boot_time": merged_boot})
            else:
                retimed = _retime_burst(burst, cur_boot)
                cur_boot = retimed["times"][-1]
                new_bursts.append(retimed)
                bid += 1
        return self._netclr_shift(_burst_to_trace(new_bursts), self.shift_bound_m)

    def insert_outgoing_bursts(self, trace: Trace) -> Trace:
        if not self.outgoing_burst_pool:
            return _copy_trace(trace)
        bursts = _extract_bursts(trace)
        new_bursts = []
        bid = 0
        packet_count = 0
        cur_boot = 0.0
        while bid < len(bursts) and packet_count < 20:
            packet_count += _burst_count(bursts[bid])
            retimed = _retime_burst(bursts[bid], cur_boot)
            cur_boot = retimed["times"][-1]
            new_bursts.append(retimed)
            bid += 1

        while bid < len(bursts):
            burst = bursts[bid]
            count = _burst_count(burst)
            if int(burst["direction"]) == 1 or count < 10 or random.random() >= self.insert_rate:
                retimed = _retime_burst(burst, cur_boot)
                cur_boot = retimed["times"][-1]
                new_bursts.append(retimed)
                bid += 1
                continue
            split_pos = random.randint(3, count - 3)
            left = {"direction": -1,
                    "times": _update_times(burst["times"][:split_pos], burst["boot_time"], cur_boot),
                    "sizes": list(burst["sizes"][:split_pos]),
                    "boot_time": cur_boot}
            cur_boot = left["times"][-1]
            sampled = random.choice(self.outgoing_burst_pool)
            mid_times = (np.asarray(sampled["timestamp"], dtype=np.float64) + cur_boot).tolist()
            mid = {"direction": 1, "times": mid_times,
                   "sizes": np.asarray(sampled["size"], dtype=np.int64).tolist(),
                   "boot_time": cur_boot}
            cur_boot = mid["times"][-1]
            right = {"direction": -1,
                     "times": _update_times(burst["times"][split_pos:], burst["times"][split_pos - 1], cur_boot),
                     "sizes": list(burst["sizes"][split_pos:]),
                     "boot_time": cur_boot}
            cur_boot = right["times"][-1]
            new_bursts.extend([left, mid, right])
            bid += 1
        return self._netclr_shift(_burst_to_trace(new_bursts), self.shift_bound_i)

    def inject_or_remove_packets(self, trace: Trace) -> Trace:
        times = trace["timestamp"].astype(np.float64).tolist()
        directions = trace["direction"].astype(np.int64).tolist()
        sizes = trace["size"].astype(np.int64).tolist()
        if not times:
            return _copy_trace(trace)
        if random.random() >= 0.5:
            inject_num = int(len(times) * self.inject_ratio)
            if inject_num <= 0:
                return _copy_trace(trace)
            positions = random.sample(range(len(times)), min(inject_num, len(times)))
            for pos in sorted(positions, reverse=True):
                new_t = random.uniform(times[pos - 1], times[pos]) if pos > 0 else 0.0
                times.insert(pos, new_t)
                directions.insert(pos, random.choice([-1, 1]))
                sizes.insert(pos, _sample_size(trace))
        else:
            remove_num = int(len(times) * self.remove_ratio)
            if remove_num <= 0:
                return _copy_trace(trace)
            for pos in sorted(random.sample(range(len(times)), min(remove_num, len(times))), reverse=True):
                times.pop(pos)
                directions.pop(pos)
                sizes.pop(pos)
        return _build_trace(times, directions, sizes)

    def add_overlapping_segment(self, trace: Trace, ex_trace: Optional[Trace]) -> Trace:
        if ex_trace is None or len(trace["direction"]) == 0 or len(ex_trace["direction"]) == 0:
            return _copy_trace(trace)
        overlap_len = min(int(len(trace["direction"]) * self.overlap_ratio), len(ex_trace["direction"]))
        if overlap_len <= 0:
            return _copy_trace(trace)
        if random.random() >= 0.5:
            ex_part = {k: v[-overlap_len:].copy() for k, v in ex_trace.items()}
            ex_part["timestamp"] = ex_part["timestamp"] - ex_part["timestamp"][0]
            return _merge_traces(trace, ex_part)
        ex_part = {k: v[:overlap_len].copy() for k, v in ex_trace.items()}
        split_idx = _find_split_idx_by_span(trace["timestamp"], ex_part["timestamp"][-1])
        ex_part["timestamp"] = ex_part["timestamp"] + trace["timestamp"][split_idx]
        fixed = {k: v[:split_idx].copy() for k, v in trace.items()}
        altered = {k: v[split_idx:].copy() for k, v in trace.items()}
        merged = _merge_traces(altered, ex_part)
        return _build_trace(np.concatenate([fixed["timestamp"], merged["timestamp"]]),
                            np.concatenate([fixed["direction"], merged["direction"]]),
                            np.concatenate([fixed["size"], merged["size"]]),
                            sort=False)

    def replace_peer_bursts(self, trace: Trace, peer_trace: Optional[Trace]) -> Trace:
        if peer_trace is None:
            return _copy_trace(trace)
        bursts = _extract_bursts(trace)
        peer_bursts = _extract_bursts(peer_trace)
        out_map = _counterpart_mapping(_sorted_burst_ids(bursts, 1), _sorted_burst_ids(peer_bursts, 1))
        in_map = _counterpart_mapping(_sorted_burst_ids(bursts, -1), _sorted_burst_ids(peer_bursts, -1))
        new_bursts = []
        cur_boot = 0.0
        for bid, burst in enumerate(bursts):
            replacement = burst
            if random.random() < self.replace_rate:
                peer_id = out_map.get(bid) if int(burst["direction"]) == 1 else in_map.get(bid)
                if peer_id is not None:
                    replacement = peer_bursts[peer_id]
            retimed = _retime_burst(replacement, cur_boot)
            cur_boot = retimed["times"][-1]
            new_bursts.append(retimed)
        return _burst_to_trace(new_bursts)

    def generate_linear_interpolation(self, trace: Trace, peer_trace: Optional[Trace]) -> Trace:
        if peer_trace is None or len(trace["direction"]) == 0 or len(peer_trace["direction"]) == 0:
            return _copy_trace(trace)
        alpha = 1.0 - random.random() * self.interp_rate
        target_len = max(1, int(alpha * len(trace["direction"]) + (1 - alpha) * len(peer_trace["direction"])))
        bursts = _extract_bursts(trace)
        peer_bursts = _extract_bursts(peer_trace)
        if not bursts or not peer_bursts:
            return _copy_trace(trace)
        aligned = _align_bursts(bursts, _resample_burst_counts(bursts, len(trace["direction"]), target_len), trace)
        aligned_peer = _align_bursts(peer_bursts, _resample_burst_counts(peer_bursts, len(peer_trace["direction"]), target_len), peer_trace)
        left = _burst_to_trace(aligned)
        right = _burst_to_trace(aligned_peer)
        n = min(len(left["direction"]), len(right["direction"]))
        if n == 0:
            return _copy_trace(trace)
        new_ts = alpha * left["timestamp"][:n] + (1 - alpha) * right["timestamp"][:n]
        signs = alpha * left["direction"][:n] + (1 - alpha) * right["direction"][:n]
        new_dir = np.where(signs >= 0, 1, -1).astype(np.int64)
        new_size = np.maximum(1, np.rint(alpha * left["size"][:n] + (1 - alpha) * right["size"][:n])).astype(np.int64)
        return _build_trace(new_ts, new_dir, new_size)


def augment_raw_dataset(input_file: str,
                        output_file: str,
                        n_aug: int = 1,
                        n: int = 1,
                        m: int = 4,
                        mode: str = "randaugment",
                        methods: Optional[Sequence[str]] = None,
                        seed: int = 2024) -> None:
    random.seed(seed)
    np.random.seed(seed)
    data = np.load(input_file, allow_pickle=True)
    X = data["raw"]
    y = data["labels"]
    hosts = data["hosts"]
    seq_len = X.shape[1]

    traces, same_class_pool, random_pool, outgoing_burst_pool = build_pools_from_raw(X, y)
    augmentor = NetRandAugmentRaw(traces, same_class_pool, random_pool, outgoing_burst_pool,
                                  n=n, m=m, methods=methods)
    X_aug_list = []
    y_aug_list = []
    for idx in tqdm(range(len(X)), desc="NetRandAugment"):
        trace = traces[idx]["trace"]
        label = int(y[idx])
        for _ in range(n_aug):
            aug_trace = augmentor.augment(trace, idx, label, mode=mode, methods=methods)
            X_aug_list.append(dict_to_raw(aug_trace, seq_len))
            y_aug_list.append(y[idx])

    np.savez_compressed(output_file,
                        raw=np.stack(X_aug_list, axis=0),
                        labels=np.asarray(y_aug_list),
                        hosts=hosts)
    print(f"Saved {len(X_aug_list)} augmented samples to {output_file}")


def _parse_methods(methods: Optional[str]) -> Optional[List[str]]:
    if methods is None or methods.strip() == "":
        return None
    return [m.strip() for m in methods.split(",") if m.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="NetRandAugment for pa3 raw .npz datasets")
    parser.add_argument("--input_file", "-i", type=str, required=True, help="Path to input raw .npz file")
    parser.add_argument("--output_file", "-o", type=str, required=True, help="Path to output raw .npz file")
    parser.add_argument("--n_aug", type=int, default=1, help="Number of augmented copies per sample")
    parser.add_argument("--seed", type=int, default=2024, help="Random seed")
    parser.add_argument("--N", type=int, default=1, help="Number of RandAugment operations")
    parser.add_argument("--M", type=int, default=4, help="RandAugment magnitude in [1, 7]")
    parser.add_argument("--methods", type=str, default=None, help="Comma-separated subset of methods")
    parser.add_argument("--mode", type=str, default="randaugment",
                        help="randaugment, random, or one concrete method name")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        raise FileNotFoundError(f"Input file does not exist: {args.input_file}")
    if os.path.exists(args.output_file):
        print(f"Output file already exists: {args.output_file}")
        return

    augment_raw_dataset(args.input_file, args.output_file,
                        n_aug=args.n_aug,
                        n=args.N,
                        m=args.M,
                        mode=args.mode,
                        methods=_parse_methods(args.methods),
                        seed=args.seed)


if __name__ == "__main__":
    main()
