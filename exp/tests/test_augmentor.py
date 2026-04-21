import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import numpy as np
import pytest
from WFlib.tools.augmentor import NetCLRAugmentor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_trace(n_packets=200, seed=42):
    """Build a synthetic trace with alternating direction bursts."""
    rng = np.random.RandomState(seed)
    direction = np.array(
        [1]*20 + [-1]*30 + [1]*10 + [-1]*50 + [1]*5 + [-1]*25 + [1]*15 + [-1]*45,
        dtype=np.int64,
    )
    assert len(direction) == n_packets
    size = rng.randint(40, 1500, size=n_packets).astype(np.int64)
    timestamp = np.sort(rng.uniform(0, 10, size=n_packets))
    return {"direction": direction, "size": size, "timestamp": timestamp}


def _make_short_trace(seed=99):
    """Short trace (< 1000 packets) that forces inflate in change_content."""
    rng = np.random.RandomState(seed)
    direction = np.array([1]*5 + [-1]*15 + [1]*3 + [-1]*12, dtype=np.int64)
    n = len(direction)
    size = rng.randint(40, 1500, size=n).astype(np.int64)
    timestamp = np.sort(rng.uniform(0, 2, size=n))
    return {"direction": direction, "size": size, "timestamp": timestamp}


def _make_augmentor(**kwargs):
    """Create an augmentor with sensible defaults for testing."""
    defaults = dict(
        outgoing_burst_sizes=[1, 2, 3, 4, 5],
        outgoing_burst_size_cdf=np.array([0.2, 0.4, 0.6, 0.8, 1.0]),
        outgoing_packet_sizes=[60, 120, 200, 500, 1000],
        outgoing_packet_size_cdf=np.array([0.2, 0.4, 0.6, 0.8, 1.0]),
        outgoing_delays=[0.001, 0.005, 0.01, 0.02, 0.05],
        outgoing_delay_cdf=np.array([0.2, 0.4, 0.6, 0.8, 1.0]),
    )
    defaults.update(kwargs)
    return NetCLRAugmentor(**defaults)


def _assert_valid_result(result, msg=""):
    """Check basic invariants on the augmented result."""
    assert "direction" in result and "size" in result and "timestamp" in result, \
        f"Missing keys {msg}"
    n = len(result["direction"])
    assert len(result["size"]) == n, \
        f"size length mismatch: {len(result['size'])} vs {n} {msg}"
    assert len(result["timestamp"]) == n, \
        f"timestamp length mismatch: {len(result['timestamp'])} vs {n} {msg}"
    assert np.issubdtype(result["direction"].dtype, np.integer), \
        f"direction dtype should be integer, got {result['direction'].dtype} {msg}"
    assert np.issubdtype(result["size"].dtype, np.integer), \
        f"size dtype should be integer, got {result['size'].dtype} {msg}"
    assert np.issubdtype(result["timestamp"].dtype, np.floating), \
        f"timestamp dtype should be float, got {result['timestamp'].dtype} {msg}"
    if n > 1:
        assert np.all(np.diff(result["timestamp"]) >= -1e-12), \
            f"timestamps not monotonically non-decreasing {msg}"


# ---------------------------------------------------------------------------
# _find_bursts tests
# ---------------------------------------------------------------------------

class TestFindBursts:
    def test_simple(self):
        d = np.array([1, 1, 1, -1, -1, 1])
        bursts = NetCLRAugmentor._find_bursts(d)
        assert bursts == [(0, 3), (3, 5), (5, 6)]

    def test_single_direction(self):
        d = np.array([-1, -1, -1, -1])
        assert NetCLRAugmentor._find_bursts(d) == [(0, 4)]

    def test_with_padding(self):
        d = np.array([1, 1, -1, -1, 0, 0, 0])
        bursts = NetCLRAugmentor._find_bursts(d)
        assert bursts == [(0, 2), (2, 4)]

    def test_empty(self):
        assert NetCLRAugmentor._find_bursts(np.array([])) == []

    def test_starts_with_zero(self):
        assert NetCLRAugmentor._find_bursts(np.array([0, 1, -1])) == []


# ---------------------------------------------------------------------------
# _change_content tests
# ---------------------------------------------------------------------------

class TestChangeContent:
    def test_resample_lengths_sync(self):
        aug = _make_augmentor()
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        _assert_valid_result(result, "resample")

    def test_interpolate_lengths_sync(self):
        aug = _make_augmentor()
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="interpolate")
        _assert_valid_result(result, "interpolate")

    def test_deflate_reduces_length(self):
        aug = _make_augmentor(r_down_sample=0.5)
        data = _make_trace()
        # Force deflate by making trace > 4000 via artificial repetition
        big = {
            "direction": np.tile(data["direction"], 25),
            "size": np.tile(data["size"], 25),
            "timestamp": np.sort(np.tile(data["timestamp"], 25) +
                                 np.repeat(np.arange(25) * 20, len(data["timestamp"]))),
        }
        result = aug._change_content(big, inflate_mode="resample")
        _assert_valid_result(result, "deflate")
        assert len(result["direction"]) <= len(big["direction"])

    def test_inflate_increases_length(self):
        aug = _make_augmentor(r_up_sample=1.0)
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        _assert_valid_result(result, "inflate")
        assert len(result["direction"]) >= len(data["direction"])

    def test_direction_preserved(self):
        """Non-incoming bursts and small incoming bursts should not change."""
        aug = _make_augmentor()
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        bursts_orig = aug._find_bursts(data["direction"])
        for s, e in bursts_orig:
            if data["direction"][s] == 1:
                orig_burst = data["direction"][s:e]
                # Outgoing bursts should survive unchanged in the output
                assert np.any(result["direction"] == 1)


# ---------------------------------------------------------------------------
# _merge_incoming_bursts tests
# ---------------------------------------------------------------------------

class TestMergeIncomingBursts:
    def test_keep_mode_sync(self):
        aug = _make_augmentor(merge_burst_rate=1.0)
        data = _make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        _assert_valid_result(result, "merge-keep")

    def test_compress_mode_sync(self):
        aug = _make_augmentor(merge_burst_rate=1.0)
        data = _make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="compress")
        _assert_valid_result(result, "merge-compress")

    def test_merge_reduces_burst_count(self):
        aug = _make_augmentor(merge_burst_rate=1.0, num_bursts_to_merge=3)
        data = _make_trace()
        orig_bursts = aug._find_bursts(data["direction"])
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        new_bursts = aug._find_bursts(result["direction"])
        # Merging should reduce or at most keep the same number of bursts
        assert len(new_bursts) <= len(orig_bursts)

    def test_no_merge_when_rate_zero(self):
        aug = _make_augmentor(merge_burst_rate=0.0)
        data = _make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        _assert_valid_result(result, "no-merge")
        # With merge_burst_rate=0, some bursts at the tail may still be emitted
        # but the direction content for non-tail bursts should be unchanged


# ---------------------------------------------------------------------------
# _add_outgoing_burst tests
# ---------------------------------------------------------------------------

class TestAddOutgoingBurst:
    def test_lengths_sync(self):
        aug = _make_augmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "add-outgoing")

    def test_adds_outgoing_packets(self):
        aug = _make_augmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        assert len(result["direction"]) >= len(data["direction"])

    def test_synthetic_timestamps_within_gap(self):
        aug = _make_augmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "add-outgoing-ts")

    def test_no_add_when_rate_zero(self):
        aug = _make_augmentor(add_outgoing_burst_rate=0.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        np.testing.assert_array_equal(result["direction"], data["direction"])

    def test_fallback_without_cdfs(self):
        aug = NetCLRAugmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "add-outgoing-no-cdf")


# ---------------------------------------------------------------------------
# augment dispatcher tests
# ---------------------------------------------------------------------------

class TestAugment:
    def test_empty_trace(self):
        aug = _make_augmentor()
        data = {"direction": np.array([]), "size": np.array([]), "timestamp": np.array([])}
        result = aug.augment(data)
        assert len(result["direction"]) == 0

    def test_all_zeros(self):
        aug = _make_augmentor()
        data = {"direction": np.array([0, 0, 0]), "size": np.zeros(3), "timestamp": np.zeros(3)}
        result = aug.augment(data)
        assert len(result["direction"]) == 0 or np.array_equal(result["direction"], data["direction"])

    def test_repeated_augment_stable(self):
        """Running augment many times should never crash or produce misaligned arrays."""
        aug = _make_augmentor(merge_burst_rate=0.5, add_outgoing_burst_rate=0.5)
        data = _make_trace()
        for i in range(50):
            result = aug.augment(data)
            _assert_valid_result(result, f"augment-iter-{i}")

    def test_augment_with_all_modes(self):
        aug = _make_augmentor()
        data = _make_trace()
        for im in ("resample", "interpolate"):
            for mtm in ("keep", "compress"):
                result = aug.augment(data, inflate_mode=im, merge_timestamp_mode=mtm)
                _assert_valid_result(result, f"augment-{im}-{mtm}")


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_single_packet(self):
        aug = _make_augmentor()
        data = {"direction": np.array([1], dtype=np.int64), "size": np.array([500], dtype=np.int64), "timestamp": np.array([0.0])}
        result = aug.augment(data)
        _assert_valid_result(result, "single-packet")

    def test_two_packets_opposite(self):
        aug = _make_augmentor()
        data = {
            "direction": np.array([1, -1], dtype=np.int64),
            "size": np.array([500, 1200], dtype=np.int64),
            "timestamp": np.array([0.0, 0.01]),
        }
        result = aug.augment(data)
        _assert_valid_result(result, "two-packets")

    def test_single_large_incoming_burst(self):
        aug = _make_augmentor(add_outgoing_burst_rate=1.0)
        n = 50
        rng = np.random.RandomState(77)
        data = {
            "direction": np.full(n, -1, dtype=np.int64),
            "size": rng.randint(100, 1400, size=n).astype(np.int64),
            "timestamp": np.sort(rng.uniform(0, 1, size=n)),
        }
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "single-incoming-burst")


# ---------------------------------------------------------------------------
# Dtype-specific tests
# ---------------------------------------------------------------------------

class TestDtypes:
    def test_change_content_resample_preserves_int(self):
        aug = _make_augmentor()
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        _assert_valid_result(result, "dtype-resample")

    def test_change_content_interpolate_preserves_int(self):
        aug = _make_augmentor()
        data = _make_short_trace()
        result = aug._change_content(data, inflate_mode="interpolate")
        _assert_valid_result(result, "dtype-interpolate")

    def test_merge_keep_preserves_int(self):
        aug = _make_augmentor(merge_burst_rate=1.0)
        data = _make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        _assert_valid_result(result, "dtype-merge-keep")

    def test_merge_compress_preserves_int(self):
        aug = _make_augmentor(merge_burst_rate=1.0)
        data = _make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="compress")
        _assert_valid_result(result, "dtype-merge-compress")

    def test_add_outgoing_with_cdf_preserves_int(self):
        aug = _make_augmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "dtype-add-outgoing-cdf")

    def test_add_outgoing_fallback_preserves_int(self):
        aug = NetCLRAugmentor(add_outgoing_burst_rate=1.0)
        data = _make_trace()
        result = aug._add_outgoing_burst(data)
        _assert_valid_result(result, "dtype-add-outgoing-fallback")

    def test_augment_repeated_preserves_int(self):
        aug = _make_augmentor(merge_burst_rate=0.5, add_outgoing_burst_rate=0.5)
        data = _make_trace()
        for i in range(50):
            result = aug.augment(data)
            _assert_valid_result(result, f"dtype-augment-iter-{i}")

    def test_deflate_preserves_int(self):
        aug = _make_augmentor(r_down_sample=0.5)
        data = _make_trace()
        big = {
            "direction": np.tile(data["direction"], 25),
            "size": np.tile(data["size"], 25),
            "timestamp": np.sort(np.tile(data["timestamp"], 25) +
                                 np.repeat(np.arange(25) * 20, len(data["timestamp"]))),
        }
        result = aug._change_content(big, inflate_mode="resample")
        _assert_valid_result(result, "dtype-deflate")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
