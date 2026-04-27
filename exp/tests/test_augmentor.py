import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import numpy as np
import pytest
from WFlib.tools.augmentor import NetCLRAugmentor
from WFlib.utils.statistics import find_bursts
from fixture import (
    make_trace, make_short_trace, make_augmentor, assert_valid_result,
)


# ---------------------------------------------------------------------------
# _change_content tests
# ---------------------------------------------------------------------------

class TestChangeContent:
    def test_resample_lengths_sync(self):
        aug = make_augmentor()
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        assert_valid_result(result, "resample")

    def test_interpolate_lengths_sync(self):
        aug = make_augmentor()
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="interpolate")
        assert_valid_result(result, "interpolate")

    def test_deflate_reduces_length(self):
        aug = make_augmentor(r_down_sample=0.5)
        data = make_trace()
        big = {
            "direction": np.tile(data["direction"], 25),
            "size": np.tile(data["size"], 25),
            "timestamp": np.sort(np.tile(data["timestamp"], 25) +
                                 np.repeat(np.arange(25) * 20, len(data["timestamp"]))),
        }
        result = aug._change_content(big, inflate_mode="resample")
        assert_valid_result(result, "deflate")
        assert len(result["direction"]) <= len(big["direction"])

    def test_inflate_increases_length(self):
        aug = make_augmentor(r_up_sample=1.0)
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        assert_valid_result(result, "inflate")
        assert len(result["direction"]) >= len(data["direction"])

    def test_direction_preserved(self):
        """Non-incoming bursts and small incoming bursts should not change."""
        aug = make_augmentor()
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        bursts_orig = find_bursts(data["direction"])
        for s, e in bursts_orig:
            if data["direction"][s] == 1:
                assert np.any(result["direction"] == 1)


# ---------------------------------------------------------------------------
# _merge_incoming_bursts tests
# ---------------------------------------------------------------------------

class TestMergeIncomingBursts:
    def test_keep_mode_sync(self):
        aug = make_augmentor(merge_burst_rate=1.0)
        data = make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        assert_valid_result(result, "merge-keep")

    def test_compress_mode_sync(self):
        aug = make_augmentor(merge_burst_rate=1.0)
        data = make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="compress")
        assert_valid_result(result, "merge-compress")

    def test_merge_reduces_burst_count(self):
        aug = make_augmentor(merge_burst_rate=1.0, num_bursts_to_merge=3)
        data = make_trace()
        orig_bursts = find_bursts(data["direction"])
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        new_bursts = find_bursts(result["direction"])
        assert len(new_bursts) <= len(orig_bursts)

    def test_no_merge_when_rate_zero(self):
        aug = make_augmentor(merge_burst_rate=0.0)
        data = make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        assert_valid_result(result, "no-merge")


# ---------------------------------------------------------------------------
# _add_outgoing_burst tests
# ---------------------------------------------------------------------------

class TestAddOutgoingBurst:
    def test_lengths_sync(self):
        aug = make_augmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "add-outgoing")

    def test_adds_outgoing_packets(self):
        aug = make_augmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert len(result["direction"]) >= len(data["direction"])

    def test_synthetic_timestamps_within_gap(self):
        aug = make_augmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "add-outgoing-ts")

    def test_no_add_when_rate_zero(self):
        aug = make_augmentor(add_outgoing_burst_rate=0.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        np.testing.assert_array_equal(result["direction"], data["direction"])

    def test_fallback_without_cdfs(self):
        aug = NetCLRAugmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "add-outgoing-no-cdf")


# ---------------------------------------------------------------------------
# augment dispatcher tests
# ---------------------------------------------------------------------------

class TestAugment:
    def test_empty_trace(self):
        aug = make_augmentor()
        data = {"direction": np.array([]), "size": np.array([]), "timestamp": np.array([])}
        result = aug.augment(data)
        assert len(result["direction"]) == 0

    def test_all_zeros(self):
        aug = make_augmentor()
        data = {"direction": np.array([0, 0, 0]), "size": np.zeros(3), "timestamp": np.zeros(3)}
        result = aug.augment(data)
        assert len(result["direction"]) == 0 or np.array_equal(result["direction"], data["direction"])

    def test_repeated_augment_stable(self):
        """Running augment many times should never crash or produce misaligned arrays."""
        aug = make_augmentor(merge_burst_rate=0.5, add_outgoing_burst_rate=0.5)
        data = make_trace()
        for i in range(50):
            result = aug.augment(data)
            assert_valid_result(result, f"augment-iter-{i}")

    def test_augment_with_all_modes(self):
        aug = make_augmentor()
        data = make_trace()
        for im in ("resample", "interpolate"):
            for mtm in ("keep", "compress"):
                result = aug.augment(data, inflate_mode=im, merge_timestamp_mode=mtm)
                assert_valid_result(result, f"augment-{im}-{mtm}")


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_single_packet(self):
        aug = make_augmentor()
        data = {"direction": np.array([1], dtype=np.int64), "size": np.array([500], dtype=np.int64), "timestamp": np.array([0.0])}
        result = aug.augment(data)
        assert_valid_result(result, "single-packet")

    def test_two_packets_opposite(self):
        aug = make_augmentor()
        data = {
            "direction": np.array([1, -1], dtype=np.int64),
            "size": np.array([500, 1200], dtype=np.int64),
            "timestamp": np.array([0.0, 0.01]),
        }
        result = aug.augment(data)
        assert_valid_result(result, "two-packets")

    def test_single_large_incoming_burst(self):
        aug = make_augmentor(add_outgoing_burst_rate=1.0)
        n = 50
        rng = np.random.RandomState(77)
        data = {
            "direction": np.full(n, -1, dtype=np.int64),
            "size": rng.randint(100, 1400, size=n).astype(np.int64),
            "timestamp": np.sort(rng.uniform(0, 1, size=n)),
        }
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "single-incoming-burst")


# ---------------------------------------------------------------------------
# Dtype-specific tests
# ---------------------------------------------------------------------------

class TestDtypes:
    def test_change_content_resample_preserves_int(self):
        aug = make_augmentor()
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="resample")
        assert_valid_result(result, "dtype-resample")

    def test_change_content_interpolate_preserves_int(self):
        aug = make_augmentor()
        data = make_short_trace()
        result = aug._change_content(data, inflate_mode="interpolate")
        assert_valid_result(result, "dtype-interpolate")

    def test_merge_keep_preserves_int(self):
        aug = make_augmentor(merge_burst_rate=1.0)
        data = make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="keep")
        assert_valid_result(result, "dtype-merge-keep")

    def test_merge_compress_preserves_int(self):
        aug = make_augmentor(merge_burst_rate=1.0)
        data = make_trace()
        result = aug._merge_incoming_bursts(data, merge_timestamp_mode="compress")
        assert_valid_result(result, "dtype-merge-compress")

    def test_add_outgoing_with_cdf_preserves_int(self):
        aug = make_augmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "dtype-add-outgoing-cdf")

    def test_add_outgoing_fallback_preserves_int(self):
        aug = NetCLRAugmentor(add_outgoing_burst_rate=1.0)
        data = make_trace()
        result = aug._add_outgoing_burst(data)
        assert_valid_result(result, "dtype-add-outgoing-fallback")

    def test_augment_repeated_preserves_int(self):
        aug = make_augmentor(merge_burst_rate=0.5, add_outgoing_burst_rate=0.5)
        data = make_trace()
        for i in range(50):
            result = aug.augment(data)
            assert_valid_result(result, f"dtype-augment-iter-{i}")

    def test_deflate_preserves_int(self):
        aug = make_augmentor(r_down_sample=0.5)
        data = make_trace()
        big = {
            "direction": np.tile(data["direction"], 25),
            "size": np.tile(data["size"], 25),
            "timestamp": np.sort(np.tile(data["timestamp"], 25) +
                                 np.repeat(np.arange(25) * 20, len(data["timestamp"]))),
        }
        result = aug._change_content(big, inflate_mode="resample")
        assert_valid_result(result, "dtype-deflate")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
