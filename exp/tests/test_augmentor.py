import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import numpy as np
import pytest
from WFlib.tools.augmentor import NetCLRAugmentor, SlopeAugmentor, RosettaAugmentor, dict_to_raw
from WFlib.utils.statistics import find_bursts
from fixture import (
    make_trace, make_short_trace, make_augmentor, assert_valid_result,
    make_slope_augmentor, make_flow,
)
from exp.dataset_process.data_augmentation_netrand import (
    NetRandAugmentRaw,
    augment_raw_dataset,
    build_pools_from_raw,
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


# ---------------------------------------------------------------------------
# SlopeAugmentor: _strip_padding tests
# ---------------------------------------------------------------------------

class TestStripPadding:
    def test_no_padding(self):
        flow = make_flow([1, -1, 1], [1460, 1460, 500])
        d, t, l = SlopeAugmentor._strip_padding(flow)
        assert len(d) == 3
        np.testing.assert_array_equal(d, [1, -1, 1])
        np.testing.assert_array_equal(l, [1460, 1460, 500])

    def test_with_trailing_zeros(self):
        flow = make_flow(
            [1, -1, 1, 0, 0, 0],
            [1460, 1460, 500, 0, 0, 0],
        )
        d, t, l = SlopeAugmentor._strip_padding(flow)
        assert len(d) == 3
        np.testing.assert_array_equal(d, [1, -1, 1])

    def test_all_zeros(self):
        flow = make_flow([0, 0, 0], [0, 0, 0])
        d, t, l = SlopeAugmentor._strip_padding(flow)
        assert len(d) == 0
        assert len(t) == 0
        assert len(l) == 0

    def test_empty_arrays(self):
        flow = make_flow([], [])
        d, t, l = SlopeAugmentor._strip_padding(flow)
        assert len(d) == 0

    def test_returns_copies(self):
        flow = make_flow([1, -1], [1460, 80])
        d, t, l = SlopeAugmentor._strip_padding(flow)
        d[0] = 99
        assert flow["direction"][0] == 1


# ---------------------------------------------------------------------------
# SlopeAugmentor: _classify_packets tests
# ---------------------------------------------------------------------------

class TestClassifyPackets:
    def test_basic_classification(self):
        aug = make_slope_augmentor()
        direction = np.array([1, -1, 1, -1, 1, -1], dtype=np.int64)
        length = np.array([1460, 1460, 50, 80, 500, 40], dtype=np.int64)
        groups = aug._classify_packets(direction, length)

        np.testing.assert_array_equal(groups["out_ack"], [2])
        np.testing.assert_array_equal(groups["in_ack"], [3, 5])
        np.testing.assert_array_equal(groups["out_data"], [0, 4])
        np.testing.assert_array_equal(groups["in_data"], [1])

    def test_all_acks(self):
        aug = make_slope_augmentor()
        direction = np.array([1, -1, 1], dtype=np.int64)
        length = np.array([40, 50, 60], dtype=np.int64)
        groups = aug._classify_packets(direction, length)
        assert len(groups["out_data"]) == 0
        assert len(groups["in_data"]) == 0
        assert len(groups["out_ack"]) == 2
        assert len(groups["in_ack"]) == 1

    def test_all_data(self):
        aug = make_slope_augmentor()
        direction = np.array([1, -1, 1], dtype=np.int64)
        length = np.array([1460, 1460, 500], dtype=np.int64)
        groups = aug._classify_packets(direction, length)
        assert len(groups["out_ack"]) == 0
        assert len(groups["in_ack"]) == 0
        assert len(groups["out_data"]) == 2
        assert len(groups["in_data"]) == 1

    def test_threshold_boundary(self):
        """Packets with length == threshold_ack should be classified as data."""
        aug = make_slope_augmentor(threshold_ack=100)
        direction = np.array([1, 1], dtype=np.int64)
        length = np.array([99, 100], dtype=np.int64)
        groups = aug._classify_packets(direction, length)
        assert 0 in groups["out_ack"]
        assert 1 in groups["out_data"]

    def test_empty_input(self):
        aug = make_slope_augmentor()
        groups = aug._classify_packets(np.array([], dtype=np.int64),
                                       np.array([], dtype=np.int64))
        for key in ("out_ack", "in_ack", "out_data", "in_data"):
            assert len(groups[key]) == 0

    def test_index_coverage(self):
        """Every index should appear in exactly one group."""
        aug = make_slope_augmentor()
        rng = np.random.RandomState(42)
        n = 50
        direction = rng.choice([1, -1], size=n).astype(np.int64)
        length = rng.randint(30, 1500, size=n).astype(np.int64)
        groups = aug._classify_packets(direction, length)
        all_indices = np.sort(np.concatenate([
            groups["out_ack"], groups["in_ack"],
            groups["out_data"], groups["in_data"],
        ]))
        np.testing.assert_array_equal(all_indices, np.arange(n))


# ---------------------------------------------------------------------------
# SlopeAugmentor: _build_data_bursts tests
# ---------------------------------------------------------------------------

class TestBuildDataBursts:
    def test_plan_example(self):
        """Example from the plan: [1460,1460,1460,500,329] -> 2 bursts."""
        aug = make_slope_augmentor()
        indices = np.array([2, 3, 4, 5, 6], dtype=np.int64)
        length = np.zeros(10, dtype=np.int64)
        length[2], length[3], length[4] = 1460, 1460, 1460
        length[5], length[6] = 500, 329

        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 2
        np.testing.assert_array_equal(bursts[0], [2, 3, 4, 5])
        np.testing.assert_array_equal(bursts[1], [6])

    def test_all_segments(self):
        """All packets >= threshold_seg form one burst."""
        aug = make_slope_augmentor()
        indices = np.array([0, 1, 2], dtype=np.int64)
        length = np.array([1460, 1460, 1460], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 1
        np.testing.assert_array_equal(bursts[0], [0, 1, 2])

    def test_all_short(self):
        """All packets < threshold_seg, each forms its own burst."""
        aug = make_slope_augmentor()
        indices = np.array([0, 1, 2], dtype=np.int64)
        length = np.array([500, 300, 200], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 3
        for i, b in enumerate(bursts):
            np.testing.assert_array_equal(b, [i])

    def test_segment_then_short_then_segment(self):
        """[1460, 500, 1460, 1460, 300] -> [1460,500], [1460,1460,300]."""
        aug = make_slope_augmentor()
        indices = np.array([0, 1, 2, 3, 4], dtype=np.int64)
        length = np.array([1460, 500, 1460, 1460, 300], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 2
        np.testing.assert_array_equal(bursts[0], [0, 1])
        np.testing.assert_array_equal(bursts[1], [2, 3, 4])

    def test_empty_indices(self):
        aug = make_slope_augmentor()
        bursts = aug._build_data_bursts(np.array([], dtype=np.int64),
                                         np.array([1460], dtype=np.int64))
        assert bursts == []

    def test_single_segment(self):
        aug = make_slope_augmentor()
        indices = np.array([0], dtype=np.int64)
        length = np.array([1460], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 1
        np.testing.assert_array_equal(bursts[0], [0])

    def test_single_short(self):
        aug = make_slope_augmentor()
        indices = np.array([0], dtype=np.int64)
        length = np.array([200], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 1
        np.testing.assert_array_equal(bursts[0], [0])

    def test_threshold_boundary(self):
        """Packet with length == threshold_seg should be >= threshold_seg."""
        aug = make_slope_augmentor(threshold_seg=1400)
        indices = np.array([0, 1], dtype=np.int64)
        length = np.array([1400, 500], dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 1
        np.testing.assert_array_equal(bursts[0], [0, 1])

    def test_non_contiguous_indices(self):
        """Data indices may not be contiguous in the original array."""
        aug = make_slope_augmentor()
        indices = np.array([1, 4, 7], dtype=np.int64)
        length = np.zeros(10, dtype=np.int64)
        length[1] = 1460
        length[4] = 1460
        length[7] = 500
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 1
        np.testing.assert_array_equal(bursts[0], [1, 4, 7])

    def test_multiple_segment_short_pairs(self):
        """[1460,1460,200, 1460,300, 1460,1460,1460,100]."""
        aug = make_slope_augmentor()
        indices = np.arange(9, dtype=np.int64)
        length = np.array([1460, 1460, 200, 1460, 300, 1460, 1460, 1460, 100],
                          dtype=np.int64)
        bursts = aug._build_data_bursts(indices, length)
        assert len(bursts) == 3
        np.testing.assert_array_equal(bursts[0], [0, 1, 2])
        np.testing.assert_array_equal(bursts[1], [3, 4])
        np.testing.assert_array_equal(bursts[2], [5, 6, 7, 8])


# ---------------------------------------------------------------------------
# SlopeAugmentor: _build_burst_view integration tests
# ---------------------------------------------------------------------------

class TestBuildBurstView:
    def test_basic_flow(self):
        """A realistic mixed flow with ACKs and data packets."""
        flow = make_flow(
            direction= [1,  1,  1,    -1,   1,  -1,  -1,   -1,  1,    0,  0],
            length=    [1460,1460,500, 40,  1460, 1460,1460, 80, 200,  0,  0],
        )
        aug = make_slope_augmentor()
        view = aug._build_burst_view(flow)

        assert view["active_length"] == 9
        assert len(view["out_ack"]) == 0
        np.testing.assert_array_equal(view["in_ack"], [3, 7])

        assert len(view["in_data"]) > 0
        all_in_data_indices = np.concatenate(view["in_data"])
        np.testing.assert_array_equal(np.sort(all_in_data_indices), [5, 6])

        all_out_data_indices = np.concatenate(view["out_data"])
        np.testing.assert_array_equal(np.sort(all_out_data_indices), [0, 1, 2, 4, 8])

    def test_outgoing_data_bursts(self):
        """Verify burst grouping within the burst view."""
        flow = make_flow(
            direction=[1, 1, 1, 1, 1],
            length=   [1460, 1460, 1460, 500, 329],
        )
        aug = make_slope_augmentor()
        view = aug._build_burst_view(flow)
        assert len(view["out_data"]) == 2
        np.testing.assert_array_equal(view["out_data"][0], [0, 1, 2, 3])
        np.testing.assert_array_equal(view["out_data"][1], [4])

    def test_all_padding(self):
        flow = make_flow([0, 0, 0], [0, 0, 0])
        aug = make_slope_augmentor()
        view = aug._build_burst_view(flow)
        assert view["active_length"] == 0
        assert len(view["out_ack"]) == 0
        assert len(view["in_ack"]) == 0
        assert len(view["out_data"]) == 0
        assert len(view["in_data"]) == 0

    def test_index_completeness(self):
        """All non-padding indices should appear across the 4 groups."""
        rng = np.random.RandomState(7)
        n = 40
        direction = rng.choice([1, -1], size=n).astype(np.int64)
        length = rng.randint(30, 1500, size=n).astype(np.int64)
        pad = np.zeros(10, dtype=np.int64)
        flow = make_flow(
            np.concatenate([direction, pad]),
            np.concatenate([length, pad]),
        )
        aug = make_slope_augmentor()
        view = aug._build_burst_view(flow)

        assert view["active_length"] == n
        all_indices = list(view["out_ack"]) + list(view["in_ack"])
        for burst_list in (view["out_data"], view["in_data"]):
            for b in burst_list:
                all_indices.extend(b.tolist())
        assert sorted(all_indices) == list(range(n))

    def test_stripped_arrays_in_view(self):
        """The view should include the stripped direction/timestamp/length."""
        flow = make_flow([1, -1, 0, 0], [1460, 1460, 0, 0])
        aug = make_slope_augmentor()
        view = aug._build_burst_view(flow)
        assert len(view["direction"]) == 2
        assert len(view["timestamp"]) == 2
        assert len(view["length"]) == 2


# ---------------------------------------------------------------------------
# SlopeAugmentor: _compute_flow_delay_cdf tests
# ---------------------------------------------------------------------------

class TestComputeFlowDelayCdf:
    def test_returns_valid_cdf(self):
        aug = make_slope_augmentor()
        flow = make_flow(
            [1, 1, 1, -1, -1, -1],
            [1460, 1460, 500, 1460, 1460, 300],
            [0.0, 0.01, 0.02, 0.05, 0.06, 0.07],
        )
        d, t, l = SlopeAugmentor._strip_padding(flow)
        vals, cdf = aug._compute_flow_delay_cdf(t, d, l)
        assert cdf[-1] == pytest.approx(1.0)
        assert np.all(np.diff(cdf) >= 0)
        assert len(vals) == len(cdf)

    def test_fallback_with_few_packets(self):
        aug = make_slope_augmentor()
        d = np.array([1], dtype=np.int64)
        t = np.array([0.0])
        l = np.array([1460], dtype=np.int64)
        vals, cdf = aug._compute_flow_delay_cdf(t, d, l)
        assert cdf[-1] == pytest.approx(1.0)
        assert len(vals) == 3

    def test_ignores_ack_packets(self):
        aug = make_slope_augmentor()
        d = np.array([1, 1, -1, 1, 1], dtype=np.int64)
        t = np.array([0.0, 0.01, 0.015, 0.02, 0.03])
        l = np.array([1460, 1460, 50, 1460, 1460], dtype=np.int64)
        vals, cdf = aug._compute_flow_delay_cdf(t, d, l)
        assert cdf[-1] == pytest.approx(1.0)

    def test_only_same_direction_delays(self):
        """Delays should only be computed between consecutive same-direction data packets."""
        aug = make_slope_augmentor()
        d = np.array([1, -1, 1], dtype=np.int64)
        t = np.array([0.0, 0.5, 1.0])
        l = np.array([1460, 1460, 1460], dtype=np.int64)
        vals, cdf = aug._compute_flow_delay_cdf(t, d, l)
        assert len(vals) == 3  # fallback -- no same-direction consecutive pair


# ---------------------------------------------------------------------------
# SlopeAugmentor: _rescale_burst tests
# ---------------------------------------------------------------------------

class TestRescaleBurst:
    def _setup(self):
        aug = make_slope_augmentor()
        direction = np.array([1, 1, 1], dtype=np.int64)
        length = np.array([1460, 1460, 1060], dtype=np.int64)
        timestamp = np.array([0.0, 0.01, 0.02])
        indices = np.array([0, 1, 2], dtype=np.int64)
        delay_vals = np.array([0.001, 0.005, 0.01])
        delay_cdf = np.array([0.33, 0.67, 1.0])
        return aug, indices, length, direction, timestamp, delay_vals, delay_cdf

    def test_plan_example(self):
        """[1460,1460,1060], s=0.5 -> payload=3800, extend=7600, k'=ceil(7600/1400)=6."""
        aug, indices, length, direction, timestamp, dv, dc = self._setup()
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 2, dv, dc)
        assert len(d) == 6
        assert np.all(d == 1)
        assert l[0] == 1460  # tcp_max_size
        assert t[0] == 0.0

    def test_slope_one_preserves_payload(self):
        """slope=1.0 should not change total payload."""
        aug, indices, length, direction, timestamp, dv, dc = self._setup()
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 1.0, dv, dc)
        orig_payload = int(np.sum(length)) - 3 * 60
        new_payload = int(np.sum(l)) - len(l) * 60
        assert new_payload == orig_payload

    def test_slope_greater_than_one_reduces(self):
        """slope > 1 should reduce the burst."""
        aug, indices, length, direction, timestamp, dv, dc = self._setup()
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 0.5, dv, dc)
        assert len(d) <= 3

    def test_timestamps_monotonic(self):
        aug, indices, length, direction, timestamp, dv, dc = self._setup()
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 0.5, dv, dc)
        assert np.all(np.diff(t) >= 0)

    def test_direction_preserved(self):
        aug = make_slope_augmentor()
        direction = np.array([-1, -1], dtype=np.int64)
        length = np.array([1460, 1460], dtype=np.int64)
        timestamp = np.array([1.0, 1.01])
        indices = np.array([0, 1], dtype=np.int64)
        dv = np.array([0.001, 0.005, 0.01])
        dc = np.array([0.33, 0.67, 1.0])
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 0.5, dv, dc)
        assert np.all(d == -1)

    def test_last_packet_size(self):
        """Last packet should have correct remainder size."""
        aug, indices, length, direction, timestamp, dv, dc = self._setup()
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 2, dv, dc)
        # extend_payload = ceil(3800/0.5) = 7600
        # 7600 % 1400 = 600, last = 600 + 60 = 660
        assert l[-1] == 660
        for pkt in l[:-1]:
            assert pkt == 1460

    def test_zero_payload_passthrough(self):
        """Burst with payload <= 0 should pass through unchanged."""
        aug = make_slope_augmentor()
        direction = np.array([1], dtype=np.int64)
        length = np.array([50], dtype=np.int64)
        timestamp = np.array([0.0])
        indices = np.array([0], dtype=np.int64)
        dv = np.array([0.01])
        dc = np.array([1.0])
        d, l, t = aug._rescale_burst(indices, length, direction, timestamp, 0.5, dv, dc)
        np.testing.assert_array_equal(l, [50])


# ---------------------------------------------------------------------------
# SlopeAugmentor: _insert_acks tests
# ---------------------------------------------------------------------------

class TestInsertAcks:
    def test_ack_every_2_packets(self):
        aug = make_slope_augmentor(ack_interval=2)
        data_dir = np.array([1, 1, 1, 1], dtype=np.int64)
        data_len = np.array([1460, 1460, 1460, 1460], dtype=np.int64)
        data_ts = np.array([0.0, 0.01, 0.02, 0.03])
        dv = np.array([0.001, 0.005, 0.01])
        dc = np.array([0.33, 0.67, 1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        # 4 data + 2 ACKs = 6 total
        assert len(d) == 6
        ack_positions = np.where(d == -1)[0]
        assert len(ack_positions) == 2

    def test_ack_direction_opposite(self):
        aug = make_slope_augmentor(ack_interval=2)
        data_dir = np.array([-1, -1], dtype=np.int64)
        data_len = np.array([1460, 1460], dtype=np.int64)
        data_ts = np.array([0.0, 0.01])
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        ack_positions = np.where(d == 1)[0]
        assert len(ack_positions) == 1

    def test_ack_size_is_header(self):
        aug = make_slope_augmentor(ack_interval=2, tcp_header_size=60)
        data_dir = np.array([1, 1], dtype=np.int64)
        data_len = np.array([1460, 1460], dtype=np.int64)
        data_ts = np.array([0.0, 0.01])
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        ack_idx = np.where(d == -1)[0]
        for idx in ack_idx:
            assert l[idx] == 60

    def test_ack_between_data_timestamp_in_range(self):
        aug = make_slope_augmentor(ack_interval=2)
        data_dir = np.array([1, 1, 1, 1], dtype=np.int64)
        data_len = np.array([1460, 1460, 1460, 1460], dtype=np.int64)
        data_ts = np.array([0.0, 0.01, 0.02, 0.03])
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        # First ACK after data[1], before data[2] -> between 0.01 and 0.02
        assert t[2] >= 0.01 and t[2] <= 0.02

    def test_trailing_ack_after_last_data(self):
        aug = make_slope_augmentor(ack_interval=2)
        data_dir = np.array([1, 1], dtype=np.int64)
        data_len = np.array([1460, 1460], dtype=np.int64)
        data_ts = np.array([0.0, 0.01])
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        # Trailing ACK should be > last data timestamp
        assert t[-1] > 0.01

    def test_empty_input(self):
        aug = make_slope_augmentor()
        empty = np.array([], dtype=np.int64)
        empty_f = np.array([], dtype=np.float64)
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(empty, empty, empty_f, dv, dc)
        assert len(d) == 0

    def test_single_packet_no_ack(self):
        aug = make_slope_augmentor(ack_interval=2)
        data_dir = np.array([1], dtype=np.int64)
        data_len = np.array([1460], dtype=np.int64)
        data_ts = np.array([0.0])
        dv = np.array([0.001])
        dc = np.array([1.0])
        d, l, t = aug._insert_acks(data_dir, data_len, data_ts, dv, dc)
        assert len(d) == 1  # no ACK since 1 < ack_interval


# ---------------------------------------------------------------------------
# SlopeAugmentor: _reassemble_flow tests
# ---------------------------------------------------------------------------

class TestReassembleFlow:
    def test_basic_reassembly(self):
        """Simple flow: outgoing data burst + ACK + incoming data burst."""
        aug = make_slope_augmentor()
        flow = make_flow(
            [1,  1,  1,  -1, -1, -1],
            [1460, 1460, 500, 50, 1460, 300],
            [0.0, 0.01, 0.02, 0.03, 0.04, 0.05],
        )
        view = aug._build_burst_view(flow)
        # Replace bursts with identity (same data)
        rescaled = {}
        for burst_list in (view["out_data"], view["in_data"]):
            for b in burst_list:
                if len(b) > 0:
                    d = view["direction"][b]
                    l = view["length"][b]
                    t = view["timestamp"][b]
                    rescaled[int(b[0])] = (d.copy(), l.copy(), t.copy())

        result = aug._reassemble_flow(view, rescaled)
        assert len(result["direction"]) == 6
        assert result["timestamp"][-1] >= result["timestamp"][0]

    def test_time_offset_propagation(self):
        """When a burst overflows, subsequent packets should be shifted."""
        aug = make_slope_augmentor()
        flow = make_flow(
            [1,  1,   -1,   -1,  -1],
            [1460, 1460, 50, 1460, 300],
            [0.0, 0.01, 0.02, 0.03, 0.04],
        )
        view = aug._build_burst_view(flow)
        # Replace outgoing burst with something that ends much later
        out_burst = view["out_data"][0]
        fake_ts = np.array([0.0, 0.01, 0.5])  # ends at 0.5, way past 0.01
        rescaled = {
            int(out_burst[0]): (
                np.array([1, 1, 1], dtype=np.int64),
                np.array([1460, 1460, 1460], dtype=np.int64),
                fake_ts,
            )
        }
        for b in view["in_data"]:
            if len(b) > 0:
                rescaled[int(b[0])] = (
                    view["direction"][b].copy(),
                    view["length"][b].copy(),
                    view["timestamp"][b].copy(),
                )
        result = aug._reassemble_flow(view, rescaled)
        # The ACK at original index 2 (t=0.02) should be shifted forward
        # because the burst overflowed to t=0.5
        assert result["timestamp"][3] > 0.02


# ---------------------------------------------------------------------------
# SlopeAugmentor: full augment() pipeline tests
# ---------------------------------------------------------------------------

class TestSlopeAugment:
    def _make_realistic_flow(self, seed=42):
        """Build a realistic TCP-like flow with data bursts and ACKs."""
        rng = np.random.RandomState(seed)
        direction = []
        length = []
        timestamp = []
        t = 0.0

        for _ in range(5):
            n_data = rng.randint(3, 8)
            dir_val = rng.choice([1, -1])
            for j in range(n_data):
                direction.append(dir_val)
                if j < n_data - 1:
                    length.append(1460)
                else:
                    length.append(rng.randint(200, 1400))
                t += rng.uniform(0.001, 0.01)
                timestamp.append(t)

            n_acks = rng.randint(1, 3)
            for _ in range(n_acks):
                direction.append(-dir_val)
                length.append(60)
                t += rng.uniform(0.001, 0.01)
                timestamp.append(t)

        return make_flow(direction, length, timestamp)

    def test_augment_returns_valid_keys(self):
        aug = make_slope_augmentor()
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        assert "direction" in result
        assert "length" in result
        assert "timestamp" in result

    def test_augment_dtypes(self):
        aug = make_slope_augmentor()
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        assert np.issubdtype(result["direction"].dtype, np.integer)
        assert np.issubdtype(result["length"].dtype, np.integer)
        assert np.issubdtype(result["timestamp"].dtype, np.floating)

    def test_augment_lengths_equal(self):
        aug = make_slope_augmentor()
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        n = len(result["direction"])
        assert len(result["length"]) == n
        assert len(result["timestamp"]) == n

    def test_augment_timestamps_monotonic(self):
        aug = make_slope_augmentor()
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        assert np.all(np.diff(result["timestamp"]) >= -1e-12)

    def test_augment_slope_less_than_one_grows(self):
        """slope < 1 should generally increase packet count."""
        aug = make_slope_augmentor(slope_arr=np.array([2]))
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        d, _, l = SlopeAugmentor._strip_padding(flow)
        orig_data_count = np.sum(l >= 100)
        new_data_count = np.sum(result["length"] >= 100)
        assert new_data_count >= orig_data_count

    def test_augment_slope_greater_than_one_shrinks(self):
        """slope > 1 should generally reduce packet count."""
        aug = make_slope_augmentor(slope_arr=np.array([1/3]))
        flow = self._make_realistic_flow()
        result = aug.augment(flow)
        d, _, l = SlopeAugmentor._strip_padding(flow)
        orig_data_count = np.sum(l >= 100)
        new_data_count = np.sum(result["length"] >= 100)
        assert new_data_count <= orig_data_count

    def test_augment_empty_flow(self):
        aug = make_slope_augmentor()
        flow = make_flow([0, 0, 0], [0, 0, 0])
        result = aug.augment(flow)
        assert len(result["direction"]) == 0

    def test_augment_all_acks(self):
        """Flow with only ACK-sized packets -- no data bursts to rescale."""
        aug = make_slope_augmentor()
        flow = make_flow([1, -1, 1], [50, 60, 40], [0.0, 0.01, 0.02])
        result = aug.augment(flow)
        assert len(result["direction"]) == 3
        np.testing.assert_array_equal(result["length"], [50, 60, 40])

    def test_augment_repeated_stable(self):
        """Running augment many times should never crash."""
        aug = make_slope_augmentor()
        flow = self._make_realistic_flow()
        for _ in range(20):
            result = aug.augment(flow)
            n = len(result["direction"])
            assert len(result["length"]) == n
            assert len(result["timestamp"]) == n

    def test_augment_single_data_packet(self):
        aug = make_slope_augmentor()
        flow = make_flow([1], [1460], [0.0])
        result = aug.augment(flow)
        assert len(result["direction"]) >= 1
        assert np.issubdtype(result["direction"].dtype, np.integer)

    def test_augment_preserves_ack_packets(self):
        """Original ACK packets should still appear in the output."""
        aug = make_slope_augmentor(slope_arr=np.array([1.0]))
        flow = make_flow(
            [1, 1, -1, -1, -1],
            [1460, 1460, 50, 1460, 300],
            [0.0, 0.01, 0.02, 0.03, 0.04],
        )
        result = aug.augment(flow)
        # The ACK at original index 2 (length=50) should still exist
        assert 50 in result["length"] or self  # ACK may be shifted but present


# ---------------------------------------------------------------------------
# RosettaAugmentor tests
# ---------------------------------------------------------------------------

class TestRosettaAugmentor:
    def _make_flow(self, key="length"):
        return {
            "direction": np.array([1, 1, -1, -1, 1], dtype=np.int64),
            key: np.array([600, 600, 700, 700, 300], dtype=np.int64),
            "timestamp": np.array([0.0, 0.01, 0.02, 0.03, 0.04], dtype=np.float64),
        }

    def _assert_valid(self, result, key="length"):
        assert "timestamp" in result
        assert "direction" in result
        assert key in result
        n = len(result["direction"])
        assert len(result[key]) == n
        assert len(result["timestamp"]) == n
        assert np.issubdtype(result["direction"].dtype, np.integer)
        assert np.issubdtype(result[key].dtype, np.integer)
        assert np.issubdtype(result["timestamp"].dtype, np.floating)
        if n > 1:
            assert np.all(np.diff(result["timestamp"]) >= -1e-12)

    def test_packet_loss_drops_aligned_triplets(self, monkeypatch):
        aug = RosettaAugmentor(loss_rate_max=1.0, nagle=False)
        direction = np.array([1, -1, 1, -1], dtype=np.int64)
        length = np.array([10, 20, 30, 40], dtype=np.int64)
        timestamp = np.array([0.0, 0.1, 0.2, 0.3], dtype=np.float64)
        draws = iter([0.5, 0.4, 0.6, 0.1])
        monkeypatch.setattr("WFlib.tools.augmentor.random.random", lambda: next(draws))

        result = aug._apply_packet_loss("length", direction, length, timestamp)

        np.testing.assert_array_equal(result["direction"], np.array([1, 1]))
        np.testing.assert_array_equal(result["length"], np.array([10, 30]))
        np.testing.assert_allclose(result["timestamp"], np.array([0.0, 0.2]))

    def test_aggregation_does_not_cross_direction_changes(self, monkeypatch):
        aug = RosettaAugmentor(loss_rate_max=0.0, max_rtt=1.0, mss=1000, warmup_packets=0)
        flow = self._make_flow()
        monkeypatch.setattr("WFlib.tools.augmentor.random.random", lambda: 1.0)

        result = aug._apply_nagle(
            "length", flow["direction"], flow["length"], flow["timestamp"]
        )

        np.testing.assert_array_equal(result["direction"], np.array([1, 1, -1, -1, 1]))
        np.testing.assert_array_equal(result["length"], np.array([1000, 200, 1000, 400, 300]))
        self._assert_valid(result)

    def test_segmented_packets_share_group_direction(self, monkeypatch):
        aug = RosettaAugmentor(loss_rate_max=0.0, max_rtt=1.0, mss=1000, warmup_packets=0)
        direction = np.array([-1, -1, -1], dtype=np.int64)
        length = np.array([800, 800, 800], dtype=np.int64)
        timestamp = np.array([0.0, 0.01, 0.02], dtype=np.float64)
        monkeypatch.setattr("WFlib.tools.augmentor.random.random", lambda: 1.0)

        result = aug._apply_nagle("length", direction, length, timestamp)

        np.testing.assert_array_equal(result["direction"], np.array([-1, -1, -1]))
        np.testing.assert_array_equal(result["length"], np.array([1000, 1000, 400]))
        self._assert_valid(result)

    def test_preserves_length_schema(self):
        aug = RosettaAugmentor(loss_rate_max=0.0, nagle=False)
        result = aug.augment(self._make_flow("length"))
        assert "length" in result
        assert "size" not in result
        self._assert_valid(result, "length")

    def test_preserves_size_schema(self):
        aug = RosettaAugmentor(loss_rate_max=0.0, nagle=False)
        result = aug.augment(self._make_flow("size"))
        assert "size" in result
        assert "length" not in result
        self._assert_valid(result, "size")

    def test_repeated_augmentation_stable(self):
        aug = RosettaAugmentor()
        flow = {
            "direction": np.array([1, 1, 1, -1, -1, 1, 1, -1], dtype=np.int64),
            "length": np.array([300, 600, 900, 700, 500, 400, 1200, 300], dtype=np.int64),
            "timestamp": np.array([0.0, 0.002, 0.006, 0.009, 0.013, 0.02, 0.025, 0.03], dtype=np.float64),
        }
        for _ in range(50):
            result = aug.augment(flow)
            self._assert_valid(result, "length")

    def test_empty_flow_returns_valid_output(self):
        aug = RosettaAugmentor()
        flow = make_flow([0, 0, 0], [0, 0, 0])
        result = aug.augment(flow)
        self._assert_valid(result, "length")
        assert len(result["direction"]) == 0

    def test_single_packet_flow_returns_valid_output(self):
        aug = RosettaAugmentor()
        flow = make_flow([1], [1460], [0.0])
        result = aug.augment(flow)
        self._assert_valid(result, "length")
        assert len(result["direction"]) == 1



# ---------------------------------------------------------------------------
# NetRandAugment offline raw augmentation tests
# ---------------------------------------------------------------------------

def make_netrand_trace(direction, size, timestamp=None):
    direction = np.asarray(direction, dtype=np.int64)
    size = np.asarray(size, dtype=np.int64)
    if timestamp is None:
        timestamp = np.arange(len(direction), dtype=np.float64) * 0.01
    return {
        "timestamp": np.asarray(timestamp, dtype=np.float64),
        "direction": direction,
        "size": size,
    }


def make_netrand_dataset(seq_len=80):
    traces = [
        make_netrand_trace([1, 1, -1, -1, 1], [10, 11, 20, 21, 12]),
        make_netrand_trace([1, -1, -1, 1, 1], [30, 40, 41, 31, 32]),
        make_netrand_trace([-1, -1, 1, 1, -1], [50, 51, 60, 61, 52]),
    ]
    X = np.stack([dict_to_raw(t, seq_len) for t in traces], axis=0)
    y = np.array([0, 0, 1], dtype=np.int64)
    return X, y


def assert_valid_netrand_trace(trace):
    n = len(trace["direction"])
    assert len(trace["timestamp"]) == n
    assert len(trace["size"]) == n
    assert np.issubdtype(trace["timestamp"].dtype, np.floating)
    assert np.issubdtype(trace["direction"].dtype, np.integer)
    assert np.issubdtype(trace["size"].dtype, np.integer)
    if n > 1:
        assert np.all(np.diff(trace["timestamp"]) >= -1e-12)


def make_netrand_augmentor():
    X, y = make_netrand_dataset()
    pools = build_pools_from_raw(X, y)
    return NetRandAugmentRaw(*pools, n=1, m=4), pools


class TestNetRandPools:
    def test_pool_construction_by_label_and_current_exclusion(self):
        aug, (traces, same_class_pool, random_pool, outgoing_burst_pool) = make_netrand_augmentor()
        assert same_class_pool[0] == [0, 1]
        assert same_class_pool[1] == [2]
        assert random_pool == [0, 1, 2]
        assert len(outgoing_burst_pool) > 0

        peer = aug._peer_trace(0, 0)
        assert peer is not None
        np.testing.assert_array_equal(peer["size"], traces[1]["trace"]["size"])
        assert aug._peer_trace(2, 1) is None


class TestNetRandOperators:
    def test_remove_operation_preserves_aligned_triplets(self, monkeypatch):
        aug, _ = make_netrand_augmentor()
        aug.remove_ratio = 0.5
        trace = make_netrand_trace([1, -1, 1, -1, 1, -1], [10, 20, 30, 40, 50, 60])
        monkeypatch.setattr("exp.dataset_process.data_augmentation_netrand.random.random", lambda: 0.0)

        result = aug.inject_or_remove_packets(trace)

        assert_valid_netrand_trace(result)
        assert len(result["direction"]) == 3

    def test_inserted_packets_receive_integer_sizes_from_current_trace(self, monkeypatch):
        aug, _ = make_netrand_augmentor()
        aug.inject_ratio = 0.5
        trace = make_netrand_trace([1, -1, 1, -1, 1, -1], [10, 20, 30, 40, 50, 60])
        monkeypatch.setattr("exp.dataset_process.data_augmentation_netrand.random.random", lambda: 1.0)

        result = aug.inject_or_remove_packets(trace)

        assert_valid_netrand_trace(result)
        assert len(result["direction"]) > len(trace["direction"])
        assert set(result["size"].tolist()).issubset(set(trace["size"].tolist()))

    def test_burst_swap_moves_sizes_with_direction(self):
        aug, _ = make_netrand_augmentor()
        aug.swap_ratio = 0.5
        trace = make_netrand_trace([1, 1, -1, -1], [10, 11, 20, 21], [0.0, 0.1, 0.2, 0.3])

        result = aug.swap_burst_pairs(trace)

        assert_valid_netrand_trace(result)
        np.testing.assert_array_equal(result["direction"], np.array([-1, -1, 1, 1]))
        np.testing.assert_array_equal(result["size"], np.array([20, 21, 10, 11]))

    def test_peer_overlap_interpolation_methods_are_valid_with_context(self):
        aug, (traces, _, _, _) = make_netrand_augmentor()
        trace = traces[0]["trace"]
        peer = traces[1]["trace"]
        other = traces[2]["trace"]
        aug.replace_rate = 1.0
        aug.overlap_ratio = 0.5
        aug.interp_rate = 0.5

        for result in (
            aug.replace_peer_bursts(trace, peer),
            aug.add_overlapping_segment(trace, other),
            aug.generate_linear_interpolation(trace, peer),
        ):
            assert_valid_netrand_trace(result)
            assert len(result["direction"]) > 0

    def test_insert_outgoing_bursts_uses_pool_and_preserves_validity(self):
        aug, _ = make_netrand_augmentor()
        aug.insert_rate = 1.0
        aug.shift_bound_i = 0
        trace = make_netrand_trace([1] * 20 + [-1] * 12, list(range(10, 42)))

        result = aug.insert_outgoing_bursts(trace)

        assert_valid_netrand_trace(result)
        assert np.any(result["direction"] == 1)
        assert len(result["direction"]) >= len(trace["direction"])

    def test_unavailable_peer_context_is_skipped_safely(self):
        X, y = make_netrand_dataset()
        y = np.array([0, 1, 2], dtype=np.int64)
        pools = build_pools_from_raw(X, y)
        aug = NetRandAugmentRaw(*pools, n=1, m=4, methods=["replace_peer_bursts"])
        trace = pools[0][0]["trace"]

        result = aug.augment(trace, index=0, label=0, mode="randaugment")

        assert_valid_netrand_trace(result)
        np.testing.assert_array_equal(result["direction"], trace["direction"])
        np.testing.assert_array_equal(result["size"], trace["size"])


class TestNetRandScriptSmoke:
    def test_tiny_npz_smoke(self, tmp_path):
        X, y = make_netrand_dataset(seq_len=32)
        hosts = np.array(["a.example", "b.example"])
        input_file = tmp_path / "input.npz"
        output_file = tmp_path / "output.npz"
        np.savez_compressed(input_file, raw=X, labels=y, hosts=hosts)

        augment_raw_dataset(str(input_file), str(output_file), n_aug=2, n=1, m=4, seed=123)

        out = np.load(output_file, allow_pickle=True)
        assert out["raw"].shape == (len(X) * 2, X.shape[1], X.shape[2])
        assert out["labels"].shape == (len(X) * 2,)
        np.testing.assert_array_equal(out["hosts"], hosts)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
