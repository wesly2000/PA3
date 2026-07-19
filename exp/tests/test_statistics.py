import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import numpy as np
import pytest
from pa3.utils.statistics import (
    find_bursts, sample_from_cdf, empirical_cdf, compute_outgoing_cdfs,
)
from fixture import make_trace


# ---------------------------------------------------------------------------
# find_bursts tests
# ---------------------------------------------------------------------------

class TestFindBursts:
    def test_simple(self):
        d = np.array([1, 1, 1, -1, -1, 1])
        bursts = find_bursts(d)
        assert bursts == [(0, 3), (3, 5), (5, 6)]

    def test_single_direction(self):
        d = np.array([-1, -1, -1, -1])
        assert find_bursts(d) == [(0, 4)]

    def test_with_padding(self):
        d = np.array([1, 1, -1, -1, 0, 0, 0])
        bursts = find_bursts(d)
        assert bursts == [(0, 2), (2, 4)]

    def test_empty(self):
        assert find_bursts(np.array([])) == []

    def test_starts_with_zero(self):
        assert find_bursts(np.array([0, 1, -1])) == []


# ---------------------------------------------------------------------------
# sample_from_cdf tests
# ---------------------------------------------------------------------------

class TestSampleFromCdf:
    def test_always_returns_valid_value(self):
        values = [10, 20, 30, 40, 50]
        cdf = np.array([0.2, 0.4, 0.6, 0.8, 1.0])
        for _ in range(200):
            v = sample_from_cdf(cdf, values)
            assert v in values

    def test_single_value_cdf(self):
        values = [42]
        cdf = np.array([1.0])
        assert sample_from_cdf(cdf, values) == 42


# ---------------------------------------------------------------------------
# empirical_cdf tests
# ---------------------------------------------------------------------------

class TestEmpiricalCdf:
    def test_uniform_values(self):
        vals = np.array([1, 2, 3, 4, 5])
        unique, cdf = empirical_cdf(vals)
        np.testing.assert_array_equal(unique, [1, 2, 3, 4, 5])
        np.testing.assert_allclose(cdf, [0.2, 0.4, 0.6, 0.8, 1.0])

    def test_repeated_values(self):
        vals = np.array([1, 1, 2, 2, 2])
        unique, cdf = empirical_cdf(vals)
        np.testing.assert_array_equal(unique, [1, 2])
        np.testing.assert_allclose(cdf, [0.4, 1.0])

    def test_single_value(self):
        vals = np.array([7, 7, 7])
        unique, cdf = empirical_cdf(vals)
        np.testing.assert_array_equal(unique, [7])
        np.testing.assert_allclose(cdf, [1.0])

    def test_last_entry_is_one(self):
        rng = np.random.RandomState(0)
        vals = rng.randint(0, 100, size=500)
        _, cdf = empirical_cdf(vals)
        assert cdf[-1] == pytest.approx(1.0)

    def test_monotonically_increasing(self):
        rng = np.random.RandomState(1)
        vals = rng.uniform(0, 10, size=300)
        _, cdf = empirical_cdf(vals)
        assert np.all(np.diff(cdf) >= 0)


# ---------------------------------------------------------------------------
# compute_outgoing_cdfs tests
# ---------------------------------------------------------------------------

def _build_raw_array(traces, seq_len):
    """Convert list of trace dicts into (N, seq_len, 3) raw array."""
    rows = []
    for t in traces:
        n = len(t["direction"])
        row = np.zeros((seq_len, 3), dtype=np.float64)
        row[:n, 0] = t["timestamp"]
        row[:n, 1] = t["direction"]
        row[:n, 2] = t["size"]
        rows.append(row)
    return np.stack(rows)


class TestComputeOutgoingCdfs:
    def test_returns_expected_keys(self):
        trace = make_trace()
        X = _build_raw_array([trace], seq_len=250)
        result = compute_outgoing_cdfs(X)
        for key in ("outgoing_burst_sizes", "outgoing_burst_size_cdf",
                     "outgoing_packet_sizes", "outgoing_packet_size_cdf",
                     "outgoing_delays", "outgoing_delay_cdf"):
            assert key in result, f"Missing key: {key}"

    def test_cdf_ends_at_one(self):
        trace = make_trace()
        X = _build_raw_array([trace], seq_len=250)
        result = compute_outgoing_cdfs(X)
        for cdf_key in ("outgoing_burst_size_cdf", "outgoing_packet_size_cdf",
                         "outgoing_delay_cdf"):
            cdf = result[cdf_key]
            assert cdf is not None, f"{cdf_key} should not be None"
            assert cdf[-1] == pytest.approx(1.0)

    def test_cdf_monotonically_increasing(self):
        trace = make_trace()
        X = _build_raw_array([trace], seq_len=250)
        result = compute_outgoing_cdfs(X)
        for cdf_key in ("outgoing_burst_size_cdf", "outgoing_packet_size_cdf",
                         "outgoing_delay_cdf"):
            cdf = result[cdf_key]
            assert np.all(np.diff(cdf) >= 0), f"{cdf_key} not monotonic"

    def test_values_match_cdf_length(self):
        trace = make_trace()
        X = _build_raw_array([trace], seq_len=250)
        result = compute_outgoing_cdfs(X)
        assert len(result["outgoing_burst_sizes"]) == len(result["outgoing_burst_size_cdf"])
        assert len(result["outgoing_packet_sizes"]) == len(result["outgoing_packet_size_cdf"])
        assert len(result["outgoing_delays"]) == len(result["outgoing_delay_cdf"])

    def test_no_outgoing_bursts(self):
        """All-incoming trace should return empty lists and None CDFs."""
        n = 30
        rng = np.random.RandomState(0)
        trace = {
            "direction": np.full(n, -1, dtype=np.int64),
            "size": rng.randint(100, 1400, size=n).astype(np.int64),
            "timestamp": np.sort(rng.uniform(0, 1, size=n)),
        }
        X = _build_raw_array([trace], seq_len=50)
        result = compute_outgoing_cdfs(X)
        assert result["outgoing_burst_sizes"] == []
        assert result["outgoing_burst_size_cdf"] is None

    def test_all_zero_padding(self):
        """Fully padded rows should be handled gracefully."""
        X = np.zeros((5, 100, 3), dtype=np.float64)
        result = compute_outgoing_cdfs(X)
        assert result["outgoing_burst_sizes"] == []
        assert result["outgoing_burst_size_cdf"] is None

    def test_multiple_traces(self):
        """CDF computed over multiple samples should still be valid."""
        traces = [make_trace(seed=s) for s in range(10)]
        X = _build_raw_array(traces, seq_len=250)
        result = compute_outgoing_cdfs(X)
        assert result["outgoing_burst_size_cdf"][-1] == pytest.approx(1.0)
        assert len(result["outgoing_packet_sizes"]) > 0

    def test_result_unpacks_into_augmentor(self):
        """The returned dict should be directly usable as kwargs."""
        from pa3.tools.augmentor import NetCLRAugmentor
        trace = make_trace()
        X = _build_raw_array([trace], seq_len=250)
        cdfs = compute_outgoing_cdfs(X)
        aug = NetCLRAugmentor(**cdfs)
        assert len(aug.outgoing_burst_sizes) > 0

    def test_single_outgoing_packet_burst(self):
        """A trace with only 1-packet outgoing bursts should have no delays."""
        trace = {
            "direction": np.array([1, -1, -1, 1, -1], dtype=np.int64),
            "size": np.array([100, 200, 300, 150, 400], dtype=np.int64),
            "timestamp": np.array([0.0, 0.1, 0.2, 0.3, 0.4]),
        }
        X = _build_raw_array([trace], seq_len=10)
        result = compute_outgoing_cdfs(X)
        assert result["outgoing_delays"] == []
        assert result["outgoing_delay_cdf"] is None
        assert len(result["outgoing_burst_sizes"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
