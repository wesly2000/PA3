"""
This file contains shared fixtures for the tests.
"""

import pytest
import numpy as np
from tempfile import TemporaryFile


@pytest.fixture
def npz_buffers():
    # Create 3 temporary .npz buffers
    stream_1 = {
        "direction": np.array([1, -1, 1, -1, 1, -1, -1, 1, -1, 1]),
        "length": np.array([132, 20, 132, 32, 132, 20, 132, 20, 132, 20]),
        "timestamp": np.array([3, 4, 5, 6, 7, 8, 11, 12, 13, 14])
    }

    stream_2 = {
        "direction": np.array([-1, 1, -1, 1, -1, 1, -1, 1]),
        "length": np.array([132, 20, 132, 32, 132, 20, 132, 20]),
        "timestamp": np.array([9, 10, 15, 16, 17, 18, 19, 20])
    }

    stream_3 = {
        "direction": np.array([1, 1, -1, -1, 1, 1, -1, 1, -1]),
        "length": np.array([132, 132, 31, 132, 20, 132, 20, 132, 20]),
        "timestamp": np.array([0, 1, 2, 21, 22, 23, 24, 25, 26])
    }

    # Convert the streams to npz buffers
    tmp_file_1, tmp_file_2, tmp_file_3 = TemporaryFile(), TemporaryFile(), TemporaryFile()
    np.savez(tmp_file_1, **stream_1)
    np.savez(tmp_file_2, **stream_2)
    np.savez(tmp_file_3, **stream_3)

    tmp_file_1.seek(0)
    tmp_file_2.seek(0)
    tmp_file_3.seek(0)

    return tmp_file_1, tmp_file_2, tmp_file_3


# ---------------------------------------------------------------------------
# Augmentor test helpers (used by test_augmentor.py and test_statistics.py)
# ---------------------------------------------------------------------------

def make_trace(n_packets=200, seed=42):
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


def make_short_trace(seed=99):
    """Short trace (< 1000 packets) that forces inflate in change_content."""
    rng = np.random.RandomState(seed)
    direction = np.array([1]*5 + [-1]*15 + [1]*3 + [-1]*12, dtype=np.int64)
    n = len(direction)
    size = rng.randint(40, 1500, size=n).astype(np.int64)
    timestamp = np.sort(rng.uniform(0, 2, size=n))
    return {"direction": direction, "size": size, "timestamp": timestamp}


def make_augmentor(**kwargs):
    """Create an augmentor with sensible defaults for testing."""
    from WFlib.tools.augmentor import NetCLRAugmentor
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


def assert_valid_result(result, msg=""):
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