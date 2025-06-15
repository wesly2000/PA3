"""
This file contains the fixture for the tests.
"""

import pytest
import numpy as np
from tempfile import TemporaryFile

@pytest.fixture
def npz_files():
    # Create 3 temporary .npz files
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

    # Convert the streams to npz objects
    tmp_file_1, tmp_file_2, tmp_file_3 = TemporaryFile(), TemporaryFile(), TemporaryFile()
    np.savez(tmp_file_1, **stream_1)
    np.savez(tmp_file_2, **stream_2)
    np.savez(tmp_file_3, **stream_3)

    tmp_file_1.seek(0)
    tmp_file_2.seek(0)
    tmp_file_3.seek(0)

    npz_files = [np.load(tmp_file_1), np.load(tmp_file_2), np.load(tmp_file_3)]

    return npz_files