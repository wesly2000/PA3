import io

import numpy as np
import pandas as pd
import pytest
from tempfile import TemporaryFile

from WFlib.tools.extractor import *
from WFlib.tools.formatter import PcapFormatter
from WFlib.utils.config import get_config
from exp.tests.test_formatter import google_file, apple_file, tiktok_file, yandex_file

from exp.tests.fixture import npz_buffers

config_path = Path.cwd() / 'config.ini'
if not config_path.exists():
    tshark_path = "tshark"
else:
    config = get_config(config_path)
    tshark_path = config['tshark'].get('tshark_path', fallback="tshark")


def test_PcapDirExtractor_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = PcapDirExtractor(src=["192.168.5.5", "10.4.0.3"])

    formatter = PcapFormatter(length=10, tshark_path=tshark_path)
    formatter.load(google_file)
    formatter.transform("www.google.com", 0, extractor)

    formatter.load(apple_file)
    formatter.transform("www.apple.com", 1, extractor)

    formatter.load(tiktok_file)
    formatter.transform("www.tiktok.com", 2, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.google.com", "www.apple.com", "www.tiktok.com"]),
              "labels": np.array([0, 1, 2]),
              "direction": np.array([[1, 1, 1, -1, -1, -1, -1, 1, 1, -1],
                                     [1, 1, -1, 1, -1, 1, 1, 1, -1, -1],
                                     [1, -1, 1, 1, 1, -1, -1, 1, 1, 1],
                                     ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapDirExtractor_2():
    extractor = PcapDirExtractor(src=["58.206.207.126", "2001:da8:283:c004:8177:495b:d038:d48a"])
    formatter = PcapFormatter(length=31, tshark_path=tshark_path)
    formatter.load(yandex_file)
    formatter.transform("www.yandex.com", 0, extractor)

    buffer = io.BytesIO()
    formatter.dump(buffer)
    buffer.seek(0)
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.yandex.com"]),
              "labels": np.array([0]),
              "direction": np.array(
                  [1, -1, 1, 1, 1, -1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, 1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1, 1, 1, 1]
                )}
    
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapTsExtractor_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = PcapTsExtractor()

    formatter = PcapFormatter(length=10, display_filter="tcp.stream != 1", tshark_path=tshark_path)

    formatter.load("exp/test_dataset/realworld_dataset/www.google.com.pcapng")
    formatter.transform("www.google.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.google.com"]),
              "labels": np.array([0]),
              "timestamp": np.array([[0.000000000, 0.019226000, 5.562068000, 5.562802000, 0, 0, 0, 0, 0, 0]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()


def test_PcapTsExtractor_2():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = PcapTsExtractor(src='192.168.5.5')

    formatter = PcapFormatter(length=10, display_filter="quic", tshark_path=tshark_path)

    formatter.load("exp/test_dataset/realworld_dataset/www.google.com.pcapng")
    formatter.transform("www.google.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.google.com"]),
              "labels": np.array([0]),
              "timestamp": np.array([[5.065814000, 5.065865000, -5.074124000, -5.074849000, -5.074850000,
                                 -5.074850000, -5.234382000, 5.236719000, -5.246387000, 5.475373000]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()


def test_PcapTsExtractor_3():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = PcapTsExtractor(src=["192.168.5.5", "10.4.0.3"])

    formatter = PcapFormatter(length=5, tshark_path=tshark_path)

    formatter.load(google_file)
    formatter.transform("www.google.com", 0, extractor)

    formatter.load(apple_file)
    formatter.transform("www.apple.com", 1, extractor)

    formatter.load(tiktok_file)
    formatter.transform("www.tiktok.com", 2, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.google.com", "www.apple.com", "www.tiktok.com"]),
              "labels": np.array([0, 1, 2]),
              "timestamp": np.array([[0.000000, 0.019226, 2.936487, -3.055774, -3.055790],
                                [0.000000000, 0.000096556, -0.001713993, 0.001745523, -0.001829495],
                                [0.000000000, -0.001680410, 0.001703165, 0.002265464, 0.002269337]
                                 ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

@pytest.fixture
def simple_csv_data():
    """
    Fixture that provides a DataFrame with realistic network packet data.
    The DataFrame contains common TShark fields with realistic values.
    """
    data = {
        'ip.src': ['192.168.1.100', '10.0.0.15', '172.16.0.25', '192.168.1.100', '10.0.0.15'],
        'ip.dst': ['8.8.8.8', '192.168.1.100', '10.0.0.15', '172.16.0.25', '8.8.8.8'],
        'frame.time_relative': [0.000000, 0.023456, 0.045678, 0.078901, 0.123456],
        'tcp.hdr_len': [20, 32, 20, 32, 20],
        'tcp.len': [1460, 1460, 1460, 1460, 1460]
    }
    return pd.DataFrame(data)

def test_CsvDirExtractor_1(simple_csv_data):
    """
    This test covers reading the first 5 packets from a .csv file, and extract the direction feature.
    """
    extractor = CsvDirExtractor(src=["192.168.1.100", "10.0.0.15"])

    result = extractor.extract(simple_csv_data)
    target = np.array([1, 1, -1, 1, 1])
    assert np.all(result == target)

def test_CsvDirExtractor_2():
    """
    This test covers reading real-world data from pcap file, and extract the direction feature.
    """
    df = pcap_to_dataframe(tshark_path, apple_file, display_filter="tcp.stream eq 1")
    extractor = CsvDirExtractor(src=["10.4.0.3"])

    result = extractor.extract(df)
    target = np.array([1, -1, 1, 1, -1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, -1, -1, 1, -1, -1, 1, 1])
    assert np.all(result == target)

def test_CsvTsExtractor_1(simple_csv_data):
    """
    This test covers reading the first 5 packets from a .csv file, and extract the timestamp feature.
    """
    extractor = CsvTsExtractor()

    result = extractor.extract(simple_csv_data)
    target = np.array([0.000000, 0.023456, 0.045678, 0.078901, 0.123456])
    assert np.all(result == target)


def test_CsvLenExtractor_1(simple_csv_data):
    """
    This test covers reading the first 5 packets from a .csv file, and extract the length feature.
    """
    extractor = CsvLenExtractor()

    result = extractor.extract(simple_csv_data)
    target = np.array([1480, 1492, 1480, 1492, 1480])
    assert np.all(result == target)


def test_pcap_to_dataframe_1():
    """
    Test reading a .pcap file and convert it to a DataFrame.
    """
    df = pcap_to_dataframe(tshark_path, apple_file, display_filter="tcp.stream eq 1")
    assert df.shape[0] == 22
    assert df.shape[1] == 9

    sni_row = df[df["tls.handshake.extensions_server_name"].notna()]
    assert sni_row.shape[0] == 1
    assert sni_row.iloc[0]["tls.handshake.extensions_server_name"] == "is1-ssl.mzstatic.com"


def test_pcap_to_dataframe_2():
    """
    Test reading a .pcap file and convert it to a DataFrame, this test covers the case that the pcap file contains UDP packets.
    """
    df = pcap_to_dataframe(tshark_path, tiktok_file, display_filter="udp.stream eq 0")
    assert df.shape[0] == 80 and \
            df.shape[1] == 9 and \
            df.iloc[1]['tls.handshake.extensions_server_name'] == 'lf16-cdn-tos.tiktokcdn-us.com' and \
            df[df['tcp.stream'].notna()].shape[0] == 0

def test_pcap_to_dataframe_3():
    """
    Test reading a .pcap file and convert it to a DataFrame, this test covers the case that the pcap file contains UDP packets.
    """
    df = pcap_to_dataframe(tshark_path, tiktok_file, display_filter="udp.stream eq 0")
    extractor = CsvLenExtractor()
    result = extractor.extract(df, protocol="udp")
    assert result[0] == 1260
    

def test_NpzHSDBSExtractor_1(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature.
    """
    extractor = NpzHSDBSExtractor(threshold=32)
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([200, -100, 100, 0, 100, 0, 100, -100, -100, 0, 0, -100, 0, -100, 0, -100, 0, -100, 0, 100, 0, 100, 0])
    assert np.all(result == target)

def test_NpzHSDBSExtractor_2(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the ignore_control_packets option is set to True.
    """
    extractor = NpzHSDBSExtractor(ignore_control_packets=True, threshold=32)
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([200, 300, -400, -200, -100, 200])
    assert np.all(result == target)

def test_NpzHSDBSExtractor_3(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the criterion option is set to HSDBSCriterion selecting the top-k streams.
    """
    # Test selecting the top-2 streams from 3 streams
    extractor = NpzHSDBSExtractor(ignore_control_packets=True, threshold=32, criteria=HSDBSCriterion(k=2))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([200, 300, -200, -100, 200])
    assert np.all(result == target)

    for npz_buffer in npz_buffers:
        npz_buffer.seek(0)

    # When k <= 0, all the streams should be selected
    extractor = NpzHSDBSExtractor(ignore_control_packets=True, threshold=32, criteria=HSDBSCriterion(k=0))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([200, 300, -400, -200, -100, 200])
    assert np.all(result == target)

    for npz_buffer in npz_buffers:
        npz_buffer.seek(0)
    # When k is larger than the number of streams, all the streams should be selected
    extractor = NpzHSDBSExtractor(ignore_control_packets=True, threshold=32, criteria=HSDBSCriterion(k=5))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([200, 300, -400, -200, -100, 200])
    assert np.all(result == target)


def test_NpzHSDBSExtractor_4(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the criterion option is set to BSExcludeCriterion.
    """
    extractor = NpzHSDBSExtractor(
        criteria=HSDBSExcludeCriterion(lower_bounds=np.array([350]), upper_bounds=np.array([450]), threshold=32), 
        ignore_control_packets=True, threshold=32)
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    total_size = np.sum(abs(size) for size in result)
    target = 1000

    assert total_size == target


def test_NpzHSDBSExtractor_5(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the criterion option is set to BSExcludeCriterion.
    """
    extractor = NpzHSDBSExtractor(
        criteria=HSDBSExcludeCriterion(lower_bounds=np.array([350, 460]), upper_bounds=np.array([450, 550]), threshold=32), 
        ignore_control_packets=True, 
        threshold=32)
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    assert len(result) == 0


def test_NpzDirExtractor_1(npz_buffers):
    """
    Test reading a .npz file and extract the direction feature.
    """
    extractor = NpzDirExtractor()
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    target = np.array([1, 1, -1, 1, -1, 1, -1, 1, -1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, -1, 1, 1, -1, 1, -1])

    assert np.all(np.sign(result) == target)

def test_VMessStripper_1(npz_buffers):
    """
    Test reading a .npz file and extract the direction feature, this test covers the case that the stripper option is set to VmessStripper.
    """
    extractor = NpzDirExtractor(stripper=VMessStripper())
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    target = np.array([1, 1, -1, 1, -1, 1, 1, -1, -1, 1, 1, -1, 1, -1, -1, 1, 1, 1, 1, 1, -1])

    assert np.all(np.sign(result) == target)


def test_VMessStripper_2(npz_buffers):
    """
    Test reading a .npz file and extract the direction feature, this test covers the case that the criterion option is set to HSDBSCriterion selecting the top-k streams.
    """
    extractor = NpzDirExtractor(stripper=VMessStripper(), criteria=HSDBSCriterion(k=1, threshold=0))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    target = np.array([1, -1, 1, 1, -1, 1, -1, 1])

    assert np.all(np.sign(result) == target)


def test_VMessStripper_3(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the criterion option is set to BSExcludeCriterion.
    """
    extractor = NpzDirExtractor(stripper=VMessStripper(), criteria=HSDBSExcludeCriterion(lower_bounds=np.array([350, 460]), upper_bounds=np.array([450, 550]), threshold=32))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    assert len(result) == 0


def test_ShadowsocksStripper_1(npz_buffers):
    """
    Test reading a .npz file and extract the direction feature, this test covers the case that the criterion option is set to HSDBSCriterion selecting the top-k streams.
    """
    extractor = NpzDirExtractor(stripper=ShadowsocksStripper(), criteria=HSDBSCriterion(k=1, threshold=0))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    target = np.array([1, -1, 1, -1, -1, 1])

    assert np.all(np.sign(result) == target)


def test_LengthExcludeCriterion_1(npz_buffers):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the criterion option is set to BSExcludeCriterion.
    """
    extractor = NpzDirExtractor(criteria=LengthExcludeCriterion(threshold=9))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = np.array([1, -1, 1, -1, 1, -1, -1, 1, -1, 1])
    assert np.all(np.sign(result) == target)


def test_WeightSplitter_1():
    """
    Test the WeightSplitter class noisy_weight_indices.
    """
    splitter = WeightSplitter(prologue_len=10, epilogue_len=10, weight=[0.2, 0.3, 0.5])
    result = np.array([splitter.noisy_weight_indices(100) for _ in range(100)])

    assert result.shape == (100, 4) and np.all(result[:, i-1] < result[:, i] for i in range(1, 100)) and np.all(0 < result[:, i] <= 100 for i in range(100))   
    
    # We use Chebyshev's inequality to test the average value of the result's first element
    sigma = np.sqrt(1/12) * 10
    mu = 20
    k = 10
    assert np.abs(np.sum(result[:, 1]) / 100 - mu) < k * sigma


def test_WeightSplitter_2():
    """
    Test the WeightSplitter class split method.
    """
    prologue_len=10
    epilogue_len=10
    splitter = WeightSplitter(prologue_len=prologue_len, epilogue_len=epilogue_len, weight=[0.2, 0.3, 0.5])
    
    prologue = [i for i in range(prologue_len)]
    epilogue = [i for i in range(90, 90 + epilogue_len)]
    stream = [(10 * i, i) for i in range(100)]

    sizes = []
    for split in splitter.split(stream):
        split_sizes = [s for _, s in split]
        sizes.extend(split_sizes[prologue_len:-epilogue_len])
        assert split_sizes[:prologue_len] == prologue and split_sizes[-epilogue_len:] == epilogue
    
    assert len(sizes) == 100 - prologue_len - epilogue_len
    assert set(sizes) == set(range(10, 90))


def test_RatioSplitter_1():
    """
    Test the RatioSplitter class split method.
    """
    prologue_len=10
    epilogue_len=10
    splitter = RatioSplitter(prologue_len=prologue_len, epilogue_len=epilogue_len, ratio=.9)
    
    prologue = [i for i in range(prologue_len)]
    epilogue = [i for i in range(110, 110 + epilogue_len)]
    stream = [(10 * i, i) for i in range(120)]

    stream_length = []

    for _ in range(100):
        sizes = []
        for split in splitter.split(stream):
            split_sizes = [s for _, s in split]
            sizes.extend(split_sizes[prologue_len:-epilogue_len])
            stream_length.append(len(sizes))
            assert set(sizes).issubset(set(range(10, 110)))
            assert split_sizes[:prologue_len] == prologue and split_sizes[-epilogue_len:] == epilogue

    sigma = np.sqrt(1/3)
    mean = 90
    k = 10
    assert np.abs(np.mean(stream_length) - mean) < k * sigma


def test_NpzRawExtractor_1(npz_buffers):
    """
    Test the NpzRawExtractor class extract method.
    """
    extractor = NpzRawExtractor(features=['direction', 'length'])
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    
    target = [
        (1, 132), (1, 132), (-1, 31), (1, 132), (-1, 20), (1, 132), (-1, 32), (1, 132), (-1, 20), (-1, 132), (1, 20), (-1, 132), (1, 20), (-1, 132), (1, 20), (-1, 132), (1, 32), (-1, 132), (1, 20), (-1, 132), (1, 20), (-1, 132), (1, 20), (1, 132), (-1, 20), (1, 132), (-1, 20),
    ]
    
    assert result == target
    

def test_NpzRawExtractor_2(npz_buffers):
    """
    Test the NpzRawExtractor class extract method using LengthCriterion.
    """
    extractor = NpzRawExtractor(features=['direction', 'length'], criteria=LengthCriterion(k=2))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)

    target = [
        (1, 132), (1, 132), (-1, 31), (1, 132), (-1, 20), (1, 132), (-1, 32), (1, 132), (-1, 20), (-1, 132), (1, 20), (-1, 132), (1, 20), (-1, 132), (1, 20), (1, 132), (-1, 20), (1, 132), (-1, 20)  
    ]
    
    assert result == target
    

def test_NpzRawExtractor_3(npz_buffers):
    """
    Test the NpzRawExtractor class extract method with VMessStripper.
    """
    extractor = NpzRawExtractor(features=['direction', 'length', 'timestamp'], stripper=VMessStripper(), criteria=LengthCriterion(k=2))
    result = []
    npz_files = [np.load(npz_buffer) for npz_buffer in npz_buffers]
    extractor.extract(result, npz_files)
    target = []
    for i, stream in enumerate(npz_files):
        if i == 1:
            continue
        tmp_list = list(zip(stream["timestamp"], stream["direction"], stream["length"]))
        for index in sorted([3, 6], reverse=True):
            del tmp_list[index]
        target += tmp_list

    target.sort(key=lambda x: x[0])

    assert result == target

# --- N-gram anomaly detection ---

def test_ngram_uniform_bin_basic():
    binned = uniform_bin([-15, -5, 0, 5, 15], lower_bound=-10, upper_bound=10, vocabulary_size=2)
    np.testing.assert_array_equal(binned, np.array([-5, -5, 5, 5, 5], dtype=np.int64))


def test_ngram_uniform_bin_vocabulary_size():
    binned = uniform_bin([-15, -5, 0, 5, 15], lower_bound=-10, upper_bound=10, vocabulary_size=4)
    np.testing.assert_array_equal(binned, np.array([-8, -3, 2, 7, 7], dtype=np.int64))
    assert len(np.unique(binned)) == 4


def test_ngram_uniform_bin_invalid_args():
    with pytest.raises(ValueError):
        uniform_bin([1, 2, 3], lower_bound=10, upper_bound=-10, vocabulary_size=5)
    with pytest.raises(ValueError):
        uniform_bin([1, 2, 3], lower_bound=0, upper_bound=10, vocabulary_size=0)


def test_build_distribution_bins_equal_mass():
    size_counts = {10: 100, 20: 100, 30: 100, 40: 100}
    bins = build_distribution_bins(size_counts, vocabulary_size=2)
    assert bins == [(10, 20, 15), (30, 40, 35)]


def test_distribution_bin_basic():
    size_counts = {10: 100, 20: 100, 30: 100, 40: 100}
    binned = distribution_bin([10, 20, 30, 40], size_counts, vocabulary_size=2)
    np.testing.assert_array_equal(binned, np.array([15, 15, 35, 35], dtype=np.int64))


def test_distribution_bin_user_example():
    size_counts = {150: 1888, -100: 105}
    bins = build_distribution_bins(size_counts, vocabulary_size=2)
    assert bins == [(-100, -100, -100), (150, 150, 150)]
    binned = distribution_bin([-100, 150, 150], size_counts, vocabulary_size=2)
    np.testing.assert_array_equal(binned, np.array([-100, 150, 150], dtype=np.int64))


def test_distribution_bin_clip():
    size_counts = {0: 100, 100: 100}
    binned = distribution_bin([-999, 0, 50, 100, 999], size_counts, vocabulary_size=2)
    np.testing.assert_array_equal(binned, np.array([0, 0, 100, 100, 100], dtype=np.int64))


def test_distribution_bin_invalid():
    with pytest.raises(ValueError):
        build_distribution_bins({}, vocabulary_size=2)
    with pytest.raises(ValueError):
        build_distribution_bins({10: 100}, vocabulary_size=0)
    with pytest.raises(ValueError):
        build_distribution_bins({10: 100, 20: 100}, vocabulary_size=3)


def test_packet_size_counter():
    data = np.array([100, -100, 100, 50], dtype=np.int64)
    assert packet_size_counter(data) == {100: 2, -100: 1, 50: 1}


def test_packet_size_binner_uniform_roundtrip():
    data = [-15, -5, 0, 5, 15]
    expected = uniform_bin(data, lower_bound=-10, upper_bound=10, vocabulary_size=2)
    binner = PacketSizeBinner.fit_uniform(-10, 10, vocabulary_size=2)
    np.testing.assert_array_equal(binner.transform(data), expected)


def test_packet_size_binner_distribution_uses_train_counts():
    flows_train = [np.array([10, 20, 30], dtype=np.int64)]
    flows_test = [np.array([40, 50], dtype=np.int64)]
    binner = PacketSizeBinner.fit_distribution(flows_train, vocabulary_size=3)
    assert binner.bin_specs == [(10, 10, 10), (20, 20, 20), (30, 30, 30)]
    np.testing.assert_array_equal(
        binner.transform(flows_test[0]),
        distribution_bin(flows_test[0], binner.size_counts, vocabulary_size=3),
    )
    assert 40 not in binner.size_counts and 50 not in binner.size_counts


def test_train_ngram_db_binned_anomaly_only():
    flow = np.array([-8, -3, 2, 7], dtype=np.int64)
    binner = PacketSizeBinner.fit_uniform(-10, 10, vocabulary_size=4)
    db = train_ngram_db(
        [flow],
        strip_indices={0},
        window_size=1,
        binner=binner,
        overlap_threshold=0.5,
    )
    assert db == {(-8,)}
    assert (10,) not in db


def test_evaluate_ngram_raw_gt_binned_predict():
    flow = np.array([-8, -3, 2, 7], dtype=np.int64)
    binner = PacketSizeBinner.fit_uniform(-10, 10, vocabulary_size=4)
    db = train_ngram_db(
        [flow],
        strip_indices={0},
        window_size=1,
        binner=binner,
        overlap_threshold=0.5,
    )
    precision, recall = evaluate_ngram(
        [flow],
        strip_indices={0},
        window_size=1,
        db=db,
        binner=binner,
        overlap_threshold=0.5,
    )
    assert precision == 1.0
    assert recall == 1.0


def test_ngram_predict_on_binned():
    flow = np.array([10, 20, 30, 40], dtype=np.int64)
    binner = PacketSizeBinner.fit_uniform(-10, 10, vocabulary_size=2)
    db = train_ngram_db(
        [flow],
        strip_indices={0, 1},
        window_size=2,
        binner=binner,
        overlap_threshold=0.5,
    )
    binned_preds = ngram_predict(binner.transform(flow), db, window_size=2)
    raw_preds = ngram_predict(flow, db, window_size=2)
    assert binned_preds[0][1] == 1
    assert raw_preds[0][1] == 0


def test_ngram_label_windows_majority():
    data = np.array([1, 2, 3, 4, 5, 6])
    labeled = label_windows(data, strip_indices={1, 2, 3}, window_size=4, overlap_threshold=0.5)
    assert labeled == [
        ((1, 2, 3, 4), 1),
        ((2, 3, 4, 5), 1),
        ((3, 4, 5, 6), 0),
    ]


def test_ngram_label_windows_empty_strip():
    data = np.array([10, 20, 30])
    labeled = label_windows(data, strip_indices=[], window_size=2)
    assert labeled == [((10, 20), 0), ((20, 30), 0)]


def test_ngram_precision_recall():
    labeled = [((1,), 1), ((2,), 0), ((3,), 1), ((4,), 0)]
    perfect = [((1,), 1), ((2,), 0), ((3,), 1), ((4,), 0)]
    all_fp = [((1,), 1), ((2,), 1), ((3,), 1), ((4,), 1)]
    all_fn = [((1,), 0), ((2,), 0), ((3,), 0), ((4,), 0)]

    p, r = ngram_precision_recall(labeled, perfect)
    assert p == 1.0 and r == 1.0

    p, r = ngram_precision_recall(labeled, all_fp)
    assert p == 0.5 and r == 1.0

    p, r = ngram_precision_recall(labeled, all_fn)
    assert p == 0.0 and r == 0.0

    assert ngram_precision_recall([], []) == (0.0, 0.0)


def test_mutual_information_perfect_association():
    windows = [("a",), ("a",), ("b",), ("b",)]
    labels = [1, 1, 0, 0]
    assert mutual_information_windows(windows, labels) > 0.0


def test_mutual_information_independent():
    windows = [("a",)] * 50 + [("b",)] * 50
    labels = [1] * 25 + [0] * 25 + [1] * 25 + [0] * 25
    assert mutual_information_windows(windows, labels) == 0.0


def test_vocabulary_objective_penalty_increases_with_vocab():
    labeled = [((10, 20), 1), ((30, 40), 0), ((10, 20), 1), ((50, 60), 0)]
    binner = PacketSizeBinner.fit_uniform(-10, 10, vocabulary_size=4)
    mi = vocabulary_objective(labeled, 4, binner, window_size=2, lambda_penalty=0.0)["mi_nats"]
    obj_small = vocabulary_objective(
        labeled, 2, binner, window_size=2, lambda_penalty=1.0
    )
    obj_large = vocabulary_objective(
        labeled, 100, binner, window_size=2, lambda_penalty=1.0
    )
    assert obj_large["penalty"] > obj_small["penalty"]
    assert obj_small["objective"] == mi - obj_small["penalty"]
    assert obj_large["objective"] == mi - obj_large["penalty"]
    assert obj_large["objective"] < obj_small["objective"]


def test_sweep_vocabulary_objective_shape():
    flows = [
        np.array([-8, -3, 2, 7], dtype=np.int64),
        np.array([10, 20, 30, 40], dtype=np.int64),
    ]
    rows = sweep_vocabulary_objective(
        flows,
        strip_indices={0},
        window_size=1,
        vocabulary_sizes=[1, 2, 4],
        fit_binner=lambda v: PacketSizeBinner.fit_uniform(-10, 10, v),
        overlap_threshold=0.5,
    )
    assert len(rows) == 3
    for row in rows:
        assert {"vocabulary_size", "mi_nats", "penalty", "objective", "n_windows"}.issubset(
            row.keys()
        )
