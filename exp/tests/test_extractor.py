import io

import numpy as np
import pandas as pd
import pytest

from WFlib.tools.extractor import *
from WFlib.tools.formatter import PcapFormatter
from WFlib.utils.config import get_config
from exp.tests.test_formatter import google_file, apple_file, tiktok_file, yandex_file

from exp.tests.fixture import npz_files

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

    formatter = PcapFormatter(length=10)
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
    formatter = PcapFormatter(length=31)
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

    formatter = PcapFormatter(length=10, display_filter="tcp.stream != 1")

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

    formatter = PcapFormatter(length=10, display_filter="quic")

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

    formatter = PcapFormatter(length=5)

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
    

def test_NpzHSDBSExtractor_1(npz_files):
    """
    Test reading a .npz file and extract the hsdbs feature.
    """
    extractor = NpzHSDBSExtractor()
    result = []
    extractor.extract(result, npz_files)

    target = np.array([200, -100, 100, 0, 100, 0, 100, -100, -100, 0, 0, -100, 0, -100, 0, -100, 0, -100, 0, 100, 0, 100, 0])
    assert np.all(result == target)

def test_NpzHSDBSExtractor_2(npz_files):
    """
    Test reading a .npz file and extract the hsdbs feature, this test covers the case that the ignore_control_packets option is set to True.
    """
    extractor = NpzHSDBSExtractor(ignore_control_packets=True)
    result = []
    extractor.extract(result, npz_files)

    target = np.array([200, 300, -400, -200, -100, 200])
    assert np.all(result == target)