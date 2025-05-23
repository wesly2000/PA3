import io

import numpy as np

from WFlib.tools.extractor import DirectionExtractor, TimeExtractor
from WFlib.tools.formatter import PcapFormatter
from exp.tests.test_formatter import google_file, apple_file, tiktok_file


def test_DirectionExtractor_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = DirectionExtractor(src=["192.168.5.5", "10.4.0.3"])

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


def test_TimeExtractor_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = TimeExtractor()

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
              "time": np.array([[0.000000000, 0.019226000, 5.562068000, 5.562802000, 0, 0, 0, 0, 0, 0]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()


def test_TimeExtractor_2():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = TimeExtractor(src='192.168.5.5')

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
              "time": np.array([[5.065814000, 5.065865000, -5.074124000, -5.074849000, -5.074850000,
                                 -5.074850000, -5.234382000, 5.236719000, -5.246387000, 5.475373000]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()


def test_TimeExtractor_3():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the timestamp feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = TimeExtractor(src=["192.168.5.5", "10.4.0.3"])

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
              "time": np.array([[0.000000, 0.019226, 2.936487, -3.055774, -3.055790],
                                [0.000000000, 0.000096556, -0.001713993, 0.001745523, -0.001829495],
                                [0.000000000, -0.001680410, 0.001703165, 0.002265464, 0.002269337]
                                 ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()
