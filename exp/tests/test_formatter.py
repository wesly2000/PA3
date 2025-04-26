from WFlib.tools.capture import *
from WFlib.tools.formatter import *

import io
import json
import tempfile
import tracemalloc
import os 

delete_file = True if os.name == "posix" else False # Only delete the file on Unix-like systems.

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"
tiktok_file = "exp/test_dataset/realworld_dataset/decryption/www.tiktok.com.pcapng"

def test_PcapFormatter_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = DirectionExtractor(src="192.168.5.5")

    formatter = PcapFormatter(length=5)
    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com"]), "labels": np.array([0]), "direction": np.array([[1, 1, 1, 1, 1]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_2():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length larger than the number of packets to test padding.
    """
    extractor = DirectionExtractor(src="192.168.5.5")

    formatter = PcapFormatter(length=12)
    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com"]), "labels": np.array([0]), "direction": np.array([[1, 1, 1, 1, 1, 1, -1, 1, 1, -1, 0, 0]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_3():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    """
    formatter = PcapFormatter(length=10)

    extractor = DirectionExtractor(src="192.168.5.5")

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
              "labels": np.array([0, 0, 1]), 
              "direction": np.array([
                  [1, 1, 1, 1, 1, 1, -1, 1, 1, -1],
                  [1, 1, -1, 1, 1, 0, 0, 0, 0, 0],
                  [-1, -1, 1, -1, 1, -1, 1, 1, -1, -1]
                  ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_4():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of display filter.
    """
    formatter = PcapFormatter(length=10, display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
              "labels": np.array([0, 0, 1]), 
              "direction": np.array([
                  [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                  [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                  [-1, -1, -1, 1, -1, -1, 0, 0, 0, 0]
                  ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_5():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of display filter.
    """
    formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=delete_file) as temp_file:
        formatter.dump(temp_file.name)
        loaded_data = json.load(temp_file)

        target = {"hosts" : ["www.baidu.com", "www.zhihu.com"], 
                "labels": [0, 0, 1], 
                "direction": [
                    [1],
                    [1, 1],
                    [-1, -1, -1, 1, -1, -1]
                    ]}
        for k, v in loaded_data.items():
            for i in range(len(v)):
                assert target[k][i] == v[i]

        if not delete_file:
            filename = temp_file.name

    if not delete_file:
        os.unlink(filename)

def test_PcapFormatter_6():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of batch_extract.
    """
    formatter = PcapFormatter(length=10)

    extractor = DirectionExtractor(src="192.168.5.5")

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()
    
    formatter.batch_extract("exp/test_dataset", buffer, ["dns.alidns.com", "firefox.settings.services.mozilla.com"], extractor)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["realworld_dataset", "simple_dataset"]), 
              "labels": np.array([0, 0, 1, 1, 1]), 
              "direction": np.array([
                  [1, 1, 1, 1, 1, -1, 1, 1, -1, -1],
                  [1, 1, 1, -1, -1, -1, -1, 1, 1, -1],
                  [1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                  [-1, -1, 1, -1, 1, -1, 1, 1, -1, -1]
                  ])}
    
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_7():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of batch_extract, and setting keep_packets to False for memory optimization.
    """
    formatter = PcapFormatter(length=10, keep_packets=False)

    extractor = DirectionExtractor(src="192.168.5.5")

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()
    
    formatter.batch_extract("exp/test_dataset", buffer, ["dns.alidns.com", "firefox.settings.services.mozilla.com"], extractor)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["realworld_dataset", "simple_dataset"]), 
              "labels": np.array([0, 0, 1, 1, 1]), 
              "direction": np.array([
                  [1, 1, 1, 1, 1, -1, 1, 1, -1, -1],
                  [1, 1, 1, -1, -1, -1, -1, 1, 1, -1],
                  [1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                  [-1, -1, 1, -1, 1, -1, 1, 1, -1, -1]
                  ])}
    
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()


# def test_PcapFormatter_8():
#     """
#     This test validates that setting keep_packets to False reduces the memory usage.
#     """
#     def measure_memory(func):
#         tracemalloc.start()  # Tracing memory usage starts
#         func()  
#         snapshot = tracemalloc.take_snapshot()  # Fetch the snapshot of the memory
#         tracemalloc.stop()  # Stop memory tracing

#         # Compute the memory usage
#         total_memory = sum(stat.size for stat in snapshot.statistics('lineno'))
#         return total_memory

#     total_memory_1 = measure_memory(test_PcapFormatter_6)
#     total_memory_2 = measure_memory(test_PcapFormatter_7)
#     assert total_memory_1 > total_memory_2

def test_PcapFormatter_9():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = DirectionExtractor(src="192.168.5.5")

    formatter = PcapFormatter(length=10)
    formatter.load("exp/test_dataset/realworld_dataset/www.google.com.pcapng")
    formatter.transform("www.google.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.google.com"]), "labels": np.array([0]), "direction": np.array([[1, 1, 1, -1, -1, -1, -1, 1, 1, -1]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

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

def test_TimeExtractor_2():
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

def test_JsonFormatter_1():
    """
    This test covers reading a .json file, and extract the direction feature, truncate/pad it to given length,
    and dump it into a .npz file.
    """
    pcap_formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_02.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_03.pcapng")
    pcap_formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=delete_file) as temp_file:
        pcap_formatter.dump(temp_file.name)
        json_formatter = JsonFormatter()
        json_formatter.load(temp_file)
        json_formatter.transform(direction=10)

        # Create an in-memory bytes buffer
        buffer = io.BytesIO()
        json_formatter.dump(buffer)
        buffer.seek(0)  # Move to the start of the buffer
        loaded_data = np.load(buffer)

        target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
                "labels": np.array([0, 0, 1]), 
                "direction": np.array([
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    [-1, -1, -1, 1, -1, -1, 0, 0, 0, 0]
                    ])}
        
        for k, v in loaded_data.items():
            assert np.all(target[k] == v)

        loaded_data.close()

        if not delete_file:
            filename = temp_file.name

    if not delete_file:
        os.unlink(filename)

def test_JsonFormatter_2():
    """
    This test covers the statistics with JsonFormatter.
    """
    pcap_formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_01.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_02.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_dataset/simple_pcap_03.pcapng")
    pcap_formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=delete_file) as temp_file:
        pcap_formatter.dump(temp_file.name)
        json_formatter = JsonFormatter()
        json_formatter.load(temp_file)

        hosts = json_formatter.get_feature_buf('hosts')
        target = ["www.baidu.com", "www.zhihu.com"]
        for i in range(len(target)):
            assert hosts[i] == target[i]

        target = [[1], [1, 1], [-1, -1, -1, 1, -1, -1]]
        directions = json_formatter.get_feature_buf('direction')
        for i in range(len(target)):
            for j in range(len(target[i])):
                assert target[i][j] == directions[i][j]

        if not delete_file:
            filename = temp_file.name

    if not delete_file:
        os.unlink(filename)

def test_DistriPcapFormatter_1():
    formatter = DistriPcapFormatter(length=10, keep_packets=False)

    extractor = DirectionExtractor(src="192.168.5.5")

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()
    
    formatter.batch_extract("exp/test_dataset", buffer, ["dns.alidns.com", "firefox.settings.services.mozilla.com"], extractor)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(['realworld_dataset', 'simple_dataset']), "labels": np.array([0, 0, 1, 1, 1])}
    for k, v in target.items():
        assert np.all(loaded_data[k] == v)

    assert loaded_data['direction'].shape == (5, 10)

    loaded_data.close()