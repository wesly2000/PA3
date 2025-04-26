"""
This file covers tests for WFlib/tools/analyzer.py
"""
from WFlib.tools.analyzer import *
from pathlib import Path
import pyshark
import os

import nest_asyncio 
nest_asyncio.apply()

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"
tiktok_file = "exp/test_dataset/realworld_dataset/decryption/www.tiktok.com.pcapng"

def test_packet_count_01():
    target = 8627
    cap = pyshark.FileCapture(input_file=baidu_proxied_file, only_summaries=True, keep_packets=False)
    cnt = packet_count(cap)

    cap.close()

    assert target == cnt

def test_packet_count_02():
    target = 8564
    cap = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tcp", only_summaries=True, keep_packets=False)
    cnt = packet_count(cap)

    cap.close()

    assert target == cnt

def test_file_count():
    base_dir = Path("exp/test_dataset")
    target = {"realworld_dataset": 2, "simple_dataset": 3}

    result = file_count(base_dir)

    assert len(target) == len(result)

    for k in result:
        assert result[k] == target[k]

def test_http2_bytes_count():
    counter = HTTP2ByteCounter()

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2 and http2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 3242, 9

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_tcp_bytes_count():
    counter = TCPByteCounter()

    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2")
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 11408, 32

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_tls_bytes_count():
    counter = TLSByteCounter()

    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2 and tls")
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10368, 16

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_udp_bytes_count():
    counter = UDPByteCounter()

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0")

    byte_count, pkt_count = 0, 0

    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 56518, 80

    capture.close() 

    assert byte_target == byte_count and packet_target == pkt_count

def test_quic_bytes_count():
    counter = QUICByteCounter()

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0 and quic")

    byte_count, pkt_count = 0, 0
    
    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 55878, 80

    capture.close()

    assert byte_target == byte_count and packet_target == pkt_count

def test_http3_bytes_count():
    counter = HTTP3ByteCounter()

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0 and http3",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})

    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    capture.close()
    byte_target, packet_target = 42925, 22

    assert byte_target == byte_count and packet_target == pkt_count


def test_capture_counter_1():
    """
    This test covers TCP/TLS/HTTP2 layered counter to the given capture.
    """
    counter = CaptureCounter(TCPByteCounter(), TLSByteCounter(), HTTP2ByteCounter())

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    result = counter.count(capture)

    capture.close()

    assert  result['tcp'][0] == 32 and result['tcp'][1] == 11408 and \
            result['tls'][0] == 16 and result['tls'][1] == 10368 and \
            result['http2'][0] == 9 and result['http2'][1] == 3242
    
def test_capture_counter_2():
    """
    This test covers UDP/QUIC/HTTP3 layered counter to the given capture."
    """
    counter = CaptureCounter(UDPByteCounter(), QUICByteCounter(), HTTP3ByteCounter())

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})

    result = counter.count(capture)

    capture.close()

    assert result['udp'][0] == 80 and result['udp'][1] == 56518 and \
           result['quic'][0] == 80 and result['quic'][1] == 55878 and \
           result['http3'][0] == 22 and result['http3'][1] == 42925
    
def test_layer_extractor_01():
    """
    This test covers extracting layers from the given capture for TLS.
    """
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "34":  # This packet contains only a single TLS layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='TCP')
            assert len(layers) == 1 and layers[0].layer_name == "tls"
        elif pkt.number == "66":  # This packet contains a DATA layer and a single TLS layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='TCP')
            assert len(layers) == 2 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "tls" and \
                    "tcp_segments" in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        elif pkt.number == "104":  # This packet contains a DATA layer and a single TLS layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='TCP')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls" and \
                    "tcp_segments" in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        elif pkt.number == "203":  # This packet contains a DATA layer and a single TLS layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='TCP')
            assert len(layers) == 0

    cap.close()

def test_layer_extractor_02():
    """
    This test covers extracting layers from the given capture for HTTP2.
    """
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "67":  # This packet contains a DATA layer and a single HTTP2 layer.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 2 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "http2" and \
                    "tls_segments" in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        if pkt.number == "104":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "http2" and \
                    layers[1].layer_name == "DATA" and \
                    layers[2].layer_name == "http2" and \
                    "tls_segments" in layers[1].field_names  # Assert we are extracting the correct DATA layer.
        if pkt.number == "170":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "DATA" and \
                    layers[2].layer_name == "http2" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    "tls_segments" in layers[0].field_names and \
                    "tls_segments" in layers[1].field_names
        if pkt.number == "221":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 7 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "DATA" and \
                    layers[2].layer_name == "DATA" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    layers[5].layer_name == "http2" and \
                    layers[6].layer_name == "http2" and \
                    "tls_segments" in layers[0].field_names and \
                    "tls_segments" in layers[1].field_names and \
                    "tls_segments" in layers[2].field_names
            
    cap.close()

def test_seq_filter_01():
    """
    This test covers seq_filter with more complex labeling functions.
    """
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "104":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            result = seq_filter(layers, lower_protocol='tls')
            layer_names = [layer.layer_name for layer in result]
            expect_num_DATA_layer = 1
            expect_num_HTTP2_layer = 1 
            assert layer_names.count("DATA") == expect_num_DATA_layer and \
                   layer_names.count("http2") == expect_num_HTTP2_layer
        
            
        if pkt.number == "221":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            result = seq_filter(layers, lower_protocol='tls')
            layer_names = [layer.layer_name for layer in result]
            expect_num_DATA_layer = 3
            expect_num_HTTP2_layer = 1 
            assert layer_names.count("DATA") == expect_num_DATA_layer and \
                   layer_names.count("http2") == expect_num_HTTP2_layer
            
    cap.close()

def test_HTTP2CellExtractor_01():
    cell_extractor = HTTP2CellExtractor()
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "104":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 2 and \
            cells[0].abs_frame_number == 104 and \
            cells[0].segment_size == [7706] and \
            cells[0].abs_segment_frame_number == [104] and \
            cells[0].size == 7706 and \
            cells[1].abs_frame_number == 104 and \
            cells[1].segment_size == [16384, 9] and \
            cells[1].abs_segment_frame_number == [104, 104] and \
            cells[1].size == 16393
            
        if pkt.number == "212":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 2 and \
            cells[0].abs_frame_number == 212 and \
            cells[0].segment_size == [16384, 9] and \
            cells[0].abs_segment_frame_number == [211, 212] and \
            cells[0].size == 16393 and \
            cells[1].abs_frame_number == 212 and \
            cells[1].segment_size == [16384, 9] and \
            cells[1].abs_segment_frame_number == [212, 212] and \
            cells[1].size == 16393
            
    cap.close()

def test_TLSCellExtractor_01():
    cell_extractor = TLSCellExtractor()
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "211":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 2 and \
            cells[0].abs_frame_number == 211 and \
            cells[0].segment_size == [15641, 765] and \
            cells[0].abs_segment_frame_number == [210, 211] and \
            cells[0].size == 16406 and \
            cells[1].abs_frame_number == 211 and \
            cells[1].segment_size == [16437] and \
            cells[1].abs_segment_frame_number == [211] and \
            cells[1].size == 16437

        if pkt.number == "220":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 2 and \
            cells[0].abs_frame_number == 220 and \
            cells[0].segment_size == [13365, 3041] and \
            cells[0].abs_segment_frame_number == [219, 220] and \
            cells[0].size == 16406 and \
            cells[1].abs_frame_number == 220 and \
            cells[1].segment_size == [31] and \
            cells[1].abs_segment_frame_number == [220] and \
            cells[1].size == 31
            
        if pkt.number == "66":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 66 and \
            cells[0].segment_size == [3838, 4236, 2824, 1412, 4096] and \
            cells[0].abs_segment_frame_number == [60, 61, 63, 65, 66] and \
            cells[0].size == 16406 
            
    cap.close()

def test_TCPCellExtractor_01():
    cell_extractor = TCPCellExtractor()
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:
        if pkt.number == "1":  
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 1 and \
            cells[0].segment_size == [40] and \
            cells[0].abs_segment_frame_number == [1] and \
            cells[0].size == 40

        if pkt.number == "220": 
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 220 and \
            cells[0].segment_size == [9916] and \
            cells[0].abs_segment_frame_number == [220] and \
            cells[0].size == 9916
            
        if pkt.number == "288": 
            cells = cell_extractor.extract(pkt)
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 288 and \
            cells[0].segment_size == [44] and \
            cells[0].abs_segment_frame_number == [288] and \
            cells[0].size == 44 
            
    cap.close()

def test_cell_comparison():
    """
    This test covers the partial order comparison of cells.
    """
    cell_1 = Cell(proto="http2", abs_frame_number=106)
    cell_1.abs_segment_frame_number = [104, 106]
    cell_2 = Cell(proto="http2", abs_frame_number=108)
    cell_2.abs_segment_frame_number = [106, 108]

    assert cell_1 < cell_2 and cell_2 > cell_1

    cell_1 = Cell(proto="http2", abs_frame_number=104)
    cell_1.abs_segment_frame_number = [101, 102, 104]
    cell_2 = Cell(proto="http2", abs_frame_number=104)
    cell_2.abs_segment_frame_number = [101, 102, 104]

    assert cell_1 == cell_2 and cell_2 == cell_1

    cell_1 = Cell(proto="http2", abs_frame_number=106)
    cell_1.abs_segment_frame_number = [104, 106]
    cell_2 = Cell(proto="http2", abs_frame_number=108)
    cell_2.abs_segment_frame_number = [104, 106]

    assert cell_1 < cell_2 and cell_2 > cell_1

def test_line_rel_building_01():
    """
    This test covers building the lower relation of a line using artificial data.
    """
    # Upper layer PDUs
    http2_cell_1 = Cell(proto="http2", abs_frame_number=106)
    http2_cell_1.abs_segment_frame_number = [104, 106]
    http2_cell_1.segment_size = [114, 514]
    http2_cell_2 = Cell(proto="http2", abs_frame_number=106)
    http2_cell_2.abs_segment_frame_number = [106]
    http2_cell_2.segment_size = [1919]
    http2_cell_3 = Cell(proto="http2", abs_frame_number=109)
    http2_cell_3.abs_segment_frame_number = [106, 108, 109]
    http2_cell_3.segment_size = [8, 10, 1145]


    line = Line(upper_protocol="http2", upper_cells=[http2_cell_1, http2_cell_2, http2_cell_3])

    target_upper_abs_byte_map = {104: (0, 114), 106: (114, 2555), 108: (2555, 2565), 109: (2565, 3710)}


    assert line.upper_abs_byte_map == target_upper_abs_byte_map
    
def test_line_rel_building_02():
    """
    This test covers building the lower relation of a line using real-world data.
    """
    tcp_filter = "tcp.stream == 2"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    line = get_adjacent_protocol_reassemble_info(cap=cap, upper_protocol="tls", lower_protocol="tcp")
    cap.close()

    target_upper_abs_byte_map = {226: (0, 1908), 228: (1908, 3320), 230: (3320, 6004), 232: (6004, 6218), 234: (6218, 6298), 235: (6298, 6390), 236: (6390, 7436), 237: (7436, 7739), 238: (7739, 8042), 239: (8042, 8104), 241: (8104, 8135), 242: (8135, 8166), 244: (8166, 9096), 246: (9096, 9700), 257: (9700, 10305), 280: (10305, 10344), 281: (10344, 10368)}
    
    assert line.upper_abs_byte_map == target_upper_abs_byte_map and \
           line.byte_counter == 10368


def test_line_rel_building_03():
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """
    tcp_filter = "tcp.stream == 0"
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    line = get_adjacent_protocol_reassemble_info(cap=cap, upper_protocol="http2", lower_protocol="tls")
    
    cap.close()

    
    counter = HTTP2ByteCounter()
    cnt = 0

    cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter, 
                                custom_parameters=["-C", "Customized", "-2"],
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    for pkt in cap:

        if "HTTP2" in pkt:
            cnt += counter.packet_count(pkt)
    
    cap.close()

    # If the first and last elements of upper_abs_byte_map is correct, the whole map should be correct.
    assert  line.upper_abs_byte_map[278] == (cnt - 17, cnt) and \
            line.upper_abs_byte_map[32] == (0, 70) and \
            line.byte_counter == cnt


def test_match_segment_number_01():
    """
    This test covers matching needed fields.
    """
    msg = "2 Reassembled TLS segments (16393 bytes): #12(2345), #23(333)"

    target = [(12, 2345), (23, 333)]
    result = match_segment_number(msg)
    for i in range(len(target)):
        assert target[i] == result[i]


# def test_get_reassemble_info():
#     """
#     This test covers getting reassemble info from the given capture.
#     """
#     tcp_filter = "tcp.stream == 0"
#     keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
#     cap = pyshark.FileCapture(input_file=apple_file, display_filter=tcp_filter,
#                                 custom_parameters=["-C", "Customized", "-2"],
#                                 override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
#     reassemble_info = get_reassemble_info(cap)
#     cap.close()