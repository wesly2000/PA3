"""
This file covers tests for WFlib/tools/analyzer.py
"""
from WFlib.tools.analyzer import *
from pathlib import Path
import pyshark
import os
import pytest

import nest_asyncio 
nest_asyncio.apply()

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"
tiktok_file = "exp/test_dataset/realworld_dataset/decryption/www.tiktok.com.pcapng"

@pytest.fixture
def baidu_proxied_cap(request):
    if 'display_filter' in request.param:
        display_filter = request.param['display_filter']
    else:
        display_filter = None
    
    cap = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter=display_filter, only_summaries=True, keep_packets=False)
    yield cap

    cap.close()

@pytest.fixture
def apple_cap(request):
    if 'display_filter' in request.param:
        display_filter = request.param['display_filter']
    else:
        display_filter = None
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"

    cap = pyshark.FileCapture(input_file=apple_file, display_filter=display_filter,
                            custom_parameters=["-C", "Customized", "-2"],
                            override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    yield cap

    cap.close()

@pytest.fixture
def tiktok_cap(request):
    if 'display_filter' in request.param:
        display_filter = request.param['display_filter']
    else:
        display_filter = None
    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"

    cap = pyshark.FileCapture(  input_file=tiktok_file, display_filter=display_filter,
                                override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    yield cap

    cap.close()

@pytest.fixture
def lines() -> Tuple[Line, Line]:
    """
    This fixture provides two lines with adjacent protocol stack.
    """
    upper_packet_0 = Packet()
    upper_packet_0.upper_protocol, upper_packet_0.lower_protocol = "http2", "tls"
    upper_packet_0.abs_frame_number = 1
    upper_packet_0.segments = {1: 200}

    upper_packet_1 = Packet()
    upper_packet_1.upper_protocol, upper_packet_1.lower_protocol = "http2", "tls"
    upper_packet_1.abs_frame_number = 2
    upper_packet_1.segments = {1: 100, 2: 100}

    upper_packet_2 = Packet()
    upper_packet_2.upper_protocol, upper_packet_2.lower_protocol = "http2", "tls"
    upper_packet_2.abs_frame_number = 3
    upper_packet_2.segments = {2: 300}

    upper_packet_3 = Packet()
    upper_packet_3.upper_protocol, upper_packet_3.lower_protocol = "http2", "tls"
    upper_packet_3.abs_frame_number = 4
    upper_packet_3.segments = {3: 250, 4: 350}

    middle_packet_0 = Packet()
    middle_packet_0.upper_protocol, middle_packet_0.lower_protocol = "tls", "tcp"
    middle_packet_0.abs_frame_number = 0
    middle_packet_0.segments = {0: 150}

    middle_packet_1 = Packet()
    middle_packet_1.upper_protocol, middle_packet_1.lower_protocol = "tls", "tcp"
    middle_packet_1.abs_frame_number = 1
    middle_packet_1.segments = {0: 55, 1: 200, 2: 50}

    middle_packet_2 = Packet()
    middle_packet_2.upper_protocol, middle_packet_2.lower_protocol = "tls", "tcp"
    middle_packet_2.abs_frame_number = 2
    middle_packet_2.segments = {2: 60, 3: 350}

    middle_packet_3 = Packet()
    middle_packet_3.upper_protocol, middle_packet_3.lower_protocol = "tls", "tcp"
    middle_packet_3.abs_frame_number = 3
    middle_packet_3.segments = {4: 155, 5: 100}

    middle_packet_4 = Packet()
    middle_packet_4.upper_protocol, middle_packet_4.lower_protocol = "tls", "tcp"
    middle_packet_4.abs_frame_number = 4
    middle_packet_4.segments = {5: 50, 6: 105, 7:55, 8: 150}

    upper_line = Line(
                    upper_packets=[upper_packet_0, upper_packet_1, upper_packet_2, upper_packet_3],
                    lower_abs_frame_numbers=[0, 1, 2, 3, 4]
                    )

    lower_line = Line(
                    upper_packets=[middle_packet_0, middle_packet_1, middle_packet_2, middle_packet_3, middle_packet_4],
                    lower_abs_frame_numbers=[0, 1, 2, 3, 4, 5, 6, 7]
                    )
    
    return upper_line, lower_line

@pytest.mark.parametrize("baidu_proxied_cap", [{}], indirect=True)
def test_packet_count_01(baidu_proxied_cap):
    target = 8627
    cnt = packet_count(baidu_proxied_cap)

    assert target == cnt

@pytest.mark.parametrize("baidu_proxied_cap", [{'display_filter': "tcp"}], indirect=True)
def test_packet_count_02(baidu_proxied_cap):
    target = 8564
    cnt = packet_count(baidu_proxied_cap)

    assert target == cnt

def test_file_count():
    base_dir = Path("exp/test_dataset")
    target = {"realworld_dataset": 2, "simple_dataset": 3}

    result = file_count(base_dir)

    assert len(target) == len(result)

    for k in result:
        assert result[k] == target[k]

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 2 and http2"}], indirect=True)
def test_http2_bytes_count(apple_cap):
    counter = HTTP2ByteCounter()
    
    byte_count, pkt_count = 0, 0
    for pkt in apple_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 3242, 9
    
    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 2"}], indirect=True)
def test_tcp_bytes_count(apple_cap):
    counter = TCPByteCounter()
    
    byte_count, pkt_count = 0, 0
    for pkt in apple_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 11408, 32
    
    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 2 and tls"}], indirect=True)
def test_tls_bytes_count(apple_cap):
    counter = TLSByteCounter()
    
    byte_count, pkt_count = 0, 0
    for pkt in apple_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10368, 16
    
    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("tiktok_cap", [{'display_filter': "udp.stream == 0"}], indirect=True)
def test_udp_bytes_count(tiktok_cap):
    counter = UDPByteCounter()

    byte_count, pkt_count = 0, 0

    for pkt in tiktok_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 56518, 80

    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("tiktok_cap", [{'display_filter': "udp.stream == 0"}], indirect=True)
def test_quic_bytes_count(tiktok_cap):
    counter = QUICByteCounter()

    byte_count, pkt_count = 0, 0
    
    for pkt in tiktok_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 55878, 80

    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("tiktok_cap", [{'display_filter': "udp.stream == 0 and http3"}], indirect=True)
def test_http3_bytes_count(tiktok_cap):
    counter = HTTP3ByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in tiktok_cap:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    tiktok_cap.close()
    byte_target, packet_target = 42925, 22

    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 2"}], indirect=True)
def test_capture_counter_1(apple_cap):
    """
    This test covers TCP/TLS/HTTP2 layered counter to the given capture.
    """
    counter = CaptureCounter(TCPByteCounter(), TLSByteCounter(), HTTP2ByteCounter())
    
    result = counter.count(apple_cap)

    assert  result['tcp'][0] == 32 and result['tcp'][1] == 11408 and \
            result['tls'][0] == 16 and result['tls'][1] == 10368 and \
            result['http2'][0] == 9 and result['http2'][1] == 3242
    
@pytest.mark.parametrize("tiktok_cap", [{'display_filter': "udp.stream == 0"}], indirect=True)
def test_capture_counter_2(tiktok_cap):
    """
    This test covers UDP/QUIC/HTTP3 layered counter to the given capture."
    """
    counter = CaptureCounter(UDPByteCounter(), QUICByteCounter(), HTTP3ByteCounter())

    result = counter.count(tiktok_cap)

    assert result['udp'][0] == 80 and result['udp'][1] == 56518 and \
           result['quic'][0] == 80 and result['quic'][1] == 55878 and \
           result['http3'][0] == 22 and result['http3'][1] == 42925

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True)
def test_layer_extractor_1(apple_cap):
    """
    This test covers extracting layers from the given capture for TLS.
    """
    for pkt in apple_cap:
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

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True)
def test_layer_extractor_2(apple_cap):
    """
    This test covers extracting layers from the given capture for HTTP2.
    """
    for pkt in apple_cap:
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

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True)  
def test_seq_filter_1(apple_cap):
    """
    This test covers seq_filter with more complex labeling functions.
    """
    for pkt in apple_cap:
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
            
@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_HTTP2CellExtractor_1(apple_cap):
    cell_extractor = HTTP2CellExtractor()
    for pkt in apple_cap:
        if pkt.number == "104":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            cells.sort()
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
            cells.sort()
            assert len(cells) == 2 and \
            cells[0].abs_frame_number == 212 and \
            cells[0].segment_size == [16384, 9] and \
            cells[0].abs_segment_frame_number == [211, 212] and \
            cells[0].size == 16393 and \
            cells[1].abs_frame_number == 212 and \
            cells[1].segment_size == [16384, 9] and \
            cells[1].abs_segment_frame_number == [212, 212] and \
            cells[1].size == 16393

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_TLSCellExtractor_1(apple_cap):
    cell_extractor = TLSCellExtractor()

    for pkt in apple_cap:
        if pkt.number == "211":  # This packet contains a DATA layer and multiple HTTP2 layers.
            cells = cell_extractor.extract(pkt)
            cells.sort()
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
            cells.sort()
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
            cells.sort()
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 66 and \
            cells[0].segment_size == [3838, 4236, 2824, 1412, 4096] and \
            cells[0].abs_segment_frame_number == [60, 61, 63, 65, 66] and \
            cells[0].size == 16406 

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_TCPCellExtractor_01(apple_cap):
    cell_extractor = TCPCellExtractor()

    for pkt in apple_cap:
        if pkt.number == "1":  
            cells = cell_extractor.extract(pkt)
            cells.sort()
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 1 and \
            cells[0].segment_size == [40] and \
            cells[0].abs_segment_frame_number == [1] and \
            cells[0].size == 40

        if pkt.number == "220": 
            cells = cell_extractor.extract(pkt)
            cells.sort()
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 220 and \
            cells[0].segment_size == [9916] and \
            cells[0].abs_segment_frame_number == [220] and \
            cells[0].size == 9916
            
        if pkt.number == "288": 
            cells = cell_extractor.extract(pkt)
            cells.sort()
            assert len(cells) == 1 and \
            cells[0].abs_frame_number == 288 and \
            cells[0].segment_size == [44] and \
            cells[0].abs_segment_frame_number == [288] and \
            cells[0].size == 44 

def test_cell_comparison():
    """
    This test covers the partial order comparison of cells.
    """
    cell_1 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=106)
    cell_1.abs_segment_frame_number = [104, 106]
    cell_2 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=108)
    cell_2.abs_segment_frame_number = [106, 108]

    assert cell_1 < cell_2 and cell_2 > cell_1

    cell_1 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=104)
    cell_1.abs_segment_frame_number = [101, 102, 104]
    cell_2 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=104)
    cell_2.abs_segment_frame_number = [101, 102, 104]

    assert cell_1 == cell_2 and cell_2 == cell_1

    cell_1 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=106)
    cell_1.abs_segment_frame_number = [104, 106]
    cell_2 = Cell(upper_protocol="http2", lower_protocol='tls', abs_frame_number=108)
    cell_2.abs_segment_frame_number = [104, 106]

    assert cell_1 < cell_2 and cell_2 > cell_1

def test_packet_construction_1():
    # Upper layer PDUs
    http2_cell_1 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_1.abs_segment_frame_number = [104, 106]
    http2_cell_1.segment_size = [114, 514]
    http2_cell_2 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_2.abs_segment_frame_number = [106]
    http2_cell_2.segment_size = [1919]

    packet = Packet(cells=[http2_cell_1, http2_cell_2])
    target = {104: 114, 106: 2433}

    assert packet.segments == target and \
            packet.abs_frame_number == 106

def test_line_rel_building_1():
    """
    This test covers building the lower relation of a line using artificial data.
    """
    # Upper layer PDUs
    http2_cell_1 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_1.abs_segment_frame_number = [104, 106]
    http2_cell_1.segment_size = [114, 514]
    http2_cell_2 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_2.abs_segment_frame_number = [106]
    http2_cell_2.segment_size = [1919]
    http2_cell_3 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=109)
    http2_cell_3.abs_segment_frame_number = [106, 108, 109]
    http2_cell_3.segment_size = [8, 10, 1145]

    packet_1 = Packet(cells=[http2_cell_1, http2_cell_2])
    packet_2 = Packet(cells=[http2_cell_3])

    line = Line(upper_packets=[packet_1, packet_2], lower_abs_frame_numbers=[104, 106, 108, 109])

    target_upper_abs_byte_map = {104: [(0, 114)], 106: [(114, 2547), (2547, 2555)], 108: [(2555, 2565)], 109: [(2565, 3710)]}


    assert line.upper_abs_byte_map == target_upper_abs_byte_map

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 2"}], indirect=True) 
def test_line_rel_building_2(apple_cap):
    """
    This test covers building the lower relation of a line using real-world data.
    """
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="tls", lower_protocol="tcp")

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == 10368 and \
           byte_counter == line.byte_counter

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_line_rel_building_3(apple_cap):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="http2", lower_protocol="tls")

    counter = HTTP2ByteCounter()
    cnt = 0

    for pkt in apple_cap:
        if "HTTP2" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    
@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_line_span_building_1(apple_cap):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="http2", lower_protocol="tls")

    # The number of bytes lower layer spans MUST be equal to the upper layer possesses
    # BUG: However, it is known that in VMess dissector, sometimes the upper layer marks some packet as HTTP/2
    # but there are no TLS layers within. Such issue is caused by the dissector, instead of the Line.
    # Therefore, we still consider the claim above holds.
    lower_span_bytes = 0
    for span in line.lower_span_map.values():
        for segment_size in span.values():
            lower_span_bytes += segment_size

    assert line.byte_counter == lower_span_bytes

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 1"}], indirect=True) 
def test_line_span_building_2(apple_cap):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="http2", lower_protocol="tls")
    lower_span_bytes = 0
    for span in line.lower_span_map.values():
        for segment_size in span.values():
            lower_span_bytes += segment_size

    assert line.byte_counter == lower_span_bytes
    
    
@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_line_seg_1(apple_cap):
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="http2", lower_protocol="tls")

    seg = line.seg(upper_abs_frame_number=201)

    target_seg = {201: 16402, 199: 16384}

    assert seg == target_seg

@pytest.mark.parametrize("apple_cap", [{'display_filter': "tcp.stream == 0"}], indirect=True) 
def test_line_span_1(apple_cap):
    line = get_adjacent_protocol_reassemble_info(cap=apple_cap, upper_protocol="http2", lower_protocol="tls")

    span = line.span(lower_abs_frame_number=199)

    target_span = {201: 16384, 199: 39144}

    assert span == target_span

def test_line_span_2(lines):
    line, _ = lines
    span = line.span(lower_abs_frame_number=2)
    target_span = {2: 100, 3: 300}

    assert span == target_span


def test_match_segment_number_1():
    """
    This test covers matching needed fields.
    """
    msg = "2 Reassembled TLS segments (16393 bytes): #12(2345), #23(333)"

    target = [(12, 2345), (23, 333)]
    result = match_segment_number(msg)
    for i in range(len(target)):
        assert target[i] == result[i]

@pytest.mark.parametrize("seq,expected", [
    ([], [0]),  # Empty list
    ([5], [0, 5]),  # Single element
    ([1, 2, 3, 4], [0, 1, 3, 6, 10]),  # Multiple elements
    ([0, 0, 0], [0, 0, 0, 0]),  # All zeros
    ([1000, 1000, 1000], [0, 1000, 2000, 3000]),  # Large numbers
])
def test_anchor_line(seq, expected):
    """
    Test anchor_line function with various input sequences.
    Tests include:
    - Empty list
    - Single element
    - Multiple elements
    - All zeros
    - Large numbers
    """
    result = anchor_line(seq)
    assert result == expected

@pytest.mark.parametrize("anchor_list,base,expected", [
    ([0, 1, 3, 6, 10], 2, 1),    # Basic case: between two points
    ([0, 1, 3, 6, 10], 0, 0),    # Edge case: at start
    ([0, 1, 3, 6, 10], 3, 2),    # Edge case: at anchor point
    ([0, 5, 10, 15], 7, 1),      # Larger gaps
])
def test_find_anchor_indices(anchor_list, base, expected):
    """
    Test find_anchor_indices function with various input sequences.
    Tests include:
    - Basic case (point between two anchors)
    - Edge case (point at start)
    - Edge case (point at anchor point)
    - Larger gaps between anchor points
    """
    result = find_anchor_indices(anchor_list, base)
    assert result == expected

@pytest.mark.parametrize("anchor_list,base,error_msg", [
    ([], 1, "Anchor list cannot be empty"),
    ([0, 1, 2], -1, "Base must be non-negative"),
    ([0, 1, 2], 2, "Base must be less than the last anchor point"),
])
def test_find_anchor_indices_errors(anchor_list, base, error_msg):
    """
    Test find_anchor_indices function error cases.
    Tests include:
    - Empty anchor list
    - Negative base point
    - Base point >= last anchor point
    """
    with pytest.raises(ValueError, match=error_msg):
        find_anchor_indices(anchor_list, base)


def test_line_merge_single_packet_1(lines):
    """
    This test covers merging a single packet from the upper line with the lower line.
    """
    upper_line, lower_line = lines
    # Case 1: The upper packet segment across no lower segments.
    packet = line_merge_single_packet(upper_line, lower_line, upper_packet_frame_number=3)

    assert packet.upper_protocol == 'http2' and \
           packet.lower_protocol == 'tcp' and \
           packet.abs_frame_number == 3
    assert packet.segments == {3: 300}

    # Case 2: The upper packet segment across no entire lower segments, but span_start and span_end belong
    # to different lower segments.
    packet = line_merge_single_packet(upper_line, lower_line, upper_packet_frame_number=1)

    assert packet.upper_protocol == 'http2' and \
           packet.lower_protocol == 'tcp' and \
           packet.abs_frame_number == 1
    assert packet.segments == {0: 55, 1: 145}

    packet = line_merge_single_packet(upper_line, lower_line, upper_packet_frame_number=2)

    assert packet.upper_protocol == 'http2' and \
           packet.lower_protocol == 'tcp' and \
           packet.abs_frame_number == 2
    assert packet.segments == {1: 55, 2: 105, 3: 40}

    # Case 3: The upper packet segment across multiple lower segments.
    packet = line_merge_single_packet(upper_line, lower_line, upper_packet_frame_number=4)

    assert packet.upper_protocol == 'http2' and \
           packet.lower_protocol == 'tcp' and \
           packet.abs_frame_number == 4
    assert packet.segments == {4: 155, 5: 145, 6: 105, 7: 55, 8: 140}

def test_line_merge_1(lines):
    """
    This test covers merging two manually created lines with adjacent protocol stack.
    """
    upper_line, lower_line = lines
    merged_line = line_merge(upper_line, lower_line)

    target_upper_abs_byte_map = {0: [(0, 55)], 1: [(55, 200), (200, 255)], 2: [(255, 360)], 3: [(360, 400), (400, 700)], 4: [(700, 855)], 5: [(855, 1000)], 6: [(1000, 1105)], 7: [(1105, 1160)], 8: [(1160, 1300)]}

    assert merged_line.upper_abs_byte_map == target_upper_abs_byte_map



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