"""
This test file is used to test Shadowsocks-related features. We make isolation from the normal tests
for better clarity.
"""
from pathlib import Path
import pyshark
import os
import pytest
import pandas as pd

from WFlib.utils.config import get_config, default_override_prefs, get_tshark_path
from WFlib.tools.analyzer import *
from WFlib.tools.visualize import *
from exp.data_analysis.http2_stream_analysis import *
from WFlib.tools.extractor import pcap_to_dataframe

import nest_asyncio 
nest_asyncio.apply()

config_path = Path.cwd() / 'config.ini'
if not config_path.exists():
    TROJAN_ENABLED = False
else:
    config = get_config(config_path)
    if 'trojan' not in config:
        TROJAN_ENABLED = False
    else:
        TROJAN_ENABLED = config['trojan'].getboolean('enabled', fallback=False)

tshark_path = get_tshark_path(config_path, 'trojan')


skip_trojan = pytest.mark.skipif(
    not TROJAN_ENABLED,
    reason="Trojan dissector not available, skip the test."
)

custom_parameters = ["-2"]


@pytest.fixture
def capture_gen(request):
    if 'index' in request.param:
        index = request.param['index']
    else:
        index = None

    host = request.param['host']

    if 'display_filter' in request.param:
        display_filter = request.param['display_filter']
    else:
        display_filter = None
    pcap_dir = f"exp/test_dataset/realworld_dataset/trojan_capture/{host}"
    if index is None:
        pcap_file =  os.path.join(pcap_dir, f"{host}.pcapng")
    else:
        pcap_file =  os.path.join(pcap_dir, f"{host}_{index}.pcapng")

    keylog_file = os.path.join(pcap_dir, "keylog.txt")
    proxy_keylog_file = os.path.join(pcap_dir, "proxy_keylog.txt")

    override_prefs = default_override_prefs('trojan', os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))
    
    cap = pyshark.FileCapture(
        input_file=pcap_file, 
        custom_parameters=custom_parameters,
        display_filter=display_filter, 
        override_prefs=override_prefs,
        tshark_path=tshark_path
        )
    
    yield cap

    cap.close()


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0, 'display_filter': 'trojan'}], indirect=True)
@skip_trojan
def test_bytes_count_1(capture_gen):
    counter = TrojanByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in capture_gen:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 555766, 73

    assert byte_target == byte_count and packet_target == pkt_count


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_layer_extractor_1(capture_gen):
    """
    This test covers extracting layers from the given capture from HTTP2 to TCP.
    """
    for pkt in capture_gen:
        if pkt.number == "361": 
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "http2" and \
                    layers[1].layer_name == "http2" and \
                    layers[2].layer_name == "DATA" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[2].field_names  
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='trojan')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls" and \
                    PROTOCOL_REASSEMBLE_FIELD['trojan'] in layers[0].field_names 
            layers = layer_extractor(pkt, upper_protocol="trojan", lower_protocol='tcp')
            assert len(layers) == 2 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "trojan" and \
                    PROTOCOL_REASSEMBLE_FIELD['tcp'] in layers[0].field_names 
        if pkt.number == "128": 
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 6 and \
                    layers[0].layer_name == "http2" and \
                    layers[1].layer_name == "http2" and \
                    layers[2].layer_name == "DATA" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[2].field_names  
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='trojan')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls" and \
                    layers[3].layer_name == "DATA" and \
                    layers[4].layer_name == "tls" and \
                    PROTOCOL_REASSEMBLE_FIELD['trojan'] in layers[0].field_names  and \
                    PROTOCOL_REASSEMBLE_FIELD['trojan'] in layers[3].field_names 
            layers = layer_extractor(pkt, upper_protocol="trojan", lower_protocol='tcp')
            assert len(layers) == 2 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "trojan" and \
                    PROTOCOL_REASSEMBLE_FIELD['tcp'] in layers[0].field_names 
        if pkt.number == "707": 
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "http2" and \
                    layers[2].layer_name == "http2" and \
                    layers[3].layer_name == "DATA" and \
                    layers[4].layer_name == "http2" and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[0].field_names and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[3].field_names


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_seq_filter_1(capture_gen):
    """
    This test covers seq_filter with more complex labeling functions.
    """
    for pkt in capture_gen:
        if pkt.number == "361":  # This packet contains a DATA layer and multiple HTTP2 layers.
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            result = seq_filter(layers, lower_protocol='tls')
            layer_names = [layer.layer_name for layer in result]
            expect_num_DATA_layer = 1
            expect_num_HTTP2_layer = 3 
            assert layer_names.count("DATA") == expect_num_DATA_layer and \
                   layer_names.count("http2") == expect_num_HTTP2_layer
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='trojan')
            result = seq_filter(layers, lower_protocol='trojan')
            layer_names = [layer.layer_name for layer in result]
            expect_num_DATA_layer = 1
            expect_num_TLS_layer = 1 
            assert layer_names.count("DATA") == expect_num_DATA_layer and \
                   layer_names.count("tls") == expect_num_TLS_layer
            layers = layer_extractor(pkt, upper_protocol="trojan", lower_protocol='tcp')
            result = seq_filter(layers, lower_protocol='tcp')
            layer_names = [layer.layer_name for layer in result]
            expect_num_DATA_layer = 1
            expect_num_TROJAN_layer = 0 
            assert layer_names.count("DATA") == expect_num_DATA_layer and \
                   layer_names.count("trojan") == expect_num_TROJAN_layer


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_line_rel_building_1(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    
    counter = HTTP2ByteCounter()
    cnt = 0

    for pkt in capture_gen:
        if "HTTP2" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_line_rel_building_2(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test TLS over Trojan line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="tls", lower_protocol="trojan")
    
    counter = TLSByteCounter()
    cnt = 0

    for pkt in capture_gen:
        layer_rename(pkt)
        if "TLS" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_line_rel_building_4(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test Trojan over TCP line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="trojan", lower_protocol="tcp")
    
    counter = TrojanByteCounter()
    cnt = 0

    for pkt in capture_gen:
        layer_rename(pkt)
        if "Trojan" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_line_span_building_1(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    lower_span_bytes = 0
    for span in line.lower_span_map.values():
        for segment_size in span.values():
            lower_span_bytes += segment_size

    assert line.byte_counter == lower_span_bytes