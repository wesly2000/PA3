"""
This test file is used to test VMess-related features. We make isolation from the normal tests
for better clarity.
"""
from pathlib import Path
import pyshark
import os
import pytest
import pandas as pd

from WFlib.utils.config import get_config, default_override_prefs
from WFlib.tools.analyzer import *
from WFlib.tools.visualize import *
from exp.data_analysis.http2_stream_analysis import *

import nest_asyncio 
nest_asyncio.apply()

config_path = Path.cwd() / 'config.ini'
if not config_path.exists():
    VMESS_ENABLED = False
else:
    config = get_config(config_path)
    if 'vmess' not in config:
        VMESS_ENABLED = False
    else:
        VMESS_ENABLED = config['vmess'].getboolean('enabled', fallback=False)


skip_vmess = pytest.mark.skipif(
    not VMESS_ENABLED,
    reason="VMess dissector not available, skip the test."
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
    pcap_dir = f"exp/test_dataset/realworld_dataset/vmess_capture/{host}"
    if index is None:
        pcap_file =  os.path.join(pcap_dir, f"{host}.pcapng")
    else:
        pcap_file =  os.path.join(pcap_dir, f"{host}_{index}.pcapng")

    proxy_keylog_file = os.path.join(pcap_dir, "proxy_keylog.txt")
    keylog_file = os.path.join(pcap_dir, "keylog.txt")

    override_prefs = default_override_prefs('vmess', os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file), None)
    
    cap = pyshark.FileCapture(
        input_file=pcap_file, 
        custom_parameters=custom_parameters,
        display_filter=display_filter, 
        override_prefs=override_prefs
        )
    
    yield cap

    cap.close()

@pytest.mark.parametrize("capture_gen", [{'host': 's.weibo.com', 'display_filter': 'vmess'}], indirect=True)
@skip_vmess
def test_vmess_bytes_count(capture_gen):
    counter = VMessByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in capture_gen:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 102837, 31

    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("capture_gen", [{'host': 's.weibo.com'}], indirect=True)
@skip_vmess
def test_layer_extractor_1(capture_gen):
    """
    This test covers extracting layers from the given capture for HTTP2.
    """
    for pkt in capture_gen:
        if pkt.number == "108": 
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "http2" and \
                    layers[2].layer_name == "http2" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[0].field_names  # Assert we are extracting the correct DATA layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='vmess')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    PROTOCOL_REASSEMBLE_FIELD['vmess'] in layers[0].field_names and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls"
        elif pkt.number == "15":
            layers = layer_extractor(pkt, upper_protocol="vmess", lower_protocol='tcp') 
            assert len(layers) == 2 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "vmess" and \
                    PROTOCOL_REASSEMBLE_FIELD['tcp'] in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        elif pkt.number == "63":
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls') 
            assert len(layers) == 2 and \
                    layers[0].layer_name == "http2" and \
                    layers[1].layer_name == "http2"

@pytest.mark.parametrize("capture_gen", [{'host': 's.weibo.com'}], indirect=True)
@skip_vmess
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
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0}], indirect=True)
@skip_vmess
def test_line_rel_building_2(capture_gen):
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
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0, 'display_filter': 'vmess'}], indirect=True)
@skip_vmess
def test_line_rel_building_3(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test TLS over VMess line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="tls", lower_protocol="vmess")
    
    counter = TLSByteCounter()
    cnt = 0

    for pkt in capture_gen:
        if "TLS" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0, 'display_filter': 'tcp.stream eq 1 or tcp.stream eq 0'}], indirect=True)
@skip_vmess
def test_line_rel_building_4(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test VMess over TCP line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="vmess", lower_protocol="tcp")
    
    counter = VMessByteCounter()
    cnt = 0

    for pkt in capture_gen:
        if "VMess" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0}], indirect=True)
@skip_vmess
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

@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 1}], indirect=True)
@skip_vmess
def test_line_span_building_2(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    lower_span_bytes = 0
    for span in line.lower_span_map.values():
        for segment_size in span.values():
            lower_span_bytes += segment_size

    assert line.byte_counter == lower_span_bytes

@pytest.mark.parametrize("capture_gen", [{'host': 's.weibo.com'}], indirect=True)
@skip_vmess
def test_line_span_building_3(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data.
    """    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    lower_span_bytes = 0
    for span in line.lower_span_map.values():
        for segment_size in span.values():
            lower_span_bytes += segment_size

    assert line.byte_counter == lower_span_bytes
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0}], indirect=True)
@skip_vmess
def test_generate_byte_segment_1(capture_gen):
    """
    This test covers generating byte segment map using real-world data
    """
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    result = generate_byte_segment([line])

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

    assert result[0][-1] == 28 and \
            result[0][-18] == 27
    
@skip_vmess
def test_h2_stream_analysis_per_host_1():
    """
    This test covers H2 stream statistics for s.weibo.com with a single stream
    """
    root = 'exp/test_dataset/realworld_dataset'
    host = 's.weibo.com'
    host_filter = {'firefox.settings.services.mozilla.com'}
    df = h2_stream_analysis_per_host(root=root, protocol='vmess', host=host, host_filter=host_filter)

    assert df.loc[0, 'h2_avg'] == 1 and \
            df.loc[0, 'avail_h2_avg'] == 1 and \
            df.loc[0, 'protocol'] == 'vmess'
    
@skip_vmess
def test_h2_stream_analysis_per_host_2():
    """
    This test covers H2 stream statistics for top.baidu.com with a multiple streams
    """
    root = 'exp/test_dataset/realworld_dataset'
    host = 'top.baidu.com'
    host_filter = {'firefox.settings.services.mozilla.com'}
    df = h2_stream_analysis_per_host(root=root, protocol='vmess', host=host, host_filter=host_filter)

    assert df.loc[0, 'h2_avg'] == 1.5 and \
            df.loc[0, 'avail_h2_avg'] == 1.5 and \
            df.loc[0, 'protocol'] == 'vmess'

 
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0, 'display_filter': 'tcp.stream eq 1 or tcp.stream eq 0'}], indirect=True)
@skip_vmess
def test_line_merge_1(capture_gen):
    """
    This test covers VMess data based line merging, which contains multiple streams.
    """    
    upper_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    proxy_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="tls", lower_protocol="vmess")
    lower_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="vmess", lower_protocol="tcp")

    merged_line = line_merge(line_merge(upper_line, proxy_line), lower_line)

    # Assert the total bytes in HTTP/2 layer is not changed by merging.
    http2_byte_counter = 0
    for span in upper_line.lower_span_map.values():
        for segment_size in span.values():
            http2_byte_counter += segment_size

    assert merged_line.byte_counter == http2_byte_counter
    # Check the continuity of the merged line.
    assert merged_line.continunity_check()

@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com', 'index': 0, 'display_filter': 'tcp.stream eq 1 or tcp.stream eq 0'}], indirect=True)
@skip_vmess
def test_get_reassemble_info(capture_gen):
    """
    This test covers VMess data based line merging, which contains multiple streams.
    """    
    upper_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    line = get_reassemble_info(capture_gen, protocol_stack=['http2', 'tls', 'vmess', 'tcp'])

    # Assert the total bytes in HTTP/2 layer is not changed by merging.
    http2_byte_counter = 0
    for span in upper_line.lower_span_map.values():
        for segment_size in span.values():
            http2_byte_counter += segment_size

    assert line.byte_counter == http2_byte_counter
    # Check the continuity of the merged line.
    assert line.continunity_check()