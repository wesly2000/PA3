"""
This test file is used to test Shadowsocks-related features. We make isolation from the normal tests
for better clarity.
"""
from pathlib import Path
import pyshark
import os
import pytest
import pandas as pd

from pa3.utils.config import get_config, default_override_prefs, get_tshark_path
from pa3.tools.analyzer import *
from pa3.tools.visualize import *
from exp.data_analysis.http2_stream_analysis import *
from pa3.tools.extractor import pcap_to_dataframe

import nest_asyncio 
nest_asyncio.apply()

config_path = Path.cwd() / 'config.ini'
if not config_path.exists():
    SS_ENABLED = False
else:
    config = get_config(config_path)
    if 'shadowsocks' not in config:
        SS_ENABLED = False
    else:
        SS_ENABLED = config['shadowsocks'].getboolean('enabled', fallback=False)

tshark_path = get_tshark_path(config_path, 'shadowsocks')


skip_shadowsocks = pytest.mark.skipif(
    not SS_ENABLED,
    reason="Shadowsocks dissector not available, skip the test."
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
    pcap_dir = f"exp/test_dataset/realworld_dataset/shadowsocks_capture/{host}"
    if index is None:
        pcap_file =  os.path.join(pcap_dir, f"{host}.pcapng")
    else:
        pcap_file =  os.path.join(pcap_dir, f"{host}_{index}.pcapng")

    keylog_file = os.path.join(pcap_dir, "keylog.txt")
    proxy_keylog_file = os.path.join(pcap_dir, "proxy_keylog.txt")

    override_prefs = default_override_prefs('shadowsocks', os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))
    
    cap = pyshark.FileCapture(
        input_file=pcap_file, 
        custom_parameters=custom_parameters,
        display_filter=display_filter, 
        override_prefs=override_prefs,
        tshark_path=tshark_path
        )
    
    yield cap

    cap.close()

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'display_filter': 'tcp.stream eq 2 and shadowsocks', 'index': 1}], indirect=True)
@skip_shadowsocks
def test_bytes_count(capture_gen):
    counter = ShadowsocksByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in capture_gen:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10920, 14

    assert byte_target == byte_count and packet_target == pkt_count

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'display_filter': 'tcp.stream eq 1 and shadowsocks', 'index': 1}], indirect=True)
@skip_shadowsocks
def test_layer_extractor_1(capture_gen):
    """
    This test covers extracting layers from the given capture for HTTP2.
    """
    for pkt in capture_gen:
        if pkt.number == "854": 
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='shadowsocks')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls" and \
                    PROTOCOL_REASSEMBLE_FIELD['shadowsocks'] in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        elif pkt.number == "500":
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls')
            assert len(layers) == 5 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "http2" and \
                    layers[2].layer_name == "http2" and \
                    layers[3].layer_name == "http2" and \
                    layers[4].layer_name == "http2" and \
                    PROTOCOL_REASSEMBLE_FIELD['tls'] in layers[0].field_names

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'display_filter': 'tcp.stream eq 1', 'index': 1}], indirect=True)
@skip_shadowsocks
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
    
@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 1, 'display_filter': 'tcp.stream eq 1'}], indirect=True)
@skip_shadowsocks
def test_line_rel_building_2(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test TLS over Shadowsocks line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="tls", lower_protocol="shadowsocks")
    
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
    
@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 1, 'display_filter': 'tcp.stream eq 4'}], indirect=True)
@skip_shadowsocks
def test_line_rel_building_3(capture_gen):
    """
    This test covers building the lower relation of a line using MORE COMPLEX real-world data, and
    test Shadowsocks over TCP line building.

    NOTE: This test fails when "tcp.stream eq 1" is used, where Frame 977 and Frame 981 are spanned from Frame 975,
    in the following OOO form:
    --------- Frame 977 ---+----           ----+----- Frame 981 ----------
                           |---- Frame 975 ----|
    causing wrong dissection which leads to wrong segmentation in Line building.
    """
    
    line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="shadowsocks", lower_protocol="tcp")
    
    counter = ShadowsocksByteCounter()
    cnt = 0

    for pkt in capture_gen:
        if "Shadowsocks" in pkt:
            cnt += counter.packet_count(pkt)

    byte_counter = 0
    for covers in line.upper_abs_byte_map.values():
        for cover in covers:
            byte_counter += cover[1] - cover[0]

    assert line.byte_counter == byte_counter and \
           cnt == line.byte_counter
    
@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 1, 'display_filter': 'tcp.stream eq 4'}], indirect=True)
@skip_shadowsocks
def test_line_merge_1(capture_gen):
    """
    This test covers Shadowsocks data based line merging, which contains multiple streams.
    """    
    upper_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="http2", lower_protocol="tls")
    proxy_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="tls", lower_protocol="shadowsocks")
    lower_line = get_adjacent_protocol_reassemble_info(cap=capture_gen, upper_protocol="shadowsocks", lower_protocol="tcp")

    merged_line = line_merge(line_merge(upper_line, proxy_line), lower_line)

    # Assert the total bytes in HTTP/2 layer is not changed by merging.
    http2_byte_counter = 0
    for span in upper_line.lower_span_map.values():
        for segment_size in span.values():
            http2_byte_counter += segment_size

    assert merged_line.byte_counter == http2_byte_counter
    # Check the continuity of the merged line.
    assert merged_line.continunity_check()

@skip_shadowsocks
def test_pcap_to_dataframe_1():
    """
    This test covers converting a pcap file to a dataframe.
    """
    proxy_keylog_file = "exp/test_dataset/realworld_dataset/shadowsocks_capture/ai.zjnav.com/proxy_keylog.txt"
    keylog_file = "exp/test_dataset/realworld_dataset/shadowsocks_capture/ai.zjnav.com/keylog.txt"
    pcap_file = "exp/test_dataset/realworld_dataset/shadowsocks_capture/ai.zjnav.com/ai.zjnav.com_1.pcapng"

    override_prefs = default_override_prefs('shadowsocks', os.path.abspath(keylog_file), os.path.abspath(proxy_keylog_file))
    df = pcap_to_dataframe(tshark_path, pcap_file, display_filter="tcp.stream eq 4", override_prefs=override_prefs)
    assert df.shape[0] == 117 and \
            df.shape[1] == 9 and \
            df.iloc[6]['tls.handshake.extensions_server_name'] == 't3.gstatic.cn'


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 1, 'display_filter': 'tcp.stream eq 4'}], indirect=True)
@skip_shadowsocks
def test_SHSearcher_1(capture_gen):
    searcher = ShadowsocksSHSearcher()
    target = 21
    expect = searcher.search(capture_gen)

    assert expect == target