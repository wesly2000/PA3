"""
This test file is used to test VMess-related features. We make isolation from the normal tests
for better clarity.
"""

from WFlib.tools.analyzer import *
from pathlib import Path
import pyshark
import os
import pytest
from WFlib.utils.config import get_config

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

custom_parameters = ["-C", "Customized", "-2"]

@pytest.fixture
def capture_gen(request):
    host = request.param['host']
    if 'display_filter' in request.param:
        display_filter = request.param['display_filter']
    else:
        display_filter = None
    pcap_dir = f"exp/test_dataset/realworld_dataset/vmess/{host}"
    pcap_file =  os.path.join(pcap_dir, f"{host}.pcapng")
    proxy_keylog_file = os.path.join(pcap_dir, "proxy_keylog.txt")
    keylog_file = os.path.join(pcap_dir, "keylog.txt")

    override_prefs = {'tls.keylog_file': os.path.abspath(keylog_file),
                      'vmess.keylog_file': os.path.abspath(proxy_keylog_file)}
    
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
def test_layer_extractor_01(capture_gen):
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
                    DATA_LAYER_MARKER['tls'] in layers[0].field_names  # Assert we are extracting the correct DATA layer.
            layers = layer_extractor(pkt, upper_protocol="tls", lower_protocol='vmess')
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    DATA_LAYER_MARKER['vmess'] in layers[0].field_names and \
                    layers[1].layer_name == "tls" and \
                    layers[2].layer_name == "tls"
        elif pkt.number == "15":
            layers = layer_extractor(pkt, upper_protocol="vmess", lower_protocol='tcp') 
            assert len(layers) == 3 and \
                    layers[0].layer_name == "DATA" and \
                    layers[1].layer_name == "vmess" and \
                    layers[2].layer_name == "vmess" and \
                    DATA_LAYER_MARKER['tcp'] in layers[0].field_names  # Assert we are extracting the correct DATA layer.
        elif pkt.number == "63":
            layers = layer_extractor(pkt, upper_protocol="http2", lower_protocol='tls') 
            assert len(layers) == 2 and \
                    layers[0].layer_name == "http2" and \
                    layers[1].layer_name == "http2"

@pytest.mark.parametrize("capture_gen", [{'host': 's.weibo.com'}], indirect=True)
@skip_vmess
def test_line_rel_building_01(capture_gen):
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
    
@pytest.mark.parametrize("capture_gen", [{'host': 'top.baidu.com'}], indirect=True)
@skip_vmess
def test_line_rel_building_02(capture_gen):
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