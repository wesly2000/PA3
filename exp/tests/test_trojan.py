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


@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'index': 0}], indirect=True)
@skip_trojan
def test_bytes_count(capture_gen):
    counter = TrojanByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in capture_gen:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10920, 14

    assert byte_target == byte_count and packet_target == pkt_count