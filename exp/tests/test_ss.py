"""
This test file is used to test Shadowsocks-related features. We make isolation from the normal tests
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
    SS_ENABLED = False
else:
    config = get_config(config_path)
    if 'ss' not in config:
        SS_ENABLED = False
    else:
        SS_ENABLED = config['ss'].getboolean('enabled', fallback=False)


skip_ss = pytest.mark.skipif(
    not SS_ENABLED,
    reason="Shadowsocks dissector not available, skip the test."
)

custom_parameters = ["-C", "Customized", "-2"]


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
    pcap_dir = f"exp/test_dataset/realworld_dataset/ss_capture/{host}"
    if index is None:
        pcap_file =  os.path.join(pcap_dir, f"{host}.pcapng")
    else:
        pcap_file =  os.path.join(pcap_dir, f"{host}_{index}.pcapng")

    keylog_file = os.path.join(pcap_dir, "keylog.txt")

    override_prefs = default_override_prefs('ss', os.path.abspath(keylog_file), None, '52564afb-8a21-4dae-be8d-991bdf3a13d8')
    
    cap = pyshark.FileCapture(
        input_file=pcap_file, 
        custom_parameters=custom_parameters,
        display_filter=display_filter, 
        override_prefs=override_prefs
        )
    
    yield cap

    cap.close()

@pytest.mark.parametrize("capture_gen", [{'host': 'ai.zjnav.com', 'display_filter': 'tcp.stream eq 2 and shadowsocks', 'index': 1}], indirect=True)
@skip_ss
def test_ss_bytes_count(capture_gen):
    counter = SSByteCounter()

    byte_count, pkt_count = 0, 0
    for pkt in capture_gen:
        byte_count += counter.packet_count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10920, 14

    assert byte_target == byte_count and packet_target == pkt_count