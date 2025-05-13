"""
This test file is used to test Shadowsocks-related features. We make isolation from the normal tests
for better clarity.
"""
from pathlib import Path
import pyshark
import os
import pytest
import pandas as pd

from WFlib.utils.config import get_config
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