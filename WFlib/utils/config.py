from pathlib import Path
from typing import Optional
from configparser import ConfigParser

SUPPORTED_BASE = ['tcp', 'tls']
SUPPORTED_PROTOCOL = ['normal', 'vmess', 'shadowsocks']

def get_config(config_path: Path):
    if config_path.exists():
        config = ConfigParser()
        config.read(config_path)
        return config
    else:
        return None


def default_override_prefs(protocol: str = 'normal', keylog_file: Optional[str] = None, proxy_keylog_file: Optional[str] = None) -> dict:
    DEFAULT_OVERRIDE_PREFS = {
                                'tcp.desegment_tcp_streams': 'TRUE',
                                'tcp.reassemble_out_of_order': 'TRUE',
                                'tcp.fastrt_supersedes_ooo': 'TRUE',
                                'tcp.no_subdissector_on_error': 'TRUE',
                                'tcp.analyze_sequence_numbers': 'TRUE'
    }
    if keylog_file is not None:
        DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = keylog_file

    if proxy_keylog_file is not None:
        if protocol == 'vmess':
            DEFAULT_OVERRIDE_PREFS['vmess.keylog_file'] = proxy_keylog_file
        elif protocol == 'shadowsocks':
            with open(proxy_keylog_file, 'r') as f:
                password = f.read().strip()
            DEFAULT_OVERRIDE_PREFS['shadowsocks.password'] = password
    return DEFAULT_OVERRIDE_PREFS
