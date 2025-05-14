from pathlib import Path

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
    
def default_override_prefs(protocol: str, keylog_file: str, proxy_keylog_file: str, password: str) -> dict:
    DEFAULT_OVERRIDE_PREFS = {
                                'tcp.desegment_tcp_streams': 'TRUE',
                                'tcp.reassemble_out_of_order': 'TRUE',
                                'tcp.fastrt_supersedes_ooo': 'TRUE',
                                'tcp.no_subdissector_on_error': 'TRUE',
                                'tcp.analyze_sequence_numbers': 'TRUE'
    }
    if protocol == 'normal':
        DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = keylog_file
    elif protocol == 'vmess':
        DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = keylog_file
        DEFAULT_OVERRIDE_PREFS['vmess.keylog_file'] = proxy_keylog_file
    elif protocol == 'shadowsocks':
        DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = keylog_file
        DEFAULT_OVERRIDE_PREFS['shadowsocks.password'] = password
    return DEFAULT_OVERRIDE_PREFS
