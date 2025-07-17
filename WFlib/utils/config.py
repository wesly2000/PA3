from pathlib import Path
from typing import Optional
from configparser import ConfigParser
import WFlib

SUPPORTED_BASE = ['tcp', 'tls']
SUPPORTED_PROTOCOL = ['normal', 'vmess', 'shadowsocks']

DEFAULT_CONFIG_PATH = Path(WFlib.__file__).parent / 'custom_config.ini'

def get_config(custom_config_path: Path):
    if custom_config_path.exists():
        config_path = custom_config_path
    elif DEFAULT_CONFIG_PATH.exists():
        config_path = DEFAULT_CONFIG_PATH
    else:
        return None
    
    config = ConfigParser()
    config.read(config_path)
    return config

def get_tshark_path(config_path: Path, protocol: str = 'normal'):
    if not config_path.exists():
        tshark_path = "tshark"
    else:
        config = get_config(config_path)
        if not config:
            tshark_path = "tshark"
        else:
            tshark_path = config[protocol].get('tshark_path', fallback="tshark")
    return tshark_path


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
        elif protocol == 'trojan':
            if keylog_file is None:  # No need to decrypt the inner TLS traffic
                DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = proxy_keylog_file
            else: # Decrypt both the inner and outer TLS traffic
                # First check if merge_keylog.txt exists in the same directory as keylog_file
                merge_keylog_file = keylog_file.replace('keylog.txt', 'merge_keylog.txt')
                if not Path(merge_keylog_file).exists():
                    # If not, merge keylog_file and proxy_keylog_file into a single file named merge_keylog.txt
                    with open(merge_keylog_file, 'w') as f:
                        with open(keylog_file, 'r') as f1:
                            f.write(f1.read())
                        # Add a newline to separate the two keylogs
                        f.write('\n')
                        with open(proxy_keylog_file, 'r') as f2:
                            f.write(f2.read())

                DEFAULT_OVERRIDE_PREFS['tls.keylog_file'] = merge_keylog_file

    return DEFAULT_OVERRIDE_PREFS
