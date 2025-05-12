from pathlib import Path

from configparser import ConfigParser

SUPPORTED_BASE = ['tcp', 'tls']
SUPPORTED_PROTOCOL = ['normal', 'vmess']

def get_config(config_path: Path):
    if config_path.exists():
        config = ConfigParser()
        config.read(config_path)
        return config
    else:
        return None