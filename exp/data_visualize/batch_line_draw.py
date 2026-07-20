import exp.data_visualize.line_draw as line_draw
import json
import logging
import os

pa3_repo_root = os.environ["PA3_REPO_ROOT"]
input_root = os.path.join(pa3_repo_root, "Dataset")
output_root = os.path.join(pa3_repo_root, "VisualSeg")
base = 'tcp'

logger = logging.getLogger(__name__)

with open("exp/data_visualize/host_common_sni.json", 'r') as f:
    host_common_sni = json.load(f)

for host in host_common_sni:
    for sni in host_common_sni[host]:
        logger.info(f"Processing host {host} sni {sni}")
        try:
            line_draw.draw_byte_segment(input_root, host, sni, base, output_root)
        except Exception as e:
            logger.error(f"Error in processing {host} sni {sni}: {e}")
            continue