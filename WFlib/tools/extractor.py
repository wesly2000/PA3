from typing import Union, List
import numpy as np
import pandas as pd
import subprocess
import logging
import io

logger = logging.getLogger(__name__)

'''
COMMENT: Shall we name a class capitalizing all letters of an abbrev., e.g., extension name of a file?
         Currently, only the first letter is capitalized, please follow the convention.
'''

FIELDS = ["tcp.stream", "ip.src", "ip.dst", "frame.time_relative", "tcp.len", "tcp.hdr_len", "tls.handshake.extensions_server_name"]

def pcap_to_dataframe(pcap_file: str, display_filter: str='tcp', fields: List[str]=FIELDS):
    """
    Read in a .pcap file, and output the selected fields into a DataFrame without creating a .csv file.
    """
    fields_args = [f'-e {field}' for field in fields]
    cmd = ['tshark', '-r', pcap_file, '-Y', display_filter] + ['-T', 'fields'] + fields_args + ['-E', "separator=,", '-E', "header=y"]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    if result.stderr:
        logger.warning(f"tshark warnings: {result.stderr}")
    csv_data = result.stdout

    if not csv_data.strip():
        raise ValueError("No data returned by tshark")
    # NOTE: It seems that when using subprocess, the column names contain strange leading whitespace.
    #       We need to strip them. Still don't know why this happens.
    df = pd.read_csv(io.StringIO(csv_data), dtype=str)
    df.columns = [col.strip() for col in df.columns]
    return df


class Extractor(object):
    """
    The class provides methods for the actual feature extraction work. This is some abstract class, and the
    extractors used MUST inherit it.
    """
    def __init__(self, name):
        self._name = name
        # self._buf = []

    # @property
    # def buf(self):
    #     return self._buf

    @property
    def name(self):
        return self._name

    def extract(self):
        raise NotImplementedError


class PcapExtractor(Extractor):
    """
    Extractors that directly extract features from .pcap files through PyShark packet iteration.
    """


class CsvExtractor(Extractor):
    """
    Extractors that extract features from .csv files (DataFrame actually) using frameworks like Pandas. Note that the .csv is generated
    directly from TShark, so the column name MUST be consistent with the corresponding field name of TShark.

    For example, the source IP address in TShark is exported with name ip.src, so the input .csv with IP source
    address MUST maintain a column named ip.src.
    """


class CsvDirExtractor(CsvExtractor):
    """
    The class that extracts direction feature from .csv files.
    """
    def __init__(self, src: Union[str, List[str]], name="direction"):
        super().__init__(name=name)
        self._src = src if isinstance(src, list) else [src]

    def extract(self, df: pd.DataFrame):
        return np.where(df['ip.src'].isin(self._src), 1, -1)
    

class CsvTsExtractor(CsvExtractor):
    """
    The class that extracts timestamp feature from .csv files.
    """
    def __init__(self, name="timestamp"):
        super().__init__(name=name)

    def extract(self, df: pd.DataFrame):
        return df['frame.relative_time'].to_numpy()
    

class CsvLenExtractor(CsvExtractor):
    """
    The class that extracts length feature of a specific protocol from .csv files.
    Currently, only TCP is supported.
    """
    def __init__(self, name="length"):
        super().__init__(name=name)

    def extract(self, df: pd.DataFrame, protocol: str="tcp"):
        if protocol == "tcp":
            return df['tcp.len'].to_numpy() + df['tcp.hdr_len'].to_numpy()
        else:
            raise NotImplementedError(f"Protocol {protocol} is not supported.")


class PcapDirExtractor(PcapExtractor):
    """
    The class provides methods for the packet direction extraction.

    Attributes
    ----------
    src : List[str]
        The source IP addresses for the extractor to decide ingress or egress.
    """
    def __init__(self, src: Union[str, List[str]], name="direction"):
        super().__init__(name=name)
        self._src = src if isinstance(src, list) else [src]

    def extract(self, pkt, target : list, only_summaries=True):
        """
        Extract the direction info and store them into target.

        Params
        ------
        pkt : packet
            The packet to extract the feature.

        target : list
            The variable to store features.
        """
        if only_summaries:
            # When only_summaries == True, pkt.source should be used.
            src = pkt.source
        else:
            if 'ip' not in pkt:
                pass  # Add some warning here
            src = pkt['ip'].src

        target.append(1 if src in self._src else -1) # 1 for egress, -1 for ingress


class PcapTsExtractor(PcapExtractor):
    """
    The timestamp extractor. Note that the time is relative time, i.e., the time after
    the first packet which is set to 0.

    Also, when extracting timestamp, one could also pack direction information with ts,
    e.g., an ingress packet (-1 direction) at time 0.114514s would lead to the timestamp
    -0.114514.
    """
    def __init__(self, name="timestamp", src=None):
        super().__init__(name=name)
        if src:
            self._src = src if isinstance(src, list) else [src]
        else:
            self._src = None

    def extract(self, pkt, target : list, only_summaries=True):
        """
        Extract the timestamp info and store them into target, if self._src is not None,
        directional timestamp will be extract instead.

        Params
        ------
        pkt : packet
            The packet to extract the feature.

        target : list
            The variable to store features.
        """
        if only_summaries:
            # When only_summaries == True, pkt.time should be used.
            ts = float(pkt.time)
            if self._src:
                src = pkt.source
        else:
            if 'frame' not in pkt:
                pass # Add some warning here
            ts = float(pkt['frame'].time_relative)
            if self._src:
                if 'ip' not in pkt:
                    raise NotImplementedError("Packet no IP layer")  # Add some warning here
                src = pkt['ip'].src

        if self._src:
            target.append(ts if src in self._src else -1 * ts)
        else:
            target.append(ts)


class PcapDeltaExtractor(PcapExtractor):
    """
    The delta time extractor. Delta time denotes for the duration between 2 consecutive packets.
    TODO: Note that since we are using display filter in analysis, one should use frame.time_delta_displayed
    instead of frame.time_delta (which is the delta when only_summaries=True in PyShark).
    """
    def __init__(self, name="delta"):
        super().__init__(name=name)
