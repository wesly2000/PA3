from typing import Union, List, Set
import numpy as np
import pandas as pd
import subprocess
import logging
import io
from pathlib import Path

logger = logging.getLogger(__name__)

'''
COMMENT: Shall we name a class capitalizing all letters of an abbrev., e.g., extension name of a file?
         Currently, only the first letter is capitalized, please follow the convention.
'''

FIELDS = ["tcp.stream", "udp.stream","ip.src", "ip.dst", "frame.time_relative", "tcp.len", "tcp.hdr_len", "udp.length", "tls.handshake.extensions_server_name"]

def pcap_to_dataframe(tshark_path: str, 
                      pcap_file: Union[str, Path], 
                      display_filter: str='tcp', 
                      override_prefs: dict=None,
                      fields: List[str]=FIELDS):
    """
    Read in a .pcap file, and output the selected fields into a DataFrame without creating a .csv file.
    """
    prefs = ['-2']
    if override_prefs:
        for key, value in override_prefs.items():
            prefs.append(f'-o')
            prefs.append(f'{key}:{value}')

    fields_args = [f'-e {field}' for field in fields]
    if display_filter:
        display_filter = ['-Y',  f"{display_filter}"]
    else:
        display_filter = []

    cmd = [tshark_path, '-r', pcap_file] + display_filter + ['-T', 'fields'] + fields_args + ['-E', "separator=,", '-E', "header=y"] + prefs

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"tshark command failed: {e}")
        raise e

    if result.stderr:
        logger.warning(f"tshark warnings in {pcap_file}: {result.stderr}")
    csv_data = result.stdout

    if not csv_data.strip():
        raise ValueError("No data returned by tshark")
    # NOTE: It seems that when using subprocess, the column names contain strange leading whitespace.
    #       We need to strip them. Still don't know why this happens.
    df = pd.read_csv(io.StringIO(csv_data), dtype=str)
    df.columns = [col.strip() for col in df.columns]
    return df


def single_pcap_extract(
        tshark_path: str, 
        pcap_file: Union[str, Path], 
        SNI_filter: Set[str]=None, 
        display_filter: str=None,
        protocol: str='normal',
        override_prefs: dict=None,
        src: List[str]=None) -> List[dict]:
    """
    Extract features from a single .pcap file.

    Params
    ------
    tshark_path : str
        The path to the tshark executable.
    pcap_file : Union[str, Path]
        The path to the .pcap file.
    SNI_filter : Union[Set[str], List[str]]
        The set of SNIs to exclude.
    display_filter : str
        The display filter to use.
    protocol : str
        The protocol of the pcap, if no proxy is used, it should be 'normal', otherwise, it is the name of the proxy protocol.
    override_prefs : dict
        The override preferences for tshark, which is mainly used for TCP reassembly and proxy traffic decryption.
    src : List[str]
        The source IP addresses to extract the direction feature.

    Returns
    -------
    result : List[dict]
        The list of dictionaries containing the extracted features.
    """
    # Split the pcap file name into host and id.
    if isinstance(pcap_file, str):
        pcap_file = Path(pcap_file)

    host, id = pcap_file.stem.split('_')

    # According to the answer, using a list of dictionaries to store the results, then convert it to a DataFrame
    # is much more efficient than appending rows to a existing DataFrame, so we use a list of dictionaries to store the results.
    # Ref: https://stackoverflow.com/a/47979665/20039811
    result = []
    df = pcap_to_dataframe(tshark_path, pcap_file, display_filter=display_filter, override_prefs=override_prefs)
    dir_extractor = CsvDirExtractor(src=src)
    ts_extractor = CsvTsExtractor()
    len_extractor = CsvLenExtractor()

    # Partition DataFrame into TCP and UDP groups
    tcp_groups = df[df["tcp.stream"].notna()].groupby("tcp.stream")
    udp_groups = df[df["udp.stream"].notna()].groupby("udp.stream")

    for stream, tcp_group in tcp_groups:
        sni_rows = tcp_group[tcp_group["tls.handshake.extensions_server_name"].notna() & ~tcp_group["tls.handshake.extensions_server_name"].isin(SNI_filter or [])]
        if sni_rows.empty:
            continue
        sni = sni_rows["tls.handshake.extensions_server_name"].iloc[0]  # Get the first (and should be only) SNI

        result.append({
            'host': host,
            'id': id,
            'sni': sni,
            'stream': stream,
            'transport': 'tcp',
            'protocol': protocol,
            'direction': dir_extractor.extract(tcp_group),
            'timestamp': ts_extractor.extract(tcp_group),
            'length': len_extractor.extract(tcp_group, protocol='tcp')
        })

    for stream, udp_group in udp_groups:
        sni_rows = udp_group[udp_group["tls.handshake.extensions_server_name"].notna() & ~udp_group["tls.handshake.extensions_server_name"].isin(SNI_filter or [])]
        if sni_rows.empty:
            continue
        sni = sni_rows["tls.handshake.extensions_server_name"].iloc[0]  # Get the first (and should be only) SNI
        
        result.append({
            'host': host,
            'id': id,
            'sni': sni,
            'stream': stream,
            'transport': 'udp',
            'protocol': protocol,
            'direction': dir_extractor.extract(udp_group),
            'timestamp': ts_extractor.extract(udp_group),
            'length': len_extractor.extract(udp_group, protocol='udp')
        })

    return result
    
    # sni_rows = df[df["tls.handshake.extensions_server_name"].notna() & ~df["tls.handshake.extensions_server_name"].isin(SNI_filter or [])]

    # for _, row in sni_rows.iterrows():
    #     # Check if the row is a TCP packet.
    #     if row["tcp.stream"] is not None:
    #         stream_df = df[df["tcp.stream"] == row["tcp.stream"]]
    #         stream = row["tcp.stream"]
    #         transport = "tcp"
    #     elif row["udp.stream"] is not None:
    #         stream_df = df[df["udp.stream"] == row["udp.stream"]]
    #         stream = row["udp.stream"]
    #         transport = "udp"
    #     else:
    #         raise ValueError("No stream number found in the row.")
        
    #     features = np.array([
    #         dir_extractor.extract(stream_df), 
    #         ts_extractor.extract(stream_df), 
    #         len_extractor.extract(stream_df)
    #         ])
        
    #     # Append a new row to the result.
    #     result.append({
    #         'host': host,
    #         'id': id,
    #         'sni': row["tls.handshake.extensions_server_name"],
    #         'stream': stream,
    #         'transport': transport,
    #         'protocol': protocol,
    #         'feature': features}
    #         )
        
    # return result


def multi_pcap_extract(
        tshark_path: str, 
        pcap_dir: Union[str, Path], 
        SNI_filter: Union[Set[str], List[str]]=None, 
        display_filter: str='tcp',
        protocol: str='normal',
        override_prefs: dict=None,
        src: List[str]=None,
        db: pd.DataFrame=None) -> List[dict]:
    """
    Extract features from multiple .pcap files.
    """
    if isinstance(pcap_dir, str):
        pcap_dir = Path(pcap_dir)

    result = []
    for file in pcap_dir.iterdir():
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:
            if db is not None:
                # Check if the host and id of the current file are in the db.
                host, id = file.stem.split('_')
                if db.isin({'host': [host], 'id': [int(id)], 'protocol': [protocol]}).all(axis=1).any():
                    logger.info(f"Host: {host}, ID: {id}, Protocol: {protocol} has been processed, skip")
                    continue
            try:
                result.extend(single_pcap_extract(tshark_path, file, SNI_filter, display_filter, protocol, override_prefs, src))
            except Exception as e:
                logger.error(f"Error extracting features from {file}: {e}, skip")
                continue
    return result


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
    The class that extracts direction feature from DataFrame.
    """
    def __init__(self, src: Union[str, List[str]], name="direction"):
        super().__init__(name=name)
        self._src = src if isinstance(src, list) else [src]

    def extract(self, df: pd.DataFrame):
        return np.where(df['ip.src'].isin(self._src), 1, -1).astype(int)
    

class CsvTsExtractor(CsvExtractor):
    """
    The class that extracts timestamp feature from DataFrame.
    """
    def __init__(self, name="timestamp"):
        super().__init__(name=name)

    def extract(self, df: pd.DataFrame):
        return df['frame.time_relative'].to_numpy(dtype=float)
    

class CsvLenExtractor(CsvExtractor):
    """
    The class that extracts length feature of a specific protocol from DataFrame.
    Currently, only TCP is supported.
    """
    def __init__(self, name="length"):
        super().__init__(name=name)

    def extract(self, df: pd.DataFrame, protocol: str="tcp"):
        if protocol == "tcp":
            return df['tcp.len'].to_numpy(dtype=int) + df['tcp.hdr_len'].to_numpy(dtype=int)
        elif protocol == "udp":
            return df['udp.length'].to_numpy(dtype=int)
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
            if 'ip' in pkt:
                src = pkt['ip'].src
            elif 'ipv6' in pkt:
                src = pkt['ipv6'].src
            else:
                raise NotImplementedError("Packet does not have IP or IPv6 layer")

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
