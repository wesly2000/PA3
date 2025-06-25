from typing import Union, List, Set, Optional, Iterable, Tuple
import numpy as np
from numpy.lib.npyio import NpzFile
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


def multi_pcap_extract(
        tshark_path: str, 
        pcap_dir: Union[str, Path], 
        SNI_filter: Union[Set[str], List[str]]=[], 
        display_filter: str='tcp',
        protocol: str='normal',
        override_prefs: dict={},
        src: List[str]=[],
        db: Optional[pd.DataFrame]=None) -> List[dict]:
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


def array_path(host: str, id: int, transport: str, stream: int, protocol: str) -> str:
    return f"{host}_{id}_{transport}_{stream}_{protocol}.npz"


class Splitter():
    """
    The class that split a list or array into multiple parts.
    """


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


class NpzExtractor(Extractor):
    """
    Extractors that extract features from .npz files. Since .npz files using key to index arrays within, the caller is responsible
    to pass the correct key.

    In the database-based data storing system, a .pcap is split to multiple arrays representation, each of which is a stream. 

    Therefore, for extracting the feature of an entire capture, the caller is responsible to pass a group of .npz file paths which 
    the caller considers enough to represent the capture.
    """
    def extract(self, target: list, npz_file_list: List[NpzFile]):
        raise NotImplementedError


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

class Criterion():
    """
    The class that provides the criterion for selecting the top-k streams. All the criteria should inherit this class,
    which must implement the select method.

    Attributes
    ----------
    k : int
        The number of streams to select. If k <= 0, all the streams will be selected.
    """
    def __init__(self, k:int=0):
        self.k = k

    def select(self, features: Iterable) -> Iterable:
        raise NotImplementedError
    

class HSDBSCriterion(Criterion):
    """
    The criterion that selects the top-k streams by Header Stripped Directional Burst Size (HSDBS) feature.
    """
    def __init__(self, k:int=0):
        self.k = k

    def select(self, features: List[List[tuple]]) -> List[List[tuple]]:
        if self.k <= 0:
            return features
        
        feature_sizes = [(i, sum(abs(size) for _, size in feature)) for i, feature in enumerate(features)]
        top_k_indices = [i for i, _ in sorted(feature_sizes, key=lambda x: x[1], reverse=True)[:self.k]]
        return [features[i] for i in top_k_indices]
    

class BSExcludeCriterion(Criterion):
    """
    The criterion that excludes the streams with burst size falls in the given range.
    """
    def __init__(self, lower_bounds: np.ndarray, upper_bounds: np.ndarray, threshold: int = 40):
        self.lower_bounds = lower_bounds
        self.upper_bounds = upper_bounds
        self.threshold = threshold

    def select(self, features: List[List[tuple]]) -> List[List[tuple]]:
        
        # Original list comprehension version:
        # return [feature for feature in features if not (self.lower_bounds <= sum(abs(size) for _, size in feature) & (sum(abs(size) for _, size in feature) <= self.upper_bounds)).any()]
        
        # Expanded for-loop version for debugging
        result = []
        for feature in features:
            total_size = sum(abs(size) - self.threshold for _, size in feature if abs(size) > self.threshold)
            in_range = (self.lower_bounds <= total_size) & (total_size <= self.upper_bounds)
            if not in_range.any():
                result.append(feature)
        return result
    

class LengthExcludeCriterion(Criterion):
    """
    The criterion that excludes the streams with length smaller than the given threshold.
    """
    def __init__(self, threshold: int):
        self.threshold = threshold
    
    def select(self, features: List[List[tuple]]) -> List[List[tuple]]:
        return [feature for feature in features if len(feature) > self.threshold]


class NpzHSDBSExtractor(NpzExtractor):
    """
    The class that extracts Header Stripped Directional Burst Size (HSDBS) feature from .npz files.

    Attributes
    ----------
    threshold : int
        The threshold for the burst size.
    ignore_control_packets : bool
        Whether to ignore control packets, e.g., SYN, ACK, etc.
    criterion : str
        The criterion to select the top-k streams.
    """
    def __init__(self, name="hsdbs", threshold:int=40, ignore_control_packets: bool=False):
        super().__init__(name=name)
        self.threshold = threshold
        self.ignore_control_packets = ignore_control_packets

    def single_stream_extract(self, npz_file: NpzFile) -> List[tuple]:
        direction_arr, length_arr, timestamp_arr = npz_file['direction'], npz_file['length'], npz_file['timestamp']

        if self.ignore_control_packets:
            # The ignore_control_packets option is used to filter out control TCP packets, e.g., SYN, ACK, etc., before creating bursts. The feature helps to maintain the burst application layer semantics.
            direction_arr = direction_arr[length_arr > self.threshold]
            timestamp_arr = timestamp_arr[length_arr > self.threshold]
            length_arr = length_arr[length_arr > self.threshold]

            if len(direction_arr) == 0:
                return []

        # A burst is created as follows:
        # + a burst size is the accumulated length of consecutive packets with the same direction;
        # + the size is directional, multiplied by the direction;
        # + the packet size being calculated must be larger than some given threshold;
        # + a burst timestamp is the timestamp of the first packet within (whether or not the packet is considered in burst size);
        # + a burst is defined as the (timestamp, size)
        bursts = []

        for direction, start, end in zip(*self._get_burst_meta_info(direction_arr)):
            packet_lengths = length_arr[start:end]
            if self.ignore_control_packets:
                burst_size = np.sum(packet_lengths - self.threshold)
            else:
                burst_size = np.sum(packet_lengths[packet_lengths > self.threshold] - self.threshold)

            bursts.append((timestamp_arr[start], direction * burst_size))

        return bursts
    

    def extract(self, target: list, npz_file_list: List[NpzFile], *criteria: Criterion):
        stream_bursts = []
        for npz_file in npz_file_list:
            stream_bursts.append(self.single_stream_extract(npz_file))
        
        for criterion in criteria:
            stream_bursts = criterion.select(stream_bursts)

        bursts = []
        for stream_burst in stream_bursts:
            bursts.extend(stream_burst)

        bursts.sort(key=lambda x: x[0])  # Sort according to timestamp information        
        target += [size for _, size in bursts]


    def _get_burst_meta_info(self, arr):
        # Find where the values change
        change_points = np.where(np.diff(arr) != 0)[0] + 1
        
        # Add start and end points
        change_points = np.concatenate(([0], change_points, [len(arr)]))
        
        # Get blocks and their indices
        directions, starts, ends = [], [], []
        
        for i in range(len(change_points) - 1):
            starts.append(change_points[i])
            ends.append(change_points[i + 1])
            directions.append(arr[change_points[i]])
        
        return directions, starts, ends
    

class Stripper():
    """
    The class that strips some elements from the original features.
    """
    def __init__(self, exclude_indices: List[int]):
        self.exclude_indices = exclude_indices

    def strip(self, feature: np.ndarray) -> np.ndarray:
        raise NotImplementedError
    
class VmessStripper(Stripper):
    """
    The class that strips the VMess feature from the original features.
    """
    def __init__(self):
        super().__init__(exclude_indices=[3])
        
    def strip(self, feature: np.ndarray) -> np.ndarray:
        return np.delete(feature, self.exclude_indices)

class NpzDirExtractor(NpzExtractor):
    """
    The class that extracts direction feature from .npz files.
    """
    def __init__(self, name="direction", stripper: Optional[Stripper]=None):
        super().__init__(name=name)
        self.stripper = stripper


    def single_stream_extract(self, npz_file: NpzFile) -> List[tuple]:
        direction_arr = npz_file['direction']
        timestamp_arr = npz_file['timestamp']
        length_arr = npz_file['length']

        if self.stripper:
            direction_arr = self.stripper.strip(direction_arr)
            timestamp_arr = self.stripper.strip(timestamp_arr)
            length_arr = self.stripper.strip(length_arr)

        return [(timestamp, direction * length) for timestamp, direction, length in zip(timestamp_arr, direction_arr, length_arr)]  

    def extract(self, target: list, npz_file_list: List[NpzFile], *criteria: Criterion):
        streams = []
        for npz_file in npz_file_list:
            streams.append(self.single_stream_extract(npz_file))

        for criterion in criteria:
            streams = criterion.select(streams)

        dir_lengths = []
        for stream in streams:
            dir_lengths.extend(stream)

        dir_lengths.sort(key=lambda x: x[0])
        # Use the sign function of the lengths to get the direction
        target += [np.sign(size) for _, size in dir_lengths]