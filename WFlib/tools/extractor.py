from collections import Counter
from dataclasses import dataclass
from typing import Union, List, Set, Optional, Iterable, Tuple, Callable, Dict, Any, Mapping
import numpy as np
from numpy.lib.npyio import NpzFile
import pandas as pd
import subprocess
import logging
import io
from pathlib import Path
import math

from sklearn.metrics import mutual_info_score, precision_score, recall_score, mutual_info_score

from WFlib.utils.statistics import greedy_mass_covering
from WFlib.tools.augmentor import FlowAugmentor


class StreamProcessingError(Exception):
    """Exception raised when stream processing fails with index information."""
    def __init__(self, message: str, stream_index: int, original_exception: Exception = None):
        self.message = message
        self.stream_index = stream_index
        self.original_exception = original_exception
        super().__init__(self.message)

logger = logging.getLogger(__name__)

'''
COMMENT: Shall we name a class capitalizing all letters of an abbrev., e.g., extension name of a file?
         Currently, only the first letter is capitalized, please follow the convention.
'''

WEIGHT_1_PART = [1.0]
WEIGHT_2_PART = [1 / 2] * 2
WEIGHT_3_PART = [1 / 3] * 3
WEIGHT_4_PART = [1 / 4] * 4
WEIGHT_5_PART = [1 / 5] * 5
WEIGHT_6_PART = [1 / 6] * 6

WEIGHT_LIST = [WEIGHT_1_PART, WEIGHT_2_PART, WEIGHT_3_PART, WEIGHT_4_PART, WEIGHT_5_PART, WEIGHT_6_PART]

SPLIT_PROB = [0.53, 0.23, 0.13, 0.07, 0.03, 0.01]


def make_split_weight_generator(split_prob: List[float]=SPLIT_PROB, weights: List[List[float]]=WEIGHT_LIST):
    assert math.isclose(sum(split_prob), 1, rel_tol=1e-5), "The sum of split_prob must be 1"
    accumulated_prob = np.cumsum(split_prob)
    weight_selection_range = np.concatenate(([0], accumulated_prob))

    def split_weight_generator():
        # Generate a random number between 0 and 1
        random_number = np.random.rand()
        # Find the index of the weight_selection_range that the random_number falls into
        index = np.searchsorted(weight_selection_range, random_number) - 1

        return weights[index]

    return split_weight_generator


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


def array_path(host: str, id: Union[int, str], transport: str, stream: int, protocol: str) -> str:
    return f"{host}_{id}_{transport}_{stream}_{protocol}.npz"


class Stripper():
    """
    The class that strips some elements from the original features. 

    WARNING: Stripper could only be used for packet-wise features, e.g., direction, packet length, packet timestamp, etc.. Moreover, the caller MUST not filter out the packets according to some criterion. For instance, please do NOT use Stripper when extracting threshold > 0. Future versions might support such cases.
    """
    LOWER_BOUND = 70
    UPPER_BOUND = 1400

    def __init__(self, protocol: str='abstract'):
        self.protocol = protocol

    def searching(self, feature: np.ndarray) -> Iterable:
        """
        The method that decide the proper indices to be stripped.
        """
        return extra_handshake_packets(stream=feature, protocol=self.protocol, lower_bound=self.LOWER_BOUND, upper_bound=self.UPPER_BOUND)

    def strip(self, feature: Union[np.ndarray, Iterable]) -> np.ndarray:
        exclude_indices = self.searching(feature)
        if isinstance(feature, np.ndarray):
            return np.delete(feature, exclude_indices)
        else:
            return [feature[i] for i in range(len(feature)) if i not in exclude_indices]
    
class VMessStripper(Stripper):
    """
    The class that strips the VMess feature from the original features.
    """
    def __init__(self):
        super().__init__(protocol='vmess')

    def searching(self, feature: np.ndarray) -> Iterable:
        return [3, 6]
    

class ShadowsocksStripper(Stripper):
    """
    The class that strips the Shadowsocks feature from the original features.
    """
    def __init__(self):
        super().__init__(protocol='shadowsocks')

    def searching(self, feature: np.ndarray) -> Iterable:
        return [3, 4, 7, 8]

class TrojanStripper(Stripper):
    """
    The class that strips the Trojan feature from the original features.
    """
    def __init__(self):
        super().__init__(protocol='trojan')

    def searching(self, feature: np.ndarray) -> Iterable:
        if len(feature) < 13:
            return []
        else:
            return [3, 4, 5, 6, 7, 8]


PROTOCOL_STRIPPER = {'vmess': VMessStripper(), 'shadowsocks': ShadowsocksStripper(), 'trojan': TrojanStripper()}


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


class Criterion():
    """
    The class that provides the criterion for selecting the top-k streams. All the criteria should inherit this class,
    which must implement the select method.
    """
    def __init__(self, name: str):
        self.name = name

    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        raise NotImplementedError
    

class SortCriterion(Criterion):
    """
    The abstract class that provides the criterion to select a given range of streams whose
    feature provided and sorted by the criterion.

    One common example is the length criterion, which selects the top-k streams with the largest length.
    """
    def __init__(self, name: str, slice: slice):
        super().__init__(name)
        self.slice = slice

    def feature_map(self, stream: Dict[str, np.ndarray]):
        """
        Map the stream to a feature, which MUST be compatible in sort method.
        """
        raise NotImplementedError
    
    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        """
        Select the streams according to the criterion. Note that the sorting order is ALWAYS ascending.
        """
        sorted_streams = sorted(streams, key=self.feature_map)
        return sorted_streams[self.slice]
    

class CheckCriterion(Criterion):
    """
    The abstract class that provides the criterion to check if a stream satisfies the given condition.
    """
    def __init__(self, name: str, condition: Callable[[Any], bool]):
        super().__init__(name)
        self.condition = condition

    def feature_map(self, stream: Dict[str, np.ndarray]):
        """
        Map the stream to a feature, which MUST be compatible in the condition.
        """
        raise NotImplementedError
    
    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        """
        Select the streams according to the criterion.
        """
        return [stream for stream in streams if self.condition(self.feature_map(stream))]
    

class Splitter():
    """
    The class that splits the stream into another stream/streams.
    """
    def __init__(self, prologue_len:int=13, epilogue_len:int=7):
        self.prologue_len = prologue_len
        self.epilogue_len = epilogue_len

    def split(self, stream: Iterable) -> Iterable:
        raise NotImplementedError

class WeightSplitter(Splitter):
    """
    The class that splits the stream into multiple streams. Each stream is considered as [Prologue] [Content] [Epilogue].
    The split is only applied to the content part.

    Attributes
    ----------
    prologue_len : int
        The length of the prologue.
    epilogue_len : int
        The length of the epilogue.
    weight : Optional[Iterable[float]]
        The partition weight for the content, the sum of weight MUST be 1. If None, the weight will be generated by the weight_generator.
    weight_generator : Callable
        The generator for the weight, note that the weight and weight_generator could not be None at the same time.
    noise_level : float
        We add noise to the given weight to create a more realistic split.
    noise_mode : str
        The mode of the noise.
    """
    def __init__(self, prologue_len:int=13, epilogue_len:int=7, weight: Optional[List[float]]=None, weight_generator: Callable=make_split_weight_generator, noise_level:float=0.05, noise_mode:str='uniform'):
        super().__init__(prologue_len, epilogue_len)
        if weight is not None:
            assert math.isclose(sum(weight), 1, rel_tol=1e-5), "The sum of weight must be 1"
            self.weight = weight
        else:
            self.weight = None

        self.weight_generator = weight_generator
        self.noise_level = noise_level
        self.noise_mode = noise_mode

    def noisy_weight_indices(self, length):
        """
        Create noisy weights and generate index for each weight given the length of the stream to split.
        """
        if self.weight is not None:
            accumulated_weight = np.cumsum(self.weight)
        else:
            accumulated_weight = np.cumsum(self.weight_generator())

        ideal_splits = np.array([length * weight for weight in accumulated_weight[:-1]])
        noise = np.random.uniform(-self.noise_level, self.noise_level, len(ideal_splits))
        noisy_splits = ideal_splits + noise * length   
        noisy_indices = np.round(noisy_splits).astype(int)         
        noisy_indices = np.clip(noisy_indices, 0, length)
        noisy_indices = np.sort(noisy_indices)
        # If there are multiple indices with the same value, we need to re-generate the noise.

        noisy_indices = np.concatenate(([0],noisy_indices, [length]))
        noisy_indices = np.unique(noisy_indices)
        if len(noisy_indices) < len(accumulated_weight):
            logger.warning(f"Duplicate indices reduced partitions to {len(noisy_indices)-1}; adjusting")
            return self.noisy_weight_indices(length)
        # Remove duplicates to avoid empty partitions
        
        return noisy_indices

    def split(self, stream: Iterable) -> Iterable:
        # Only fetch the content part of the stream
        timestamps, sizes = [], []
        for t, s in stream:
            timestamps.append(t)
            sizes.append(s)

        prologue, epilogue = sizes[:self.prologue_len], sizes[-self.epilogue_len:]
        content = sizes[self.prologue_len : -self.epilogue_len]
        noisy_indices = self.noisy_weight_indices(len(content))
        split_contents = [content[noisy_indices[i] : noisy_indices[i+1]] for i in range(len(noisy_indices) - 1)]

        
        for c in split_contents:
            new_sizes = prologue + c + epilogue
            # Randomly sample len(new_sizes) elements from timestamps
            new_timestamps = np.random.choice(timestamps, size=len(new_sizes), replace=False)
            new_timestamps.sort()
            # Zip the new_timestamps and new_sizes
            new_stream = list(zip(new_timestamps, new_sizes))
            yield new_stream


class RatioSplitter(Splitter):
    """
    The class that splits the stream into a SINGLE stream based on the given ratio. When ratio is larger than 1, the stream
    would be extended, otherwise, the stream would be truncated. The extension and truncation are done by randomly sampling the
    original stream.
    """
    def __init__(self, prologue_len:int=13, epilogue_len:int=7, ratio: float=0.9, noise_level:float=0.1, noise_mode:str='uniform'):
        super().__init__(prologue_len, epilogue_len)
        self.ratio = ratio
        self.noise_level = noise_level
        self.noise_mode = noise_mode

    def split(self, stream: Iterable) -> Iterable:
        # Only fetch the content part of the stream
        timestamps, sizes = [], []
        for t, s in stream:
            timestamps.append(t)
            sizes.append(s)

        prologue= stream[:self.prologue_len]
        content_sizes = sizes[self.prologue_len : -self.epilogue_len]
        content_timestamps = timestamps[self.prologue_len : -self.epilogue_len]
        delta_timestamps = np.concatenate(([0], np.diff(content_timestamps)))
        
        # Sample the content part with noise
        noisy_ratio = self.ratio + np.random.uniform(-self.noise_level, self.noise_level)
        if noisy_ratio < 1:  # Truncate the stream
            sample_sizes = content_sizes[:int(len(content_sizes) * noisy_ratio)]
            sample_timestamps = content_timestamps[:int(len(content_timestamps) * noisy_ratio)]
        else:  # Extend the stream
            # Copy the content sizes and timestamps
            sample_sizes = content_sizes[:]
            sample_timestamps = content_timestamps[:]
            noisy_ratio -= 1
            while noisy_ratio > 1:
                sample_sizes.extend(content_sizes)
                # Add perturbation to the timestamps
                sample_timestamps.extend([sample_timestamps[-1] + delta_ts for delta_ts in delta_timestamps] )
                noisy_ratio -= 1
            if noisy_ratio > 0:
                sample_sizes.extend(content_sizes[:int(len(content_sizes) * noisy_ratio)])
                sample_timestamps.extend([sample_timestamps[-1] + delta_ts for delta_ts in delta_timestamps[:int(len(content_sizes) * noisy_ratio)]] )

        new_content = list(zip(sample_timestamps, sample_sizes))
        # Create the new epilogue
        # Delay the timestamp of epilogue to the end of the new content
        epilogue_sizes = sizes[-self.epilogue_len:]
        epilogue_delta_timestamps = np.concatenate(([0], np.diff(timestamps[-self.epilogue_len:])))
        epilogue_timestamps = [sample_timestamps[-1] + delta_ts for delta_ts in epilogue_delta_timestamps]
        epilogue = list(zip(epilogue_timestamps, epilogue_sizes))
        
        new_stream = prologue + new_content + epilogue

        yield new_stream
    

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
    def __init__(self, name: str, stripper: Optional[Stripper]=None, criteria: Optional[Union[List[Criterion], Criterion]]=None, ):
        super().__init__(name=name)
        if criteria is None:
            self.criteria = []
        elif isinstance(criteria, list):
            self.criteria = criteria
        else:
            self.criteria = [criteria]

    def extract(self, target: list, npz_file_list: List[NpzFile]):
        raise NotImplementedError
    
    def load_streams(self, npz_file_list: List[NpzFile]) -> List[Dict[str, np.ndarray]]:
        """
        A stream is a dict of timestamp, direction, length arrays.
        """
        streams = []
        for npz_file in npz_file_list:
            stream = {}
            stream['timestamp'] = npz_file['timestamp']
            stream['direction'] = npz_file['direction']
            stream['length'] = npz_file['length']
            streams.append(stream)
        return streams


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
    

class HSDBSCriterion(SortCriterion):
    """
    The criterion that selects the top-k streams by Header Stripped Directional Burst Size (HSDBS) feature.
    """
    def __init__(self, k:int=0, threshold:int=40):
        self.k = k
        self.threshold = threshold
        if k > 0:
            _slice = slice(-k, None)
            super().__init__(name="hsdbs", slice=_slice)

    def feature_map(self, stream: Dict[str, np.ndarray]):
        """
        Map the stream to a feature, which MUST be compatible in sort method.
        """
        length = stream['length']
        return np.sum(length[length > self.threshold] - self.threshold)
    
    
    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        if self.k <= 0:
            return streams
        else:
            return super().select(streams)
    

class LengthCriterion(SortCriterion):
    """
    The criterion that selects the top-k streams by stream length feature.
    """
    def __init__(self, k:int=0):
        self.k = k
        if k > 0:
            _slice = slice(-k, None)
            super().__init__(name="length", slice=_slice)

    def feature_map(self, stream: Dict[str, np.ndarray]):
        return len(stream['length'])
    
    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        if self.k <= 0:
            return streams
        else:
            return super().select(streams)
    

class LengthExcludeCriterion(CheckCriterion):
    """
    The criterion that excludes the streams with the number of frames smaller than the given threshold.
    """
    def __init__(self, threshold: int = 32):
        self.threshold = threshold
        def condition(length):
            return length > self.threshold
        super().__init__(name="length_exclude", condition=condition)

    def feature_map(self, stream: Dict[str, np.ndarray]):
        return len(stream['length'])
    


class HSDBSExcludeCriterion(CheckCriterion):
    """
    The criterion that excludes the streams with burst size falls in the given range.
    """
    def __init__(self, lower_bounds: np.ndarray, upper_bounds: np.ndarray, threshold: int = 40):
        self.lower_bounds = lower_bounds
        self.upper_bounds = upper_bounds
        self.threshold = threshold
        def condition(feature):
            in_range = (self.lower_bounds <= feature) & (feature <= self.upper_bounds)
            return not in_range.any()
        super().__init__(name="hsdbs_exclude", condition=condition)


    def feature_map(self, stream: Dict[str, np.ndarray]):
        length = stream['length']
        return np.sum(length[length > self.threshold] - self.threshold)
    

    def select(self, streams: List[Dict[str, np.ndarray]]) -> List[Dict[str, np.ndarray]]:
        return super().select(streams)


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
    def __init__(self, name="hsdbs", threshold:int=40, ignore_control_packets: bool=False, criteria: Optional[Union[List[Criterion], Criterion]]=None):
        super().__init__(name=name, criteria=criteria)
        self.threshold = threshold
        self.ignore_control_packets = ignore_control_packets

    def single_stream_extract(self, stream: Dict[str, np.ndarray]) -> List[tuple]:
        direction_arr, length_arr, timestamp_arr = stream['direction'], stream['length'], stream['timestamp']

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
    

    def extract(self, target: list, npz_file_list: List[NpzFile]):
        streams = self.load_streams(npz_file_list)
        for criterion in self.criteria:
            streams = criterion.select(streams)
        
        stream_bursts = []
        for stream in streams:
            stream_bursts.append(self.single_stream_extract(stream))

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
    

PROTOCOL_ANCHOR = {'vmess': [5], 'shadowsocks': [6], 'trojan': [14, 16]}

def extra_handshake_packets(stream: Union[np.ndarray, List[int]], protocol: str, lower_bound: int, upper_bound: int, prologue_length=3):
    """
    Given a stream of directional packet sizes, search for the anchor point, and erase the redundant handshake packets.

    The sequence of the stream is as follows:

    SYN-SYN+ACK-ACK---X---CH_1---[CH_2]---ACKs---remaining packets
    """
    possible_anchors = PROTOCOL_ANCHOR[protocol.lower()]

    LEAST_PACKETS = 20  # The stream should contain a minimum number of packets.
    if len(stream) < LEAST_PACKETS:
        return [] 

    anchor = 0

    # Searching for the anchor point
    for possible_anchor in possible_anchors:
        # There are 4 heuristic standard to check if current frame is not a Client Hello:
        # 1. This frame is negative (send by Server);
        # 2. The next frame is not an ACK frame;
        # 3. The current frame exceeds upper_bound (a value bit smaller than MSS) in size;
        # 4. The current frame is smaller than lower_bound (a TCP control frame)
        # If not a Client Hello, continue searching
        if  stream[possible_anchor] < 0 or \
            abs(stream[possible_anchor + 1]) > lower_bound or \
            abs(stream[possible_anchor]) > upper_bound or \
            abs(stream[possible_anchor]) < lower_bound:  
            continue

        # This is a Client Hello, get the anchor.
        anchor = possible_anchor
        break

    if anchor == 0:
        return []
    
    redundant_indices = []
    # It is possible that a Client Hello is split into multiple packets (a common case is 2 according to our research).
    first_segment = last_segment = anchor
    if abs(stream[first_segment - 1]) >= upper_bound:  # The Client Hello is split into two packets.
        first_segment -= 1

    ack = 0
    data = 0
    for i in range(prologue_length, first_segment):
        if abs(stream[i]) <= lower_bound:  # This is an ACK packet
            ack += 1
        else:
            data += 1

        redundant_indices.append(i)

    if ack > data:
        return []
    
    for i in range(data - ack):
        redundant_indices.append(i + last_segment + 1)

    return redundant_indices


class NpzDirExtractor(NpzExtractor):
    """
    The class that extracts directional packet length feature from .npz files.

    TODO: Shall we return the error when IndexError occurs, which would be used by the caller to log some warnings? Currently, we just pass it.
    """
    def __init__(self, name="direction", stripper: Optional[Stripper]=None, criteria: Optional[Union[List[Criterion], Criterion]]=None):
        super().__init__(name=name, criteria=criteria)
        self.stripper = stripper

    def single_stream_extract(self, stream: Dict[str, np.ndarray]) -> List[tuple]:
        direction_arr, timestamp_arr, length_arr = stream['direction'], stream['timestamp'], stream['length']

        if self.stripper:
            try:
                direction_arr = self.stripper.strip(direction_arr)
                timestamp_arr = self.stripper.strip(timestamp_arr)
                length_arr = self.stripper.strip(length_arr)
            except IndexError as e:
                pass

        return [(timestamp, direction * length) for timestamp, direction, length in zip(timestamp_arr, direction_arr, length_arr)]  

    def extract(self, target: list, npz_file_list: List[NpzFile]):
        streams = self.load_streams(npz_file_list)

        for criterion in self.criteria:
            streams = criterion.select(streams)

        dir_lengths = []
        for stream in streams:
            dir_lengths.extend(self.single_stream_extract(stream))

        dir_lengths.sort(key=lambda x: x[0])
        target += [size for _, size in dir_lengths]


class NpzRawExtractor(NpzExtractor):
    """
    This class extracts one, or multiple raw features from the .npz files, i.e., features among direction, length and timestamp.
    Note that this class is originally designed for connecting to TSAM/TAM generators in exp/dataset_process/gen_tsam.py and
    exp/dataset_process/gen_tam.py, respectively.

    The caller should be careful that this class generates features in 2D or 3D dimensions, where the corresponding Formatter
    MUST consider padding proper values if the dimension is larger than 1.

    The return, when the dimension is larger than 1, is a list of tuples, where each tuple contains the feature vector of a
    single packet.

    Dimension is specified using the name of raw feature. For instance, passing ['direction', 'length'] to the features arg would
    lead to a 2D feature vector. Note that whether or NOT the timestamp is included in the features, the resulting feature is
    ALWAYS sorted according to timestamp by ascending order.
    """
    supported_features = {'direction', 'length', 'timestamp'}

    def __init__(self, features: Union[Set[str], List[str]], name: str='raw', stripper: Optional[Stripper]=None, criteria: Optional[Union[List[Criterion], Criterion]]=None, augmentor: Optional[FlowAugmentor]=None):
        super().__init__(name=name, criteria=criteria)
        self.stripper = stripper
        self.augmentor = augmentor
        features = set(features)
        assert features.issubset(self.supported_features), f"Unsupported features: {features - self.supported_features}"
        features = list(features)
        # Sort features in order: timestamp, direction, length
        feature_order = {'timestamp': 0, 'direction': 1, 'length': 2}
        self.features = sorted(features, key=lambda x: feature_order[x])

    def single_stream_extract(self, stream: Dict[str, np.ndarray]) -> List[tuple]:
        # TODO: Add support for augmentation.
        if self.augmentor:
            stream = self.augmentor.augment(stream)

        timestamp_arr, feature_arrs = stream['timestamp'], [stream[feature] for feature in self.features]
        raw_arr = [(timestamp, tuple(features)) for timestamp, *features in zip(timestamp_arr, *feature_arrs)]
        if self.stripper:
            try:
                raw_arr = self.stripper.strip(raw_arr)
            except IndexError as e:
                pass

        return raw_arr

    def extract(self, target: list, npz_file_list: List[NpzFile]):
        streams = self.load_streams(npz_file_list)

        for criterion in self.criteria:
            streams = criterion.select(streams)

        raw_features = []
        for stream in streams:
            raw_features.extend(self.single_stream_extract(stream))

        raw_features.sort(key=lambda x: x[0])
        target += [feature for _, feature in raw_features]


# --- N-gram anomaly detection ---

def uniform_bin(
    data: Union[np.ndarray, List],
    lower_bound: int,
    upper_bound: int,
    vocabulary_size: int,
) -> np.ndarray:
    """
    Discretize a 1-D integer array into uniform bins and return integer bin midpoints.

    The interval [lower_bound, upper_bound] is split into vocabulary_size equal-width bins.
    Values below lower_bound or above upper_bound are clipped to the first/last bin.
    """
    if vocabulary_size <= 0 or lower_bound >= upper_bound:
        raise ValueError(
            "vocabulary_size must be positive and lower_bound must be less than upper_bound"
        )

    data = np.asarray(data, dtype=np.int64)
    edges = np.linspace(lower_bound, upper_bound, vocabulary_size + 1, dtype=np.int64)
    bin_idx = np.digitize(data, edges) - 1
    bin_idx = np.clip(bin_idx, 0, vocabulary_size - 1)
    midpoints = (edges[:-1] + edges[1:]) // 2
    return midpoints[bin_idx]


def packet_size_counter(data: Union[np.ndarray, List]) -> Dict[int, int]:
    """Build a signed packet-size histogram from a 1-D flow array."""
    return dict(Counter(np.asarray(data, dtype=np.int64)))


def build_distribution_bins(
    size_counts: Mapping[int, int],
    vocabulary_size: int,
) -> List[Tuple[int, int, int]]:
    """
    Partition distinct packet sizes into equal-mass bins.

    Returns a list of (bin_min, bin_max, representative) where representative is
    (bin_min + bin_max) // 2. Each distinct size is assigned to exactly one bin.
    """
    if vocabulary_size <= 0:
        raise ValueError("vocabulary_size must be positive")

    items = sorted((int(size), int(count)) for size, count in size_counts.items() if count > 0)
    if not items:
        raise ValueError("size_counts must contain at least one positive count")
    if vocabulary_size > len(items):
        raise ValueError("vocabulary_size cannot exceed the number of distinct packet sizes")

    if vocabulary_size == len(items):
        return [(size, size, size) for size, _ in items]

    total = sum(count for _, count in items)
    target = total / vocabulary_size
    bins: List[Tuple[int, int, int]] = []
    current_sizes: List[int] = []
    current_mass = 0

    for size, count in items:
        if current_sizes and len(bins) < vocabulary_size - 1 and current_mass >= target:
            bin_min, bin_max = current_sizes[0], current_sizes[-1]
            bins.append((bin_min, bin_max, (bin_min + bin_max) // 2))
            current_sizes = []
            current_mass = 0

        current_sizes.append(size)
        current_mass += count

    if current_sizes:
        bin_min, bin_max = current_sizes[0], current_sizes[-1]
        bins.append((bin_min, bin_max, (bin_min + bin_max) // 2))

    return bins


def distribution_bin(
    data: Union[np.ndarray, List],
    size_counts: Mapping[int, int],
    vocabulary_size: int,
) -> np.ndarray:
    """
    Discretize data using equal-mass bins derived from an empirical size histogram.

    Values below the smallest or above the largest supported size are clipped to the
    first or last bin. Values between bins are assigned by bin_max boundaries.
    """
    bins = build_distribution_bins(size_counts, vocabulary_size)
    data = np.asarray(data, dtype=np.int64)
    bin_mins = np.array([spec[0] for spec in bins], dtype=np.int64)
    bin_maxs = np.array([spec[1] for spec in bins], dtype=np.int64)
    representatives = np.array([spec[2] for spec in bins], dtype=np.int64)

    idx = np.searchsorted(bin_maxs, data, side="left")
    idx = np.clip(idx, 0, len(representatives) - 1)
    result = representatives[idx]
    result[data < bin_mins[0]] = representatives[0]
    result[data > bin_maxs[-1]] = representatives[-1]
    return result


@dataclass(frozen=True)
class PacketSizeBinner:
    """
    Fit-once packet-size discretizer for train/test n-gram pipelines.

    Use fit_uniform or fit_distribution on training data, then transform flows
    or individual windows at test time with the same spec.
    """

    mode: str
    vocabulary_size: int
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    size_counts: Optional[Dict[int, int]] = None
    bin_specs: Optional[List[Tuple[int, int, int]]] = None

    @classmethod
    def fit_uniform(
        cls,
        lower_bound: int,
        upper_bound: int,
        vocabulary_size: int,
    ) -> "PacketSizeBinner":
        if vocabulary_size <= 0 or lower_bound >= upper_bound:
            raise ValueError(
                "vocabulary_size must be positive and lower_bound must be less than upper_bound"
            )
        return cls(
            mode="uniform",
            vocabulary_size=vocabulary_size,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )

    @classmethod
    def fit_distribution(
        cls,
        flows_or_counts: Union[Mapping[int, int], Iterable[Union[np.ndarray, List]]],
        vocabulary_size: int,
    ) -> "PacketSizeBinner":
        if isinstance(flows_or_counts, Mapping):
            size_counts = {int(size): int(count) for size, count in flows_or_counts.items()}
        else:
            size_counts: Dict[int, int] = {}
            for flow in flows_or_counts:
                for size, count in packet_size_counter(flow).items():
                    size_counts[size] = size_counts.get(size, 0) + count
        bin_specs = build_distribution_bins(size_counts, vocabulary_size)
        return cls(
            mode="distribution",
            vocabulary_size=vocabulary_size,
            size_counts=size_counts,
            bin_specs=bin_specs,
        )

    def transform(self, data: Union[np.ndarray, List]) -> np.ndarray:
        if self.mode == "uniform":
            return uniform_bin(
                data,
                lower_bound=self.lower_bound,
                upper_bound=self.upper_bound,
                vocabulary_size=self.vocabulary_size,
            )
        return distribution_bin(data, self.size_counts, self.vocabulary_size)

    def transform_window(self, window: Tuple[int, ...]) -> Tuple[int, ...]:
        return tuple(int(v) for v in self.transform(window))


def label_windows(
    data: Union[np.ndarray, List],
    strip_indices: Iterable[int],
    window_size: int,
    overlap_threshold: float = 0.9,
) -> List[Tuple[Tuple, int]]:
    """
    Slide a window over data and label each window anomalous (1) when more than
    overlap_threshold of its packet indices appear in strip_indices.
    """
    data = np.asarray(data, dtype=np.int64)
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    if len(data) < window_size:
        return []

    strip_set = set(strip_indices)
    labeled = []
    for i in range(len(data) - window_size + 1):
        window_indices = range(i, i + window_size)
        m = sum(1 for j in window_indices if j in strip_set)
        window = tuple(int(v) for v in data[i:i + window_size])
        label = 1 if m / window_size > overlap_threshold else 0
        labeled.append((window, label))
    return labeled


def build_ngram_db(labeled_windows: List[Tuple[Tuple, int]]) -> Set[Tuple]:
    """
    Build an anomaly-signature database from binned training windows (label == 1).
    """
    return {window for window, label in labeled_windows if label == 1}


def train_ngram_db(
    flows_train: Iterable[Union[np.ndarray, List]],
    strip_indices: Iterable[int],
    window_size: int,
    binner: PacketSizeBinner,
    overlap_threshold: float = 0.9,
) -> Set[Tuple]:
    """
    Training phase: label windows on raw flows, bin anomalous windows, build signature DB.
    """
    labeled_binned: List[Tuple[Tuple, int]] = []
    for flow in flows_train:
        for window, label in label_windows(
            flow, strip_indices, window_size, overlap_threshold
        ):
            labeled_binned.append((binner.transform_window(window), label))
    return build_ngram_db(labeled_binned)


def evaluate_ngram(
    flows_test: Iterable[Union[np.ndarray, List]],
    strip_indices: Iterable[int],
    window_size: int,
    db: Set[Tuple],
    binner: PacketSizeBinner,
    overlap_threshold: float = 0.9,
) -> Tuple[float, float]:
    """
    Testing phase: ground truth from raw flows; predictions from binned flows.
    """
    labeled: List[Tuple[Tuple, int]] = []
    predictions: List[Tuple[Tuple, int]] = []
    for flow in flows_test:
        labeled.extend(
            label_windows(flow, strip_indices, window_size, overlap_threshold)
        )
        predictions.extend(
            ngram_predict(binner.transform(flow), db, window_size)
        )
    return ngram_precision_recall(labeled, predictions)


def collect_labeled_windows(
    flows: Iterable[Union[np.ndarray, List]],
    strip_indices: Iterable[int],
    window_size: int,
    overlap_threshold: float = 0.9,
) -> List[Tuple[Tuple, int]]:
    """Concatenate label_windows results over multiple raw flows."""
    labeled: List[Tuple[Tuple, int]] = []
    for flow in flows:
        labeled.extend(
            label_windows(flow, strip_indices, window_size, overlap_threshold)
        )
    return labeled


def _window_as_label(window: Tuple) -> str:
    """Encode a window tuple as a scalar label for discrete MI estimators."""
    return repr(window)


def mutual_information_windows(
    windows: List[Tuple],
    labels: List[int],
) -> float:
    """
    Plug-in mutual information I(W; Y) in nats for discrete window tuples and binary labels.
    """
    if not windows or not labels or len(windows) != len(labels):
        return 0.0
    if len(set(labels)) < 2:
        return 0.0
    window_labels = [_window_as_label(window) for window in windows]
    return float(mutual_info_score(labels, window_labels))


def vocabulary_objective(
    labeled_windows: List[Tuple[Tuple, int]],
    vocabulary_size: int,
    binner: PacketSizeBinner,
    *,
    window_size: int,
    lambda_penalty: float = 1.0,
    penalty_mode: str = "log_mdl",
) -> Dict[str, float]:
    """
    Compute J(|V|) = I(Q(W), Y) - penalty for a fitted binner and raw labeled windows.
    """
    if vocabulary_size < 1:
        raise ValueError("vocabulary_size must be at least 1")

    binned_windows = [binner.transform_window(window) for window, _ in labeled_windows]
    labels = [label for _, label in labeled_windows]
    for window in binned_windows:
        if len(window) != window_size:
            raise ValueError(
                f"expected window length {window_size}, got {len(window)}"
            )

    mi_nats = mutual_information_windows(binned_windows, labels)
    if penalty_mode == "log_mdl":
        penalty = lambda_penalty * window_size * math.log(vocabulary_size)
    elif penalty_mode == "exact_power":
        penalty = float(vocabulary_size ** window_size)
    else:
        raise ValueError(f"unsupported penalty_mode: {penalty_mode}")

    return {
        "mi_nats": mi_nats,
        "penalty": penalty,
        "objective": mi_nats - penalty,
        "n_windows": float(len(labeled_windows)),
        "n_distinct_binned_windows": float(len(set(binned_windows))),
    }


def sweep_vocabulary_objective(
    flows: Iterable[Union[np.ndarray, List]],
    strip_indices: Iterable[int],
    window_size: int,
    vocabulary_sizes: Iterable[int],
    *,
    fit_binner: Callable[[int], PacketSizeBinner],
    overlap_threshold: float = 0.9,
    lambda_penalty: float = 1.0,
    penalty_mode: str = "log_mdl",
) -> List[Dict[str, float]]:
    """
    Sweep vocabulary size and return MI, penalty, and objective per |V|.

    Uses all provided flows for labeling (caller controls calibration set).
    """
    labeled = collect_labeled_windows(
        flows, strip_indices, window_size, overlap_threshold
    )
    rows: List[Dict[str, float]] = []
    for vocabulary_size in vocabulary_sizes:
        binner = fit_binner(vocabulary_size)
        row = vocabulary_objective(
            labeled,
            vocabulary_size,
            binner,
            window_size=window_size,
            lambda_penalty=lambda_penalty,
            penalty_mode=penalty_mode,
        )
        row["vocabulary_size"] = float(vocabulary_size)
        rows.append(row)
    return rows


def ngram_predict(
    binned_data: Union[np.ndarray, List],
    db: Set[Tuple],
    window_size: int,
) -> List[Tuple[Tuple, int]]:
    """
    Signature-based prediction: windows in the anomaly DB are predicted anomalous (1).
    """
    binned_data = np.asarray(binned_data, dtype=np.int64)
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    if len(binned_data) < window_size:
        return []

    predictions = []
    for i in range(len(binned_data) - window_size + 1):
        window = tuple(int(v) for v in binned_data[i:i + window_size])
        pred = 1 if window in db else 0
        predictions.append((window, pred))
    return predictions


def strip_window_tuple(
    binned_flow: Union[np.ndarray, List],
    strip_indices: Iterable[int],
    window_size: int,
) -> Optional[Tuple[int, ...]]:
    """
    Extract the contiguous binned window aligned to strip_indices (starts at min index).
    Returns None if the flow is too short for that window.
    """
    if window_size <= 0:
        raise ValueError("window_size must be positive")

    windows = []
    for idx in range(len(strip_indices) - 1):
        start = strip_indices[idx]
        end = start + window_size
        binned_flow = np.asarray(binned_flow, dtype=np.int64)
        if end > len(binned_flow):
            break
        windows.append(tuple(int(v) for v in binned_flow[start:end]))
    return windows


def flow_anomaly_vote(
    binned_flow: Union[np.ndarray, List],
    db: Set[Tuple],
    window_size: int,
    *,
    strip_indices: Optional[Iterable[int]] = None,
) -> int:
    """
    Return 1 if the flow is anomalous under the signature DB.

    When strip_indices is set, only the strip-aligned window is checked (same span as
    training strip labeling). Otherwise every sliding window is checked.
    """
    if strip_indices is not None:
        windows = strip_window_tuple(binned_flow, strip_indices, window_size)
        if len(windows) == 0:
            return 0
        return int(any(window in db for window in windows))

    predictions = ngram_predict(binned_flow, db, window_size)
    return int(any(label == 1 for _, label in predictions))


def flow_protocol_votes(
    flow: Union[np.ndarray, List],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
) -> Dict[str, int]:
    """Per-protocol binary vote: 1 if the strip window is in that protocol's anomaly DB."""
    votes: Dict[str, int] = {}
    for protocol in protocols:
        binned = binners[protocol].transform(flow)
        indices = None if strip_indices is None else strip_indices[protocol]
        votes[protocol] = flow_anomaly_vote(
            binned,
            ngram_dbs[protocol],
            window_size,
            strip_indices=indices,
        )
    return votes


def flow_protocol_votes_heuristic(
    flow: Union[np.ndarray, List],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
) -> Dict[str, int]:
    """Heuristic classifier for protocol identification."""
    if abs(flow[3]) > 60 and abs(flow[3]) < 200:
        if abs(flow[4]) > 60 and abs(flow[4]) < 200:
            return {"vmess": 0, "shadowsocks": 1, "trojan": 0}
        else:
            return {"vmess": 1, "shadowsocks": 0, "trojan": 0}

    if abs(flow[3]) > 300:
        return {"vmess": 0, "shadowsocks": 0, "trojan": 1}
    
    return {"vmess": 0, "shadowsocks": 0, "trojan": 0}


def pcap_protocol_votes(
    paths: Iterable[Union[str, Path]],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
    min_len: int = 15,
) -> Dict[str, int]:
    """Sum per-flow protocol votes across all flows in a capture."""
    vote = {protocol: 0 for protocol in protocols}
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        data = np.load(path)
        if len(data["direction"]) < min_len:
            continue
        flow = data["direction"][:min_len] * data["length"][:min_len]
        flow_votes = flow_protocol_votes(
            flow,
            ngram_dbs,
            binners,
            protocols,
            window_size,
            strip_indices=strip_indices,
        )
        for protocol in protocols:
            vote[protocol] += flow_votes[protocol]
    return vote


def pcap_protocol_votes_heuristic(
    paths: Iterable[Union[str, Path]],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
    min_len: int = 15,
) -> Dict[str, int]:
    """Sum per-flow protocol votes across all flows in a capture."""
    vote = {protocol: 0 for protocol in protocols}
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        data = np.load(path)
        if len(data["direction"]) < min_len:
            continue
        flow = data["direction"][:min_len] * data["length"][:min_len]
        flow_votes = flow_protocol_votes_heuristic(
            flow,
            ngram_dbs,
            binners,
            protocols,
            window_size,
            strip_indices=strip_indices,
        )
        for protocol in protocols:
            vote[protocol] += flow_votes[protocol]
    return vote


def predict_protocol_from_votes(vote: Mapping[str, int]) -> str:
    """Return the protocol name with the highest vote (lexicographic tie-break)."""
    if not vote:
        raise ValueError("vote must not be empty")
    return max(vote, key=lambda p: (vote[p], p))


def _tied_top_protocols(vote: Mapping[str, int]) -> List[str]:
    top = max(vote.values())
    return [protocol for protocol, count in vote.items() if count == top]


def _random_protocol_choice(
    options: Iterable[str],
    rng: Optional[np.random.Generator] = None,
) -> str:
    choices = list(options)
    if not choices:
        raise ValueError("options must not be empty")
    if rng is None:
        rng = np.random.default_rng()
    return choices[int(rng.integers(0, len(choices)))]


def identify_pcap_protocol_with_fallback(
    paths: Iterable[Union[str, Path]],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
    min_len: int = 15,
    rng: Optional[np.random.Generator] = None,
) -> str:
    """
    Identify pcap protocol: strip n-gram vote, heuristic if all-zero, else argmax.

    All-zero after heuristic: random among protocols. Tied top vote: random among tied.
    """
    protocol_list = list(protocols)
    vote = pcap_protocol_votes(
        paths,
        ngram_dbs,
        binners,
        protocol_list,
        window_size,
        strip_indices=strip_indices,
        min_len=min_len,
    )
    if max(vote.values()) == 0:
        vote = pcap_protocol_votes_heuristic(
            paths,
            ngram_dbs,
            binners,
            protocol_list,
            window_size,
            strip_indices=strip_indices,
            min_len=min_len,
        )
    if max(vote.values()) == 0:
        return _random_protocol_choice(protocol_list, rng)

    tied = _tied_top_protocols(vote)
    if len(tied) > 1:
        return _random_protocol_choice(tied, rng)
    return predict_protocol_from_votes(vote)


def train_ngram_protocol_models(
    train_dir: Union[str, Path],
    protocols: Iterable[str],
    strip_indices: Mapping[str, Iterable[int]],
    window_size: int,
    lower_bound: int,
    upper_bound: int,
    vocab_sizes: Mapping[str, int],
    train_samples: Mapping[str, int],
) -> Tuple[Dict[str, Set[Tuple]], Dict[str, "PacketSizeBinner"]]:
    """Train per-protocol n-gram DB and binner from ``{protocol}.pkl`` flow lists."""
    import pickle

    train_path = Path(train_dir)
    ngram_dbs: Dict[str, Set[Tuple]] = {}
    binners: Dict[str, PacketSizeBinner] = {}
    for protocol in protocols:
        pkl_file = train_path / f"{protocol}.pkl"
        with open(pkl_file, "rb") as f:
            flows = pickle.load(f)
        binner = PacketSizeBinner.fit_uniform(
            lower_bound,
            upper_bound,
            vocabulary_size=vocab_sizes[protocol],
        )
        binners[protocol] = binner
        ngram_dbs[protocol] = train_ngram_db(
            flows[: train_samples[protocol]],
            strip_indices[protocol],
            window_size,
            binner,
        )
    return ngram_dbs, binners


def identify_protocol_pcap(
    paths: Iterable[Union[str, Path]],
    ngram_dbs: Mapping[str, Set[Tuple]],
    binners: Mapping[str, "PacketSizeBinner"],
    protocols: Iterable[str],
    window_size: int,
    *,
    strip_indices: Optional[Mapping[str, Iterable[int]]] = None,
    min_len: int = 15,
) -> str:
    """Identify proxy protocol for a pcap from accumulated n-gram votes."""
    vote = pcap_protocol_votes(
        paths,
        ngram_dbs,
        binners,
        protocols,
        window_size,
        strip_indices=strip_indices,
        min_len=min_len,
    )
    return predict_protocol_from_votes(vote)


def ngram_precision_recall(
    labeled_windows: List[Tuple[Tuple, int]],
    predictions: List[Tuple[Tuple, int]],
) -> Tuple[float, float]:
    """
    Compute precision and recall for window-level binary labels.
    """
    if len(labeled_windows) != len(predictions):
        raise ValueError("labeled_windows and predictions must have the same length")
    if not labeled_windows:
        return 0.0, 0.0

    y_true = [label for _, label in labeled_windows]
    y_pred = [label for _, label in predictions]
    return (
        float(precision_score(y_true, y_pred, zero_division=0)),
        float(recall_score(y_true, y_pred, zero_division=0)),
    )


SNI_BIN_SIZE = {
    'firefox-settings-attachments.cdn.mozilla.net': 20000, 
    'firefox.settings.services.mozilla.com': 500, 
    'content-signature-2.cdn.mozilla.net': 1000
}

def sni_cover(statistic_root: Union[str, Path], protocol: str, sni: str, coverage: float):
    """
    Compute the cover of stream size for an SNI to achieve the given coverage.

    Params
    ----------
    statistic_root : str | Path
        Root dir to store the stream size statistics, the corresponding statistics file MUST be .csv files.
    protocol : str
        The proxy protocol used 
    sni : str
        The target SNI, which decides the bin size in use. Note that the macro SNI_BIN_SIZE is a empirical value, which MAY change later
    coverage : float
        Threshold that the resulting cover occupies the whole spanning range of the arr
    """
    df = pd.read_csv(f"{statistic_root}/{sni}.csv")
    array = df[protocol].dropna().to_numpy().astype(np.int64)
    cover, actual_coverage = greedy_mass_covering(array, SNI_BIN_SIZE[sni], coverage)

    return cover, actual_coverage