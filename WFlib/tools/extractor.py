from typing import Union, List
import numpy as np
import pandas as pd

'''
COMMENT: Shall we name a class capitalizing all letters of an abbrev., e.g., extension name of a file?
         Currently, only the first letter is capitalized, please follow the convention.
'''

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
    def __init__(self, src: Union[str, List[str]], name="dir"):
        super().__init__(name=name)
        self._src = src if isinstance(src, list) else [src]

    def extract(self, df: pd.DataFrame):
        return np.where(df['ip.src'].isin(self._src), 1, -1)


class PcapDirExtractor(PcapExtractor):
    """
    The class provides methods for the packet direction extraction.

    Attributes
    ----------
    src : List[str]
        The source IP addresses for the extractor to decide ingress or egress.
    """
    def __init__(self, src: Union[str, List[str]], name="dir"):
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
    def __init__(self, name="ts", src=None):
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
