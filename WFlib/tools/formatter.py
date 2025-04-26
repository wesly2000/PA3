import numpy as np
import pyshark
import json
from pathlib import Path
import warnings
import multiprocessing
from WFlib.tools.capture import SNI_exclude_filter
from typing import Union, List
import asyncio
import os

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


class DirectionExtractor(Extractor):
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

class TimeExtractor(Extractor):
    """
    The timestamp extractor. Note that the time is relative time, i.e., the time after
    the first packet which is set to 0. 
    
    Also, when extracting timestamp, one could also pack direction information with ts, 
    e.g., an ingress packet (-1 direction) at time 0.114514s would lead to the timestamp
    -0.114514.
    """
    def __init__(self, name="time", src=None):
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

class DeltaExtractor(Extractor):
    """
    The delta time extractor. Delta time denotes for the duration between 2 consecutive packets.
    TODO: Note that since we are using display filter in analysis, one should use frame.time_delta_displayed
    instead of frame.time_delta (which is the delta when only_summaries=True in PyShark).
    """
    def __init__(self, name="delta"):
        super().__init__(name=name)

class Formatter(object):
    """
    This class provides a universal format transformer between np.array (or tensor) between all other
    network files, e.g., .pcap, .csv, .json, etc.

    Since the models of WFlib and all other util functions request .npz format, this abstract class provides
    interfaces to transform arbitrary format into .npz files. Optionally, the implement could also
    extend methods that transform the original data into other file formats.

    All other formats that use the models, except for .npz itself, SHOULD inherit this class.
    All the classes that inherit this class MUST implement the load and transform methods.
    """
    def __init__(self, length=0):
        """
        Attributes
        ----------
        length : int
            The expected length of each feature vector, once length > 0, the resulting feature vector would be
            truncated or padded to the target length; if length <= 0, no truncation/padding is performed.
        raw_buf : Any
            The buffer to hold the loaded data in raw form.

        buf : dict:
            The buffer to hold the dict data, which should be the form like {lable_1: data_1, lable_2: data_2, ...},
            where label_X is a string, and data_X should be a np.ndarray.
        """
        self._length = length
        self._raw_buf = None
        self._buf = dict()
        self._buf['hosts'] = []
        self._buf['labels'] = []

    @property
    def length(self):
        return self._length
    
    # @length.setter
    # def length(self, length):
    #     self._length = length

    def load(self, file):
        """
        The load method that read in files specified by path into raw_buf.

        Params
        ------
        file : file|str
            The file path to be read.
        """
        raise NotImplementedError
    
    def transform(self):
        """
        Transform the raw_buf to buf, which is the operation to transform any data into dict form.
        """
        raise NotImplementedError

    def dump(self, file):
        """
        The dump method that write the buf to the file specified by file.

        Params
        ------
        file : file|str
            The file path to be read.
        """

        self._buf['hosts'] = np.array(self._buf['hosts'])
        self._buf['labels'] = np.array(self._buf['labels'])
        for k in self._buf.keys():
            if k not in ['hosts', 'labels']:
                self._buf[k] = np.stack(self._buf[k])

        np.savez(file=file, **self._buf)

class PcapFormatter(Formatter):
    """
    The class to convert .pcap files to .npz files. Moreover, it supports to convert .pcap files to .json files for
    raw feature extraction (See Attributes in __init__), where no truncation/padding would be applied.
    """
    def __init__(self, length=0, only_summaries=True, keep_packets=True, display_filter=None):
        """
        Attributes
        ----------
        labels : list 
            The labels for the files used. Each file corresponds to one label.

        hosts : list
            The hostnames of the requested websites. The index of a host corresponds to the the value of the label.

        display_filter : str
            The display filter to apply to tshark when reading .pcap files.

        only_summaries : bool
            Whether to read packets with only summarizing info. This property is a PyShark attribute, which allows
            a much faster reading but much fewer messages. These messages include:
            pkt.delta         pkt.info          pkt.no            pkt.stream        pkt.window
            pkt.destination   pkt.ip id         pkt.protocol      pkt.summary_line
            pkt.host          pkt.length        pkt.source        pkt.time,
            where pkt is a packet generated from __next__ of capture.

            NOTE: only_summaries is buggy that PyShark will only read the first packet of the .pcap file. To fix 
            this issue, change the code in pyshark/tshark/output_parser/tshark_xml.py, line 25,
            FROM
            if self._parse_summaries:
            TO
            if self._parse_summaries and self._psml_structure is None:
            
            See discussion at https://github.com/KimiNewt/pyshark/issues/648

            NOTE: For the bug above, official PyShark library has fixed it in 
            https://github.com/KimiNewt/pyshark/commit/5bef3687fc821e0cc4e1606531b004ff827ad8f9,
            so if you installed the new version, the issue should no longer appear. If you have the old version
            installed and you still want only_summaries, please refer to the method above for a quick fix.

        keep_packets : bool
            Whether to keep packets in the capture. Setting to False largely reduce memory consumption.

        Ref: https://www.cnblogs.com/cscshi/p/15705070.html

        raw : bool
            The length of feature vector differs between .pcap files, since the number of valid packets differs.
            It is convenient to leverage the length variable to extract aligned feature vectors using truncation/padding.
            However, sometimes it may be useful, e.g., when the length is hard to decide, to extract the raw features 
            without truncation/padding for further processing. 

            Therefore, the raw attribute is introduced to indicate whether to truncate/pad the feature vectors. The
            reason to introduce this redundant attribute is for semantic clarity. Note that when raw is True, the data
            are stored in nested lists instead of concatenated ndarray. Further, the it would be dumped to .json files
            instead of .npz for better flexibility.

        For example, for each of the hosts in [www.baidu.com, www.google.com, www.zhihu.com], we capture 3 request 
        traces (.pcap). Then the labels after performing transform should be [0, 0, 0, 1, 1, 1, 2, 2, 2].
        """
        super().__init__(length=length)
        self._display_filter = display_filter
        self._only_summaries = only_summaries
        self._keep_packets = keep_packets
        self._raw = length <= 0

    @property
    def display_filter(self):
        return self._display_filter
    
    @display_filter.setter
    def display_filter(self, display_filter):
        self._display_filter = display_filter

    def load(self, file):
        self._raw_buf = pyshark.FileCapture(input_file=file, 
                                            display_filter=self.display_filter,
                                            only_summaries=self._only_summaries,
                                            keep_packets=self._keep_packets)

    def transform(self, host : str, label : int, *extractors : Extractor):
        """
        The transform method to extract features from self.raw_buf using the extractors. 
        
        NOTE: Ideally, the host and label parameters could be inferred from the filename. 
        However, the inference is considered not the duty of the formatter itself but that of
        the caller.

        NOTE: We defer the truncation/padding to the point when the whole .pcap is iterated
        through to keep the integrity lest some extractor depends on that. Later the lazy mode
        might be introduced to make the integrity optional.

        TODO: Introduce lazy mode.

        Params
        ------
        host : str
            The hostname of the requested website.

        label : int
            The label assigned to the features extracted from the file.

        extractors : list of Extractor
            The extractors each of which extracts the feature named after Extractor.name, note that 
            ONLY packet-level extractors should be passed. Burst/Flow-level or higher level extractors
            should be used as extended methods.
        """
        if host not in self._buf['hosts']:
            self._buf['hosts'].append(host)

        self._buf['labels'].append(label)
        tmp_buf = dict()

        for extractor in extractors:
            tmp_buf[extractor.name] = []
            # Initialize a new list for the given feature name
            if extractor.name not in self._buf:
                self._buf[extractor.name] = []
        
        # The temporaty buffer to hold the features extracted from current self._raw_buf

        for pkt in self._raw_buf:
            for extractor in extractors:
                extractor.extract(pkt, tmp_buf[extractor.name], only_summaries=self._only_summaries)

        self._raw_buf.close()

        # Dump features into ndarray, and append to self._buf[name]
        for extractor in extractors:
            if not self._raw:
                if self._length <= len(tmp_buf[extractor.name]): # Truncate
                    self._buf[extractor.name].append(np.array(tmp_buf[extractor.name][:self._length]))
                else:
                    padding = 0
                    padding_len = self._length - len(tmp_buf[extractor.name])
                    self._buf[extractor.name].append(np.array(tmp_buf[extractor.name] + [padding] * padding_len))
            else:
                self._buf[extractor.name].append(tmp_buf[extractor.name])

    def dump(self, file):
        if self._raw:  # Dump the file to .json format
            with open(file, "w") as f:
                json.dump(self._buf, f)
                return

        super().dump(file)

    def batch_extract(self, base_dir, output_file, SNIs=None, *extractors):
        """
        Extract all the given features from all the files in the given base directory.

        Params
        ------
        base_dir : str
            The base directory to hold all the .pcap files, the directory structure should be
            the same as that created by batch_capture.

        output_file : str
            The file to store all the features extracted.

        extractors : Extractor
            The extractors for feature extraction.
        """
        base_dir_path = Path(base_dir)
        label = 0  # Processing a hostname will increase the label by 1

        # Iterate over all subdirectories in the base directory
        for subdir in sorted(base_dir_path.iterdir()):
            if subdir.is_dir():  # Check if it's a directory
                # print(f"Processing directory {subdir.name}")
                host = subdir.name #  Consider using subdir.name
                for file in subdir.iterdir():
                    if file.is_file() and file.suffix in ['.pcapng', '.pcap']:  # Ensure it's a pcap(ng) file
                        display_filter = SNI_exclude_filter(file, SNIs)
                        self.display_filter = display_filter
                        self.load(file=file)
                        self.transform(host, label, *extractors)
                label += 1

        self.dump(output_file)

class DistriPcapFormatter(PcapFormatter):
    """
    The distributed (multi-process) version of PcapFormatter. We trigger each process to handle one host (sub-directory)
    separately. We need to align the host order among different base directory, e.g., normal and vmess. However, and the
    order of multi-process extract is hard to control. 

    Therefore, the distributed batch_extract follows the process-then-merge paradigm: Each process handles one host and
    the result is stored in a un-ordered list. After all hosts are processed, the formatter will order the content of the
    list according to some given host order.

    For example, suppose the base dir contains 'www.google.com', 'www.baidu.com' and 'yandex.com'. The given host order is
    the alphabetical order of them, i.e., ['www.baidu.com', 'www.google.com', 'yandex.com']. Suppose the hosts are finished
    in the order ['yandex.com', 'www.baidu.com', 'www.google.com']. Then, the un-ordered list should be:
    [('yandex.com', X_1), ('www.baidu.com', X_2), ('www.google.com', X_3)]. 
    
    Afterwards, one should order them following the given order, which leads to:
    [('www.baidu.com', X_2), ('www.google.com', X_3), ('yandex.com', X_1)]. 

    Finally, we make similar buffer as in PcapFormatter for later dump.

    c.sort(key=lambda x: x[0])
    """
    def __init__(self, length=0, only_summaries=True, keep_packets=True, display_filter=None, num_worker=4):
        super().__init__(length, only_summaries, keep_packets, display_filter)
        self._num_worker = num_worker

    def load(self, file):
        raise NotImplementedError()

    def transform(self, host : str, label : int, *extractors : Extractor):
        raise NotImplementedError()
    
    def load_and_transform(self, buf, file, *extractors : Extractor):
        # BUG: Running all pytest suite causes DistriPcapFormatter to raise
        # RuntimeError: Event loop is already running.
        # This error might raise with the same reason as that in Jupyter Notebook.
        # Explicitly creating a event loop seems to (partially) solve this issue.

        # This method is mentioned in https://github.com/KimiNewt/pyshark/issues/674,
        # note that on Linux, SelectorEventLoop should be used, while ProactorEventLoop is used on Windows.
        # However, on Windows it seems that this error does not occur due to a previous
        # fix (https://github.com/KimiNewt/pyshark/commit/78b48d65a7b3745456c30e37b1ebac75af984657).
        # Therefore, we only create explicit event loop when the platform is *nix.
        # UPDATE: The issue remains, no idea about this:(

        tmp_buf = {extractor.name : [] for extractor in extractors}

        cap = pyshark.FileCapture(input_file=file, 
                                  display_filter=self.display_filter,
                                  only_summaries=self._only_summaries,
                                  keep_packets=self._keep_packets)
        
        for pkt in cap:
            for extractor in extractors:
                extractor.extract(pkt, tmp_buf[extractor.name], only_summaries=self._only_summaries)

        cap.close()

        # Dump features into ndarray, and append to self._buf[name]
        for extractor in extractors:
            if not self._raw:
                if self._length <= len(tmp_buf[extractor.name]): # Truncate
                    buf[extractor.name].append(np.array(tmp_buf[extractor.name][:self._length]))
                else:
                    padding = 0
                    padding_len = self._length - len(tmp_buf[extractor.name])
                    buf[extractor.name].append(np.array(tmp_buf[extractor.name] + [padding] * padding_len))
            else:
                buf[extractor.name].append(tmp_buf[extractor.name])

    def batch_extract(self, base_dir, output_file, SNIs=None, *extractors: Extractor):
        '''
        Example
        -------
        Suppose we have two sub-directories under the base, say /home/base/www.google.com and /home/base/www.baidu.com. Moreover,
        we used 2 extractors, which representing feature_1, feature_2, respectively.
        self._raw_buf is initially an empty list.

        The hosts are 'www.google.com', 'www.baidu.com'. Then, self. should be
        [
            ('www.google.com', {'feature_0': [X_0, X_1, ..., X_m], 'feature_1': [Y_0, Y_1, ..., Y_m]}), 
            ('www.baidu.com',  {'feature_0': [X_0, X_1, ..., X_n], 'feature_1': [Y_0, Y_1, ..., Y_n]})
        ],
        where each feature should be an np.array of shape (1, self._length).

        Afterwards, we sort self._raw_buf in-place according to the alphabetical order of the hostname, which leads to
        [
            ('www.baidu.com',  {'feature_0': [X_0, X_1, ..., X_n], 'feature_1': [Y_0, Y_1, ..., Y_n]}),
            ('www.google.com', {'feature_0': [X_0, X_1, ..., X_m], 'feature_1': [Y_0, Y_1, ..., Y_m]}), 
        ],
        then we send these elements to self._buf along with labels, whose structure is consistent with that of PcapFormatter.
        {
            'hosts': ['www.baidu.com', 'www.google.com'],
            'labels': [0, 0, 0, ..., 0 (n 0's), 1, 1, ..., 1 (m 1's)],
            'feature_0': [X_0, X_1, ..., X_n, X_0, X_1, ..., X_m],
            'feature_1': [Y_0, Y_1, ..., Y_n, Y_0, Y_1, ..., Y_m]
        }, 
        which could be dumped into .npz.
        '''
        base_dir_path = Path(base_dir)
        subdir_list = sorted(filter(lambda subdir: subdir.is_dir(), base_dir_path.iterdir()))
        # hosts = [subdir.name for subdir in subdir_list]
        with multiprocessing.Manager() as manager:
            self._raw_buf = manager.list()
            num_workers = self._num_worker

            with multiprocessing.Pool(num_workers) as pool:
                # Note that multiprocessing uses pickle to dump the single-process task, and it re-import the task
                # during the execution. Therefore, the single-process task must in the top-level (importable) scope.
                # See https://stackoverflow.com/questions/72766345/attributeerror-cant-pickle-local-object-in-multiprocessing.
                pool.starmap(single_dir_batch_extract, [(self, SNIs, subdir, self._raw_buf, *extractors) for subdir in subdir_list])

            self._raw_buf = list(self._raw_buf)
        # Merge stage
        # First, we sort self._raw_buf according to the alphabetical order of the hostnames.
        self._raw_buf.sort(key=lambda x: x[0])
        label = 0
        for (host, array_dict) in self._raw_buf:
            num = len(array_dict[extractors[0].name]) # Fetch the number of samples within a host
            self._buf['labels'] += [label] * num 
            self._buf['hosts'].append(host)
            for extractor in extractors:
                if extractor.name in self._buf:
                    self._buf[extractor.name] += array_dict[extractor.name]
                else:
                    self._buf[extractor.name] = array_dict[extractor.name]
            label += 1

        self.dump(output_file)
        
def single_dir_batch_extract(formatter : DistriPcapFormatter, SNIs : None, subdir : Path, results : list, *extractors : Extractor):
    """
    Extract the feature array for the subdir, and prepend the name of the host to it
    to extract the Name-Feature pair.

    Params
    ------
    subdir : Path
        The sub-directory to extract the feature array.

    results : list
        The pool to append all the sub-process results.
    """
    print(f"Processing directory {subdir.name}")
    host = subdir.name #  Consider using subdir.name
    buf = {extractor.name : [] for extractor in extractors}
    for file in subdir.iterdir():
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:  # Ensure it's a pcap(ng) file
            display_filter = SNI_exclude_filter(file, SNIs)
            formatter.display_filter = display_filter
            formatter.load_and_transform(buf, file, *extractors)

    results.append((host, buf))


class JsonFormatter(Formatter):
    """
    The formatter for .json files. This file includes some extensive utility functions for feature post-processing.
    """
    def __init__(self):
        super().__init__()

    def load(self, file):
        self._raw_buf = json.load(file)

    def transform(self, debug=True, **kwargs):
        """
        The function to align each feature to the corresponding length. The kwargs is like {name_1: length_1, ..., name_n: length_n}.
        For each name, this function tries to fetch them and ignore those not in the self._raw_buf with warnings. 
        
        Note that the special name 'labels' and 'hosts' should not be used since they are not features. If you find the warnings
        annoying you could turn it off by setting debug=False.
        """
        if not debug:
            warnings.filterwarnings('ignore')

        self._buf['labels'] = np.array(self._raw_buf['labels'])
        self._buf['hosts'] = np.array(self._raw_buf['hosts'])

        for name, length in kwargs.items():
            if name in ['labels', 'hosts']:
                warnings.warn("Names 'labels' and 'hosts' are reserved and could not used for truncation/padding.")
                continue 
            elif name not in self._raw_buf:
                warnings.warn(f"Key {name} is not present in the data.")
                continue
            else:
                if name not in self._buf:
                    self._buf[name] = []  # Create corresponding container if not exist
                for feature in self._raw_buf[name]:  # Iterate through all the feature vectors and do truncation/padding
                    if length <= len(feature): # Truncate
                        self._buf[name].append(np.array(feature[:length]))
                    else:
                        padding = 0
                        padding_len = length - len(feature)
                        self._buf[name].append(np.array(feature + [padding] * padding_len))

    def get_feature_buf(self, name):
        """
        Get the un-transformed feature buffer by its name.
        """
        return self._raw_buf[name]