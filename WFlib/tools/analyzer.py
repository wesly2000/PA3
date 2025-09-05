# from captum import attr
from tqdm import tqdm
# import torch
import numpy as np
import pyshark 
from pathlib import Path
import re
from typing import List, Tuple, Union
import pandas as pd
from WFlib.utils.statistics import jaccard_similarity

AES_128_GCM_TAG_LEN = 16
CHACHA20_POLY1305_TAG_LEN = 16

PROTOCOL_REASSEMBLE_FIELD = {
    "tls": "tls_segments",
    "tcp": "tcp_segments",
    "vmess": "vmess_fragments",
    "shadowsocks": "shadowsocks_msg_fragments",
    "trojan": "trojan_fragments"
}

# def feature_attr(model, attr_method, X, y, num_classes):
#     """
#     Calculate feature attributions for a given model using a specified attribution method.
    
#     Args:
#     - model: The neural network model to interpret.
#     - attr_method: The attribution method to use (e.g., 'DeepLiftShap').
#     - X: The input data (features) as a numpy array or torch tensor.
#     - y: The labels for the input data.
#     - num_classes: The number of distinct classes in the data.
    
#     Returns:
#     - attr_values: An array of attribution values for each class.
#     """
    
#     # Set the model to evaluation mode
#     model.eval()
    
#     # Initialize the attribution model based on the chosen method
#     if attr_method in ["DeepLiftShap"]:
#         attr_model = eval(f"attr.{attr_method}")(model)
#     else:
#         attr_model = eval(f"attr.{attr_method}")(model.forward)
    
#     # Prepare background and test data for each class
#     bg_traffic = []
#     test_traffic = {}
#     for web in range(num_classes):
#         bg_test_X = X[y == web]
#         assert bg_test_X.shape[0] >= 12
#         bg_traffic.append(bg_test_X[0:2])  # Use the first 2 samples as background
#         test_traffic[web] = bg_test_X[2:12]  # Use the next 10 samples for testing

#     # Concatenate all background traffic into a single tensor
#     bg_traffic = torch.concat(bg_traffic, axis=0)

#     attr_values = []
#     # Iterate over each class to calculate attribution values
#     for web in tqdm(range(num_classes)):
#         # Calculate attributions for the test samples using the background samples
#         attr_result = attr_model.attribute(test_traffic[web], bg_traffic, target=web)
#         # Aggregate the attribution results
#         attr_result = attr_result.detach().numpy().squeeze().sum(axis=0).sum(axis=0)
#         attr_values.append(attr_result)
    
#     attr_values = np.array(attr_values)
#     return attr_values  # Return the attribution values

def packet_count(capture):
    """
    Count the number of packets within the given capture, possible display filter may be applied.
    """
    cnt = 0
    for _ in capture:
        cnt += 1
    return cnt

def file_count(base_dir : Path):
    '''
    For each subdirectory (per represents a website) in the base_dir,
    count the number of .pcap(ng) files and put the results in a dict.
    '''
    cnt = dict()
    subdirs = list(filter(lambda x: x.is_dir(), base_dir.iterdir()))

    for subdir in sorted(subdirs):
        cnt[subdir.name] = sum(1 for _ in filter( # Only count pcap(ng) files
                lambda x: x.is_file() and x.suffix in ['.pcapng', '.pcap'], subdir.iterdir()
                )
            )

    return cnt

# TODO: Consider replace all the non-HTTP counter's count method to only count the underlying
# TCP/UDP payload length.

class ByteCounter():
    """
    Abstraction of protocol specific byte counter.

    Attribute
    ---------
    name : str
        The name of the byte counter, commonly it should be the name the protocol.
    """
    def __init__(self, name):
        self.name = name

    def layer_count(self, layer, extra_data = None) -> int:
        """
        Count the number of layers of the given protocol within the given packet.
        """
        raise NotImplementedError()

    def packet_count(self, pkt) -> int:
        """
        Count the byte number of proto layer within the given packet.
        """
        raise NotImplementedError()
    

class HTTP3ByteCounter(ByteCounter):
    def __init__(self, name='http3'):
        super().__init__(name)
        self.uni_stream_hdr_len = 1  # The length of HTTP/3 unidirectional stream type

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        # if hasattr(h3_layer, "stream_uni_type"):
        #     for sut in h3_layer.stream_uni_type.all_fields:
        #         cnt += int(sut.size)  # Uni Stream has one extra stream type byte
        if hasattr(layer, "stream_uni"):
            cnt += int(layer.stream_uni.size)
            return cnt  # It seems that in Wireshark, UNI Stream has contained the length including the frames within
        # Note that HTTP/3 frame length and type are both variable-length integers.
        if hasattr(layer, "frame_length"):
            # Some HTTP/3 packets may not have frame length/type field.
            for fl in layer.frame_length.all_fields:
                cnt += int(fl.showname_value) + int(fl.size)
            for ft in layer.frame_type.all_fields:
                cnt += int(ft.size)

        return cnt

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "HTTP3" in pkt:
            h3_layers = filter(lambda layer: layer.layer_name == "http3", pkt.layers)
            h3_layer_lengths = map(self.layer_count, h3_layers)
            cnt += sum(h3_layer_lengths)

        return cnt

class HTTP2ByteCounter(ByteCounter):
    def __init__(self, name='http2'):
        super().__init__(name)
        self.preface_len = 24  # HTTP/2 Connection Preface
        self.header_len = 9  # 9-octet header

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.length) + self.header_len if hasattr(layer, "length") else self.preface_len
    
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "HTTP2" in pkt:  # Check if HTTP/2 is present in the decrypted packet
            h2_layers = filter(lambda layer: layer.layer_name == "http2", pkt.layers)
            h2_layer_lengths = map(self.layer_count, h2_layers)
            cnt += sum(h2_layer_lengths)

        return cnt
    

class TLSByteCounter(ByteCounter):
    def __init__(self, name='tls'):
        super().__init__(name)
        self.type_len = 1  # TLS record type
        self.ver_len = 2  # TLS version
        self.length_len = 2  # TLS record length

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        # The method to iterate through all records within a TLS layer is provided by
        # https://github.com/KimiNewt/pyshark/issues/419
        for rl in layer.record_length.all_fields:  # Each TLS layer may contain multiple TLS records
            cnt += int(rl.showname_value) + self.type_len + self.ver_len + self.length_len

        return cnt

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "TLS" in pkt:  
            tls_layers = filter(lambda layer: layer.layer_name == "tls", pkt.layers)  # One packet may contain multiple TLS layers
            tls_layer_lengths = map(self.layer_count, tls_layers)
            cnt += sum(tls_layer_lengths)

        return cnt
    

class QUICByteCounter(ByteCounter):
    def __init__(self, name='quic'):
        super().__init__(name)
        self.udp_hdr_len = 8  # UDP header length

    def layer_count(self, layer, extra_data = None) -> int:
        """
        TODO: QUIC leverages UDP to do packet counting, try to isolate this issue.
        """
        raise NotImplementedError("QUICByteCounter.layer_count is not implemented, since the isolation of UDP is not done yet.")

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "QUIC" in pkt:  
            quic_packets = filter(lambda layer: layer.layer_name == "quic", pkt.layers)  # One packet may contain multiple QUIC packets (QUIC uses packet instead of layer as its PDU)
            for quic_packet in quic_packets:  
                # If the packet has coalesced padding data, the length of the packet is equal to the
                # UDP payload data length. See the discussions below:
                # https://github.com/quicwg/base-drafts/issues/3333 (0-padding outside of QUIC packets)
                # https://github.com/mozilla/neqo/pull/1850 (0-padding seems not changed)
                if hasattr(quic_packet, "coalesced_padding_data"):
                    cnt = int(pkt['udp'].length) - self.udp_hdr_len
                    break
                # It seems that a QUIC packet already contains the length of the packet.
                # We don't need to calculate each QUIC frame length as TLS records.
                cnt += int(quic_packet.packet_length)

        return cnt

class TCPByteCounter(ByteCounter):
    def __init__(self, name='tcp'):
        super().__init__(name)

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.len) + int(layer.hdr_len)
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "TCP" in pkt:  
            tcp_layer = pkt['tcp']
            cnt += self.layer_count(tcp_layer)

        return cnt
    

class UDPByteCounter(ByteCounter):
    def __init__(self, name='udp'):
        super().__init__(name)

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.length)  # udp.length already contains the length of the UDP header
 
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "UDP" in pkt:  
            udp_layer = pkt['udp']
            cnt += self.layer_count(udp_layer)

        return cnt
    

class VMessByteCounter(ByteCounter):
    TYPE_REQUEST = '1'
    TYPE_RESPONSE = '2'
    TYPE_DATA = '3'  # The VMess Data layer, DO NOT confuse with the DATA layer in reassemble.
    def __init__(self, name='vmess'):
        super().__init__(name)
        self.auth_len = 16  # VMess authentication length
        self.nonce_len = 8   # VMess nonce length
        # According to Clash Imple., VMess response header contains 4 bytes.
        # The port command is not used. See https://xtls.github.io/development/protocols/vmess.html
        self.response_hdr_len = 4  
        # According to Clash Imple., VMess with AEAD contains a length field of size 2 for each request and response.
        # Moreover, the size of length field in Data layer coincide with the value, we abuse the notation.
        self.length_len = 2  

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        if layer.layer_type == self.TYPE_REQUEST:
            # In AEAD mode of Clash Imple., the length and request are encrypted separately, each of which
            # contains a 16-byte (AES-128-GCM, which is commonly used) authentication tag.
            cnt += self.auth_len + self.nonce_len + self.length_len + AES_128_GCM_TAG_LEN + int(layer.request_length) + AES_128_GCM_TAG_LEN
        elif layer.layer_type == self.TYPE_RESPONSE:  
            # FIX: The attached VMess Data frame is now considered as a part of the response.
            cnt += self.response_hdr_len + AES_128_GCM_TAG_LEN + self.length_len + AES_128_GCM_TAG_LEN + self.length_len + int(layer.payload_length)
        elif layer.layer_type == self.TYPE_DATA:
            cnt += self.length_len + int(layer.payload_length)
        else:
            raise ValueError(f"Unknown VMess layer type: {layer.layer_type}")

        return cnt

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "VMess" in pkt:  
            vmess_layers = filter(lambda layer: layer.layer_name == "vmess", pkt.layers)  # One packet may contain multiple TLS layers
            vmess_layer_lengths = map(self.layer_count, vmess_layers)
            cnt += sum(vmess_layer_lengths)

        return cnt
    

class ShadowsocksByteCounter(ByteCounter):
    TYPE_SALT = '1'
    TYPE_RELAY_HEADER = '2'
    TYPE_STREAM_DATA = '3'
    def __init__(self, name='shadowsocks'):
        super().__init__(name)
        self.salt_len = 32  # The length of the salt
        # According to Clash Imple., Shadowsocks with AEAD contains a length field of size 2 for each relay header.
        # Moreover, the size of length field in Stream Data layer coincide with the value, we abuse the notation.
        self.length_len = 2  
        self.port_len = 2  # The length of the port
        self.domain_type_len = 1  # The length of the domain type
        self.domain_length_len = 1  # The size of the domain length

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        if layer.layer_type == self.TYPE_SALT:
            cnt += self.salt_len
        elif layer.layer_type == self.TYPE_RELAY_HEADER:  
            # In AEAD mode of Clash Imple., the Shadowsocks length and request are encrypted separately, each of which
            # contains a 16-byte (AES-128-GCM, which is commonly used) authentication tag.
            cnt += self.port_len + self.domain_type_len + self.domain_length_len + int(layer.dst_addr_domainname_len) + CHACHA20_POLY1305_TAG_LEN + self.length_len + CHACHA20_POLY1305_TAG_LEN
        elif layer.layer_type == self.TYPE_STREAM_DATA:
            cnt += self.length_len + CHACHA20_POLY1305_TAG_LEN + int(layer.payload_length) + CHACHA20_POLY1305_TAG_LEN
        else:
            raise ValueError(f"Unknown Shadowsocks layer type: {layer.layer_type}")

        return cnt
    
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "Shadowsocks" in pkt:  
            ss_layers = filter(lambda layer: layer.layer_name == "shadowsocks", pkt.layers)  # One packet may contain multiple TLS layers
            ss_layer_lengths = map(self.layer_count, ss_layers)
            cnt += sum(ss_layer_lengths)

        return cnt
    
class TrojanByteCounter(ByteCounter):
    TYPE_TLS = '1'
    TYPE_HTTP = '2'

    type_len = 1  # Trojan record type
    ver_len = 2  # Trojan version
    length_len = 2  # Trojan record length

    def __init__(self, name='trojan'):
        super().__init__(name)

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        try:
            for rl in layer.record_length.all_fields:  
                cnt += int(rl.showname_value) + self.type_len + self.ver_len + self.length_len
        except AttributeError as _:
            for rl in layer.tls_record_length.all_fields:
                cnt += int(rl.showname_value) + self.type_len + self.ver_len + self.length_len

        return cnt
    
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "Trojan" in pkt:  
            trojan_layers = filter(lambda layer: layer.layer_showname == "trojan", pkt.layers)  # One packet may contain multiple TLS layers
            trojan_layer_lengths = map(self.layer_count, trojan_layers)
            cnt += sum(trojan_layer_lengths)

        return cnt
    
PROTOCOL_BYTE_COUNTER = {
    "tls": TLSByteCounter(),
    "tcp": TCPByteCounter(),
    "http2": HTTP2ByteCounter(),
    "vmess": VMessByteCounter(),
    "shadowsocks": ShadowsocksByteCounter(),
    "trojan": TrojanByteCounter(),
}

class CaptureCounter():
    def __init__(self, *counters: ByteCounter):
        self.counters = counters
        

    def count(self, cap):
        result = {counter.name: [0, 0] for counter in self.counters}  # The byte count of each protocol within the capture.
        for pkt in cap:
            for counter in self.counters:
                cnt = counter.packet_count(pkt)
                if cnt > 0:
                    result[counter.name][0] += 1  # The number of packets with non-zero byte count.
                result[counter.name][1] += cnt  

        return result
    

class Cell():
    """
    Abstraction of Wireshark PDU for any protocol. The comparison (<, >, ==, <=, >=) is for partial order.
    Especially, the == operator checks if two cells have the same abs_frame_number and abs_segment_frame_number.
    Don't use it as a check for all the attributes of two cells.
    """
    def __init__(self, upper_protocol, lower_protocol, abs_frame_number):
        self.upper_protocol = upper_protocol
        self.lower_protocol = lower_protocol
        self.abs_frame_number = abs_frame_number 
        self.abs_segment_frame_number = []
        self.rel_frame_number = None
        self.rel_segment_frame_number = []
        self.segment_size = []
        self.size = 0

    def __eq__(self, other):
        if not isinstance(other, Cell):
            raise TypeError("Can only compare with another Cell object")
        if self.upper_protocol != other.upper_protocol or self.lower_protocol != other.lower_protocol:
            raise ValueError(f"Cannot compare {self} with {other}, since they are not from the same protocol.")
        if self.abs_frame_number == other.abs_frame_number and \
            self.abs_segment_frame_number == other.abs_segment_frame_number:
            return True
        else:
            return False
        
    def __lt__(self, other):
        if not isinstance(other, Cell):
            raise TypeError("Can only compare with another Cell object")
        
        if self.upper_protocol != other.upper_protocol or self.lower_protocol != other.lower_protocol:
            raise ValueError(f"Cannot compare {self} with {other}, since they are not from the same protocol.")
        
        if self.abs_frame_number < other.abs_frame_number:
            assert max(self.abs_segment_frame_number) <= max(other.abs_segment_frame_number), "Bad Order: Previous frame has segments beyond the next frame."
            return True

        elif self.abs_frame_number > other.abs_frame_number:
            assert max(self.abs_segment_frame_number) >= max(other.abs_segment_frame_number), "Bad Order: Next frame has segments before the previous frame."
            return False
        
        else:  # If the two cells are from the same frame, compare there segment number.
            if self == other:
                return False
            else:  # Their segment number are not the same.
                # TODO: more complicated check, for sanity check here, e.g., self.abs_segment_frame_number = [2, 3] and other.abs_segment_frame_number = [1, 2, 3, 4], such case MUST NOT happen.
                if min(self.abs_segment_frame_number) < min(other.abs_segment_frame_number):
                    return True
                else:
                    return False
                
    def __gt__(self, other):
        if not isinstance(other, Cell):
            raise TypeError("Can only compare with another Cell object")

        if self.upper_protocol != other.upper_protocol or self.lower_protocol != other.lower_protocol:
            raise ValueError(f"Cannot compare {self} with {other}, since they are not from the same protocol.")

        if self.abs_frame_number > other.abs_frame_number:
            assert max(self.abs_segment_frame_number) >= max(other.abs_segment_frame_number), "Bad Order: Next frame has segments before the previous frame."
            return True 

        elif self.abs_frame_number < other.abs_frame_number:
            assert max(self.abs_segment_frame_number) <= max(other.abs_segment_frame_number), "Bad Order: Previous frame has segments beyond the next frame."
            return False

        else:  # If the two cells are from the same frame, compare there segment number.
            if self == other:
                return False
            else:  # Their segment number are not the same.
                # TODO: more complicated check, for sanity check here, e.g., self.abs_segment_frame_number = [2, 3] and other.abs_segment_frame_number = [1, 2, 3, 4], such case MUST NOT happen.
                if max(self.abs_segment_frame_number) > max(other.abs_segment_frame_number):
                    return True
                else:
                    return False
                
class CellExtractor(object):
    """
    Select the reassemble info related field for each protocol in DATA layer.
    """
    def __init__(self):
        self._name = "abstract" 

    @property
    def name(self):
        return self._name
    
    def layer_extract(self, layer, frame_number: int, lower_protocol) -> Cell:
        cell = Cell(upper_protocol=self.name, lower_protocol=lower_protocol, abs_frame_number=frame_number)
        
        if lower_protocol is not None and layer.layer_name == "DATA":
            # Make tls_segments to more generic.
            for segment_frame_number, segment_size in match_segment_number(
                layer.get_field(
                    PROTOCOL_REASSEMBLE_FIELD[lower_protocol]
                    )
                ):

                cell.abs_segment_frame_number.append(segment_frame_number)
                cell.segment_size.append(segment_size)

        elif layer.layer_name == self.name:
            counter = PROTOCOL_BYTE_COUNTER[self.name]
            cell.abs_segment_frame_number.append(frame_number)
            cell.segment_size.append(counter.layer_count(layer))

        else:
            raise ValueError(f"Protocol mismatch: only support {self.name} and DATA layer, but got {layer.layer_name}")
        
        cell.size = sum(cell.segment_size)
        
        return cell
    
    def extract(self, pkt, lower_protocol: str) -> List[Cell]:
        """
        Extract reassemble information from the given packet with the given protocol.

        Params
        ------
        pkt: 
            The packet to extract reassemble information from.
        lower_protocol: str | None
            The protocol to extract reassemble information from. If None, this function does not
            extract reassemble information from the given packet. Please always set it to
            not None value unless you are extracting the reassemble info for the lowest protocol
            in a protocol stack, whose reassemble info is not needed or not implemented.
        """
        lower_protocol = lower_protocol.lower()
        filtered_layers = seq_filter(layer_extractor(pkt, self.name, lower_protocol), lower_protocol)
        cells = []

        for layer in filtered_layers:
            cell = self.layer_extract(layer, int(pkt.number), lower_protocol)
            cells.append(cell)
        
        return cells
    

class HTTP2CellExtractor(CellExtractor):
    def __init__(self):
        self._name = "http2"

    def extract(self, pkt, lower_protocol="tls") -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class TLSCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "tls"

    def extract(self, pkt, lower_protocol="tcp") -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class VMessCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "vmess"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class ShadowsocksCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "shadowsocks"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class TCPCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "tcp"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class TrojanCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "trojan"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)


PROCOCOL_CELL_EXTRACTOR = {
    "tcp": TCPCellExtractor(),  
    "tls": TLSCellExtractor(),
    "vmess": VMessCellExtractor(),
    "http2": HTTP2CellExtractor(),
    "shadowsocks": ShadowsocksCellExtractor(),
    "trojan": TrojanCellExtractor(),
}
                
class Packet():
    """
    Abstraction of Wireshark packet, whose bytes comes from the Cells with the same abs_frame_number and protocol.
    For example, an HTTP/2 Packet consists of a list of HTTP/2 Cells with the same abs_frame_number. Packet object
    merges the segments in the cells with the same frame number, which is more continuous, and avoids repetitive
    segment information. Therefore, using Frame the caller is responsible to assure all the cells have the same
    frame number.

    Packet uses dictionary to store segment information, which should be more convenient to fetch values.

    The partial order of packets only depends on frame number.
    """
    def __init__(self, cells: List[Cell] = None):
        self._segments = dict()
        # If cells is not None, initialize the packet with the cells.
        self.upper_protocol = None
        self.lower_protocol = None
        self.abs_frame_number = None
        if cells is not None:
            self.upper_protocol = cells[0].upper_protocol  
            self.lower_protocol = cells[0].lower_protocol  
            # The absolute frame number is the same as the cells' abs_frame_number
            self.abs_frame_number = cells[0].abs_frame_number  
            for cell in cells:
                for segment_frame_number, segment_size in zip(cell.abs_segment_frame_number, cell.segment_size):
                    # Merge sizes with the same segment_frame_number
                    self._segments[segment_frame_number] = self._segments.setdefault(segment_frame_number, 0) + segment_size

    @property
    def segments(self):
        return self._segments
    
    @segments.setter
    def segments(self, segments):
        self._segments = segments

    def __lt__(self, other):
        if not isinstance(other, Packet):
            raise TypeError("Can only compare with another Packet object")
        
        return self.abs_frame_number < other.abs_frame_number
    
    def __gt__(self, other):
        if not isinstance(other, Packet):
            raise TypeError("Can only compare with another Packet object")
        
        return self.abs_frame_number > other.abs_frame_number

class Line():
    """
    The compound of two list of Cells, each line is the abstract representation of a stream byte-segment map 
    between the given upper protocol and lower protocol. 
    
    For example, a line with upper protocol HTTP/2 and lower protocol TLS within stream 1 represents the following:

    HTTP/2 Layer     -------------       ---------------      --------     ----------------------
                     |     |\     \      |  | \       \   
                     |     | \     \     |  |  \       \ 
                     |     |  \     \    |  |   \       \     ...  
                     |     |   \     \   |  |    \       \ 
                     |     |    \     \ /   /     \       \ 
    TLS Layer     ----------  --------------    -----------      --------------      --------------------
    """
    def __init__(self, 
                 upper_packets: List[Packet], 
                 lower_abs_frame_numbers: List[int],
                 sanity_check = False
                 ):
        self._upper_protocol = upper_packets[0].upper_protocol
        self._lower_protocol = upper_packets[0].lower_protocol
        self._upper_packets = sorted(upper_packets)  # Defer the sorting to the Line instead of CellExtractor
        
        """
        COMMENT: Shall we make lower_abs_frame_numbers a dict, whose values indicate the relative
        index of each lower frame?
        Currently, such work is deferred to generate_byte_stream, and the line does not maintain
        that dict.
        """
        self._lower_abs_frame_numbers = lower_abs_frame_numbers

        if sanity_check:
            self.sanity_check()

        self._upper_abs_byte_map = None  # COMMENT: shall we build the map in lazy mode?
        self._lower_span_map = None  # COMMENT: shall we build the map in lazy mode?
        self._byte_counter = 0  # Count how many bytes in the upper layer in total

    def continunity_check(self):
        """
        Continunity Check: All cover, sorted by their beginning (or ending) point, should be continuous
        as a byte stream.
        """
        if len(self.upper_abs_byte_map) <= 1:
            return True  # We define that when there are less than 2 covers within a map, it is continuous

        total_covers = []
        for covers in self.upper_abs_byte_map.values():
            total_covers += covers

        total_covers.sort(key=lambda x: x[0])

        for i in range(len(total_covers) - 1):
            if total_covers[i][1] != total_covers[i+1][0]:
                return False 
            
        return True

    def sanity_check(self):
        """
        Check if the line is valid.
        
        TODO: Implement cell_order_check and frame_contain_check.
        """
        def cell_order_check(cells):
            raise NotImplementedError() 

        def frame_contain_check(lower_abs_frame_numbers, upper_abs_frame_numbers):
            raise NotImplementedError()
        
    @property
    def byte_counter(self):
         # byte_counter needs to iterate through the upper_cells, build the map together.
        if self._upper_abs_byte_map is None: 
                self.upper_rel_building()
        return self._byte_counter

    @property
    def upper_abs_byte_map(self):
        if self._upper_abs_byte_map is None:  # Lazy build the map if not built yet.
            self.upper_rel_building()
        return self._upper_abs_byte_map
    
    @property
    def lower_span_map(self):
        if self._lower_span_map is None:  # Lazy build the map if not built yet.
            self.lower_span_building()
        return self._lower_span_map
    
    @property
    def lower_abs_frame_numbers(self):
        return self._lower_abs_frame_numbers
    
    @property
    def upper_protocol(self):
        return self._upper_protocol
    
    @property
    def lower_protocol(self):
        return self._lower_protocol
    
    @property
    def upper_packet_frame_numbers(self):
        """
        We only provide the frame numbers of the upper packets instead of packets for protection.
        """
        return [packet.abs_frame_number for packet in self._upper_packets]

    def upper_rel_building(self):
        """
        Build the relative reassemble information for upper layer according to their absolute frame number.
        Upper relative reassemble contains which lower frame (abs) contains which bytes in upper layer.
        """
        byte_counter = 0  # Count how many bytes in the upper layer in total
        # COMMENT: shall we explicitly create closed-interval or right-open interval then use for-loop 
        #          to implicitly ignore the last byte index?
        upper_abs_byte_map = dict()

        for packet in self._upper_packets:
            for segment_frame_number, segment_size in sorted(packet.segments.items()):
                if segment_frame_number in upper_abs_byte_map:
                    upper_abs_byte_map[segment_frame_number].append(  # If the segment frame number is already in the map, update the byte range
                        (byte_counter, byte_counter + segment_size)
                    )
                else:  # If the segment frame number is not in the map, create the entry
                    upper_abs_byte_map[segment_frame_number] = [(byte_counter, byte_counter + segment_size)]

                byte_counter += segment_size  # Update the byte counter

        self._byte_counter = byte_counter

        self._upper_abs_byte_map = upper_abs_byte_map

    def lower_span_building(self):
        lower_span_map = dict()
        for lower_segment_frame_number in self._upper_abs_byte_map:
            lower_span_map[lower_segment_frame_number] = self.span(lower_segment_frame_number)

        self._lower_span_map = lower_span_map 

    def seg(self, upper_abs_frame_number: int) -> dict:
        """
        Given the absolute frame number of a upper layer frame, return its segment and segment size list.
        For example, an HTTP/2 frame, say Frame 25 might be reassembled by multiple TLS frames, say Frame 23, 24, 25, where TLS Frame 23 contributes 20 bytes, Frame 24 contributes 10 bytes, and Frame 25 contributes 26 bytes. Then the segments of the HTTP/2 frame are {23: 20, 24: 10, 25: 26}.
        """
        for packet in self._upper_packets:
            if packet.abs_frame_number == upper_abs_frame_number:
                return packet.segments
            
        raise ValueError(f"No packet found with frame number {upper_abs_frame_number}")

    def span(self, lower_abs_frame_number: int) -> dict:
        """
        Given the absolute frame number of a lower layer frame, return the upper segment and segment size it spans.
        Similar to seg, a lower frame might participate in multiple upper frames. For example, a TLS frame, say Frame 23, might reassemble HTTP/2 Frame 23 with 30 bytes, Frame 24 with 20 bytes. Then the span of the TLS frame are {23: 30, 24: 20}.
        """
        span = dict()
        # Note that the required segment may consist all packets with frame number larger or equal than its frame number.
        # For multiple stream case, even the segment does not consists the next packet, it may consist the packets after the
        # next packet.
        # However, if a packet contains segments equal to it, meanwhile, this packet contains segments whose frame numbers
        # are larger than the required frame number, the searching process could terminate.
        # NOTE: the claims above requires packets sorted.
        no_further_search = False
        for packet in self._upper_packets:
            if packet.abs_frame_number >= lower_abs_frame_number:
                # Search all the segments of the packet, and find if there are the required segment
                possible_no_further_search = False
                for abs_segment_frame_number, segment_size in packet.segments.items():
                    if abs_segment_frame_number == lower_abs_frame_number:
                        # When the packet contains the lower_abs_frame_number, check if there are segment numbers larger than it
                        # for early termination.
                        possible_no_further_search = True
                        span[packet.abs_frame_number] = span.setdefault(packet.abs_frame_number, 0) + segment_size

                if possible_no_further_search:
                    for frame_number in packet.segments.keys():
                        if frame_number > lower_abs_frame_number:
                            no_further_search = True 
                            break
            
            if no_further_search:
                break

        return span
    

def layer_rename(pkt):
    if "tls" in pkt and "trojan" not in pkt:
        # This is a Trojan pre-handshake, which is a TLS handshake process, we mark these packets as Trojan packets.
        for i in range(len(pkt.layers)):
            if pkt.layers[i].layer_name == "tls":
                pkt.layers[i].layer_name = "trojan"
                pkt.layers[i].layer_showname = "trojan"
        return 
    
    for i in range(len(pkt.layers)):
        if pkt.layers[i].layer_showname == "trojan" or pkt.layers[i].layer_showname == "fake trojan":
            pkt.layers[i].layer_name = pkt.layers[i].layer_showname


def layer_extractor(pkt, upper_protocol, lower_protocol):
    """
    In PyShark, the reassembly information is wrapped in the DATA layer, which is a fake-field-wrapper. When there are multiple upper layers, multiple DATA layer might be used. For example, given a packet TCP/TLS/HTTP2, there are 3 possible cases, we list the corresponding layers for each of them:

    + 1. The TLS layer is reassembled, but HTTP2 layer is not (TCP/DATA/TLS/HTTP2/DATA);
    + 2. The TLS layer is not reassembled, but HTTP2 layer is (TCP/TLS/DATA/HTTP2/DATA);
    + 3. Both TLS and HTTP2 layers are reassembled (TCP/DATA/TLS/DATA/HTTP2/DATA),

    where the last DATA layer is for Lua-related information that should be ignored.

    Extract all layers of the given protocol, if the layer is built upon a DATA layer, prepend the DATA layer to the layer list. Caller is responsible to ensure that the order of upper_protocol and lower_protocol is correct. Moreover, caller is responsible to ensure the continuity of upper_protocol and lower_protocol.

    For example, if the packet stack is TCP/TLS/HTTP2, the following params:
    {upper_protocol: 'http2', lower_protocol: 'tcp'},
    {upper_protocol: 'tls', lower_protocol: 'http2'},

    will lead to unexpected behavior. Callee does not handle the above cases since in practice they are valid, e.g., HTTP tunnel may build TLS upon HTTP.

    If the packet does not contain either upper_protocol or lower_protocol, return an empty list.
    """
    upper_protocol = upper_protocol.lower()
    lower_protocol = lower_protocol.lower()

    supported_protocols = ['tcp', 'tls', 'http2', 'vmess', 'shadowsocks', 'trojan']
    if upper_protocol not in supported_protocols or lower_protocol not in supported_protocols:
        raise ValueError(f"Unsupported protocol: only the following protocols are supported: {supported_protocols}")
    # Assure the packet protocol stack contains both upper and lower protocols.
    if upper_protocol not in pkt or lower_protocol not in pkt:
        return []  
    
    layers = []

    if upper_protocol == 'trojan' or lower_protocol == 'trojan': 
        layer_rename(pkt)

    for layer in pkt.layers:
        # When upper_protocol == lower_protocol, no need to extract reassemble info
        if layer.layer_name == 'DATA' and upper_protocol != lower_protocol:
            if PROTOCOL_REASSEMBLE_FIELD[lower_protocol] in layer.field_names:
                layers.append(layer)
        elif layer.layer_name == upper_protocol:
            layers.append(layer)

    return layers

# def layer_label_func(layer):
#     """
#     This function maps a layer to the label. Note that DATA layer is the x (or 0) in seq_filter.
#     """
#     return 0 if layer.layer_name == 'DATA' else 1


def seq_filter(seq, lower_protocol):
    """
    Filter the redundant layers from the original list of layers. For example, if the original list of layers is:
    [DATA, DATA, TLS, TLS, TLS], then according to Wireshark dissection result, one DATA would cover the same
    byte range as one TLS layer. 

    The correspondence between DATA and TLS layers seem to be random (MAYBE there is some algorithm), since we do
    not concern about the real content of the data contained, we remove the TLS which has the same size as the DATA.
    """
    if len(seq) == 0:
        return []

    to_remove = set()

    for i, layer in enumerate(seq):
        if layer.layer_name == 'DATA':
            for j in range(i + 1, len(seq)):
                if j not in to_remove and seq[j].layer_name != 'DATA':
                    # Compute current layer size
                    layer_size = PROTOCOL_BYTE_COUNTER[seq[j].layer_name].layer_count(seq[j])
                    data_layer_size = 0
                    # Compute DATA layer size
                    for _, segment_size in match_segment_number(
                        layer.get_field(PROTOCOL_REASSEMBLE_FIELD[lower_protocol])):
                        data_layer_size += segment_size
                    # TODO: A (quite rare) is that a DATA layer covers multiple layers, but searching the exact Cells
                    # that the DATA layer covers seems hard. We do not handle this case now :(
                    if layer_size == data_layer_size:
                        to_remove.add(j)
                        break

    new_seq = [seq[i] for i in range(len(seq)) if i not in to_remove]
    return new_seq

def match_segment_number(s: str): 
    """
    Extract numbers after symbol '#'.  
    """
    pattern = r'#(\d+)\((\d+)\)'
    results = re.findall(pattern, s)
    res = [(int(idx), int(size)) for idx, size in results]
    return res


def cross_layer_segment_merge_single_cell():
    pass

def cross_layer_segment_merge():
    pass

def anchor_line(seq: list)-> list:
    """
    Given a list of positive numbers, return a list of anchor points. Suppose the input list is [x_0, x_2, ..., x_{n-1}],
    the anchor points a_0, a_1, ..., a_n are computed as follows:
    1. a_0 = 0;
    2. a_i = a_{i-1} + x_{i-1}, for i = 1, 2, ..., n.
    """
    anchor_points = [0]
    cur_anchor = 0
    for number in seq:
        cur_anchor += number
        anchor_points.append(cur_anchor)
    return anchor_points

def find_anchor_indices(anchor_list: list, base: int) -> int:
    """
    Find the index of the point in anchor list that is the largest element less than or equal to the base.
    
    Args:
        anchor_list: List of anchor points (must be non-decreasing)
        base: The base point (must be non-negative and less than last anchor point)
        
    Returns:
        int: The index of the largest element <= base
            
    Raises:
        ValueError: If input constraints are violated
    """
    if not anchor_list:
        raise ValueError("Anchor list cannot be empty")
    if base < 0:
        raise ValueError("Base must be non-negative")
    if base >= anchor_list[-1]:
        raise ValueError("Base must be less than the last anchor point")
        
    idx = 0
    for i, anchor in enumerate(anchor_list):
        if anchor <= base:
            idx = i
        else:
            break
    return idx

def line_merge_single_packet(upper_line: Line, lower_line: Line, upper_packet_frame_number: int) -> Packet:
    """
    For a given packet within the line, find its reassemble info in across the lines, and create
    the new packet representing the cross-layer reassemble info.
    """
    def span_range(span: dict, upper_packet_frame_number: int) -> Tuple[int, int]:
        """
        Given the span of a middle packet, find the byte range it spans for the given upper packet.
        """
        upper_segment_sizes = []
        span_start_idx = span_end_idx = 0
        for idx, (upper_segment_frame_number, upper_segment_size) in enumerate(sorted(span.items())):
            upper_segment_sizes.append(upper_segment_size)
            if upper_segment_frame_number == upper_packet_frame_number:
                span_start_idx = idx
                span_end_idx = idx + 1
                break
        
        bases = anchor_line(upper_segment_sizes)
        span_start, span_end = bases[span_start_idx], bases[span_end_idx]
        return span_start, span_end

    NEXT_INDEX_OFFSET = 1
    packet = Packet()
    segments = packet.segments
    packet.abs_frame_number = upper_packet_frame_number
    packet.upper_protocol, packet.lower_protocol = upper_line.upper_protocol, lower_line.lower_protocol
    upper_seg = upper_line.seg(upper_packet_frame_number)
    for middle_segment_frame_number in upper_seg:
        middle_seg = lower_line.seg(middle_segment_frame_number)
        middle_span = upper_line.span(middle_segment_frame_number)
        # Create base sequence, and find the start and end byte index in the span.
        span_start, span_end = span_range(middle_span, upper_packet_frame_number)

        sorted_middle_keys = sorted(middle_seg.keys())
        # Create anchor sequence
        anchors = anchor_line([middle_seg[key] for key in sorted_middle_keys])
        anchor_start_idx, anchor_end_idx = find_anchor_indices(anchors, span_start), find_anchor_indices(anchors, span_end)
        first_segment_number = sorted_middle_keys[anchor_start_idx]
        last_segment_number = sorted_middle_keys[anchor_end_idx]
        # If anchor_start_idx == anchor_end_idx, such case is illustrated in the following figure:
        # + represents the anchor points;
        # * represents the bases;
        # 0 represents the starting point of bases and anchors.
        #
        #    target_base_idx  target_base_idx + 1
        # 0-----------------------*--------------*--------------------*-----------*
        # 
        #    anchor_end_idx
        #   anchor_start_idx  span_start     span_end
        # 0--------+--------------^--------------^------+------------------------------------+----------+
        #                         |--------------|
        #                           segment_size    
        #
        # In this case, only one segment (span_end - span_start) is needed.
        if anchor_start_idx == anchor_end_idx:
            segments[first_segment_number] = segments.setdefault(first_segment_number, 0) + (span_end - span_start)
            continue

        # Compute the number of entire segments in the span, note that the first entire segment, if any, must start
        # at the point right after anchor_start_idx, so we need to add 1 to the anchor_start_idx when computing the
        # number of entire segments.
        entire_segments_num = anchor_end_idx - (anchor_start_idx + NEXT_INDEX_OFFSET)
        for i in range(entire_segments_num):
            # Append the reassemble info for entire segments to the packet
            lower_segment_frame_number = sorted_middle_keys[anchor_start_idx + NEXT_INDEX_OFFSET + i]
            lower_segment_size = middle_seg[lower_segment_frame_number]
            segments[lower_segment_frame_number] = segments.setdefault(lower_segment_frame_number, 0) + lower_segment_size

        # Append the reassemble info for partial segments to the packet
        # Like in the case of the first entire segment, the size of the first segment is computed left-to-right,
        # which means we should compute the distance between the span_start and the point right after anchor_start_idx.
        # We illustrate the case in the following figure:
        #
        #                    target_base_idx                           target_base_idx + 1
        # 0----------*--------------*--------------------------------------------*-----------*
        # 
        #                               (also anchor_end_idx + 1 in this case)
        #   anchor_start_idx   span_start            anchor_end_idx          span_end
        # 0--------+----------------^----------------------+---------------------^--------------+----------+
        #                           |----------------------|---------------------|
        #                              first_segment_size     last_segment_size
        # Therefore, the segments are segments[sorted(middle_seg.keys())[anchor_start_idx]] = first_segment_size
        # and segments[sorted(middle_seg.keys())[anchor_end_idx]] = last_segment_size.
        #
        first_segment_size = anchors[anchor_start_idx + NEXT_INDEX_OFFSET] - span_start
        last_segment_size = span_end - anchors[anchor_end_idx]
        segments[first_segment_number] = segments.setdefault(first_segment_number, 0) + first_segment_size
        segments[last_segment_number] = segments.setdefault(last_segment_number, 0) + last_segment_size
        
    return packet
    
def line_merge(upper_line: Line, lower_line: Line) -> Line:
    """
    Merge two lines with adjacent protocol stack, and create a new line for cross-layer segmentation 
    analysis.

    COMMENT: Shall we make this method a method of Line class? In other words, shall we change the upper_line
    to a new line or create a new line?
    """
    assert upper_line.lower_protocol == lower_line.upper_protocol, f"Not adjacent lines, upper_line.lower_protocol is {upper_line.lower_protocol}, lower_line.upper_protocol is {lower_line.upper_protocol}"
    merged_packets = [
        line_merge_single_packet(upper_line, lower_line, frame_number) for frame_number in upper_line.upper_packet_frame_numbers]
    
    return Line(upper_packets=merged_packets, lower_abs_frame_numbers=lower_line.lower_abs_frame_numbers)

def get_adjacent_protocol_reassemble_info(cap: pyshark.FileCapture, upper_protocol: str, lower_protocol: str, tunnel_tls: bool=False) -> Line:
    """
    Extract the reassemble information for each packet given the adjacent upper_protocol and lower_protocol, e.g.,
    TLS over TCP, HTTP2 over TLS. This function is a component of get_reassemble_info.
    """
    upper_protocol = upper_protocol.lower()
    lower_protocol = lower_protocol.lower()

    upper_packets = []
    lower_abs_frame_numbers = []

    for pkt in cap:

        if tunnel_tls: 
            layer_rename(pkt)

        if upper_protocol in pkt:
            packet = Packet(PROCOCOL_CELL_EXTRACTOR[upper_protocol].extract(pkt, lower_protocol=lower_protocol))
            upper_packets.append(packet)
        if lower_protocol in pkt:
            lower_abs_frame_numbers.append(int(pkt.number))


    line = Line(upper_packets=upper_packets, lower_abs_frame_numbers=lower_abs_frame_numbers)
    
    if not line.continunity_check():
        raise ValueError("Discontinuous line")

    return line

def get_reassemble_info(cap: pyshark.FileCapture, protocol_stack: List[str] = ['http2', 'tls', 'tcp'], tunnel_tls: bool=False) -> Line: 
    """
    Extract the reassemble information for each packet given the protocol stack, and return the line of reassemble info.

    Note that the caller is responsible to ensure that the protocol stack is valid, since many protocol stack that are less common are actually valid with respect to the RFC docs, which might be used for some special purposes, e.g., proxy.


    TODO: Add support to UDP stack.

    Parameters 
    ----------
    cap: pyshark.FileCapture
        The capture file.
    protocol_stack: List[str]
        The ordered list of protocols, the first one is the upper bound of the stack, the last one the lower bound.
        For example, for a protocol stack TCP/VMess/TLS/HTTP2, if we want to extract all the layer reassembly, one
        should set the protocol_stack to ['http2', 'tls', 'vmess', 'tcp'].

    Returns 
    ------- 
    Line
        The line of reassemble info.
    """
    # Fetch 2 consecutive protocols from the protocol stack
    merged_line = None
    for i in range(len(protocol_stack) - 1):
        upper_protocol = protocol_stack[i]
        lower_protocol = protocol_stack[i + 1]
        line = get_adjacent_protocol_reassemble_info(cap, upper_protocol, lower_protocol, tunnel_tls=tunnel_tls)
        if merged_line is None:
            merged_line = line
        else:
            merged_line = line_merge(merged_line, line)
    
    return merged_line


def sni_similarity(host: str, proto_a: str, proto_b: str, db: pd.DataFrame) -> float:
    """
    Compute the Jaccard similarity of the given host between two protocols. The SNI set of the host is draw from the given database.
    """
    host_sni_a = db.query(f"host == '{host}' and protocol == '{proto_a}'")["sni"].tolist()
    host_sni_b = db.query(f"host == '{host}' and protocol == '{proto_b}'")["sni"].tolist()
    return jaccard_similarity(host_sni_a, host_sni_b) 


def user_agent_fetch(cap: pyshark.FileCapture) -> str:
    """
    Fetch the browser version from a HTTP/2 Frame within the capture, if no HTTP/2 Frame is found, raise ValueError.
    """
    for pkt in cap:
        if 'http2' in pkt:
            for layer in pkt.layers:
                if layer.layer_name == 'http2' and layer.get_field('headers_user_agent') is not None:
                    return layer.get_field('headers_user_agent')
                
    raise ValueError("No User Agent Found")


class SHSearcher():
    """
    The class to search for the TLS Server Hello frame.
    """
    def __init__(self, search_limit=30):
        self.search_limit = search_limit

    def search(self, cap: pyshark.FileCapture) -> int:
        """
        Search for the Server Hello frame in a given capture. If found, return the frame number. If the search_limit is reached or the capture is too short such that no SH is found, return -1.
        """
        for i, pkt in enumerate(cap):
            if i >= self.search_limit:
                break 
            if 'tls' in pkt:
                for layer in pkt.layers:
                    if layer.layer_name == 'tls' and layer.get_field('handshake_type') == '2':
                        return i

        return -1
    

class VMessSHSearcher(SHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)


class ShadowsocksSHSearcher(SHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)


class TrojanSHSearcher(SHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)

    def search(self, cap: pyshark.FileCapture) -> int:
        for i, pkt in enumerate(cap):
            if i >= self.search_limit:
                break 
            # Trojan contains tunneled TLS, we need the Server Hello in the tunneled TLS layer.
            if 'trojan' in pkt:
                for layer in pkt.layers:
                    if layer.layer_name == 'tls' and layer.get_field('handshake_type') == '2':
                        return i

        return -1
    

PROTOCOL_SH_SEARCHER = {
    'normal': SHSearcher(),
    'vmess': VMessSHSearcher(),
    'shadowsocks': ShadowsocksSHSearcher(),
    'trojan': TrojanSHSearcher(),
}

class CHSearcher():
    """
    The class to search for the TLS Client Hello frame.
    """
    def __init__(self, search_limit=30):
        self.search_limit = search_limit

    def search(self, cap: pyshark.FileCapture) -> int:
        """
        Search for the Client Hello frame in a given capture. If found, return the frame number. If the search_limit is reached or the capture is too short such that no SH is found, return -1.
        """
        for i, pkt in enumerate(cap):
            if i >= self.search_limit:
                break 
            if 'tls' in pkt:
                for layer in pkt.layers:
                    if layer.layer_name == 'tls' and layer.get_field('handshake_type') == '1':
                        return i

        return -1
    

class VMessCHSearcher(CHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)


class ShadowsocksCHSearcher(CHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)


class TrojanCHSearcher(CHSearcher):
    def __init__(self, search_limit=30):
        super().__init__(search_limit)

    def search(self, cap: pyshark.FileCapture) -> int:
        for i, pkt in enumerate(cap):
            if i >= self.search_limit:
                break 
            # Trojan contains tunneled TLS, we need the Client Hello in the tunneled TLS layer.
            if 'trojan' in pkt:
                for layer in pkt.layers:
                    if layer.layer_name == 'tls' and layer.get_field('handshake_type') == '1':
                        return i

        return -1
    

PROTOCOL_CH_SEARCHER = {
    'normal': CHSearcher(),
    'vmess': VMessCHSearcher(),
    'shadowsocks': ShadowsocksCHSearcher(),
    'trojan': TrojanCHSearcher(),
}