from captum import attr
from tqdm import tqdm
import torch
import numpy as np
import pyshark 
from pathlib import Path
import re
from typing import List, Callable, Optional, Tuple

AES_128_GCM_TAG_LEN = 16

def feature_attr(model, attr_method, X, y, num_classes):
    """
    Calculate feature attributions for a given model using a specified attribution method.
    
    Args:
    - model: The neural network model to interpret.
    - attr_method: The attribution method to use (e.g., 'DeepLiftShap').
    - X: The input data (features) as a numpy array or torch tensor.
    - y: The labels for the input data.
    - num_classes: The number of distinct classes in the data.
    
    Returns:
    - attr_values: An array of attribution values for each class.
    """
    
    # Set the model to evaluation mode
    model.eval()
    
    # Initialize the attribution model based on the chosen method
    if attr_method in ["DeepLiftShap"]:
        attr_model = eval(f"attr.{attr_method}")(model)
    else:
        attr_model = eval(f"attr.{attr_method}")(model.forward)
    
    # Prepare background and test data for each class
    bg_traffic = []
    test_traffic = {}
    for web in range(num_classes):
        bg_test_X = X[y == web]
        assert bg_test_X.shape[0] >= 12
        bg_traffic.append(bg_test_X[0:2])  # Use the first 2 samples as background
        test_traffic[web] = bg_test_X[2:12]  # Use the next 10 samples for testing

    # Concatenate all background traffic into a single tensor
    bg_traffic = torch.concat(bg_traffic, axis=0)

    attr_values = []
    # Iterate over each class to calculate attribution values
    for web in tqdm(range(num_classes)):
        # Calculate attributions for the test samples using the background samples
        attr_result = attr_model.attribute(test_traffic[web], bg_traffic, target=web)
        # Aggregate the attribution results
        attr_result = attr_result.detach().numpy().squeeze().sum(axis=0).sum(axis=0)
        attr_values.append(attr_result)
    
    attr_values = np.array(attr_values)
    return attr_values  # Return the attribution values

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
            cnt += self.response_hdr_len + AES_128_GCM_TAG_LEN + self.length_len + AES_128_GCM_TAG_LEN
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

PROTOCOL_BYTE_COUNTER = {
    "tls": TLSByteCounter(),
    "tcp": TCPByteCounter(),
    "http2": HTTP2ByteCounter(),
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
    def __init__(self, cells: List[Cell]):
        self._segments = dict()
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
                 upper_protocol: str, upper_cells: List[Cell], 
                 lower_protocol: str, lower_abs_frame_numbers: List[int],
                 sanity_check = False
                 ):
        self._upper_layer = upper_protocol
        self._upper_cells = sorted(upper_cells)  # Defer the sorting to the Line instead of CellExtractor
        self._lower_layer = lower_protocol
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
    def lower_abs_frame_numbers(self):
        return self._lower_abs_frame_numbers

    def upper_rel_building(self):
        """
        Build the relative reassemble information for upper layer according to their absolute frame number.
        Upper relative reassemble contains which lower frame (abs) contains which bytes in upper layer.
        """
        byte_counter = 0  # Count how many bytes in the upper layer in total
        # COMMENT: shall we explicitly create closed-interval or right-open interval then use for-loop 
        #          to implicitly ignore the last byte index?
        upper_abs_byte_map = dict()

        for i in range(len(self._upper_cells)):
            for segment_frame_number, segment_size in zip(self._upper_cells[i].abs_segment_frame_number, self._upper_cells[i].segment_size):
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
        pass

    def seg(self, upper_abs_frame_number: int) -> dict:
        """
        Given the absolute frame number of a upper layer frame, return its segment and segment size list.

        COMMENT: shall we merge the segment number/size for the same segment? YES
        COMMENT: is the order important? NO
        """
        seg = dict()
        for cell in self._upper_cells:
            if cell.abs_frame_number == upper_abs_frame_number:
                for abs_segment_frame_number, segment_size in zip(cell.abs_segment_frame_number, cell.segment_size):
                    seg[abs_segment_frame_number] = seg.setdefault(abs_segment_frame_number, 0) + segment_size

        return seg

    def span(self, lower_abs_frame_number: int) -> List:
        """
        Given the absolute frame number of a lower layer frame, return the upper segment and segment size it spans.
        """
        span = dict()
        # Note that the required segment may consist all cells with frame number larger or equal than its frame number.
        # For multiple stream case, even the segment does not consists the next cell, it may consist the cells after the
        # next cell.
        # However, if a cell contains segments equal to it, meanwhile, this cell contains segments whose frame numbers
        # are larger than the required frame number, the searching process could terminate.
        # NOTE: the claims above requires cells sorted.
        no_further_search = False
        for cell in self._upper_cells:
            if cell.abs_frame_number >= lower_abs_frame_number:
                # Search all the segments of the cell, and find if there are the required segment
                possible_no_further_search = False
                for abs_segment_frame_number, segment_size in zip(cell.abs_segment_frame_number, cell.segment_size):
                    if abs_segment_frame_number == lower_abs_frame_number:
                        # When the cell contains the lower_abs_frame_number, check if there are segment numbers larger than it
                        # for early termination.
                        possible_no_further_search = True
                        span[cell.abs_frame_number] = span.setdefault(cell.abs_frame_number, 0) + segment_size

                if possible_no_further_search:
                    for frame_number in cell.abs_segment_frame_number:
                        if frame_number > lower_abs_frame_number:
                            no_further_search = True 
                            break
            
            if no_further_search:
                break

        return span


PROTOCOL_REASSEMBLE_FIELD = {
    "tls": "tls_segments",
    "tcp": "tcp_segments",
    "vmess": "vmess_segments",
}

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

    def extract(self, pkt, lower_protocol="TLS") -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class TLSCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "tls"

    def extract(self, pkt, lower_protocol="TCP") -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

class TCPCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "tcp"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    


class VMessCellExtractor(CellExtractor):
    def __init__(self):
        self._name = "tcp"

    def extract(self, pkt, lower_protocol='tcp') -> List[Cell]:
        return super().extract(pkt, lower_protocol)
    

PROCOCOL_CELL_EXTRACTOR = {
    "tcp": TCPCellExtractor(),  
    "tls": TLSCellExtractor(),
    "http2": HTTP2CellExtractor(),
}

DATA_LAYER_MARKER = {'tcp': 'tcp_segments', 'tls': 'tls_segments', 'vmess': 'vmess_fragments'}


def layer_extractor(pkt, upper_protocol, lower_protocol):
    """
    Extract all layers of the given protocol, if the layer is built upon a DATA layer, 
    prepend the DATA layer to the layer list. Caller is responsible to ensure that
    the order of upper_protocol and lower_protocol is correct. Moreover, caller is
    responsible to ensure the continuity of upper_protocol and lower_protocol.

    For example, if the packet stack is TCP/TLS/HTTP2, the following params:
    {upper_protocol: 'http2', lower_protocol: 'tcp'},
    {upper_protocol: 'tls', lower_protocol: 'http2'},

    will lead to unexpected behavior. Callee does not handle the above cases since in 
    practice they are valid, e.g., HTTP tunnel may build TLS upon HTTP.

    If the packet does not contain either upper_protocol or lower_protocol, return an empty list.
    """
    upper_protocol = upper_protocol.lower()
    lower_protocol = lower_protocol.lower()

    supported_protocols = ['tcp', 'tls', 'http2', 'vmess']
    if upper_protocol not in supported_protocols or lower_protocol not in supported_protocols:
        raise ValueError(f"Unsupported protocol: only the following protocols are supported: {supported_protocols}")
    # Assure the packet protocol stack contains both upper and lower protocols.
    if upper_protocol not in pkt or lower_protocol not in pkt:
        return []  
    
    layers = []

    for layer in pkt.layers:
        # When upper_protocol == lower_protocol, no need to extract reassemble info
        if layer.layer_name == 'DATA' and upper_protocol != lower_protocol:
            if DATA_LAYER_MARKER[lower_protocol] in layer.field_names:
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

def get_adjacent_protocol_reassemble_info(cap: pyshark.FileCapture, upper_protocol: str, lower_protocol: str) -> Line:
    """
    Extract the reassemble information for each packet given the adjacent upper_protocol and lower_protocol, e.g.,
    TLS over TCP, HTTP2 over TLS. This function is a component of get_reassemble_info.
    """
    upper_protocol = upper_protocol.lower()
    lower_protocol = lower_protocol.lower()

    upper_cells = []
    lower_abs_frame_numbers = []

    for pkt in cap:
        if upper_protocol in pkt:
            upper_cells += PROCOCOL_CELL_EXTRACTOR[upper_protocol].extract(pkt, lower_protocol=lower_protocol)
        if lower_protocol in pkt:
            lower_abs_frame_numbers.append(int(pkt.number))


    line = Line(
        upper_protocol=upper_protocol, 
        upper_cells=upper_cells, 
        lower_protocol=lower_protocol,
        lower_abs_frame_numbers=lower_abs_frame_numbers,
        )
    
    if not line.continunity_check():
        raise ValueError("Discontinuous line")

    return line

def cross_layer_segment_merge_single_cell():
    pass

def cross_layer_segment_merge():
    pass

def line_merge(upper_line: Line, lower_line: Line) -> Line:
    """
    Merge two lines with adjacent protocol stack, and create a new line for cross-layer segmentation 
    analysis.
    """

def get_reassemble_info(cap: pyshark.FileCapture, protocol_stack: List[str] = ['TCP', 'TLS',]): 
    """
    Extract the reassemble information for each packet given the protocol stack. In PyShark, the reassembly information is wrapped in the DATA layer, which is a fake-field-wrapper. When there are multiple upper layers, multiple DATA layer might be used. For example, given a packet TCP/TLS/HTTP2, there are 3 possible cases, we list the corresponding layers for each of them:

    + 1. The TLS layer is reassembled, but HTTP2 layer is not (TCP/DATA/TLS/HTTP2/DATA);
    + 2. The TLS layer is not reassembled, but HTTP2 layer is (TCP/TLS/DATA/HTTP2/DATA);
    + 3. Both TLS and HTTP2 layers are reassembled (TCP/DATA/TLS/DATA/HTTP2/DATA),

    where the last DATA layer is for Lua-related information that should be ignored.

    However, for protocols above the transport layer, there might be multiple layers for the same protocol, e.g.,
    TCP/DATA/TLS/TLS/TLS/DATA/HTTP2/HTTP2. 
                  ^   ^         ^     ^

    One could deduce that for a given protocol, reassembly would only happen at the its first layer. Therefore, we
    need to separately handle the remaining layers (marked with ^).


    TODO: Add support to UDP stack.

    Parameters 
    ----------
    cap: pyshark.FileCapture
        The capture file.
    protocol_stack: List[str]
        The ordered list of protocols, the first one is the lower bound of the stack, the last one the upper bound.
        For example, for a protocol stack TCP/VMess/TLS/HTTP2, if we want to extract all the layer reassembly, one
        should set the protocol_stack to ['TCP', 'VMess', 'TLS', 'HTTP2'].

    Returns 
    ------- 
    res_dict: dict, {K: [v1, ...], ...} 
        K is the packet index in the same form of Wireshark, namely, starts from 1. 
        [v1, ...] denotes the reassembled indices, whose values will be K in turn and have the same reassembled list. 
        For example, {1: [1, 2], 2: [1, 2]}. 
    """
    # res_dict = {} # {index: [reassemble packets]}
    # for i in tqdm(range(packet_count(cap)), "get reassemble info"): 
    #     if cap[i].transport_layer == 'TCP': # ignore the UDP based protocols 
    #         frame_num = int(cap[i].frame_info.get_field('number')) # get the number of frame
    #         res_dict[frame_num] = [] # init i-th position as empty 
    #         segment_index = [] 
    #         # print(f'${i}$: ${pcap[i].layers}')
    #         for layer in cap[i].layers: 
    #             if layer.layer_name == 'DATA': # fake-field-wrapper is renamed to data in pyshark
    #                 for field in layer.field_names: 
    #                     if field == 'tcp_segments': # reassemble will appearance in the last packet
    #                         field_obj = layer.get_field(field) 
    #                         content = field_obj.main_field.get_default_value() 
    #                         segment_index.extend(match_segment_number(content)) 
    #         for index in segment_index: # cover related values with its reassemble info
    #             res_dict[index] = segment_index 
    
    # return res_dict
    res_dict = {protocol: [] for protocol in protocol_stack} # {index: [reassemble packets]}
    cell_extractor = CellExtractor()
    for pkt in cap: 
        # for protocol in protocol_stack: 
        #     if protocol in pkt:
        #         res_dict[protocol].extend(cell_extractor.extract(pkt, protocol))
        # if protocol in pkt:
        #     frame_num = int(pkt.frame_info.get_field('number')) # get the number of frame
        #     res_dict[frame_num] = [] # init i-th position as empty 
        #     segment_index = [] 
        #     # print(f'${i}$: ${pcap[i].layers}')
        #     for layer in pkt.layers: 
        #         if layer.layer_name == 'DATA': # fake-field-wrapper is renamed to data in pyshark
        #             for field in layer.field_names: 
        #                 if field == 'tcp_segments': # reassemble will appearance in the last packet
        #                     field_obj = layer.get_field(field) 
        #                     content = field_obj.main_field.get_default_value() 
        #                     segment_index.extend(match_segment_number(content)) 
        #     for index in segment_index: # cover related values with its reassemble info
        #         res_dict[index] = segment_index 
        frame_num = int(pkt.frame_info.get_field('number'))
        if frame_num == 58:
            pass
    
    return res_dict