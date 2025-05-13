from WFlib.tools.analyzer import Cell, Line, Packet
from WFlib.tools.visualize import *

def test_generate_byte_segment_01():
    http2_cell_0 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_0.abs_segment_frame_number = [104, 106]
    http2_cell_0.segment_size = [1, 1]

    packet_0 = Packet([http2_cell_0])

    http2_line_short = Line(upper_packets=[packet_0], lower_abs_frame_numbers=[104, 106])

    http2_cell_1 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_1.abs_segment_frame_number = [104, 106]
    http2_cell_1.segment_size = [2, 3]
    http2_cell_2 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=106)
    http2_cell_2.abs_segment_frame_number = [106]
    http2_cell_2.segment_size = [3]
    http2_cell_3 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=109)
    http2_cell_3.abs_segment_frame_number = [106, 108, 109]
    http2_cell_3.segment_size = [2, 1, 2]

    packet_1, packet_2 = Packet([http2_cell_1, http2_cell_2]), Packet([http2_cell_3])

    http2_line_mid = Line(upper_packets=[packet_1, packet_2], lower_abs_frame_numbers=[104, 106, 108, 109])

    http2_cell_4 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=1107)
    http2_cell_4.abs_segment_frame_number = [1104, 1106, 1107]
    http2_cell_4.segment_size = [2, 4, 1]
    http2_cell_5 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=1107)
    http2_cell_5.abs_segment_frame_number = [1107, 1107, 1107]
    http2_cell_5.segment_size = [1, 1, 2]
    http2_cell_6 = Cell(upper_protocol="http2", lower_protocol="tls", abs_frame_number=1109)
    http2_cell_6.abs_segment_frame_number = [1107, 1108, 1109]
    http2_cell_6.segment_size = [2, 1, 1]

    packet_3, packet_4 = Packet([http2_cell_4, http2_cell_5]), Packet([http2_cell_6])

    http2_line_long = Line(upper_packets=[packet_3, packet_4], lower_abs_frame_numbers=[1104, 1106, 1107, 1108, 1109])
    # Make more samples to avoid IQR losing efforts on small datasets
    lines = [http2_line_short, http2_line_mid, http2_line_mid, http2_line_mid, http2_line_mid, http2_line_mid, http2_line_long]

    # The shortest line should be removed, and the cutoff should be 13.
    byte_segments = generate_byte_segment(lines)
    assert len(byte_segments) == 5, "The number of byte segments should be 4."
    expected = [np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]), 
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2])]
    
    assert all(np.array_equal(segment, expected_segment) for segment, expected_segment in zip(byte_segments, expected))