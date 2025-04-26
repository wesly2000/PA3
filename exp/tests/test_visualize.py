from WFlib.tools.analyzer import Cell, Line 
from WFlib.tools.visualize import *

def test_generate_byte_segment_01():
    http2_cell_0 = Cell(proto="http2", abs_frame_number=106)
    http2_cell_0.abs_segment_frame_number = [104, 106]
    http2_cell_0.segment_size = [1, 1]

    http2_line_short = Line(upper_protocol="http2", upper_cells=[http2_cell_0])

    http2_cell_1 = Cell(proto="http2", abs_frame_number=106)
    http2_cell_1.abs_segment_frame_number = [104, 106]
    http2_cell_1.segment_size = [2, 3]
    http2_cell_2 = Cell(proto="http2", abs_frame_number=106)
    http2_cell_2.abs_segment_frame_number = [106]
    http2_cell_2.segment_size = [3]
    http2_cell_3 = Cell(proto="http2", abs_frame_number=109)
    http2_cell_3.abs_segment_frame_number = [106, 108, 109]
    http2_cell_3.segment_size = [2, 1, 2]

    http2_line_mid = Line(upper_protocol="http2", upper_cells=[http2_cell_1, http2_cell_2, http2_cell_3])

    http2_cell_4 = Cell(proto="http2", abs_frame_number=1107)
    http2_cell_4.abs_segment_frame_number = [1104, 1106, 1107]
    http2_cell_4.segment_size = [2, 4, 3]
    http2_cell_5 = Cell(proto="http2", abs_frame_number=1107)
    http2_cell_5.abs_segment_frame_number = [1107, 1107, 1107]
    http2_cell_5.segment_size = [1, 1, 2]
    http2_cell_6 = Cell(proto="http2", abs_frame_number=1109)
    http2_cell_6.abs_segment_frame_number = [1107, 1108, 1109]
    http2_cell_6.segment_size = [2, 1, 2]

    http2_line_long = Line(upper_protocol="http2", upper_cells=[http2_cell_4, http2_cell_5, http2_cell_6])

    lines = [http2_line_short, http2_line_mid, http2_line_mid, http2_line_mid, http2_line_long]

    # The shortest line should be removed, and the cutoff should be 13.
    byte_segments = generate_byte_segment(lines)
    assert len(byte_segments) == 4, "The number of byte segments should be 4."
    expected = [np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]), 
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3]),
                np.array([0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2])]
    
    assert all(np.array_equal(segment, expected_segment) for segment, expected_segment in zip(byte_segments, expected))