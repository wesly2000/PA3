from WFlib.tools.analyzer import Line 
from WFlib.utils.statistics import IQR_bound
from typing import List
import numpy as np

def generate_byte_stream(segment_byte_map: dict, cutoff: int, abs_lower_frame_numbers: List[int]) -> np.ndarray:
        """
        Generate segment index for a segment-byte map with the cutoff. We illustrate the generate process with 
        an example, where the upper_abs_byte_map is {226: (0, 3), 228: (3, 5), 230: (5, 12)}, and cutoff is 9. 
        Note that the right point of each interval is exclusive. 
        
        The segment index is generated in the relative sense, i.e., 226 is the 0-th segment, 228 is the 
        1-st, 230 is the 2-nd. Therefore, the result is [0, 0, 0, 1, 1, 2, 2, 2, 2].
        """
        rel_lower_frame_numbers = {abs_frame_number: i for i, abs_frame_number in enumerate(abs_lower_frame_numbers)}
        byte_segment = np.array([0] * cutoff)

        for seg_idx in segment_byte_map:
            for cover in segment_byte_map[seg_idx]:
                byte_segment[cover[0] : min(cutoff, cover[1])] = rel_lower_frame_numbers[seg_idx]

        return byte_segment

def generate_byte_segment(lines: List[Line]) -> List[np.ndarray]:
    """
    Generate segment index for each line, then return the byte segment arrays.
    
    Since each line may differ in size, the smallest one is used as a cutoff. To avoid outliers, we
    use IQR to filter out those lines that are too short.
    """
    byte_count_arr = np.array([line.byte_counter for line in lines])
    if byte_count_arr.shape[0] > 1:
        lower_bound, upper_bound = IQR_bound(byte_count_arr)

        # Filter out outliers (lines with byte_counter within the IQR range)
        filtered_lines = [line for line in lines if lower_bound <= line.byte_counter <= upper_bound]

        # Calculate the minimum byte_counter among the filtered lines
    else:
        # No need to do IQR when only 1 elements within (it occurs in some tests)
        filtered_lines = lines

    min_byte_count = min([line.byte_counter for line in filtered_lines])

    result = []
    for i, line in enumerate(filtered_lines):
        try:
            result.append(generate_byte_stream(line.upper_abs_byte_map, min_byte_count, line.lower_abs_frame_numbers)) 
        except Exception as e:
            print(f"Error in Line {i}: {e}")
    return result
