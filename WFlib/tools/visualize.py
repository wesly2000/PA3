from WFlib.tools.analyzer import Line 
from typing import List
import numpy as np

def generate_byte_segment(lines: list[Line]) -> List[np.ndarray]:
    """
    Generate segment index for each line, then return the byte segment arrays.
    
    Since each line may differ in size, the smallest one is used as a cutoff. To avoid outliers, we
    use IQR to filter out those lines that are too short.
    """
    byte_count_arr = np.array([line.byte_counter for line in lines])
    Q1 = np.percentile(byte_count_arr, 25)  # Lower quartile (25th percentile)
    Q3 = np.percentile(byte_count_arr, 75)  # Upper quartile (75th percentile)

    IQR = Q3 - Q1  # Interquartile range (IQR)
    lower_bound = Q1 - 1.5 * IQR  # Lower bound for outliers (adjust as needed)

    # Filter out outliers (lines with byte_counter below the lower bound)
    filtered_lines = [line for line in lines if line.byte_counter >= lower_bound]

    # Calculate the minimum byte_counter among the filtered lines
    min_byte_count = min([line.byte_counter for line in filtered_lines])

    def generate_byte_segment_single_line(line: Line, cutoff: int) -> np.ndarray:
        """
        Generate segment index for a single line with the cutoff. We illustrate the generate process with 
        an example, where the upper_abs_byte_map is {226: (0, 3), 228: (3, 5), 230: (5, 12)}, and cutoff is 9. 
        Note that the right point of each interval is exclusive. 
        
        The segment index is generated in the relative sense, i.e., 226 is the 0-th segment, 228 is the 
        1-st, 230 is the 2-nd. Therefore, the result is [0, 0, 0, 1, 1, 2, 2, 2, 2].
        """
        abs_segment_idx = [key for key in line.upper_abs_byte_map.keys()]
        abs_segment_idx.sort()
        byte_segment = []


        for i, idx in enumerate(abs_segment_idx):
            if line.upper_abs_byte_map[idx][1] >= cutoff:
                for j in range(line.upper_abs_byte_map[idx][0], cutoff):
                    byte_segment.append(i)
                break
            else:
                for j in range(line.upper_abs_byte_map[idx][0], line.upper_abs_byte_map[idx][1]):
                    byte_segment.append(i)

        return np.array(byte_segment)
    
    return [generate_byte_segment_single_line(line, min_byte_count) for line in filtered_lines]
    
# def avg_array(arrays: List[np.ndarray]) -> np.ndarray:
#     """
#     Average the segment index of each line. The result is a list of segment index. The length of the list is the cutoff.
#     """
#     merged_array = np.array(arrays)
#     avg_array = np.mean(merged_array, axis=0)
#     return avg_array
