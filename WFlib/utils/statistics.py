import numpy as np
from typing import Union, List
def IQR_bound(array: Union[np.array, List]):
    arr_sorted = np.sort(array)

    lower_half = arr_sorted[:len(arr_sorted)//2]    
    upper_half = arr_sorted[(len(arr_sorted)+1)//2:]

    Q1 = np.median(lower_half)
    Q3 = np.median(upper_half)

    IQR = Q3 - Q1  # Interquartile range (IQR)
    lower_bound = Q1 - 1.5 * IQR  # Lower bound for outliers
    upper_bound = Q3 + 1.5 * IQR  # Upper bound for outliers

    return lower_bound, upper_bound