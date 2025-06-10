import numpy as np
from typing import Union, List
import random

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

def sample(iterator, k):
    """
    Samples k elements from an iterable object.

    :param iterator: an object that is iterable
    :param k: the number of items to sample
    """
    # fill the reservoir to start
    result = [next(iterator) for _ in range(k)]

    n = k - 1
    for item in iterator:
        n += 1
        s = random.randint(0, n)
        if s < k:
            result[s] = item

    return result