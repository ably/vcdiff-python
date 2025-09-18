"""Adler-32 checksum implementation for VCDIFF"""

from typing import Union


# Base for modulo arithmetic
ADLER32_BASE = 65521
# Number of iterations we can safely do before applying the modulo
ADLER32_NMAX = 5552


def compute_checksum(initial: int, data: Union[bytes, bytearray]) -> int:
    """Compute the Adler32 checksum for the given data
    
    Args:
        initial: Initial checksum value (typically 1)
        data: Data to compute checksum for
        
    Returns:
        The computed Adler32 checksum
    """
    if not data:
        return initial
    
    s1 = initial & 0xFFFF
    s2 = (initial >> 16) & 0xFFFF
    
    index = 0
    length = len(data)
    
    while length > 0:
        k = min(length, ADLER32_NMAX)
        length -= k
        
        for i in range(k):
            s1 += data[index]
            s2 += s1
            index += 1
        
        s1 %= ADLER32_BASE
        s2 %= ADLER32_BASE
    
    return (s2 << 16) | s1