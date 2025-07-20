"""Variable-length integer encoding/decoding - RFC 3284 Section 2"""

import io
from typing import BinaryIO

from .types import VARINT_CONTINUATION_BIT, VARINT_VALUE_MASK
from .exceptions import VCDIFFError


def read_varint(reader: BinaryIO) -> int:
    """Read a variable-length integer as defined in RFC 3284 Section 2
    
    Follows the same algorithm as the Go reference implementation.
    
    Args:
        reader: Binary reader to read from
        
    Returns:
        The decoded integer value
        
    Raises:
        VCDIFFError: If the varint is malformed or too long
    """
    result = 0
    start_pos = getattr(reader, 'tell', lambda: 0)()
    
    for i in range(5):  # Maximum 5 bytes for 32-bit integer
        try:
            byte_data = reader.read(1)
            if not byte_data:
                bytes_read = i
                raise VCDIFFError(
                    f"unexpected EOF while reading varint at offset {start_pos}: "
                    f"expected continuation or termination byte after {bytes_read} bytes"
                )
            
            b = byte_data[0]
        except (OSError, IOError) as e:
            raise VCDIFFError(f"error reading varint: {e}") from e
        
        # Shift previous result left by 7 bits and add the new 7-bit value
        # This matches the Go reference: result = (result << 7) | uint32(b&VarintValueMask)
        result = (result << 7) | (b & VARINT_VALUE_MASK)
        
        # Check if continuation bit is clear (end of varint)
        if b & VARINT_CONTINUATION_BIT == 0:
            return result
    
    # If we've read 5 bytes without finding the end, the data is invalid
    raise VCDIFFError(
        f"invalid varint at offset {start_pos}: exceeds maximum 5-byte encoding "
        "(continuation bit never cleared)"
    )