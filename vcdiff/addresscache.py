"""Address cache implementation for VCDIFF COPY instructions"""

import io
from typing import BinaryIO, List

from .types import SELF_MODE, HERE_MODE
from .varint import read_varint
from .exceptions import VCDIFFError


class AddressCache:
    """Manages address encoding/decoding for COPY instructions"""
    
    def __init__(self, near_size: int, same_size: int):
        """Initialize address cache with specified sizes
        
        Args:
            near_size: Size of the "near" address cache (typically 4)
            same_size: Size of the "same" address cache (typically 3 * 256)
        """
        self.near_size = near_size
        self.same_size = same_size
        self.near: List[int] = [0] * near_size
        self.next_near_slot = 0
        self.same: List[int] = [0] * (same_size * 256)
        self.address_stream: BinaryIO = io.BytesIO()
    
    def reset(self, addresses: bytes) -> None:
        """Reset the address cache for a new window
        
        Args:
            addresses: Address section data for this window
        """
        self.next_near_slot = 0
        
        # Clear near cache
        for i in range(len(self.near)):
            self.near[i] = 0
        
        # Clear same cache
        for i in range(len(self.same)):
            self.same[i] = 0
        
        self.address_stream = io.BytesIO(addresses)
    
    def decode_address(self, here: int, mode: int) -> int:
        """Decode an address using the specified mode
        
        Args:
            here: Current position in target stream
            mode: Addressing mode to use
            
        Returns:
            The decoded address
            
        Raises:
            VCDIFFError: If the addressing mode is invalid or cache is uninitialized
        """
        # Validate addressing mode
        if mode > 8:
            raise VCDIFFError(f"invalid address cache mode {mode}: valid modes are 0-8")
        
        if mode == SELF_MODE:
            addr = read_varint(self.address_stream)
        
        elif mode == HERE_MODE:
            offset = read_varint(self.address_stream)
            if offset > here:
                raise VCDIFFError(f"HERE mode offset {offset} exceeds current position {here}")
            addr = here - offset
        
        else:
            # Near cache or same cache modes
            if mode - 2 < self.near_size:
                # Near cache
                cache_index = mode - 2
                if self.near[cache_index] == 0:
                    raise VCDIFFError(f"near cache slot {cache_index} is uninitialized")
                offset = read_varint(self.address_stream)
                addr = self.near[cache_index] + offset
            else:
                # Same cache
                m = mode - (2 + self.near_size)
                if m >= self.same_size:
                    raise VCDIFFError(
                        f"same cache mode {mode} exceeds available slots "
                        f"(max {2 + self.near_size + self.same_size - 1})"
                    )
                
                byte_data = self.address_stream.read(1)
                if not byte_data:
                    raise VCDIFFError("unexpected EOF while reading same cache address")
                
                b = byte_data[0]
                addr = self.same[m * 256 + b]
        
        self.update(addr)
        return addr
    
    def update(self, address: int) -> None:
        """Update the address cache with a new address
        
        Args:
            address: Address to add to the cache
        """
        if self.near_size > 0:
            self.near[self.next_near_slot] = address
            self.next_near_slot = (self.next_near_slot + 1) % self.near_size
        
        if self.same_size > 0:
            self.same[address % (self.same_size * 256)] = address