"""Address cache implementation for VCDIFF COPY instructions"""

import io
from typing import BinaryIO, List

from .types import SELF_MODE, HERE_MODE
from .varint import read_varint
from .exceptions import VCDIFFError


class AddressCache:
    """Manages address encoding/decoding for COPY instructions"""
    
    def __init__(self, near_size: int, same_blocks: int):
        """Initialize address cache with specified sizes
        
        Args:
            near_size: s_near, the number of slots in the "near" cache (typically 4)
            same_blocks: s_same, the number of 256-slot blocks in the "same" cache
                (typically 3, so the cache holds 768 addresses)
        """
        self.near_size = near_size
        self.same_blocks = same_blocks
        self.near: List[int] = [0] * near_size
        self.next_near_slot = 0
        self.same: List[int] = [0] * (same_blocks * 256)
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
            VCDIFFError: If the addressing mode is invalid
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
                # Near cache. Both caches are zero filled at the start of a window
                # (RFC 3284 section 5.1), so 0 is an ordinary cached address here.
                cache_index = mode - 2
                offset = read_varint(self.address_stream)
                addr = self.near[cache_index] + offset
            else:
                # Same cache
                m = mode - (2 + self.near_size)
                if m >= self.same_blocks:
                    raise VCDIFFError(
                        f"same cache mode {mode} exceeds available slots "
                        f"(max {2 + self.near_size + self.same_blocks - 1})"
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
        
        if self.same_blocks > 0:
            # RFC 3284 section 5.1: the slot with index addr % (s_same * 256)
            self.same[address % len(self.same)] = address
