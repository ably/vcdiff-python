"""VCDIFF data types and constants - RFC 3284 compliance"""

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional


# VCDIFF magic bytes and version - RFC 3284 Section 4.1
VCDIFF_MAGIC_1 = 0xD6  # First magic byte: 'V' with high bit set
VCDIFF_MAGIC_2 = 0xC3  # Second magic byte: 'C' with high bit set  
VCDIFF_MAGIC_3 = 0xC4  # Third magic byte: 'D' with high bit set
VCDIFF_VERSION = 0x00  # Version 0 as defined in RFC 3284

# VCDIFFMagic is the expected magic number sequence - RFC 3284 Section 4.1
VCDIFF_MAGIC = bytes([VCDIFF_MAGIC_1, VCDIFF_MAGIC_2, VCDIFF_MAGIC_3])

# Header indicator flags - RFC 3284 Section 4.1
VCD_DECOMPRESS = 0x01  # VCD_DECOMPRESS: secondary compression used
VCD_CODETABLE = 0x02   # VCD_CODETABLE: custom instruction table used
VCD_APPHEADER = 0x04   # VCD_APPHEADER: application header present

# Window indicator flags - RFC 3284 Section 4.2
VCD_SOURCE = 0x01   # VCD_SOURCE: window uses source data
VCD_TARGET = 0x02   # VCD_TARGET: window uses target data
VCD_ADLER32 = 0x04  # VCD_ADLER32: window includes Adler-32 checksum (non-standard extension)

# Variable-length integer encoding constants - RFC 3284 Section 2
VARINT_CONTINUATION_BIT = 0x80  # High bit indicates continuation
VARINT_VALUE_MASK = 0x7F        # Mask for 7-bit value portion
VARINT_MAX_SHIFT = 32           # Maximum shift to prevent overflow
VARINT_SHIFT_INCREMENT = 7      # Bits to shift for each byte

# Instruction code ranges - RFC 3284 Section 5
RUN_INSTRUCTION_MIN = 0    # RUN instructions: 0-17
RUN_INSTRUCTION_MAX = 17   # RUN instructions: 0-17
ADD_INSTRUCTION_MIN = 18   # ADD instructions: 18-161
ADD_INSTRUCTION_MAX = 161  # ADD instructions: 18-161
COPY_INSTRUCTION_MIN = 162 # COPY instructions: 162-255
COPY_INSTRUCTION_MAX = 255 # COPY instructions: 162-255

# Address cache configuration - RFC 3284 Section 5.3
NEAR_CACHE_SIZE = 4         # Size of "near" address cache
SAME_CACHE_SIZE = 3 * 256   # Size of "same" address cache
INSTRUCTION_TABLE_SIZE = 256 # Size of instruction code table

# File format validation constants
MINIMUM_FILE_SIZE = 4  # Minimum VCDIFF file size (magic + version)

# Address modes
SELF_MODE = 0  # SELF addressing mode
HERE_MODE = 1  # HERE addressing mode


class InstructionType(IntEnum):
    """VCDIFF instruction types"""
    NO_OP = 0
    ADD = 1
    RUN = 2
    COPY = 3


@dataclass
class Header:
    """VCDIFF file header"""
    magic: bytes
    version: int
    indicator: int


@dataclass 
class Window:
    """VCDIFF window structure - RFC 3284 Section 4.2 and 4.3"""
    win_indicator: int                    # Win_Indicator - RFC 3284 Section 4.2
    source_segment_size: int = 0          # Source segment size - RFC 3284 Section 4.2
    source_segment_position: int = 0      # Source segment position - RFC 3284 Section 4.2
    target_window_length: int = 0         # Length of the target window - RFC 3284 Section 4.3
    delta_encoding_length: int = 0        # Length of the delta encoding - RFC 3284 Section 4.3
    delta_indicator: int = 0              # Delta_Indicator - RFC 3284 Section 4.3
    data_section_length: int = 0          # Length of data for ADDs and RUNs - RFC 3284 Section 4.3
    instruction_section_length: int = 0   # Length of instructions section - RFC 3284 Section 4.3
    address_section_length: int = 0       # Length of addresses for COPYs - RFC 3284 Section 4.3
    data_section: bytes = b''             # Data section for ADDs and RUNs - RFC 3284 Section 4.3
    instruction_section: bytes = b''      # Instructions and sizes section - RFC 3284 Section 4.3
    address_section: bytes = b''          # Addresses section for COPYs - RFC 3284 Section 4.3
    checksum: int = 0                     # Adler-32 checksum of target window (VCD_ADLER32 extension)
    has_checksum: bool = False            # Whether VCD_ADLER32 bit is set in WinIndicator


@dataclass
class Instruction:
    """Single VCDIFF instruction from the code table"""
    type: InstructionType
    size: int
    mode: int


@dataclass
class RuntimeInstruction:
    """Instruction with resolved size during decoding"""
    type: InstructionType
    size: int
    mode: int = 0
    addr: int = 0
    data: bytes = b''


@dataclass
class ParsedDelta:
    """Complete parsed VCDIFF delta structure"""
    header: Header
    windows: List[Window]
    instructions: List[RuntimeInstruction]