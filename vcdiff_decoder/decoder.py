"""VCDIFF decoder implementation - RFC 3284 compliance"""

import io
from typing import BinaryIO, List, Optional, Union

from .types import (
    Header, Window, ParsedDelta, RuntimeInstruction, InstructionType,
    VCDIFF_MAGIC, VCDIFF_VERSION, MINIMUM_FILE_SIZE,
    VCD_DECOMPRESS, VCD_CODETABLE, VCD_APPHEADER,
    VCD_SOURCE, VCD_TARGET, VCD_ADLER32,
    NEAR_CACHE_SIZE, SAME_CACHE_SIZE
)
from .exceptions import (
    VCDIFFError, InvalidMagicError, InvalidVersionError, InvalidFormatError,
    CorruptedDataError, InvalidChecksumError,
    err_unexpected_eof, err_data_overrun, err_invalid_value, err_out_of_bounds
)
from .varint import read_varint
from .adler32 import compute_checksum
from .addresscache import AddressCache
from .codetable import DEFAULT_CODE_TABLE


class Decoder:
    """VCDIFF decoder interface"""
    
    def __init__(self, source: Union[bytes, bytearray]):
        """Initialize decoder with source data
        
        Args:
            source: Source data for applying deltas
        """
        self.source = bytes(source)
    
    def decode(self, delta: Union[bytes, bytearray]) -> bytes:
        """Decode a VCDIFF delta and return target data
        
        Args:
            delta: VCDIFF delta data
            
        Returns:
            The decoded target data
            
        Raises:
            VCDIFFError: If the delta is malformed or cannot be decoded
        """
        # Parse the delta to get structured information
        parsed = parse_delta(delta)
        
        # Process all windows and accumulate target data
        target = bytearray()
        
        for window in parsed.windows:
            # Decode this window's target data
            window_target = self._decode_window(window, self.source)
            target.extend(window_target)
        
        return bytes(target)
    
    def _decode_window(self, window: Window, source: bytes) -> bytes:
        """Decode a single window using the source data and window instructions
        
        Args:
            window: Window to decode
            source: Source data
            
        Returns:
            Decoded target data for this window
            
        Raises:
            VCDIFFError: If the window cannot be decoded
        """
        # Initialize address cache
        address_cache = AddressCache(NEAR_CACHE_SIZE, SAME_CACHE_SIZE)
        address_cache.reset(window.address_section)
        
        # Create target buffer
        target = bytearray()
        
        # Get source segment for this window
        source_segment = b''
        source_length = 0
        if window.win_indicator & VCD_SOURCE:
            # Use source data
            start = window.source_segment_position
            end = start + window.source_segment_size
            if end > len(source):
                raise InvalidFormatError("source segment extends beyond source data")
            source_segment = source[start:end]
            source_length = len(source_segment)
        
        # Parse and execute the actual instructions
        instructions = self._parse_instructions(
            window.instruction_section, 
            window.data_section, 
            address_cache
        )
        
        # Execute each instruction
        for instruction in instructions:
            if instruction.type == InstructionType.NO_OP:
                # Skip
                continue
            
            elif instruction.type == InstructionType.ADD:
                # Add data from the instruction's data
                if len(instruction.data) != instruction.size:
                    raise InvalidFormatError("ADD instruction data size mismatch")
                target.extend(instruction.data)
            
            elif instruction.type == InstructionType.COPY:
                # Decode the address using the address cache
                here = len(target) + source_length
                addr = address_cache.decode_address(here, instruction.mode)
                
                # Determine if copying from source or target
                if addr < source_length:
                    # Copy from source segment
                    end = addr + instruction.size
                    if end > source_length:
                        raise err_out_of_bounds("COPY", addr, instruction.size, source_length)
                    target.extend(source_segment[addr:end])
                else:
                    # Copy from target data (self-referential copy)
                    target_addr = addr - source_length
                    if target_addr >= len(target):
                        raise VCDIFFError(
                            f"COPY instruction address {addr} references target position "
                            f"{target_addr} but target only has {len(target)} bytes"
                        )
                    
                    # Handle overlapping copies byte by byte
                    for i in range(instruction.size):
                        if target_addr + i >= len(target):
                            raise VCDIFFError(
                                f"COPY instruction would read beyond target bounds: "
                                f"position {target_addr + i}, target size {len(target)}"
                            )
                        target.append(target[target_addr + i])
            
            elif instruction.type == InstructionType.RUN:
                # Repeat a single byte
                if len(instruction.data) != 1:
                    raise InvalidFormatError("RUN instruction must have exactly 1 data byte")
                run_byte = instruction.data[0]
                target.extend([run_byte] * instruction.size)
            
            else:
                raise InvalidFormatError(f"unknown instruction type: {instruction.type}")
        
        # Validate Adler32 checksum if present
        if window.has_checksum:
            computed = compute_checksum(1, target)  # Adler32 starts with initial value 1
            if computed != window.checksum:
                raise InvalidChecksumError(
                    f"checksum validation failed: expected 0x{window.checksum:08x}, "
                    f"got 0x{computed:08x}"
                )
        
        return bytes(target)
    
    def _parse_instructions(
        self, 
        instruction_data: bytes, 
        data_section: bytes, 
        address_cache: AddressCache
    ) -> List[RuntimeInstruction]:
        """Parse the instruction data from a window using the code table
        
        Args:
            instruction_data: Raw instruction bytes
            data_section: Data section for ADD and RUN instructions
            address_cache: Address cache for this window
            
        Returns:
            List of runtime instructions
            
        Raises:
            VCDIFFError: If instructions cannot be parsed
        """
        stream = io.BytesIO(instruction_data)
        instructions = []
        data_index = 0
        instruction_offset = 0
        
        while True:
            code_data = stream.read(1)
            if not code_data:
                break
            
            code = code_data[0]
            
            # Each code can have up to 2 instructions
            for slot in range(2):
                instruction = DEFAULT_CODE_TABLE.get(code, slot)
                if instruction.type == InstructionType.NO_OP:
                    continue
                
                size = instruction.size
                if size == 0 and instruction.type != InstructionType.NO_OP:
                    size = read_varint(stream)
                
                runtime_inst = RuntimeInstruction(
                    type=instruction.type,
                    size=size,
                    mode=instruction.mode
                )
                
                # Handle instruction-specific data
                if instruction.type == InstructionType.ADD:
                    if data_index + size > len(data_section):
                        raise err_data_overrun("ADD", instruction_offset, size, len(data_section) - data_index)
                    runtime_inst.data = data_section[data_index:data_index + size]
                    data_index += size
                
                elif instruction.type == InstructionType.RUN:
                    if data_index >= len(data_section):
                        raise VCDIFFError(
                            f"RUN instruction at offset {instruction_offset} requires 1 byte "
                            "but no data available in data section"
                        )
                    runtime_inst.data = bytes([data_section[data_index]])
                    data_index += 1
                
                elif instruction.type == InstructionType.COPY:
                    # Address will be decoded when needed during execution
                    runtime_inst.mode = instruction.mode
                
                instructions.append(runtime_inst)
            
            instruction_offset += 1
        
        return instructions


def decode(source: Union[bytes, bytearray], delta: Union[bytes, bytearray]) -> bytes:
    """Decode a VCDIFF delta against source data
    
    Args:
        source: Source data
        delta: VCDIFF delta data
        
    Returns:
        The decoded target data
        
    Raises:
        VCDIFFError: If the delta cannot be decoded
    """
    decoder = Decoder(source)
    return decoder.decode(delta)


def parse_delta(delta: Union[bytes, bytearray]) -> ParsedDelta:
    """Parse a VCDIFF delta and return a structured representation
    
    Args:
        delta: VCDIFF delta data
        
    Returns:
        Parsed delta structure
        
    Raises:
        VCDIFFError: If the delta cannot be parsed
    """
    delta_bytes = bytes(delta)
    if len(delta_bytes) < MINIMUM_FILE_SIZE:
        raise InvalidFormatError("delta too small to be valid VCDIFF")
    
    parsed = ParsedDelta(
        header=Header(b'', 0, 0),
        windows=[],
        instructions=[]
    )
    
    stream = io.BytesIO(delta_bytes)
    
    _parse_header(stream, parsed)
    
    while stream.tell() < len(delta_bytes):
        window = _parse_window(stream)
        parsed.windows.append(window)
        
        # Create address cache for this window
        address_cache = AddressCache(NEAR_CACHE_SIZE, SAME_CACHE_SIZE)
        address_cache.reset(window.address_section)
        
        # Parse instructions using the instruction section and data section
        decoder_instance = Decoder(b'')  # Temporary decoder for parsing
        instructions = decoder_instance._parse_instructions(
            window.instruction_section,
            window.data_section,
            address_cache
        )
        parsed.instructions.extend(instructions)
    
    return parsed


def _parse_header(stream: BinaryIO, parsed: ParsedDelta) -> None:
    """Parse the VCDIFF header section
    
    Args:
        stream: Input stream
        parsed: Parsed delta to update
        
    Raises:
        VCDIFFError: If the header is invalid
    """
    # Read 3 magic bytes as defined in RFC 3284
    magic = stream.read(3)
    if len(magic) < 3:
        raise err_unexpected_eof("VCDIFF magic bytes", 3 - len(magic))
    
    # Compare magic bytes - RFC 3284 Section 4.1
    if magic != VCDIFF_MAGIC:
        raise InvalidMagicError(
            f"invalid VCDIFF magic bytes at offset 0: expected "
            f"{VCDIFF_MAGIC.hex()} but got {magic.hex()}"
        )
    
    version_data = stream.read(1)
    if not version_data:
        raise err_unexpected_eof("version byte", 1)
    
    version = version_data[0]
    if version != VCDIFF_VERSION:
        raise InvalidVersionError(
            f"invalid version at offset 3: value {version}, "
            f"only version {VCDIFF_VERSION} is supported"
        )
    
    indicator_data = stream.read(1)
    if not indicator_data:
        raise err_unexpected_eof("header indicator", 1)
    
    indicator = indicator_data[0]
    
    # Check for reserved bits in header indicator
    valid_header_bits = VCD_DECOMPRESS | VCD_CODETABLE | VCD_APPHEADER
    if indicator & ~valid_header_bits != 0:
        raise err_invalid_value("header indicator", 4, indicator, "reserved bits must be zero")
    
    parsed.header = Header(magic, version, indicator)


def _parse_window(stream: BinaryIO) -> Window:
    """Parse a single VCDIFF window
    
    Args:
        stream: Input stream
        
    Returns:
        Parsed window
        
    Raises:
        VCDIFFError: If the window is invalid
    """
    indicator_data = stream.read(1)
    if not indicator_data:
        raise err_unexpected_eof("window indicator", 1)
    
    indicator = indicator_data[0]
    
    # Check for reserved bits in window indicator
    valid_bits = VCD_SOURCE | VCD_TARGET | VCD_ADLER32
    if indicator & ~valid_bits != 0:
        raise err_invalid_value("window indicator", stream.tell() - 1, indicator, "reserved bits must be zero")
    
    window = Window(win_indicator=indicator)
    
    if indicator & VCD_SOURCE:
        window.source_segment_size = read_varint(stream)
        window.source_segment_position = read_varint(stream)
    
    # Read the length of the delta encoding
    window.delta_encoding_length = read_varint(stream)
    
    # Read the delta encoding section - RFC 3284 Section 4.3
    delta_data = stream.read(window.delta_encoding_length)
    if len(delta_data) != window.delta_encoding_length:
        raise err_unexpected_eof("delta encoding", window.delta_encoding_length - len(delta_data))
    
    # Parse the delta encoding according to RFC 3284 Section 4.3
    delta_stream = io.BytesIO(delta_data)
    
    # 1. Length of the target window
    window.target_window_length = read_varint(delta_stream)
    
    # 2. Delta_Indicator byte
    delta_indicator_data = delta_stream.read(1)
    if not delta_indicator_data:
        raise err_unexpected_eof("delta indicator", 1)
    window.delta_indicator = delta_indicator_data[0]
    
    # 3. Length of data for ADDs and RUNs
    window.data_section_length = read_varint(delta_stream)
    
    # 4. Length of instructions section
    window.instruction_section_length = read_varint(delta_stream)
    
    # 5. Length of addresses for COPYs
    window.address_section_length = read_varint(delta_stream)
    
    # Handle VCD_ADLER32 extension - checksum comes AFTER section lengths but BEFORE data sections
    if indicator & VCD_ADLER32:
        window.has_checksum = True
        # Read the 4-byte checksum from the delta encoding data
        checksum_bytes = delta_stream.read(4)
        if len(checksum_bytes) != 4:
            raise err_unexpected_eof("Adler32 checksum", 4 - len(checksum_bytes))
        # Convert to uint32 (big-endian)
        window.checksum = (
            (checksum_bytes[0] << 24) |
            (checksum_bytes[1] << 16) |
            (checksum_bytes[2] << 8) |
            checksum_bytes[3]
        )
    
    # 6. Data section for ADDs and RUNs
    window.data_section = delta_stream.read(window.data_section_length)
    if len(window.data_section) != window.data_section_length:
        raise err_unexpected_eof("data section", window.data_section_length - len(window.data_section))
    
    # 7. Instructions and sizes section
    window.instruction_section = delta_stream.read(window.instruction_section_length)
    if len(window.instruction_section) != window.instruction_section_length:
        raise err_unexpected_eof("instruction section", window.instruction_section_length - len(window.instruction_section))
    
    # 8. Addresses section for COPYs
    if window.address_section_length > 0:
        window.address_section = delta_stream.read(window.address_section_length)
        if len(window.address_section) != window.address_section_length:
            raise err_unexpected_eof("address section", window.address_section_length - len(window.address_section))
    
    return window