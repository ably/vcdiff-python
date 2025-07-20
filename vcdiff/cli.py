"""VCDIFF command-line interface"""

import io
import sys
from pathlib import Path
from typing import BinaryIO, List, Optional

import click

from . import decode, parse_delta
from .types import InstructionType, VCD_DECOMPRESS, VCD_CODETABLE, VCD_APPHEADER, VCD_SOURCE, VCD_TARGET, VCD_ADLER32


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """VCDIFF CLI Tool
    
    A command-line tool for working with VCDIFF (RFC 3284) delta files.
    
    VCDIFF is a format for expressing one data stream as a variant of another data stream,
    commonly used for binary differencing, compression, and patch applications.
    """
    pass


@cli.command()
@click.option("-b", "--base", "base_file", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to base document file")
@click.option("-d", "--delta", "delta_file", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to VCDIFF delta file")
@click.option("-o", "--output", "output_file", type=click.Path(path_type=Path),
              help="Path to output file (default: stdout)")
def apply(base_file: Path, delta_file: Path, output_file: Optional[Path]):
    """Apply a VCDIFF delta to a base document
    
    Apply a VCDIFF delta to a base document to produce the target document.
    
    The base document is the original file, and the delta contains the changes
    needed to transform it into the target document.
    
    Examples:
      vcdiff apply -base old.txt -delta patch.vcdiff -output new.txt
      vcdiff apply -base old.txt -delta patch.vcdiff  # Output to stdout
    """
    try:
        # Read base and delta files
        base_data = base_file.read_bytes()
        delta_data = delta_file.read_bytes()
        
        # Apply delta
        result = decode(base_data, delta_data)
        
        # Write output
        if output_file:
            output_file.write_bytes(result)
        else:
            sys.stdout.buffer.write(result)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("-d", "--delta", "delta_file", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to VCDIFF delta file")
def parse(delta_file: Path):
    """Parse a VCDIFF delta and show human-readable representation
    
    Parse a VCDIFF delta file and display its contents in a human-readable format.
    
    This command shows the VCDIFF header information, window details, and
    instruction sequences contained in the delta file.
    
    Examples:
      vcdiff parse -delta patch.vcdiff
      vcdiff parse -d patch.vcdiff  # Short form
    """
    try:
        delta_data = delta_file.read_bytes()
        parsed = parse_delta(delta_data)
        
        _print_delta(parsed)
        click.echo()
        
        _print_instructions(parsed, sys.stdout)
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("-b", "--base", "base_file", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to base document file")
@click.option("-d", "--delta", "delta_file", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to VCDIFF delta file")
def analyze(base_file: Path, delta_file: Path):
    """Analyze a VCDIFF delta with base document context
    
    Analyze a VCDIFF delta file with access to the base document to provide
    detailed information about the instructions and referenced data.
    
    This command shows the same information as 'parse' but also includes
    hexdump-style output of the actual data chunks referenced by COPY instructions.
    
    Examples:
      vcdiff analyze -base old.txt -delta patch.vcdiff
      vcdiff analyze -b old.txt -d patch.vcdiff  # Short form
    """
    try:
        base_data = base_file.read_bytes()
        delta_data = delta_file.read_bytes()
        parsed = parse_delta(delta_data)
        
        _print_delta(parsed)
        click.echo()
        
        _print_detailed_instructions(parsed, base_data, sys.stdout)
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _print_delta(parsed):
    """Print delta structure information"""
    _print_header(parsed.header)
    click.echo(f"  Windows:   {len(parsed.windows)}")
    
    for i, window in enumerate(parsed.windows):
        click.echo(f"  Window {i}:")
        _print_window(window)


def _print_header(header):
    """Print header information"""
    click.echo("VCDIFF Header:")
    click.echo(f"  Magic:     0x{header.magic[0]:02x} 0x{header.magic[1]:02x} 0x{header.magic[2]:02x}")
    click.echo(f"  Version:   0x{header.version:02x}")
    
    click.echo(f"  Indicator: 0x{header.indicator:02x}", nl=False)
    if header.indicator != 0:
        flags = []
        if header.indicator & VCD_DECOMPRESS:
            flags.append("VCD_DECOMPRESS")
        if header.indicator & VCD_CODETABLE:
            flags.append("VCD_CODETABLE")
        if header.indicator & VCD_APPHEADER:
            flags.append("VCD_APPHEADER")
        
        if flags:
            click.echo(f" ({', '.join(flags)})")
        else:
            click.echo()
    else:
        click.echo()


def _print_window(window):
    """Print window information"""
    click.echo(f"    WinIndicator:   0x{window.win_indicator:02x}", nl=False)
    if window.win_indicator != 0:
        flags = []
        if window.win_indicator & VCD_SOURCE:
            flags.append("VCD_SOURCE")
        if window.win_indicator & VCD_TARGET:
            flags.append("VCD_TARGET")
        if window.win_indicator & VCD_ADLER32:
            flags.append("VCD_ADLER32")
        
        if flags:
            click.echo(f" ({', '.join(flags)})")
        else:
            click.echo()
    else:
        click.echo()
    
    click.echo(f"    SourceSegmentSize:  0x{window.source_segment_size:x} ({window.source_segment_size})")
    click.echo(f"    SourceSegmentPosition:   0x{window.source_segment_position:x} ({window.source_segment_position})")
    click.echo(f"    TargetWindowLength:  0x{window.target_window_length:x} ({window.target_window_length})")
    click.echo(f"    DeltaEncodingLength: 0x{window.delta_encoding_length:x} ({window.delta_encoding_length})")
    click.echo(f"    DeltaIndicator: 0x{window.delta_indicator:02x}")
    click.echo(f"    DataSectionLength: 0x{window.data_section_length:x} ({window.data_section_length})")
    click.echo(f"    InstructionSectionLength: 0x{window.instruction_section_length:x} ({window.instruction_section_length})")
    click.echo(f"    AddressSectionLength: 0x{window.address_section_length:x} ({window.address_section_length})")
    if window.has_checksum:
        click.echo(f"    Adler32:     0x{window.checksum:08x}")


def _print_instructions(parsed, output):
    """Print instruction summary"""
    output.write("  Offset Code Type1 Size1  @Addr1 + Type2 Size2 @Addr2\n")
    
    for window in parsed.windows:
        _print_window_instructions(window, output)


def _print_window_instructions(window, output):
    """Print instructions for a single window"""
    instruction_stream = io.BytesIO(window.instruction_section)
    address_stream = io.BytesIO(window.address_section)
    
    offset = 0
    
    while True:
        code_data = instruction_stream.read(1)
        if not code_data:
            break
        
        code = code_data[0]
        
        # Look up instructions from code table
        from .codetable import DEFAULT_CODE_TABLE
        inst1 = DEFAULT_CODE_TABLE.get(code, 0)
        inst2 = DEFAULT_CODE_TABLE.get(code, 1)
        
        output.write(f"  {offset:06x} {code:03d}  ")
        
        # Print first instruction
        if inst1.type != InstructionType.NO_OP:
            _print_single_instruction(inst1, instruction_stream, address_stream, output)
        
        # Print second instruction if it exists
        if inst2.type != InstructionType.NO_OP:
            output.write(" + ")
            _print_single_instruction(inst2, instruction_stream, address_stream, output)
        
        output.write("\n")
        offset += 1


def _print_single_instruction(inst, instruction_stream, address_stream, output):
    """Print a single instruction"""
    # Get instruction type string
    type_str = {
        InstructionType.ADD: "ADD",
        InstructionType.COPY: f"CPY_{inst.mode}",
        InstructionType.RUN: "RUN",
        InstructionType.NO_OP: "NOOP"
    }.get(inst.type, f"UNK_{inst.type:02x}")
    
    # Get size
    size = inst.size
    if size == 0 and inst.type != InstructionType.NO_OP:
        from .varint import read_varint
        size = read_varint(instruction_stream)
    
    # Get address for COPY instructions
    addr_str = ""
    if inst.type == InstructionType.COPY:
        from .varint import read_varint
        
        if inst.mode == 0:  # SELF mode
            addr = read_varint(address_stream)
            addr_str = f"S@{addr}"
        elif inst.mode == 1:  # HERE mode
            offset = read_varint(address_stream)
            addr_str = f"H@{offset}"
        else:
            # Near/Same cache modes
            if inst.mode < 6:
                offset = read_varint(address_stream)
                addr_str = f"N{inst.mode - 2}@{offset}"
            else:
                b_data = address_stream.read(1)
                if b_data:
                    b = b_data[0]
                    addr_str = f"S{inst.mode - 6}@{b}"
    
    if inst.type == InstructionType.COPY:
        output.write(f"{type_str} {size:6d} {addr_str}")
    else:
        output.write(f"{type_str} {size:6d}")


def _print_detailed_instructions(parsed, base_data: bytes, output):
    """Print detailed instruction information with data context"""
    output.write("Instructions with Data Context:\n")
    output.write("===============================\n\n")
    
    for i, instruction in enumerate(parsed.instructions):
        output.write(f"Instruction {i + 1}:\n")
        
        inst_type = {
            InstructionType.ADD: "ADD",
            InstructionType.COPY: "COPY",
            InstructionType.RUN: "RUN",
            InstructionType.NO_OP: "NOOP"
        }.get(instruction.type, f"UNK({instruction.type:02x})")
        
        output.write(f"  Type: {inst_type}\n")
        output.write(f"  Mode: 0x{instruction.mode:02x}\n")
        output.write(f"  Size: 0x{instruction.size:x} ({instruction.size} bytes)\n")
        
        if instruction.type == InstructionType.COPY:
            output.write(f"  Addr: 0x{instruction.addr:x} ({instruction.addr})\n")
            
            if instruction.addr < len(base_data):
                end_addr = min(instruction.addr + instruction.size, len(base_data))
                output.write(f"  Data from base [0x{instruction.addr:x}:0x{end_addr:x}]:\n")
                _print_hex_dump(base_data[instruction.addr:end_addr], output, instruction.addr)
            else:
                output.write("  Data: <address out of bounds>\n")
        elif instruction.data:
            output.write("  Data:\n")
            _print_hex_dump(instruction.data, output, 0)
        
        output.write("\n")


def _print_hex_dump(data: bytes, output, base_offset: int):
    """Print hexdump-style output"""
    bytes_per_line = 16
    
    for i in range(0, len(data), bytes_per_line):
        end = min(i + bytes_per_line, len(data))
        line = data[i:end]
        
        output.write(f"    {base_offset + i:08x}  ")
        
        # Hex bytes
        for j in range(bytes_per_line):
            if j < len(line):
                output.write(f"{line[j]:02x} ")
            else:
                output.write("   ")
            
            if j == 7:
                output.write(" ")
        
        # ASCII representation
        output.write(" |")
        for b in line:
            if 32 <= b <= 126:
                output.write(chr(b))
            else:
                output.write(".")
        output.write("|\n")


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()