"""VCDIFF default code table implementation - RFC 3284 Section 5"""

from typing import List, Tuple

from .types import Instruction, InstructionType


class CodeTable:
    """VCDIFF instruction code table"""
    
    def __init__(self):
        """Initialize empty code table"""
        # Initialize all entries to NO_OP
        self.entries: List[Tuple[Instruction, Instruction]] = [
            (
                Instruction(InstructionType.NO_OP, 0, 0),
                Instruction(InstructionType.NO_OP, 0, 0)
            )
            for _ in range(256)
        ]
    
    def get(self, code: int, slot: int) -> Instruction:
        """Get the instruction at the given code and slot
        
        Args:
            code: Instruction code (0-255)
            slot: Slot number (0 or 1)
            
        Returns:
            The instruction at the specified code and slot
        """
        return self.entries[code][slot]


def build_default_code_table() -> CodeTable:
    """Create the default code table specified in RFC 3284
    
    Returns:
        The default code table
    """
    ct = CodeTable()
    
    # Entry 0: RUN with size 0
    ct.entries[0] = (
        Instruction(InstructionType.RUN, 0, 0),
        Instruction(InstructionType.NO_OP, 0, 0)
    )
    
    # Entries 1-18: ADD with sizes 0-17
    for i in range(18):
        ct.entries[i + 1] = (
            Instruction(InstructionType.ADD, i, 0),
            Instruction(InstructionType.NO_OP, 0, 0)
        )
    
    index = 19
    
    # Entries 19-162: COPY instructions with different modes and sizes
    for mode in range(9):
        # COPY with size 0 (size will be read from stream)
        ct.entries[index] = (
            Instruction(InstructionType.COPY, 0, mode),
            Instruction(InstructionType.NO_OP, 0, 0)
        )
        index += 1
        
        # COPY with sizes 4-18
        for size in range(4, 19):
            ct.entries[index] = (
                Instruction(InstructionType.COPY, size, mode),
                Instruction(InstructionType.NO_OP, 0, 0)
            )
            index += 1
    
    # Entries 163-234: Combined ADD+COPY instructions
    for mode in range(6):
        for add_size in range(1, 5):
            for copy_size in range(4, 7):
                ct.entries[index] = (
                    Instruction(InstructionType.ADD, add_size, 0),
                    Instruction(InstructionType.COPY, copy_size, mode)
                )
                index += 1
    
    # Entries 235-246: More combined ADD+COPY instructions
    for mode in range(6, 9):
        for add_size in range(1, 5):
            ct.entries[index] = (
                Instruction(InstructionType.ADD, add_size, 0),
                Instruction(InstructionType.COPY, 4, mode)
            )
            index += 1
    
    # Entries 247-255: COPY+ADD combinations
    for mode in range(9):
        ct.entries[index] = (
            Instruction(InstructionType.COPY, 4, mode),
            Instruction(InstructionType.ADD, 1, 0)
        )
        index += 1
    
    return ct


# Default code table instance
DEFAULT_CODE_TABLE = build_default_code_table()