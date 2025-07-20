"""VCDIFF exception classes"""


class VCDIFFError(Exception):
    """Base exception for VCDIFF operations"""
    pass


class InvalidMagicError(VCDIFFError):
    """Invalid VCDIFF magic bytes"""
    pass


class InvalidVersionError(VCDIFFError):
    """Unsupported VCDIFF version"""
    pass


class InvalidFormatError(VCDIFFError):
    """Invalid VCDIFF format"""
    pass


class CorruptedDataError(VCDIFFError):
    """Corrupted VCDIFF data"""
    pass


class InvalidChecksumError(VCDIFFError):
    """Invalid checksum"""
    pass


def err_unexpected_eof(context: str, bytes_needed: int) -> VCDIFFError:
    """Create unexpected EOF error with context"""
    return VCDIFFError(f"unexpected EOF while reading {context}: need {bytes_needed} bytes")


def err_data_overrun(instruction: str, offset: int, needed: int, available: int) -> VCDIFFError:
    """Create data overrun error"""
    return VCDIFFError(
        f"{instruction} instruction at offset {offset} requires {needed} bytes "
        f"but only {available} available in data section"
    )


def err_invalid_value(field: str, offset: int, value, reason: str) -> VCDIFFError:
    """Create invalid value error"""
    return VCDIFFError(f"invalid {field} at offset {offset}: value {value}, {reason}")


def err_out_of_bounds(instruction: str, address: int, size: int, max_bound: int) -> VCDIFFError:
    """Create out of bounds error"""
    return VCDIFFError(
        f"{instruction} instruction address {address} + size {size} exceeds bounds (max {max_bound})"
    )