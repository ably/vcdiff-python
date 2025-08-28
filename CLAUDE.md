# VCDIFF Python Implementation - Development Guidelines

## Project Overview

This is a complete Python implementation of VCDIFF (RFC 3284) delta compression format, algorithmically compatible with the Go implementation at https://github.com/ably/vcdiff-go. The implementation follows the same design patterns and passes the same comprehensive test suite.

**Copyright holder:** Ably Realtime Limited

## Implementation Status

✅ **Complete and Working**
- **Decoder**: Full VCDIFF delta decoding with all instruction types (ADD, COPY, RUN)
- **Parser**: Complete delta parsing with structured output
- **Checksum**: Adler32 checksum validation fully implemented
- **Address Cache**: Complete address cache implementation for COPY instructions
- **Error Handling**: Comprehensive validation with detailed error messages
- **CLI**: Full command-line interface with apply, parse, and analyze commands
- **Testing**: Passes all 85 test cases from the shared vcdiff-tests submodule

## Test Results

- **General Positive Tests**: 20/20 passed ✅
- **Targeted Negative Tests**: 33/33 passed ✅
- **Targeted Positive Tests**: 32/32 passed ✅
- **Total**: 85/85 test cases passed (100% success rate)

## Architecture

### Core Modules

- **`vcdiff/types.py`**: Constants, data structures, and type definitions
- **`vcdiff/exceptions.py`**: Exception hierarchy and error utilities
- **`vcdiff/varint.py`**: Variable-length integer encoding/decoding
- **`vcdiff/adler32.py`**: Adler32 checksum implementation
- **`vcdiff/addresscache.py`**: Address cache for COPY instruction addressing
- **`vcdiff/codetable.py`**: Default instruction code table (RFC 3284 Section 5)
- **`vcdiff/decoder.py`**: Main decoder implementation and delta parser
- **`vcdiff/cli.py`**: Command-line interface

### Key Design Principles

1. **RFC 3284 Compliance**: Follows the specification exactly
2. **Go Compatibility**: Algorithmically identical to the Go implementation
3. **Error Handling**: Comprehensive validation with specific error messages
4. **Type Safety**: Full type hints for better maintainability

## CLI Commands

### Apply Delta
```bash
vcdiff apply -base source.txt -delta patch.vcdiff -output target.txt
vcdiff apply -base source.txt -delta patch.vcdiff  # Output to stdout
```

### Parse Delta Structure
```bash
vcdiff parse -delta patch.vcdiff
```

### Detailed Analysis
```bash
vcdiff analyze -base source.txt -delta patch.vcdiff
```

## Development Workflow

### Setup
```bash
cd vcdiff-py
pip install -e .[dev]  # Install in development mode
```

### Running Tests
```bash
pytest                    # Run all tests
pytest -v                 # Verbose output
pytest --cov=vcdiff      # With coverage
```

### Code Quality
```bash
black .                   # Format code
flake8 vcdiff/           # Lint code  
mypy vcdiff/             # Type checking
```

## Project Structure

```
vcdiff-py/
├── vcdiff/                 # Main package
│   ├── __init__.py        # Package interface
│   ├── types.py           # Constants and data structures
│   ├── exceptions.py      # Error handling
│   ├── varint.py          # Variable-length integers
│   ├── adler32.py         # Checksum implementation
│   ├── addresscache.py    # Address cache
│   ├── codetable.py       # Instruction code table
│   ├── decoder.py         # Main decoder logic
│   └── cli.py             # Command-line interface
├── tests/                 # Test suite
│   ├── __init__.py
│   └── test_vcdiff.py     # Comprehensive tests
├── submodules/            # Git submodules
│   └── vcdiff-tests/      # Shared test suite
├── setup.py              # Package setup
├── pyproject.toml        # Modern Python packaging
├── pytest.ini           # Test configuration
├── README.md             # User documentation
└── CLAUDE.md             # This file
```

## Key Implementation Details

### Constants and Magic Values
All numeric constants are properly defined with RFC references:
```python
VCDIFF_MAGIC = bytes([0xD6, 0xC3, 0xC4])  # RFC 3284 Section 4.1
VCDIFF_VERSION = 0x00                      # Version 0
VCD_SOURCE = 0x01                          # Window uses source data
VCD_ADLER32 = 0x04                         # Adler32 checksum extension
```

### Error Handling
Comprehensive error hierarchy with specific error types:
- `InvalidMagicError`: Invalid VCDIFF magic bytes
- `InvalidVersionError`: Unsupported version
- `InvalidFormatError`: Malformed delta structure
- `CorruptedDataError`: Data corruption detected
- `InvalidChecksumError`: Checksum validation failure

### Address Cache Implementation
Full implementation of RFC 3284 Section 5.3 address cache with:
- Near cache (4 entries, LRU replacement)
- Same cache (768 entries, direct indexing)
- Multiple addressing modes (SELF, HERE, near, same)

### Instruction Execution
Complete instruction processing:
- **ADD**: Copy data from delta's data section
- **COPY**: Copy from source or target with address cache resolution
- **RUN**: Repeat single byte multiple times
- **Compound Instructions**: Handle dual instructions in single code

### Test Integration
Uses the same `vcdiff-tests` submodule as the Go implementation:
- Positive test cases: Real-world delta scenarios
- Negative test cases: Malformed input validation
- Targeted test cases: Specific feature validation

## Compatibility

### With Go Implementation
- Identical algorithm implementation
- Same error conditions and messages
- Compatible CLI interface
- Shared test suite (100% pass rate)

### Python Versions
- Minimum: Python 3.8
- Tested: Python 3.8, 3.9, 3.10, 3.11, 3.12

## Limitations (Same as Go Implementation)

- **Encoding**: Only decoding is implemented (no delta creation)
- **Application Headers**: Not supported (VCD_APPHEADER)
- **Secondary Compression**: Not supported (VCD_DECOMPRESS) 
- **Custom Code Tables**: Not supported (VCD_CODETABLE)

## Performance Notes

- Efficient byte-by-byte copying for overlapping COPY operations
- Memory-efficient delta parsing with streaming readers
- Optimized address cache with proper data structures
- All test cases complete in under 2 seconds total

## Future Enhancements

Potential areas for extension:
1. **Encoding Support**: Delta creation functionality
2. **Compression**: Secondary compression algorithm integration
3. **Custom Code Tables**: Support for application-specific instruction tables
4. **Streaming**: Large file support with streaming I/O

## Maintenance Notes

- Keep in sync with Go implementation changes
- Update shared test suite regularly
- Maintain RFC 3284 compliance
- Monitor Python version compatibility