# VCDIFF Python Decoder

A Python implementation of a VCDIFF (RFC 3284) decoder library and command-line tool for efficient binary differencing and compression.

## Overview

The library provides a VCDIFF decoder that can decode delta files created according to RFC 3284 - The VCDIFF Generic Differencing and Compression Data Format. VCDIFF is a format for expressing one data stream as a variant of another data stream, commonly used for binary differencing, compression, and patch applications.

## Features

- **Python Library**: RFC 3284 compliant VCDIFF decoding with clean, Pythonic API
- **Command-Line Tool**: Apply deltas and inspect VCDIFF file structure
- **Comprehensive Validation**: Support for all VCDIFF instruction types (ADD, COPY, RUN)
- **Address Caching**: Efficient decoding with proper address cache implementation
- **Checksum Validation**: Full Adler-32 checksum validation support
- **Robust Error Handling**: Detailed error messages for debugging malformed files
- **Extensive Testing**: 85 test cases with reference implementation validation
- **Type Safety**: Full type hints for better development experience

## Limitations

- **Application Headers**: This implementation does not handle application header information
- **Secondary Compression**: This decoder does not support secondary compression (e.g., gzip, bzip2)
- **Compatibility**: Works with VCDIFF deltas created using `xdelta3 -e -S -A` (no secondary compression, no application header)

## Checksum Support

- **VCD_ADLER32**: This implementation detects and parses the VCD_ADLER32 extension (bit 0x04 in window indicator)
- **Non-standard Extension**: The Adler-32 checksum is not part of RFC 3284 but is supported by some implementations
- **Validation**: Full Adler-32 checksum validation is implemented and performed during decoding
- **Display**: Checksums are displayed in the CLI output as `Adler32: 0x########`

## Installation

```bash
pip install vcdiff
```

### Development Installation

```bash
poetry install
```

### Cloning with Test Suite

This repository includes the VCDIFF test suite as a git submodule. To clone the repository with all test cases:

```bash
git clone --recursive https://github.com/ably/vcdiff-py.git
```

If you've already cloned the repository without the submodule, initialize it:

```bash
git submodule update --init --recursive
```

To update the test suite submodule to the latest version:

```bash
git submodule update --remote
```

## Quick Start

### Library Usage

```python
import vcdiff_decoder

# Read the source file
with open("original.txt", "rb") as f:
    source = f.read()

# Read the VCDIFF delta file
with open("changes.vcdiff", "rb") as f:
    delta_data = f.read()

# Apply the delta to reconstruct the target
try:
    result = vcdiff_decoder.decode(source, delta_data)
    print(f"Decoded result: {result}")
except vcdiff_decoder.VCDIFFError as e:
    print(f"Decoding failed: {e}")
```

## API Reference

### Core Functions

#### `vcdiff.decode(source: bytes, delta: bytes) -> bytes`

Decodes a VCDIFF delta file using the provided source data and returns the reconstructed target data.

**Parameters:**
- `source`: The original source data (may be empty for deltas that don't reference source)
- `delta`: The VCDIFF delta file data

**Returns:**
- Decoded target data as bytes

**Raises:**
- `VCDIFFError`: If decoding fails (malformed delta, checksum validation failure, etc.)

#### `vcdiff.Decoder(source: bytes)`

Creates a new decoder instance with the specified source data. Useful for decoding multiple deltas against the same source.

**Parameters:**
- `source`: The source data for decoding operations

**Returns:**
- A `Decoder` instance that can be used to decode multiple deltas

#### `decoder.decode(delta: bytes) -> bytes`

Decodes a single VCDIFF delta using the decoder's source data.

### Error Handling

The decoder provides detailed error messages for various failure conditions:
- Invalid VCDIFF format or magic bytes
- Malformed varint encoding
- Out-of-bounds memory access attempts
- Checksum validation failures
- Truncated or corrupted delta files

**Exception Hierarchy:**
- `VCDIFFError`: Base exception for all VCDIFF-related errors
- `InvalidMagicError`: Invalid VCDIFF magic bytes
- `InvalidVersionError`: Unsupported VCDIFF version
- `InvalidFormatError`: Malformed delta structure
- `CorruptedDataError`: Data corruption detected
- `InvalidChecksumError`: Checksum validation failure

## Testing

### Prerequisites

For comprehensive testing, this project uses xdelta3 as a reference implementation to verify the correctness of the decoder.

#### Installing xdelta3

##### macOS (Homebrew)
```bash
brew install xdelta
```

##### Linux (Ubuntu/Debian)
```bash
sudo apt-get install xdelta3
```

### Running Tests

To run the Python unit tests:

```bash
poetry run pytest
```

To run tests with coverage:

```bash
poetry run pytest --cov=vcdiff tests/
```

To run the comprehensive test suite against the VCDIFF test cases (requires submodule):

```bash
poetry run pytest tests/test_vcdiff.py -v
```

The test suite includes:
- **20 general positive tests**: Valid VCDIFF files that should decode successfully
- **33 targeted negative tests**: Invalid VCDIFF files that should be rejected with appropriate errors
- **32 targeted positive tests**: Specific feature validation tests
- **Total**: 85 test cases with 100% pass rate

### Test Results
- **General Positive Tests**: 20/20 passed ✅
- **Targeted Negative Tests**: 33/33 passed ✅
- **Targeted Positive Tests**: 32/32 passed ✅

## Contributing

Contributions are welcomed. Please follow these guidelines:

### Getting Started

1. Fork the repository
2. Clone your fork with submodules: `git clone --recursive <your-fork-url>`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

### Development Guidelines

- **Code Style**: Follow PEP 8 formatting (`black .` for automatic formatting)
- **Type Hints**: All new code should include proper type annotations
- **Testing**: All new features must include tests
- **Documentation**: Update documentation for any API changes
- **Commits**: Use clear, descriptive commit messages

### Before Submitting

Ensure your contribution passes all checks:

```bash
# Run all tests
pytest

# Format code
black .

# Lint code
flake8 vcdiff/

# Type checking
mypy vcdiff/
```

### Reporting Issues

When reporting bugs, please include:
- Python version
- Operating system
- Minimal reproduction case
- Expected vs actual behavior
- Sample VCDIFF files (if applicable)

### Feature Requests

For new features, please:
- Check existing issues first
- Describe the use case
- Provide RFC 3284 references if applicable
- Consider backwards compatibility

## Requirements

- **Python**: 3.8 or higher
- **Development Dependencies**:
  - `pytest>=7.0.0`
  - `pytest-cov>=4.0.0`
  - `black>=22.0.0`
  - `flake8>=5.0.0`
  - `mypy>=1.0.0`

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

## References

- [RFC 3284: The VCDIFF Generic Differencing and Compression Data Format](https://tools.ietf.org/html/rfc3284)
- [xdelta3: VCDIFF binary diff tool](https://github.com/jmacd/xdelta)
- [Go VCDIFF Implementation](https://github.com/ably/vcdiff-go) - Algorithmically compatible sibling project