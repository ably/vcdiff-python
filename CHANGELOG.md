# Changelog

## [0.1.0](https://github.com/ably/vcdiff-python/tree/v0.1.0) (2025-09-16)

This is the initial release of the VCDIFF (RFC 3284) decoder library for Python. 
It provides the following features:

- Complete VCDIFF (RFC 3284) delta compression format decoder implementation
- Full delta parsing with structured output capabilities
- Adler32 checksum validation for data integrity
- Address cache implementation for COPY instruction optimization
- Comprehensive error handling with detailed error messages
- Command-line interface with apply, parse, and analyze commands
- Support for all VCDIFF instruction types (ADD, COPY, RUN)
- Compatible with Python 3.7+
- 100% test coverage with 85/85 test cases passing
- Comprehensive test suite integration via vcdiff-tests submodule