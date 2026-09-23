# Changelog

## [0.2.0](https://github.com/ably/vcdiff-python/tree/v0.2.0) (2026-09-23)

### Fixed

- The near address cache no longer rejects a slot holding address 0. RFC 3284 section 5.1 zero
  fills both caches at the start of a window, so 0 is an ordinary cached address, and a COPY
  addressed against it (a copy from the start of the source, for instance) raised
  "near cache slot N is uninitialized" instead of decoding
  [#692](https://github.com/ably/ably-pubsub-python/issues/692)
- The same address cache is now sized and indexed consistently. It was allocated with
  `s_same * 256 * 256` slots while being read at `(mode - 6) * 256 + byte`, so every address at or
  above 768 was stored where no read could reach it and resolved to address 0, silently producing
  the wrong output for deltas that use same modes
  [#692](https://github.com/ably/ably-pubsub-python/issues/692)

### Breaking changes

These affect only code that imports the internal modules directly. The public API exported from
`vcdiff_decoder` (`decode`, `Decoder`, `parse_delta` and the exception types) is unchanged.

- `vcdiff_decoder.types.SAME_CACHE_SIZE` (`3 * 256`) is removed and replaced by
  `SAME_CACHE_BLOCKS` (`3`), the RFC 3284 `s_same` value: the number of 256-slot blocks in the same
  cache rather than a slot count. Code that imported `SAME_CACHE_SIZE` must switch to
  `SAME_CACHE_BLOCKS` (multiply by 256 if you need the number of slots)

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
