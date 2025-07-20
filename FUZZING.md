# Fuzz Testing for VCDIFF Python Library

This document outlines the fuzz testing strategies for the VCDIFF Python implementation. We use multiple fuzzing approaches to ensure robustness and security.

## Overview

Fuzz testing is critical for VCDIFF implementations because:
- **Untrusted Input**: VCDIFF deltas often come from external sources
- **Complex Parsing**: Multiple nested data structures with variable-length encoding
- **Memory Safety**: Potential for buffer overruns and infinite loops
- **Security**: Malformed deltas could cause crashes or unexpected behavior

## Fuzzing Approaches

### 1. Hypothesis-based Property Testing (Recommended)

**Tool**: [Hypothesis](https://hypothesis.readthedocs.io/)
**Advantages**: 
- Excellent Python integration
- Property-based testing with shrinking
- Deterministic replay of failures
- Custom strategies for VCDIFF structures

### 2. AFL++ with Python-AFL

**Tool**: [python-afl](https://github.com/jwilk/python-afl) + [AFL++](https://aflplus.plus/)
**Advantages**:
- Industry-standard coverage-guided fuzzing
- Excellent at finding edge cases
- Persistent mode for performance
- Mutation strategies

### 3. Atheris (Google's Python Fuzzer)

**Tool**: [Atheris](https://github.com/google/atheris)
**Advantages**:
- Native Python fuzzing with libFuzzer backend
- Easy integration with existing code
- Excellent performance
- Coverage tracking

### 4. OSS-Fuzz Integration

**Tool**: [OSS-Fuzz](https://google.github.io/oss-fuzz/)
**Advantages**:
- Continuous fuzzing in Google's infrastructure
- Automatic bug reporting
- Corpus management
- ClusterFuzz integration

## Implementation Strategy

### Phase 1: Hypothesis Property Testing

Start with property-based testing using Hypothesis:

```python
# tests/test_fuzz_hypothesis.py
from hypothesis import given, strategies as st, settings, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant
import vcdiff

@given(
    source=st.binary(),
    delta=st.binary(min_size=0, max_size=1024)
)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_decode_never_panics(source, delta):
    """Decoder should never raise unexpected exceptions"""
    try:
        result = vcdiff.decode(source, delta)
        # If successful, result should be bytes
        assert isinstance(result, bytes)
        # Result shouldn't be unreasonably large
        assert len(result) <= 10 * 1024 * 1024  # 10MB limit
    except vcdiff.VCDIFFError:
        # Expected errors are fine
        pass
    except Exception as e:
        # Unexpected exceptions should be reported
        pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")
```

### Phase 2: Atheris Integration

Use Atheris for coverage-guided fuzzing:

```python
# fuzz_atheris.py
import atheris
import sys
import vcdiff

def TestOneInput(data):
    """Atheris fuzzing harness"""
    if len(data) < 4:
        return
    
    # Split data into source and delta
    split_point = data[0] % len(data)
    source = data[1:split_point+1]
    delta = data[split_point+1:]
    
    try:
        result = vcdiff.decode(source, delta)
        # Sanity check on result
        if len(result) > 50 * 1024 * 1024:  # 50MB limit
            raise ValueError("Result too large")
    except vcdiff.VCDIFFError:
        # Expected VCDIFF errors are fine
        pass
    except (MemoryError, SystemExit, KeyboardInterrupt):
        # Re-raise system exceptions
        raise
    except Exception as e:
        # Log unexpected exceptions but don't fail
        # (Atheris will track these as interesting inputs)
        pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

### Phase 3: AFL++ Integration

Use AFL++ for long-term continuous fuzzing:

```python
# fuzz_afl.py
import afl
import sys
import vcdiff

def main():
    afl.init()
    
    while afl.loop(1000):  # Persistent mode
        try:
            # Read from stdin (AFL input)
            data = sys.stdin.buffer.read()
            
            if len(data) < 4:
                continue
                
            # Split input into source and delta
            split_point = data[0] % len(data)
            source = data[1:split_point+1]
            delta = data[split_point+1:]
            
            # Test decode function
            try:
                result = vcdiff.decode(source, delta)
                # Basic sanity check
                assert isinstance(result, bytes)
                assert len(result) <= 100 * 1024 * 1024  # 100MB
            except vcdiff.VCDIFFError:
                pass  # Expected errors
            except (MemoryError, SystemExit):
                raise
            except Exception:
                pass  # Let AFL track interesting cases
                
        except (SystemExit, KeyboardInterrupt):
            break
        except:
            pass

if __name__ == "__main__":
    main()
```

## Target Functions for Fuzzing

### Core Functions
1. **`vcdiff.decode(source, delta)`** - Main entry point
2. **`vcdiff.parse_delta(delta)`** - Delta parser
3. **`Decoder.decode(delta)`** - Decoder instance method

### Internal Components
1. **Variable-length integers** - `varint.read_varint()`
2. **Address cache** - `AddressCache.decode_address()`
3. **Instruction parsing** - `_parse_instructions()`
4. **Window decoding** - `_decode_window()`
5. **Header parsing** - `_parse_header()`

## Fuzzing Harness Design

### Input Generation Strategy

```python
# Custom Hypothesis strategies for VCDIFF
import hypothesis.strategies as st

def vcdiff_magic():
    """Generate valid/invalid VCDIFF magic bytes"""
    return st.one_of(
        st.just(b'\xd6\xc3\xc4'),  # Valid magic
        st.binary(min_size=3, max_size=3)  # Random 3 bytes
    )

def vcdiff_header():
    """Generate VCDIFF headers"""
    return st.builds(
        lambda magic, version, indicator: magic + bytes([version, indicator]),
        magic=vcdiff_magic(),
        version=st.integers(0, 255),
        indicator=st.integers(0, 255)
    )

def malformed_varint():
    """Generate potentially malformed varints"""
    return st.one_of(
        st.binary(min_size=0, max_size=0),  # Empty
        st.binary(min_size=1, max_size=1),  # Single byte
        st.binary(min_size=2, max_size=6),  # Multi-byte
        st.just(b'\x80' * 10),  # Too long
    )
```

### Coverage Tracking

Monitor code coverage during fuzzing:

```python
# coverage_fuzzer.py
import coverage
import vcdiff
import random
import time

def fuzz_with_coverage(duration_seconds=3600):
    """Run fuzzing while tracking coverage"""
    cov = coverage.Coverage()
    cov.start()
    
    start_time = time.time()
    test_count = 0
    
    try:
        while time.time() - start_time < duration_seconds:
            # Generate random inputs
            source = bytes(random.getrandbits(8) for _ in range(random.randint(0, 1000)))
            delta = bytes(random.getrandbits(8) for _ in range(random.randint(0, 1000)))
            
            try:
                vcdiff.decode(source, delta)
            except vcdiff.VCDIFFError:
                pass
            except Exception:
                pass
            
            test_count += 1
            if test_count % 1000 == 0:
                print(f"Tested {test_count} inputs...")
    
    finally:
        cov.stop()
        cov.save()
        
        # Generate coverage report
        print(f"\nCoverage Report after {test_count} tests:")
        cov.report(include="vcdiff/*")
        cov.html_report(directory="coverage_html")
```

## Continuous Integration

### GitHub Actions Fuzzing

```yaml
# .github/workflows/fuzz.yml
name: Fuzz Testing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  fuzz-hypothesis:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: |
        pip install hypothesis pytest
        pip install -e .
    - name: Run Hypothesis fuzzing
      run: pytest tests/test_fuzz_hypothesis.py -v --tb=short
      timeout-minutes: 30

  fuzz-atheris:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install Atheris
      run: pip install atheris
    - name: Run Atheris fuzzing
      run: python fuzz_atheris.py -max_total_time=1800  # 30 minutes
      continue-on-error: true
```

## Expected Findings

### Common Vulnerability Classes
1. **Buffer overflows** - In self-referential copies
2. **Integer overflows** - In size calculations
3. **Infinite loops** - In instruction processing
4. **Memory exhaustion** - Through large allocations
5. **Format string bugs** - In error messages
6. **Denial of Service** - Through complex inputs

### Performance Issues
1. **Quadratic complexity** - In overlapping copies
2. **Memory leaks** - In error paths
3. **Stack overflow** - In recursive parsing

## Corpus Management

### Seed Corpus
- Valid VCDIFF files from test suite
- Minimal valid headers
- Edge case inputs (empty files, maximum sizes)
- Known problematic inputs from Go fuzzing

### Corpus Minimization
```bash
# AFL corpus minimization
afl-cmin -i input_corpus -o minimized_corpus -- python fuzz_afl.py

# Custom minimizer for Hypothesis
python minimize_corpus.py --input corpus/ --output minimal_corpus/
```

## Running Fuzz Tests

### Quick Start
```bash
# Install fuzzing dependencies
pip install hypothesis atheris python-afl-pip

# Run property-based fuzzing
pytest tests/test_fuzz_hypothesis.py

# Run Atheris fuzzing (5 minutes)
python fuzz_atheris.py -max_total_time=300

# Run AFL++ fuzzing
echo "sample_input" | python fuzz_afl.py
```

### Production Fuzzing
```bash
# Long-term AFL++ fuzzing
mkdir -p fuzz_inputs fuzz_outputs
echo -e "\\xd6\\xc3\\xc4\\x00\\x00" > fuzz_inputs/minimal.vcdiff
afl-fuzz -i fuzz_inputs -o fuzz_outputs -- python fuzz_afl.py

# Atheris with large time budget
python fuzz_atheris.py -max_total_time=86400  # 24 hours
```

## Best Practices

1. **Test in Isolation**: Each fuzz target should test one component
2. **Monitor Resources**: Set memory/time limits to prevent hangs
3. **Reproduce Failures**: Save failing inputs for regression testing
4. **Regular Updates**: Keep fuzz corpus synchronized with test changes
5. **Multiple Strategies**: Use different fuzzers for comprehensive coverage
6. **CI Integration**: Run lightweight fuzzing on every PR

## Security Considerations

- Never run fuzzers with elevated privileges
- Isolate fuzzing in containers/VMs when possible  
- Monitor system resources during long fuzzing campaigns
- Review all fuzzing findings before fixing
- Consider impact of findings on downstream users