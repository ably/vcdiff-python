"""Property-based fuzz testing using Hypothesis"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant
import sys
from pathlib import Path

# Add the parent directory to the path so we can import vcdiff
sys.path.insert(0, str(Path(__file__).parent.parent))

import vcdiff
from vcdiff.exceptions import VCDIFFError
from vcdiff.varint import read_varint
from vcdiff.addresscache import AddressCache
import io


class TestFuzzDecode:
    """Fuzz tests for the main decode function"""
    
    @given(
        source=st.binary(max_size=1024),
        delta=st.binary(max_size=1024)
    )
    @settings(
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=200,
        deadline=None
    )
    def test_decode_never_crashes(self, source, delta):
        """Decoder should never crash with unexpected exceptions"""
        try:
            result = vcdiff.decode(source, delta)
            # If successful, result should be bytes
            assert isinstance(result, bytes)
            # Result shouldn't be unreasonably large (potential zip bomb protection)
            assert len(result) <= 50 * 1024 * 1024  # 50MB limit
        except VCDIFFError:
            # Expected VCDIFF errors are fine
            pass
        except (MemoryError, SystemExit, KeyboardInterrupt):
            # Re-raise critical system exceptions
            raise
        except Exception as e:
            # Any other exception is a bug
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")
    
    @given(
        source=st.binary(max_size=100),
        delta=st.binary(max_size=100).filter(lambda x: len(x) >= 5)
    )
    @settings(max_examples=100)
    def test_decode_with_valid_magic(self, source, delta):
        """Test with potentially valid VCDIFF magic bytes"""
        # Replace first 3 bytes with valid magic
        if len(delta) >= 3:
            modified_delta = b'\xd6\xc3\xc4' + delta[3:]
            try:
                result = vcdiff.decode(source, modified_delta)
                assert isinstance(result, bytes)
                assert len(result) <= 10 * 1024 * 1024
            except VCDIFFError:
                pass  # Expected for invalid format after magic
    
    def test_decode_with_known_seeds(self):
        """Test with known problematic inputs from Go fuzzing"""
        test_cases = [
            # Invalid magic
            (b"SOURCE", b"\xff\xff\xff"),
            # Truncated header
            (b"SOURCE", b"\xd6\xc3\xc4"),
            # Invalid version
            (b"SOURCE", b"\xd6\xc3\xc4\x99"),
            # Valid magic but malformed content
            (b"TEST", b"\xd6\xc3\xc4\x00\x00" + b"\x80" * 10),
            # Empty source and delta
            (b"", b""),
            # Very long source with short delta
            (b"A" * 1000, b"\xd6\xc3\xc4\x00\x00"),
        ]
        
        for source, delta in test_cases:
            try:
                result = vcdiff.decode(source, delta)
                assert isinstance(result, bytes)
            except VCDIFFError:
                pass  # Expected


class TestFuzzVarint:
    """Fuzz tests for variable-length integer parsing"""
    
    @given(data=st.binary(max_size=20))
    @settings(max_examples=300)
    def test_varint_never_crashes(self, data):
        """ReadVarint should never crash"""
        try:
            result = read_varint(io.BytesIO(data))
            # If successful, should be a valid integer
            assert isinstance(result, int)
            assert 0 <= result <= 0xFFFFFFFF  # uint32 range
        except VCDIFFError:
            # Expected for malformed varints
            pass
        except (EOFError, OSError):
            # Expected for truncated input
            pass
        except Exception as e:
            pytest.fail(f"Unexpected varint exception: {type(e).__name__}: {e}")
    
    def test_varint_known_cases(self):
        """Test varint with known edge cases"""
        test_cases = [
            b"",  # Empty
            b"\x00",  # Zero
            b"\x7f",  # 127 (max single byte)
            b"\x80\x01",  # 128 (min two bytes)
            b"\x80",  # Incomplete two byte
            b"\x80\x80\x80\x80\x80",  # Too long (5 bytes all with continuation)
            b"\xff\xff\xff\xff\x7f",  # Maximum valid 5-byte varint
            b"\xff\xff\xff\xff\xff",  # Invalid (6th byte would overflow)
        ]
        
        for data in test_cases:
            try:
                result = read_varint(io.BytesIO(data))
                assert isinstance(result, int)
                assert result <= 0xFFFFFFFF
            except (VCDIFFError, EOFError):
                pass  # Expected for invalid cases


class TestFuzzAddressCache:
    """Fuzz tests for address cache functionality"""
    
    @given(
        address_data=st.binary(max_size=100),
        here=st.integers(0, 0xFFFFFFFF),
        mode=st.integers(0, 255)
    )
    @settings(max_examples=200)
    def test_address_cache_never_crashes(self, address_data, here, mode):
        """Address cache should never crash"""
        try:
            cache = AddressCache(4, 3)  # Standard sizes
            cache.reset(address_data)
            
            result = cache.decode_address(here, mode)
            assert isinstance(result, int)
            assert 0 <= result <= 0xFFFFFFFF
        except VCDIFFError:
            # Expected for invalid modes or malformed data
            pass
        except Exception as e:
            pytest.fail(f"Unexpected address cache exception: {type(e).__name__}: {e}")
    
    def test_address_cache_edge_cases(self):
        """Test address cache with specific edge cases"""
        cache = AddressCache(4, 3)
        
        test_cases = [
            # (address_data, here, mode, should_succeed)
            (b"", 0, 0, False),  # Empty data, SELF mode
            (b"\x00", 100, 1, True),  # HERE mode, offset 0
            (b"\x64", 100, 1, True),  # HERE mode, offset 100
            (b"\x65", 100, 1, False),  # HERE mode, offset > here
            (b"\xff", 0, 9, False),  # Invalid mode
            (b"\x00", 0xFFFFFFFF, 0, True),  # Max values
        ]
        
        for address_data, here, mode, should_succeed in test_cases:
            cache.reset(address_data)
            try:
                result = cache.decode_address(here, mode)
                if not should_succeed:
                    pytest.fail(f"Expected failure for mode {mode} but got {result}")
                assert isinstance(result, int)
            except VCDIFFError:
                if should_succeed:
                    pytest.fail(f"Unexpected failure for valid case: mode {mode}")


class TestFuzzParseDelta:
    """Fuzz tests for delta parsing"""
    
    @given(delta=st.binary(max_size=500))
    @settings(max_examples=150)
    def test_parse_delta_never_crashes(self, delta):
        """ParseDelta should never crash"""
        try:
            result = vcdiff.parse_delta(delta)
            # If successful, should have proper structure
            assert result is not None
            assert hasattr(result, 'header')
            assert hasattr(result, 'windows')
            assert hasattr(result, 'instructions')
            assert isinstance(result.windows, list)
            assert isinstance(result.instructions, list)
            # Sanity check on counts
            assert len(result.windows) <= 1000
            assert len(result.instructions) <= 10000
        except VCDIFFError:
            # Expected for invalid deltas
            pass
        except Exception as e:
            pytest.fail(f"Unexpected parse exception: {type(e).__name__}: {e}")


# Custom strategies for more targeted VCDIFF fuzzing
@st.composite
def vcdiff_header_strategy(draw):
    """Generate potentially valid VCDIFF headers"""
    magic = draw(st.one_of(
        st.just(b'\xd6\xc3\xc4'),  # Valid magic
        st.binary(min_size=3, max_size=3)  # Random magic
    ))
    version = draw(st.integers(0, 255))
    indicator = draw(st.integers(0, 255))
    return magic + bytes([version, indicator])


@st.composite
def vcdiff_window_strategy(draw):
    """Generate potentially valid window indicators"""
    return draw(st.integers(0, 255))


class TestFuzzWithCustomStrategies:
    """Fuzz tests using custom VCDIFF-aware strategies"""
    
    @given(
        source=st.binary(max_size=200),
        header=vcdiff_header_strategy(),
        extra_data=st.binary(max_size=300)
    )
    @settings(max_examples=100)
    def test_with_structured_input(self, source, header, extra_data):
        """Test with more structured VCDIFF-like input"""
        delta = header + extra_data
        try:
            result = vcdiff.decode(source, delta)
            assert isinstance(result, bytes)
            assert len(result) <= 10 * 1024 * 1024
        except VCDIFFError:
            pass


def test_performance_with_large_inputs():
    """Test that large inputs don't cause excessive memory usage or hangs"""
    import time
    
    # Test with progressively larger inputs
    for size in [1000, 10000, 50000]:
        source = b"A" * size
        delta = b"\xd6\xc3\xc4\x00\x00" + b"\x80" * (size // 100)
        
        start_time = time.time()
        try:
            vcdiff.decode(source, delta)
        except VCDIFFError:
            pass
        
        elapsed = time.time() - start_time
        # Should complete within reasonable time (not hang)
        assert elapsed < 5.0, f"Decode took too long: {elapsed:.2f}s for size {size}"


if __name__ == "__main__":
    # Run with: python -m pytest tests/test_fuzz_hypothesis.py -v
    pytest.main([__file__, "-v", "--tb=short"])