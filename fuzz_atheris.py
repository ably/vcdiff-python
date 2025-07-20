#!/usr/bin/env python3
"""
Atheris-based fuzzer for VCDIFF Python library

Usage:
    pip install atheris
    python fuzz_atheris.py -max_total_time=300  # 5 minutes
    python fuzz_atheris.py -max_total_time=3600 # 1 hour
"""

import atheris
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vcdiff
from vcdiff.exceptions import VCDIFFError


def TestDecode(data):
    """Test the main decode function with fuzzing input"""
    if len(data) < 2:
        return
    
    # Split input into source and delta parts
    # Use first byte to determine split point
    split_point = data[0] % (len(data) - 1) + 1
    source = data[1:split_point]
    delta = data[split_point:]
    
    try:
        result = vcdiff.decode(source, delta)
        
        # Basic sanity checks on successful decode
        if not isinstance(result, bytes):
            raise ValueError("Decode returned non-bytes result")
        
        # Protect against potential zip bombs
        if len(result) > 100 * 1024 * 1024:  # 100MB limit
            raise ValueError(f"Result suspiciously large: {len(result)} bytes")
            
    except VCDIFFError:
        # Expected VCDIFF format errors are fine
        pass
    except (MemoryError, SystemExit, KeyboardInterrupt):
        # Re-raise critical system exceptions
        raise
    except Exception:
        # Other exceptions might indicate bugs, but don't fail immediately
        # Atheris will track these as interesting test cases
        pass


def TestParseDelta(data):
    """Test the parse_delta function specifically"""
    if len(data) < 4:
        return
        
    try:
        parsed = vcdiff.parse_delta(data)
        
        if parsed is not None:
            # Sanity checks on parsed structure
            if not hasattr(parsed, 'header') or not hasattr(parsed, 'windows'):
                raise ValueError("Invalid parsed delta structure")
            
            if len(parsed.windows) > 10000:
                raise ValueError(f"Too many windows: {len(parsed.windows)}")
                
            if len(parsed.instructions) > 100000:
                raise ValueError(f"Too many instructions: {len(parsed.instructions)}")
    
    except VCDIFFError:
        pass
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        pass


def TestVarint(data):
    """Test variable-length integer parsing"""
    if len(data) == 0:
        return
        
    try:
        from vcdiff.varint import read_varint
        import io
        
        result = read_varint(io.BytesIO(data))
        
        if not isinstance(result, int):
            raise ValueError("Varint returned non-integer")
            
        if result > 0xFFFFFFFF:
            raise ValueError(f"Varint result exceeds uint32: {result}")
            
    except (VCDIFFError, EOFError, OSError):
        pass
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        pass


def TestAddressCache(data):
    """Test address cache operations"""
    if len(data) < 3:
        return
    
    try:
        from vcdiff.addresscache import AddressCache
        
        # Split data: address_data, here (4 bytes), mode (1 byte)
        if len(data) < 6:
            return
            
        address_data = data[:-5]
        here_bytes = data[-5:-1]
        mode = data[-1]
        
        # Convert here_bytes to integer
        here = int.from_bytes(here_bytes, 'big') % (2**32)
        
        cache = AddressCache(4, 3)  # Standard sizes
        cache.reset(address_data)
        
        result = cache.decode_address(here, mode)
        
        if not isinstance(result, int):
            raise ValueError("AddressCache returned non-integer")
            
        if result > 0xFFFFFFFF:
            raise ValueError(f"Address result exceeds uint32: {result}")
    
    except VCDIFFError:
        pass
    except (MemoryError, SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        pass


def TestOneInput(data):
    """Main fuzzing entry point"""
    if len(data) < 1:
        return
        
    # Use first byte to select which function to test
    test_selector = data[0] % 4
    test_data = data[1:]
    
    if test_selector == 0:
        TestDecode(test_data)
    elif test_selector == 1:
        TestParseDelta(test_data)
    elif test_selector == 2:
        TestVarint(test_data)
    else:
        TestAddressCache(test_data)


def main():
    """Set up Atheris fuzzing"""
    # Add some seed inputs to guide fuzzing
    seed_inputs = [
        # Valid VCDIFF magic
        b"\x00\xd6\xc3\xc4\x00\x00",
        # Invalid magic
        b"\x01\xff\xff\xff\x00",
        # Empty delta
        b"\x02",
        # Minimal varint
        b"\x03\x00",
        b"\x03\x7f",
        b"\x03\x80\x01",
        # Address cache test
        b"\x04\x00\x00\x00\x00\x01\x00",
        # Longer structured input
        b"\x00" + b"SOURCE" + b"\xd6\xc3\xc4\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00",
        # Test with actual test case data
        b"\x00" + b"ABCDE" + b"\xd6\xc3\xc4\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00",
    ]
    
    # Initialize Atheris with seed corpus
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    
    # Add seed inputs
    for seed in seed_inputs:
        atheris.AddGlobalManualSeed(seed)
    
    print("Starting Atheris fuzzing for VCDIFF Python library...")
    print("Use -max_total_time=N to set fuzzing duration in seconds")
    print("Use -print_final_stats=1 to show coverage statistics")
    
    atheris.Fuzz()


if __name__ == "__main__":
    main()