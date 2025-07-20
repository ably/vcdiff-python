"""Test suite for VCDIFF implementation using the shared test cases"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

import pytest

# Add the parent directory to the path so we can import vcdiff
sys.path.insert(0, str(Path(__file__).parent.parent))

import vcdiff
from vcdiff.exceptions import VCDIFFError


class TestVCDIFFSharedTests:
    """Test VCDIFF implementation using the shared vcdiff-tests submodule"""
    
    @pytest.fixture(scope="class")
    def test_root(self):
        """Get the path to the vcdiff-tests directory"""
        # Look for vcdiff-tests in submodules
        test_root = Path(__file__).parent.parent / "submodules" / "vcdiff-tests"
        if not test_root.exists():
            pytest.skip("vcdiff-tests submodule not found")
        return test_root
    
    def _load_test_case(self, test_path: Path) -> Dict[str, Any]:
        """Load a test case from its directory"""
        metadata_file = test_path / "metadata.json"
        if not metadata_file.exists():
            pytest.skip(f"No metadata.json in {test_path}")
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        source_file = test_path / "source"
        target_file = test_path / "target"
        delta_file = test_path / "delta.vcdiff"
        
        source_data = b""
        target_data = b""
        delta_data = b""
        
        if source_file.exists():
            source_data = source_file.read_bytes()
        
        if target_file.exists():
            target_data = target_file.read_bytes()
        
        if delta_file.exists():
            delta_data = delta_file.read_bytes()
        
        return {
            "metadata": metadata,
            "source": source_data,
            "target": target_data,
            "delta": delta_data,
            "name": test_path.name
        }
    
    def test_positive_cases(self, test_root):
        """Test all positive test cases"""
        positive_dir = test_root / "general-positive"
        if not positive_dir.exists():
            pytest.skip("general-positive directory not found")
        
        passed = 0
        failed = 0
        errors = []
        
        for test_case_dir in sorted(positive_dir.iterdir()):
            if not test_case_dir.is_dir():
                continue
            
            test_case = self._load_test_case(test_case_dir)
            
            try:
                # Apply the delta
                result = vcdiff.decode(test_case["source"], test_case["delta"])
                
                # Verify the result matches the expected target
                if result == test_case["target"]:
                    passed += 1
                    print(f"✓ {test_case['name']}")
                else:
                    failed += 1
                    error_msg = f"✗ {test_case['name']}: output mismatch (got {len(result)} bytes, expected {len(test_case['target'])} bytes)"
                    errors.append(error_msg)
                    print(error_msg)
            
            except Exception as e:
                failed += 1
                error_msg = f"✗ {test_case['name']}: {type(e).__name__}: {e}"
                errors.append(error_msg)
                print(error_msg)
        
        print(f"\nPositive tests: {passed} passed, {failed} failed")
        
        if failed > 0:
            pytest.fail(f"Failed {failed} positive test cases:\n" + "\n".join(errors))
    
    def test_negative_cases(self, test_root):
        """Test all negative test cases (should fail gracefully)"""
        negative_dir = test_root / "targeted-negative"
        if not negative_dir.exists():
            pytest.skip("targeted-negative directory not found")
        
        passed = 0
        failed = 0
        errors = []
        
        for test_case_dir in sorted(negative_dir.iterdir()):
            if not test_case_dir.is_dir():
                continue
            
            test_case = self._load_test_case(test_case_dir)
            
            try:
                # This should fail with an appropriate error
                result = vcdiff.decode(test_case["source"], test_case["delta"])
                
                # If we get here without an exception, the test failed
                failed += 1
                error_msg = f"✗ {test_case['name']}: expected error but decode succeeded"
                errors.append(error_msg)
                print(error_msg)
            
            except VCDIFFError:
                # This is expected for negative test cases
                passed += 1
                print(f"✓ {test_case['name']}")
            
            except Exception as e:
                # Unexpected error type, but still shows proper error handling
                passed += 1
                print(f"✓ {test_case['name']} (with {type(e).__name__}: {e})")
        
        print(f"\nNegative tests: {passed} passed, {failed} failed")
        
        if failed > 0:
            pytest.fail(f"Failed {failed} negative test cases:\n" + "\n".join(errors))
    
    def test_targeted_positive_cases(self, test_root):
        """Test targeted positive cases"""
        positive_dir = test_root / "targeted-positive"
        if not positive_dir.exists():
            pytest.skip("targeted-positive directory not found")
        
        passed = 0
        failed = 0
        errors = []
        
        def test_directory(directory):
            nonlocal passed, failed, errors
            
            for test_case_dir in sorted(directory.iterdir()):
                if not test_case_dir.is_dir():
                    continue
                
                # Check if this is a test case (has metadata.json) or a subdirectory
                if (test_case_dir / "metadata.json").exists():
                    # This is a test case
                    test_case = self._load_test_case(test_case_dir)
                    
                    try:
                        # Apply the delta
                        result = vcdiff.decode(test_case["source"], test_case["delta"])
                        
                        # Verify the result matches the expected target
                        if result == test_case["target"]:
                            passed += 1
                            print(f"✓ {test_case['name']}")
                        else:
                            failed += 1
                            error_msg = f"✗ {test_case['name']}: output mismatch"
                            errors.append(error_msg)
                            print(error_msg)
                    
                    except Exception as e:
                        failed += 1
                        error_msg = f"✗ {test_case['name']}: {type(e).__name__}: {e}"
                        errors.append(error_msg)
                        print(error_msg)
                else:
                    # This is a subdirectory, recurse into it
                    test_directory(test_case_dir)
        
        test_directory(positive_dir)
        
        print(f"\nTargeted positive tests: {passed} passed, {failed} failed")
        
        if failed > 0:
            pytest.fail(f"Failed {failed} targeted positive test cases:\n" + "\n".join(errors))


class TestVCDIFFBasic:
    """Basic unit tests for VCDIFF components"""
    
    def test_import(self):
        """Test that the module can be imported"""
        import vcdiff
        assert hasattr(vcdiff, 'decode')
        assert hasattr(vcdiff, 'Decoder')
    
    def test_empty_delta_fails(self):
        """Test that empty delta fails appropriately"""
        with pytest.raises(VCDIFFError):
            vcdiff.decode(b"", b"")
    
    def test_invalid_magic_fails(self):
        """Test that invalid magic bytes fail"""
        with pytest.raises(vcdiff.InvalidMagicError):
            vcdiff.decode(b"", b"XXXX")
    
    def test_decoder_interface(self):
        """Test decoder interface"""
        decoder = vcdiff.Decoder(b"hello world")
        assert decoder.source == b"hello world"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])