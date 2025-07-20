#!/usr/bin/env python3
"""
Simple fuzzer for VCDIFF Python library without external dependencies

This is a basic mutation-based fuzzer that can be used for initial testing
without requiring AFL++ or Atheris installation.
"""

import random
import sys
import time
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

import vcdiff
from vcdiff.exceptions import VCDIFFError


class SimpleFuzzer:
    """Basic mutation-based fuzzer for VCDIFF"""
    
    def __init__(self, seed_corpus=None):
        self.seed_corpus = seed_corpus or []
        self.crash_count = 0
        self.test_count = 0
        self.interesting_cases = []
        
    def add_seed(self, source, delta, name="unknown"):
        """Add a seed input to the corpus"""
        self.seed_corpus.append((source, delta, name))
        
    def mutate_bytes(self, data, mutation_rate=0.1):
        """Apply random mutations to byte data"""
        if not data:
            return data
            
        mutated = bytearray(data)
        
        # Determine number of mutations
        num_mutations = max(1, int(len(data) * mutation_rate))
        
        for _ in range(num_mutations):
            mutation_type = random.choice(['flip', 'insert', 'delete', 'replace', 'duplicate'])
            
            if mutation_type == 'flip' and len(mutated) > 0:
                # Bit flip
                pos = random.randint(0, len(mutated) - 1)
                bit = random.randint(0, 7)
                mutated[pos] ^= (1 << bit)
                
            elif mutation_type == 'insert':
                # Insert random byte
                pos = random.randint(0, len(mutated))
                byte_val = random.randint(0, 255)
                mutated.insert(pos, byte_val)
                
            elif mutation_type == 'delete' and len(mutated) > 0:
                # Delete random byte
                pos = random.randint(0, len(mutated) - 1)
                del mutated[pos]
                
            elif mutation_type == 'replace' and len(mutated) > 0:
                # Replace with random byte
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
                
            elif mutation_type == 'duplicate' and len(mutated) > 0:
                # Duplicate a section
                start = random.randint(0, len(mutated) - 1)
                end = min(start + random.randint(1, 10), len(mutated))
                section = mutated[start:end]
                pos = random.randint(0, len(mutated))
                mutated[pos:pos] = section
        
        return bytes(mutated)
    
    def generate_random_input(self):
        """Generate completely random source and delta"""
        source_len = random.randint(0, 1000)
        delta_len = random.randint(0, 1000)
        
        source = bytes(random.randint(0, 255) for _ in range(source_len))
        delta = bytes(random.randint(0, 255) for _ in range(delta_len))
        
        return source, delta
    
    def test_input(self, source, delta, name="generated"):
        """Test a single input and classify the result"""
        self.test_count += 1
        
        try:
            start_time = time.time()
            result = vcdiff.decode(source, delta)
            elapsed = time.time() - start_time
            
            # Success case - check for interesting properties
            if elapsed > 1.0:  # Slow execution
                self.interesting_cases.append((source, delta, f"{name}_slow_{elapsed:.2f}s"))
            
            if len(result) > 10 * len(source) + len(delta):  # High expansion ratio
                ratio = len(result) / max(1, len(source) + len(delta))
                self.interesting_cases.append((source, delta, f"{name}_expansion_{ratio:.1f}x"))
                
            return "success"
            
        except VCDIFFError as e:
            # Expected error
            return f"vcdiff_error: {str(e)[:50]}"
            
        except MemoryError:
            self.interesting_cases.append((source, delta, f"{name}_memory_error"))
            return "memory_error"
            
        except Exception as e:
            # Unexpected error - potential bug
            self.crash_count += 1
            self.interesting_cases.append((source, delta, f"{name}_crash_{type(e).__name__}"))
            print(f"CRASH #{self.crash_count}: {type(e).__name__}: {e}")
            print(f"  Source length: {len(source)}")
            print(f"  Delta length: {len(delta)}")
            print(f"  Source: {source[:50]}{'...' if len(source) > 50 else ''}")
            print(f"  Delta: {delta[:50]}{'...' if len(delta) > 50 else ''}")
            return f"crash: {type(e).__name__}"
    
    def fuzz_mutations(self, duration_seconds=60):
        """Run mutation-based fuzzing"""
        print(f"Starting mutation fuzzing for {duration_seconds} seconds...")
        print(f"Seed corpus: {len(self.seed_corpus)} entries")
        
        start_time = time.time()
        results = {}
        
        while time.time() - start_time < duration_seconds:
            if self.seed_corpus and random.random() < 0.7:
                # Mutate existing seed
                source, delta, name = random.choice(self.seed_corpus)
                
                # Mutate source or delta (or both)
                if random.random() < 0.5:
                    source = self.mutate_bytes(source)
                if random.random() < 0.5:
                    delta = self.mutate_bytes(delta)
                    
                test_name = f"mutated_{name}"
            else:
                # Generate random input
                source, delta = self.generate_random_input()
                test_name = "random"
            
            result = self.test_input(source, delta, test_name)
            results[result] = results.get(result, 0) + 1
            
            if self.test_count % 1000 == 0:
                elapsed = time.time() - start_time
                rate = self.test_count / elapsed
                print(f"  Tests: {self.test_count}, Rate: {rate:.1f}/sec, "
                      f"Crashes: {self.crash_count}, Interesting: {len(self.interesting_cases)}")
        
        return results
    
    def fuzz_structured(self, duration_seconds=60):
        """Run structured fuzzing targeting specific VCDIFF components"""
        print(f"Starting structured fuzzing for {duration_seconds} seconds...")
        
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            # Generate structured VCDIFF-like input
            strategy = random.choice(['magic', 'header', 'varint', 'window'])
            
            if strategy == 'magic':
                # Focus on magic bytes
                magic_variants = [
                    b'\xd6\xc3\xc4',  # Valid
                    b'\xd6\xc3\xc5',  # Close to valid
                    b'\x00\x00\x00',  # Zeros
                    b'\xff\xff\xff',  # All bits set
                ]
                magic = random.choice(magic_variants)
                rest = bytes(random.randint(0, 255) for _ in range(random.randint(0, 50)))
                delta = magic + rest
                source = bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
                
            elif strategy == 'header':
                # Valid magic with various headers
                delta = b'\xd6\xc3\xc4'  # Magic
                delta += bytes([random.randint(0, 255)])  # Version
                delta += bytes([random.randint(0, 255)])  # Indicator
                delta += bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
                source = bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
                
            elif strategy == 'varint':
                # Focus on varint edge cases
                varint_patterns = [
                    b'\x00',  # 0
                    b'\x7f',  # 127
                    b'\x80\x01',  # 128
                    b'\x80\x80\x80\x80\x80',  # Long continuation
                    b'\xff\xff\xff\xff\x7f',  # Max valid
                ]
                pattern = random.choice(varint_patterns)
                # Mutate the pattern
                if random.random() < 0.3:
                    pattern = self.mutate_bytes(pattern)
                
                delta = b'\xd6\xc3\xc4\x00\x00' + pattern
                source = b''
                
            else:  # window
                # Try to construct a minimal window
                delta = b'\xd6\xc3\xc4\x00\x00'  # Header
                delta += bytes([random.randint(0, 7)])  # Window indicator
                # Add some random window data
                delta += bytes(random.randint(0, 255) for _ in range(random.randint(0, 50)))
                source = bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
            
            self.test_input(source, delta, f"structured_{strategy}")
    
    def save_interesting_cases(self, output_dir="fuzz_findings"):
        """Save interesting test cases for further analysis"""
        if not self.interesting_cases:
            return
            
        os.makedirs(output_dir, exist_ok=True)
        
        for i, (source, delta, description) in enumerate(self.interesting_cases):
            case_dir = Path(output_dir) / f"case_{i:04d}_{description}"
            case_dir.mkdir(exist_ok=True)
            
            with open(case_dir / "source", "wb") as f:
                f.write(source)
            with open(case_dir / "delta", "wb") as f:
                f.write(delta)
            with open(case_dir / "description.txt", "w") as f:
                f.write(f"Description: {description}\n")
                f.write(f"Source length: {len(source)}\n")
                f.write(f"Delta length: {len(delta)}\n")
        
        print(f"Saved {len(self.interesting_cases)} interesting cases to {output_dir}/")


def load_test_seeds():
    """Load seed inputs from the test suite"""
    seeds = []
    
    # Try to load from vcdiff-tests
    test_dir = Path("submodules/vcdiff-tests/targeted-positive")
    if test_dir.exists():
        for case_dir in test_dir.iterdir():
            if case_dir.is_dir() and (case_dir / "metadata.json").exists():
                try:
                    source = (case_dir / "source").read_bytes()
                    delta = (case_dir / "delta.vcdiff").read_bytes()
                    seeds.append((source, delta, case_dir.name))
                except Exception:
                    pass
    
    # Add some minimal seeds
    minimal_seeds = [
        (b"", b"\xd6\xc3\xc4\x00\x00", "empty_minimal"),
        (b"TEST", b"\xd6\xc3\xc4\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00", "test_minimal"),
        (b"ABCDEFGH", b"\xff\xff\xff", "invalid_magic"),
    ]
    seeds.extend(minimal_seeds)
    
    return seeds


def main():
    """Main fuzzing entry point"""
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    else:
        duration = 60  # 1 minute default
    
    fuzzer = SimpleFuzzer()
    
    # Load seed corpus
    seeds = load_test_seeds()
    for source, delta, name in seeds:
        fuzzer.add_seed(source, delta, name)
    
    print(f"Simple VCDIFF Fuzzer")
    print(f"Duration: {duration} seconds")
    print(f"Loaded {len(seeds)} seed inputs")
    print("-" * 50)
    
    # Run different fuzzing strategies
    mutation_time = duration // 2
    structured_time = duration - mutation_time
    
    # Mutation-based fuzzing
    mutation_results = fuzzer.fuzz_mutations(mutation_time)
    
    # Structured fuzzing
    fuzzer.fuzz_structured(structured_time)
    
    # Report results
    print("\n" + "=" * 50)
    print("FUZZING RESULTS")
    print("=" * 50)
    print(f"Total tests: {fuzzer.test_count}")
    print(f"Crashes: {fuzzer.crash_count}")
    print(f"Interesting cases: {len(fuzzer.interesting_cases)}")
    
    print(f"\nResult distribution:")
    for result, count in sorted(mutation_results.items()):
        print(f"  {result}: {count}")
    
    # Save interesting cases
    if fuzzer.interesting_cases:
        fuzzer.save_interesting_cases()
    
    print(f"\nFuzzing completed. Run with larger duration for more thorough testing.")
    print(f"Example: python fuzz_simple.py 3600  # 1 hour")


if __name__ == "__main__":
    main()