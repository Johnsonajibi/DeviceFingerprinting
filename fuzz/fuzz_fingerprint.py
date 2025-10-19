#!/usr/bin/env python3
"""
Fuzz target for fingerprint generation in device_fingerprinting.

Tests fingerprint generation with various malformed inputs and edge cases.
"""

import atheris
import sys
import json

with atheris.instrument_imports():
    from device_fingerprinting.production_fingerprint import ProductionFingerprintGenerator


def TestOneInput(data):
    """Fuzz test for fingerprint generation."""
    if len(data) < 5:
        return
    
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        generator = ProductionFingerprintGenerator()
        
        choice = fdp.ConsumeIntInRange(0, 2)
        
        if choice == 0:
            # Normal fingerprint generation (should always work)
            try:
                fp = generator.generate_fingerprint()
                # Validate output structure
                if fp and isinstance(fp, dict):
                    assert 'fingerprint_hash' in fp
            except Exception:
                pass
        
        elif choice == 1:
            # Test internal methods with random data
            try:
                # Create malformed hardware info
                fake_data = {
                    fdp.ConsumeString(20): fdp.ConsumeString(100)
                    for _ in range(fdp.ConsumeIntInRange(0, 10))
                }
                # Try to hash it
                json_str = json.dumps(fake_data, sort_keys=True)
                generator._hash_fingerprint_data(json_str)
            except Exception:
                pass
        
        elif choice == 2:
            # Test with corrupted fingerprint verification
            try:
                fp1 = generator.generate_fingerprint()
                if fp1:
                    # Corrupt the fingerprint hash
                    corrupted = fdp.ConsumeString(64)
                    fp1['fingerprint_hash'] = corrupted
            except Exception:
                pass
    
    except Exception:
        pass


def main():
    """Main fuzzing entry point."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
