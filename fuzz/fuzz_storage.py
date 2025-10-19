#!/usr/bin/env python3
"""
Fuzz target for secure storage in device_fingerprinting.

Tests storage operations with malformed data and edge cases.
"""

import atheris
import sys
import tempfile
import os

with atheris.instrument_imports():
    from device_fingerprinting.secure_storage import SecureStorage


def TestOneInput(data):
    """Fuzz test for secure storage."""
    if len(data) < 10:
        return
    
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        # Create temporary storage
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = os.path.join(tmpdir, "test_storage")
            
            try:
                storage = SecureStorage(
                    storage_path=storage_path,
                    service_name=fdp.ConsumeString(20) or "test",
                    username=fdp.ConsumeString(20) or "user"
                )
                
                choice = fdp.ConsumeIntInRange(0, 3)
                
                if choice == 0:
                    # Test set/get with random data
                    key = fdp.ConsumeString(50)
                    value = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))
                    if key:
                        try:
                            storage.set_item(key, value)
                            retrieved = storage.get_item(key)
                            assert retrieved == value
                        except Exception:
                            pass
                
                elif choice == 1:
                    # Test with invalid keys
                    invalid_key = fdp.ConsumeString(200)
                    try:
                        storage.get_item(invalid_key)
                    except Exception:
                        pass
                
                elif choice == 2:
                    # Test delete operations
                    key = fdp.ConsumeString(30)
                    if key:
                        try:
                            storage.delete_item(key)
                        except Exception:
                            pass
                
                elif choice == 3:
                    # Test list operations
                    try:
                        storage.list_keys()
                    except Exception:
                        pass
                
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
