#!/usr/bin/env python3
"""
Fuzz target for cryptographic functions in device_fingerprinting.

This fuzzer tests the crypto module for crashes, exceptions, and security issues.
"""

import atheris
import sys

# Import after atheris to enable instrumentation
with atheris.instrument_imports():
    from device_fingerprinting.crypto import Crypto


def TestOneInput(data):
    """Fuzz test for crypto operations."""
    if len(data) < 10:
        return
    
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        crypto = Crypto()
        
        # Fuzz encryption/decryption
        choice = fdp.ConsumeIntInRange(0, 4)
        
        if choice == 0:
            # Test encryption with random data
            plaintext = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))
            password = fdp.ConsumeString(32)
            if password:
                try:
                    encrypted = crypto.encrypt_data(plaintext, password)
                    # Try to decrypt it back
                    if encrypted:
                        crypto.decrypt_data(encrypted, password)
                except Exception:
                    pass
        
        elif choice == 1:
            # Test decryption with malformed data
            ciphertext = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))
            password = fdp.ConsumeString(32)
            if password:
                try:
                    crypto.decrypt_data(ciphertext, password)
                except Exception:
                    pass
        
        elif choice == 2:
            # Test hashing with various inputs
            data_to_hash = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 10000))
            try:
                crypto.hash_data(data_to_hash)
            except Exception:
                pass
        
        elif choice == 3:
            # Test key derivation with various parameters
            password = fdp.ConsumeString(128)
            salt = fdp.ConsumeBytes(32)
            if password and salt:
                try:
                    crypto.derive_key(password, salt)
                except Exception:
                    pass
        
        elif choice == 4:
            # Test with completely random method calls
            plaintext = fdp.ConsumeBytes(100)
            password = fdp.ConsumeString(20)
            try:
                encrypted = crypto.encrypt_data(plaintext, password)
                # Corrupt the encrypted data
                if encrypted and len(encrypted) > 10:
                    corrupted = bytearray(encrypted)
                    corrupted[5] ^= 0xFF  # Flip bits
                    crypto.decrypt_data(bytes(corrupted), password)
            except Exception:
                pass
    
    except Exception:
        # Expected exceptions are fine, we're looking for crashes
        pass


def main():
    """Main fuzzing entry point."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
