#!/usr/bin/env python3
"""
Fuzz target for cryptographic functions in device_fingerprinting.

This fuzzer tests the crypto module for crashes, exceptions, and security issues.
"""

import atheris
import sys

# Import after atheris to enable instrumentation
with atheris.instrument_imports():
    from device_fingerprinting.crypto import (
        initialize_crypto_manager, 
        encrypt_data, 
        decrypt_data, 
        sign_data, 
        verify_signature
    )


def TestOneInput(data):
    """Fuzz test for crypto operations."""
    if len(data) < 10:
        return
    
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        # Initialize crypto manager with random password
        password = fdp.ConsumeString(32)
        if not password:
            password = "default_fuzz_password"
        
        initialize_crypto_manager(password)
        
        # Fuzz encryption/decryption
        choice = fdp.ConsumeIntInRange(0, 4)
        
        if choice == 0:
            # Test encryption with random data
            plaintext = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1000))
            if plaintext:
                try:
                    encrypted = encrypt_data(plaintext)
                    # Try to decrypt it back
                    if encrypted:
                        decrypt_data(encrypted)
                except Exception:
                    pass
        
        elif choice == 1:
            # Test decryption with malformed data
            ciphertext = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))
            try:
                decrypt_data(ciphertext)
            except Exception:
                pass
        
        elif choice == 2:
            # Test signing with various inputs
            test_data = {"test": fdp.ConsumeString(100)}
            try:
                signature = sign_data(test_data)
                # Try to verify it
                if signature:
                    verify_signature(signature, test_data)
            except Exception:
                pass
        
        elif choice == 3:
            # Test signature verification with tampered data
            test_data = {"original": fdp.ConsumeString(50)}
            tampered_data = {"tampered": fdp.ConsumeString(50)}
            try:
                signature = sign_data(test_data)
                # Try to verify with wrong data
                if signature:
                    verify_signature(signature, tampered_data)
            except Exception:
                pass
        
        elif choice == 4:
            # Test with completely random encrypted data corruption
            plaintext = fdp.ConsumeString(100)
            if plaintext:
                try:
                    encrypted = encrypt_data(plaintext)
                    # Corrupt the encrypted data
                    if encrypted and len(encrypted) > 10:
                        corrupted = bytearray(encrypted)
                        corrupted[5] ^= 0xFF  # Flip bits
                        decrypt_data(bytes(corrupted))
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
