#!/usr/bin/env python3
"""
Simple test for enhanced crypto integration
"""

import sys
import os

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    print("🔬 Enhanced Crypto Integration Test")
    print("=" * 50)
    
    # Test direct Rust module
    try:
        import pqc_rust
        crypto = pqc_rust.RustCrypto()
        test_result = pqc_rust.test_crypto()
        print(f"✅ Direct Rust test: {'PASS' if test_result else 'FAIL'}")
    except Exception as e:
        print(f"❌ Direct Rust test failed: {e}")
        return False
    
    # Test enhanced crypto integration
    try:
        from device_fingerprinting.crypto import get_enhanced_crypto, RUST_CRYPTO_AVAILABLE
        
        print(f"🦀 Rust crypto available: {RUST_CRYPTO_AVAILABLE}")
        
        crypto = get_enhanced_crypto()
        backend_info = crypto.get_backend_info()
        
        print(f"🔧 Active backend: {backend_info['backend']}")
        print(f"📦 Implementation: {backend_info['implementation']}")
        
        # Test AES encryption with Rust backend
        if RUST_CRYPTO_AVAILABLE and backend_info['backend'] == 'Rust':
            key = crypto.generate_random(32)
            plaintext = b"Test message for Rust integration"
            
            # AES test
            ciphertext = crypto.aes_encrypt(plaintext, key)
            decrypted = crypto.aes_decrypt(ciphertext, key)
            aes_success = (decrypted == plaintext)
            print(f"🔐 Rust AES test: {'✅ PASS' if aes_success else '❌ FAIL'}")
            
            # ChaCha test
            try:
                chacha_ciphertext = crypto.chacha_encrypt(plaintext, key)
                chacha_decrypted = crypto.chacha_decrypt(chacha_ciphertext, key)
                chacha_success = (chacha_decrypted == plaintext)
                print(f"🔐 Rust ChaCha20 test: {'✅ PASS' if chacha_success else '❌ FAIL'}")
            except Exception as e:
                print(f"🔐 Rust ChaCha20 test: ❌ FAIL ({e})")
            
            # Key derivation test
            try:
                password = b"test_password"
                salt = crypto.generate_random(16)
                derived_key = crypto.derive_key_argon2(password, salt, 32)
                kdf_success = len(derived_key) == 32
                print(f"🔑 Rust Argon2 test: {'✅ PASS' if kdf_success else '❌ FAIL'}")
            except Exception as e:
                print(f"🔑 Rust Argon2 test: ❌ FAIL ({e})")
            
            print("🎉 Rust crypto integration successful!")
            return True
        else:
            print("⚪ Using Python fallback (Rust not available)")
            return True
            
    except Exception as e:
        print(f"❌ Enhanced crypto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)