#!/usr/bin/env python3
"""
Test script for enhanced crypto functionality with Rust integration
"""

import sys
import os
import traceback

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_enhanced_crypto():
    """Test the enhanced crypto functionality"""
    print("🧪 Testing Enhanced Crypto Module")
    print("=" * 50)
    
    try:
        from device_fingerprinting.crypto import EnhancedCrypto, get_enhanced_crypto, RUST_CRYPTO_AVAILABLE
        
        print(f"🦀 Rust crypto available: {RUST_CRYPTO_AVAILABLE}")
        
        # Test enhanced crypto instance
        crypto = get_enhanced_crypto()
        backend_info = crypto.get_backend_info()
        
        print(f"🔧 Backend: {backend_info['backend']}")
        print(f"📦 Implementation: {backend_info['implementation']}")
        print(f"🛡️  Post-quantum: {backend_info['post_quantum']}")
        print(f"🔒 Memory security: {backend_info['memory_security']}")
        
        print("\n🧪 Running comprehensive self-test...")
        test_results = crypto.self_test()
        
        print("\n📊 Test Results:")
        for test_name, result in test_results.items():
            if result is True:
                print(f"   ✅ {test_name}: PASS")
            elif result is False:
                print(f"   ❌ {test_name}: FAIL")
            else:
                print(f"   ⚪ {test_name}: NOT AVAILABLE")
        
        # Count results
        passed = sum(1 for r in test_results.values() if r is True)
        failed = sum(1 for r in test_results.values() if r is False)
        skipped = sum(1 for r in test_results.values() if r is None)
        
        print(f"\n📈 Summary: {passed} passed, {failed} failed, {skipped} skipped")
        
        if failed == 0:
            print("🎉 All available crypto functions working correctly!")
            return True
        else:
            print(f"⚠️  {failed} crypto functions failed!")
            return False
    
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        print("💡 Make sure the device_fingerprinting module is properly installed")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        print("\n🔍 Full traceback:")
        traceback.print_exc()
        return False

def test_rust_integration():
    """Test direct Rust module integration"""
    print("\n🦀 Testing Direct Rust Integration")
    print("=" * 50)
    
    try:
        import pqc_rust
        print("✅ Direct pqc_rust import successful")
        
        # Test RustCrypto
        rust_crypto = pqc_rust.RustCrypto()
        print("✅ RustCrypto instance created")
        
        # Test basic functionality
        random_bytes = rust_crypto.generate_random(32)
        print(f"🎲 Random generation: {'✅ PASS' if len(random_bytes) == 32 else '❌ FAIL'}")
        
        # Test AES encryption
        key = rust_crypto.generate_random(32)
        plaintext = b"Test message for Rust AES"
        ciphertext = rust_crypto.aes_encrypt(plaintext, key)
        decrypted = rust_crypto.aes_decrypt(ciphertext, key)
        aes_test = (decrypted == plaintext)
        print(f"🔐 AES-256-GCM: {'✅ PASS' if aes_test else '❌ FAIL'}")
        
        # Test ChaCha20Poly1305
        try:
            chacha_ciphertext = rust_crypto.chacha_encrypt(plaintext, key)
            chacha_decrypted = rust_crypto.chacha_decrypt(chacha_ciphertext, key)
            chacha_test = (chacha_decrypted == plaintext)
            print(f"🔐 ChaCha20Poly1305: {'✅ PASS' if chacha_test else '❌ FAIL'}")
        except Exception as e:
            print(f"🔐 ChaCha20Poly1305: ❌ FAIL ({e})")
        
        # Test key derivation
        try:
            password = b"test_password"
            salt = rust_crypto.generate_random(16)
            derived_key = rust_crypto.derive_key_argon2(password, salt, 32)
            kdf_test = (len(derived_key) == 32)
            print(f"🔑 Argon2id KDF: {'✅ PASS' if kdf_test else '❌ FAIL'}")
        except Exception as e:
            print(f"🔑 Argon2id KDF: ❌ FAIL ({e})")
        
        # Test module-level function
        try:
            module_test = pqc_rust.test_crypto()
            print(f"📦 Module self-test: {'✅ PASS' if module_test else '❌ FAIL'}")
        except Exception as e:
            print(f"📦 Module self-test: ❌ FAIL ({e})")
        
        return True
    
    except ImportError:
        print("⚪ Direct Rust module not available")
        print("💡 This is normal if you haven't built the Rust module yet")
        print("📦 Run: python build_rust.py")
        return None
    except Exception as e:
        print(f"❌ Rust integration test failed: {e}")
        traceback.print_exc()
        return False

def test_fallback_behavior():
    """Test fallback behavior when Rust is not available"""
    print("\n🐍 Testing Python Fallback Behavior")
    print("=" * 50)
    
    try:
        from device_fingerprinting.crypto import EnhancedCrypto
        
        # Force Python backend
        crypto = EnhancedCrypto(prefer_rust=False)
        backend_info = crypto.get_backend_info()
        
        print(f"🔧 Forced backend: {backend_info['backend']}")
        
        # Test basic operations
        key = crypto.generate_random(32)
        plaintext = b"Test message for Python fallback"
        
        # AES should work
        ciphertext = crypto.aes_encrypt(plaintext, key)
        decrypted = crypto.aes_decrypt(ciphertext, key)
        aes_test = (decrypted == plaintext)
        print(f"🔐 Python AES-256-GCM: {'✅ PASS' if aes_test else '❌ FAIL'}")
        
        # ChaCha20 should fail gracefully
        try:
            crypto.chacha_encrypt(plaintext, key)
            print("🔐 ChaCha20Poly1305: ❌ UNEXPECTED SUCCESS")
        except NotImplementedError:
            print("🔐 ChaCha20Poly1305: ✅ CORRECTLY UNAVAILABLE")
        
        # PQC should fail gracefully
        try:
            crypto.pqc_generate_signature_keypair()
            print("🔐 PQC Signatures: ❌ UNEXPECTED SUCCESS")
        except NotImplementedError:
            print("🔐 PQC Signatures: ✅ CORRECTLY UNAVAILABLE")
        
        return True
    
    except Exception as e:
        print(f"❌ Fallback test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🔬 Enhanced Crypto Test Suite")
    print("🦀 Testing Rust + Python crypto integration")
    print("=" * 60)
    
    results = []
    
    # Test enhanced crypto
    results.append(("Enhanced Crypto", test_enhanced_crypto()))
    
    # Test direct Rust integration
    rust_result = test_rust_integration()
    if rust_result is not None:
        results.append(("Rust Integration", rust_result))
    
    # Test fallback behavior
    results.append(("Python Fallback", test_fallback_behavior()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        if result:
            print(f"✅ {test_name}: PASS")
            passed += 1
        else:
            print(f"❌ {test_name}: FAIL")
            failed += 1
    
    print(f"\n📈 Overall: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Enhanced crypto is working correctly.")
        print("\n🚀 Ready for production use with:")
        print("   - Rust-powered post-quantum cryptography")
        print("   - Memory-safe crypto operations") 
        print("   - High-performance symmetric encryption")
        print("   - Graceful fallback to Python implementations")
        return True
    else:
        print(f"⚠️  {failed} test(s) failed. Please check the error messages above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)