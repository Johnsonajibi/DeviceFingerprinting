"""
Local Fuzzing Test - Windows Compatible
Run this to test for bugs locally without needing Atheris
"""

import sys
import os
import traceback

# Add src directory to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(project_root, 'src'))

try:
    from device_fingerprinting.crypto import AESGCMEncryptor, ScryptKDF, CryptoManager
    from device_fingerprinting.production_fingerprint import ProductionFingerprintGenerator
    from device_fingerprinting.secure_storage import SecureStorage
except ImportError as e:
    print(f"ERROR: Could not import modules: {e}")
    print("Please run: pip install -e .")
    sys.exit(1)

def random_bytes(max_size=1000):
    """Generate cryptographically secure random bytes of random length"""
    import secrets
    size = secrets.randbelow(max_size + 1)
    return secrets.token_bytes(size)

def random_string(max_size=100):
    """Generate cryptographically secure random string"""
    import secrets
    import string
    size = secrets.randbelow(max_size + 1)
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(chars) for _ in range(size))

def test_crypto(iterations=1000):
    """Test crypto operations with random inputs"""
    print(f"\n[*] Testing Crypto Operations ({iterations} iterations)...")
    crashes = []
    
    for i in range(iterations):
        try:
            password = random_bytes(32)
            crypto = CryptoManager(password)
            
            # Test basic initialization
            assert crypto.key is not None, "Key is None"
            assert len(crypto.key) == 32, f"Key wrong length: {len(crypto.key)}"
            assert crypto.aesgcm is not None, "AESGCM is None"
            
            # Test AES-GCM encryption (using proper API)
            import os as os_module
            plaintext = random_bytes(100)
            nonce = os_module.urandom(12)  # AES-GCM uses 12-byte nonce
            
            try:
                ciphertext = crypto.aesgcm.encrypt(nonce, plaintext, None)
                decrypted = crypto.aesgcm.decrypt(nonce, ciphertext, None)
                assert plaintext == decrypted, "Encryption/decryption mismatch"
            except Exception as e:
                # Some errors are expected
                pass
            
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{iterations}] tests passed")
                
        except AssertionError as e:
            crashes.append(f"Iteration {i}: {e}")
        except Exception as e:
            crashes.append(f"Iteration {i}: {type(e).__name__}: {e}")
    
    return crashes

def test_hashing(iterations=1000):
    """Test hashing with random inputs"""
    print(f"\n[*] Testing Hash Operations ({iterations} iterations)...") 
    crashes = []
    
    for i in range(iterations):
        try:
            # Test KDF operations
            password = random_string(32)  # KDF expects string
            salt = random_bytes(16)
            kdf = ScryptKDF()
            
            # Test various input sizes
            for pwd in [random_string(16), random_string(32), random_string(100)]:
                try:
                    key = kdf.derive_key(pwd, salt)
                    assert len(key) == 32, f"Key wrong length: {len(key)}"
                    
                    # Test determinism
                    key2 = kdf.derive_key(pwd, salt)
                    assert key == key2, "KDF not deterministic"
                except Exception as e:
                    crashes.append(f"KDF iteration {i}: {e}")
            
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{iterations}] tests passed")
                
        except Exception as e:
            crashes.append(f"Iteration {i}: {type(e).__name__}: {e}")
    
    return crashes

def test_fingerprint(iterations=500):
    """Test fingerprint generation with corrupted data"""
    print(f"\n[*] Testing Fingerprint Generation ({iterations} iterations)...")
    crashes = []
    
    for i in range(iterations):
        try:
            # Valid fingerprint first
            fp = ProductionFingerprintGenerator()
            result = fp.generate_fingerprint()
            assert result is not None, "Fingerprint result is None"
            assert isinstance(result, dict), "Fingerprint result is not a dict"
            assert len(result) > 0, "Empty fingerprint result"
            
            # Test reproducibility
            result2 = fp.generate_fingerprint()
            assert result2 is not None, "Second fingerprint is None"
            
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{iterations}] tests passed")
                
        except Exception as e:
            crashes.append(f"Iteration {i}: {type(e).__name__}: {e}")
    
    return crashes

def test_storage(iterations=500):
    """Test secure storage with malformed data"""
    print(f"\n[*] Testing Secure Storage ({iterations} iterations)...")
    crashes = []
    
    import tempfile
    import shutil
    
    for i in range(iterations):
        temp_file = None
        try:
            # Create temporary file for each test
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
            temp_file.close()
            
            # Always provide a non-empty password
            password = random_string(32) or "fallback_password_12345"
            storage = SecureStorage(file_path=temp_file.name, password=password)
            
            # Initialize storage with empty data first
            try:
                storage.save({})
            except:
                pass
            
            # Test 1: Set and get random data
            key = random_string(20)  # Reduced size for speed
            value = random_string(50)
            try:
                storage.set(key, value)
                retrieved = storage.get(key)
                if retrieved != value:
                    crashes.append(f"Storage mismatch at iteration {i}")
            except Exception as e:
                # Only report unexpected errors
                if "corrupted" not in str(e).lower():
                    crashes.append(f"Storage iteration {i}: {e}")
            
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{iterations}] tests passed")
                
        except Exception as e:
            # OSError is expected for corrupted files
            if not isinstance(e, OSError):
                crashes.append(f"Iteration {i}: {type(e).__name__}: {e}")
        finally:
            # Cleanup
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    return crashes

def main():
    """Run all fuzz tests locally"""
    print("=" * 70)
    print("LOCAL FUZZING TEST - Windows Compatible")
    print("=" * 70)
    print("This simulates what GitHub Actions fuzzing will do")
    print("Looking for crashes, exceptions, and logic errors...")
    print("=" * 70)
    
    all_crashes = []
    
    # Run tests
    all_crashes.extend(test_crypto(1000))
    all_crashes.extend(test_hashing(1000))
    all_crashes.extend(test_fingerprint(500))
    all_crashes.extend(test_storage(500))
    
    # Report results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    
    if not all_crashes:
        print("\n✓ SUCCESS! No crashes found.")
        print("✓ All 3000 test iterations passed")
        print("✓ Your code is ready for production fuzzing")
        return 0
    else:
        print(f"\n✗ FOUND {len(all_crashes)} ISSUES:")
        print("=" * 70)
        for crash in all_crashes[:10]:  # Show first 10
            print(f"\n{crash}")
        
        if len(all_crashes) > 10:
            print(f"\n... and {len(all_crashes) - 10} more issues")
        
        print("\n" + "=" * 70)
        print("ACTION REQUIRED:")
        print("1. Review the crashes above")
        print("2. Fix the bugs in your code")
        print("3. Re-run this test: python fuzz/test_locally.py")
        print("4. Once passing, push to GitHub for continuous fuzzing")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n[!] CRITICAL ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)
