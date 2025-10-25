#!/usr/bin/env python3
"""
Test PQC integration focusing on pqcdualusb 0.15.0 and classical fallback
"""

import sys
import traceback
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_basic_imports():
    """Test that core modules can be imported"""
    print("=" * 60)
    print("Testing Basic Imports")
    print("=" * 60)
    
    try:
        from device_fingerprinting.hybrid_pqc import HybridPQC
        print("✅ HybridPQC import successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_pqcdualusb_integration():
    """Test pqcdualusb 0.15.0 integration"""
    print("\n" + "=" * 60)
    print("Testing pqcdualusb 0.15.0 Integration")
    print("=" * 60)
    
    try:
        import pqcdualusb
        print(f"✅ pqcdualusb imported successfully")
        
        # Test get_security_info
        try:
            info = pqcdualusb.get_security_info()
            print(f"✅ Security info retrieved: {info}")
            return True
        except Exception as e:
            print(f"⚠️  Security info failed: {e}")
            return False
            
    except ImportError as e:
        print(f"❌ pqcdualusb import failed: {e}")
        return False

def test_hybrid_pqc_initialization():
    """Test HybridPQC initialization with different backends"""
    print("\n" + "=" * 60)
    print("Testing HybridPQC Initialization")
    print("=" * 60)
    
    try:
        from device_fingerprinting.hybrid_pqc import HybridPQC
        
        # Test initialization
        pqc = HybridPQC()
        print(f"✅ HybridPQC initialized")
        print(f"   Backend: {pqc.backend}")
        print(f"   Status: {pqc.get_status()}")
        
        return True
        
    except Exception as e:
        print(f"❌ HybridPQC initialization failed: {e}")
        traceback.print_exc()
        return False

def test_key_operations():
    """Test key generation and basic operations"""
    print("\n" + "=" * 60)
    print("Testing Key Operations")
    print("=" * 60)
    
    try:
        from device_fingerprinting.hybrid_pqc import HybridPQC
        
        pqc = HybridPQC()
        
        # Generate keys
        print("Generating keys...")
        public_key, private_key = pqc.generate_keypair()
        print(f"✅ Keys generated successfully")
        print(f"   Public key size: {len(public_key)} bytes")
        print(f"   Private key size: {len(private_key)} bytes")
        
        # Test signing and verification
        test_data = b"Test message for signing"
        print(f"\nSigning test data: {test_data}")
        
        signature = pqc.sign(private_key, test_data)
        print(f"✅ Signature created, size: {len(signature)} bytes")
        
        # Verify signature
        is_valid = pqc.verify(public_key, test_data, signature)
        print(f"✅ Signature verification: {is_valid}")
        
        return is_valid
        
    except Exception as e:
        print(f"❌ Key operations failed: {e}")
        traceback.print_exc()
        return False

def test_device_fingerprinting_integration():
    """Test integration with device fingerprinting"""
    print("\n" + "=" * 60)
    print("Testing Device Fingerprinting Integration")
    print("=" * 60)
    
    try:
        from device_fingerprinting import DeviceFingerprinter
        
        fingerprinter = DeviceFingerprinter(use_pqc=True)
        print("✅ DeviceFingerprinter with PQC initialized")
        
        # Generate a fingerprint
        fingerprint = fingerprinter.generate_fingerprint()
        print(f"✅ Fingerprint generated successfully")
        print(f"   Fingerprint length: {len(fingerprint)}")
        print(f"   Sample: {fingerprint[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Device fingerprinting integration failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("Testing PQC Integration with pqcdualusb 0.15.0")
    print("=" * 80)
    
    results = []
    
    # Run tests
    results.append(("Basic Imports", test_basic_imports()))
    results.append(("pqcdualusb Integration", test_pqcdualusb_integration()))
    results.append(("HybridPQC Initialization", test_hybrid_pqc_initialization()))
    results.append(("Key Operations", test_key_operations()))
    results.append(("Device Fingerprinting", test_device_fingerprinting_integration()))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:30} {status}")
        if result:
            passed += 1
    
    print(f"\nTests passed: {passed}/{len(results)}")
    
    if passed == len(results):
        print("🎉 All tests passed! PQC integration is working correctly.")
    elif passed > 0:
        print("⚠️  Some tests passed. System has partial functionality.")
    else:
        print("❌ All tests failed. Please check the configuration.")
    
    return passed == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)