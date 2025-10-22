#!/usr/bin/env python3
"""
Quick test to check if PQC (Post-Quantum Cryptography) is functioning
"""

print("=" * 60)
print("PQC Functionality Test")
print("=" * 60)

# Test 1: Check if PQC modules can be imported
print("\n[1] Testing PQC module imports...")
try:
    from device_fingerprinting.hybrid_pqc import (
        HybridPQC,
        generate_pqc_keys,
        is_pqc_supported,
    )
    print("✅ HybridPQC modules imported successfully")
except ImportError as e:
    print(f"❌ Failed to import HybridPQC: {e}")
    exit(1)

# Test 2: Check if pqcdualusb library is available
print("\n[2] Checking if pqcdualusb library is installed...")
try:
    import pqcdualusb
    print(f"✅ pqcdualusb version: {pqcdualusb.__version__}")
    
    # Get security information from new version
    try:
        security_info = pqcdualusb.get_security_info()
        print(f"   - Security Info: {security_info}")
    except:
        print("   - Security info not available")
    
    pqc_library_available = True
except ImportError:
    print("⚠️  pqcdualusb not installed (optional dependency)")
    pqc_library_available = False

# Test 3: Check PQC support status
print("\n[3] Checking PQC support status...")
supported = is_pqc_supported()
print(f"PQC Supported: {supported}")

# Test 4: Initialize HybridPQC
print("\n[4] Initializing HybridPQC with Dilithium3...")
try:
    pqc = HybridPQC(algorithm="Dilithium3")
    print(f"✅ HybridPQC initialized")
    print(f"   - PQC Available: {pqc.pqc_available}")
    print(f"   - PQC Library: {pqc.pqc_library}")
    print(f"   - Algorithm: {pqc.algorithm}")
except Exception as e:
    print(f"❌ Failed to initialize HybridPQC: {e}")
    exit(1)

# Test 5: Generate PQC keys
print("\n[5] Generating PQC keys...")
try:
    keys = generate_pqc_keys()  # Fixed: no algorithm parameter needed
    if keys:
        public_key, private_key = keys
        print(f"✅ PQC keys generated successfully")
        print(f"   - Public key size: {len(public_key)} bytes")
        print(f"   - Private key size: {len(private_key)} bytes")
    else:
        print("⚠️  PQC keys not generated (library not available)")
except Exception as e:
    print(f"❌ Failed to generate keys: {e}")

# Test 6: Test hybrid signing and verification 
print("\n[6] Testing Hybrid PQC signing and verification...")
try:
    # Test with HybridPQC directly (more reliable)
    test_message = b"Test message for Hybrid PQC signing"
    
    # Sign with hybrid method
    signature = pqc.sign(test_message)
    print(f"✅ Message signed with hybrid method (signature length: {len(signature)} chars)")
    
    # Verify
    is_valid = pqc.verify(signature, test_message)
    print(f"✅ Signature verification: {is_valid}")
    
    if is_valid:
        print("✅ Hybrid PQC signing/verification working correctly!")
        print(f"   - Security Status: {pqc.get_info().get('security_status', 'Unknown')}")
        print(f"   - Backend: {pqc.get_info().get('backend_type', 'Unknown')}")
    else:
        print("❌ Signature verification failed!")
        
except Exception as e:
    print(f"❌ Signing/verification test failed: {e}")
    import traceback
    traceback.print_exc()

# Summary
print("\n" + "=" * 60)
print("PQC Test Summary")
print("=" * 60)
print(f"Module Import: ✅")
print(f"pqcdualusb Library: {'✅ Installed' if pqc_library_available else '⚠️  Not installed'}")
print(f"PQC Support: {'✅ Enabled' if supported else '⚠️  Disabled'}")
print(f"Key Generation: {'✅ Working' if pqc.pqc_available else '⚠️  Fallback mode'}")
print("=" * 60)

if not pqc_library_available:
    print("\n💡 To enable full PQC support, install: pip install pqcdualusb>=0.15.0")
    print("   Or install with PQC extras: pip install device-fingerprinting-pro[pqc]")
    print("   For real quantum resistance, also install: pip install liboqs python-oqs")
    print("   Alternative backends: cpp-pqc, rust-pqc")
