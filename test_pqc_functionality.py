"""
Quick test to verify PQC functionality
"""
import sys
sys.path.insert(0, 'src')

from device_fingerprinting.hybrid_pqc import HybridPQC

print("=" * 60)
print("PQC FUNCTIONALITY TEST")
print("=" * 60)

# Initialize PQC
print("\n1. Initializing HybridPQC...")
pqc = HybridPQC()

# Get info
info = pqc.get_info()
print("\n2. PQC Configuration:")
print(f"   - PQC Available: {info['pqc_available']}")
print(f"   - Library: {info['pqc_library']}")
print(f"   - Algorithm: {info['algorithm']}")
print(f"   - Production Ready: {info['production_ready']}")

if 'backend_info' in info:
    print(f"   - Backend: {info['backend_info'].get('backend', 'N/A')}")
    print(f"   - Signature Algorithm: {info['backend_info'].get('sig_algorithm', 'N/A')}")
    print(f"   - KEM Algorithm: {info['backend_info'].get('kem_algorithm', 'N/A')}")

# Test signing
print("\n3. Testing Signature Generation...")
test_message = b"Test message for PQC verification"
signature = pqc.sign(test_message)
print(f"   ✓ Signature created: {len(signature)} characters")

# Test verification
print("\n4. Testing Signature Verification...")
is_valid = pqc.verify(signature, test_message)
print(f"   ✓ Verification result: {is_valid}")

if is_valid:
    print("\n   ✅ SUCCESS: Signature verified correctly!")
else:
    print("\n   ❌ FAILURE: Signature verification failed!")
    sys.exit(1)

# Test tamper detection
print("\n5. Testing Tamper Detection...")
tampered_message = b"Tampered message"
is_tampered = pqc.verify(signature, tampered_message)
print(f"   ✓ Tampered verification: {is_tampered}")

if not is_tampered:
    print("   ✅ SUCCESS: Tampering detected correctly!")
else:
    print("   ❌ FAILURE: Tampering not detected!")
    sys.exit(1)

# Test key info
print("\n6. Testing Key Properties...")
if hasattr(pqc, 'pqc_public_key') and pqc.pqc_public_key:
    print(f"   - Public Key Size: {len(pqc.pqc_public_key)} bytes")
if hasattr(pqc, 'pqc_private_key') and pqc.pqc_private_key:
    print(f"   - Private Key Size: {len(pqc.pqc_private_key)} bytes")
print(f"   - Classical Key Size: {len(pqc.classical_key)} bytes")

print("\n" + "=" * 60)
print("✅ ALL PQC TESTS PASSED!")
print("=" * 60)
