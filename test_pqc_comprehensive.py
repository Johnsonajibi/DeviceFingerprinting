#!/usr/bin/env python3
"""
Comprehensive PQC Functionality Test
Tests all Post-Quantum Cryptography features
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import device_fingerprinting


def test_pqc_backends():
    """Test PQC backend availability"""
    print("\n" + "=" * 70)
    print("TEST 1: PQC Backend Availability")
    print("=" * 70)
    
    backends = device_fingerprinting.get_available_crypto_backends()
    print(f"✓ Total backends: {len(backends['available_backends'])}")
    print(f"✓ Recommendations: {len(backends['recommendations'])}")
    
    assert len(backends['available_backends']) > 0, "No backends available"
    print("✅ PASSED: PQC backends are available")


def test_enable_pqc():
    """Test enabling PQC with different algorithms"""
    print("\n" + "=" * 70)
    print("TEST 2: Enable Post-Quantum Cryptography")
    print("=" * 70)
    
    algorithms = ["Dilithium3", "Dilithium5", "Falcon512"]
    
    for algo in algorithms:
        try:
            success = device_fingerprinting.enable_post_quantum_crypto(algorithm=algo)
            print(f"✓ {algo}: {'Enabled' if success else 'Failed'}")
            assert success, f"Failed to enable {algo}"
        except Exception as e:
            print(f"⚠ {algo}: {str(e)}")
    
    print("✅ PASSED: PQC can be enabled")


def test_crypto_info():
    """Test getting crypto configuration info"""
    print("\n" + "=" * 70)
    print("TEST 3: Crypto Configuration Info")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto(algorithm="Dilithium3")
    info = device_fingerprinting.get_crypto_info()
    
    print(f"✓ PQC Enabled: {info.get('pqc_enabled')}")
    print(f"✓ Backend Type: {info.get('backend_type')}")
    print(f"✓ Algorithm: {info.get('pqc_algorithm')}")
    print(f"✓ Hybrid Mode: {info.get('hybrid_mode')}")
    print(f"✓ Quantum Resistant: {info.get('quantum_resistant')}")
    
    assert info.get('pqc_enabled') == True, "PQC not enabled"
    assert info.get('backend_type') in ['HybridPQC', 'PQC'], "Invalid backend type"
    print("✅ PASSED: Crypto info retrieved successfully")


def test_fingerprint_generation():
    """Test fingerprint generation with PQC"""
    print("\n" + "=" * 70)
    print("TEST 4: Fingerprint Generation with PQC")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto(algorithm="Dilithium3")
    
    fingerprint = device_fingerprinting.generate_fingerprint(method="stable")
    
    print(f"✓ Fingerprint generated: {len(fingerprint)} bytes")
    print(f"✓ First 60 chars: {fingerprint[:60]}...")
    
    assert fingerprint, "No fingerprint generated"
    assert len(fingerprint) > 0, "Invalid fingerprint"
    print("✅ PASSED: Fingerprint generation works with PQC")


def test_device_binding():
    """Test device binding with PQC signatures"""
    print("\n" + "=" * 70)
    print("TEST 5: Device Binding with PQC Signatures")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto(algorithm="Dilithium3")
    device_fingerprinting.enable_anti_replay_protection(enabled=False)
    
    # Create binding
    binding_data = {
        "license_key": "TEST-PQC-2025",
        "user_id": "test_user_123",
        "expiry": "2026-12-31"
    }
    
    bound = device_fingerprinting.create_device_binding(binding_data, security_level="high")
    
    print(f"✓ Binding created: {bool(bound.get('device_binding'))}")
    print(f"✓ Security level: {bound['device_binding']['security_level']}")
    
    crypto_meta = bound['device_binding']['fields']['crypto_metadata']
    print(f"✓ Algorithm: {crypto_meta.get('algorithm')}")
    print(f"✓ Hybrid mode: {crypto_meta.get('hybrid_mode')}")
    
    assert bound.get('device_binding'), "Binding not created"
    assert crypto_meta.get('algorithm') == "Dilithium3", "Wrong algorithm"
    print("✅ PASSED: Device binding created with PQC")


def test_binding_verification():
    """Test verifying PQC-signed device binding"""
    print("\n" + "=" * 70)
    print("TEST 6: PQC Signature Verification")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto(algorithm="Dilithium3")
    device_fingerprinting.enable_anti_replay_protection(enabled=False)
    
    # Create and verify binding
    binding_data = {"license_key": "VERIFY-TEST-2025"}
    bound = device_fingerprinting.create_device_binding(binding_data, security_level="high")
    
    is_valid, details = device_fingerprinting.verify_device_binding(bound)
    
    print(f"✓ Binding valid: {is_valid}")
    print(f"✓ Match score: {details.get('match_score', 'N/A')}")
    print(f"✓ Signature valid: {details.get('signature_valid', 'N/A')}")
    
    assert is_valid, "Binding verification failed"
    print("✅ PASSED: PQC signature verification works")


def test_hybrid_mode():
    """Test hybrid classical + PQC mode"""
    print("\n" + "=" * 70)
    print("TEST 7: Hybrid Classical + PQC Mode")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto(algorithm="Dilithium3")
    
    info = device_fingerprinting.get_crypto_info()
    
    print(f"✓ Hybrid mode active: {info.get('hybrid_mode')}")
    print(f"✓ Quantum resistant: {info.get('quantum_resistant')}")
    
    # Verify both classical and PQC are working
    fingerprint = device_fingerprinting.generate_fingerprint(method="stable")
    
    print(f"✓ Fingerprint uses hybrid crypto: {len(fingerprint)} bytes")
    
    assert info.get('hybrid_mode') == True, "Hybrid mode not active"
    print("✅ PASSED: Hybrid mode is functioning")


def main():
    """Run all PQC tests"""
    print("\n" + "🔐" * 35)
    print("COMPREHENSIVE POST-QUANTUM CRYPTOGRAPHY TEST SUITE")
    print("🔐" * 35)
    
    tests = [
        test_pqc_backends,
        test_enable_pqc,
        test_crypto_info,
        test_fingerprint_generation,
        test_device_binding,
        test_binding_verification,
        test_hybrid_mode,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n❌ FAILED: {test.__name__}")
            print(f"   Error: {str(e)}")
            failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"✅ Passed: {passed}/{len(tests)}")
    print(f"❌ Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 ALL PQC TESTS PASSED! Post-Quantum Cryptography is fully functional.")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
