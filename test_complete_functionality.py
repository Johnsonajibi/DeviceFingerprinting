#!/usr/bin/env python3
"""
Complete Functionality Test
Tests all major features of the Device Fingerprinting library
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import device_fingerprinting

def test_basic_fingerprinting():
    """Test basic device fingerprinting"""
    print("\n" + "=" * 70)
    print("TEST 1: Basic Device Fingerprinting")
    print("=" * 70)
    
    fp = device_fingerprinting.DeviceFingerprintGenerator()
    result = fp.generate()
    
    print(f"✓ Fingerprint Generated: {len(result.fingerprint)} bytes")
    print(f"✓ Method: {result.method}")
    print(f"✓ Confidence: {result.confidence}")
    print(f"✓ Components: {len(result.components)}")
    
    # Test determinism
    result2 = fp.generate()
    assert result.fingerprint == result2.fingerprint, "Fingerprints should be deterministic"
    print(f"✓ Deterministic: Same fingerprint on regeneration")
    
    print("✅ PASSED: Basic fingerprinting works correctly")
    return True


def test_advanced_fingerprinting():
    """Test advanced device fingerprinting"""
    print("\n" + "=" * 70)
    print("TEST 2: Advanced Device Fingerprinting")
    print("=" * 70)
    
    afp = device_fingerprinting.AdvancedDeviceFingerprinter()
    result = afp.generate()
    
    print(f"✓ Advanced Fingerprint: {len(result.fingerprint)} bytes")
    print(f"✓ Method: {result.method}")
    print(f"✓ Confidence: {result.confidence}")
    
    assert result.confidence >= 0.8, "Advanced fingerprint should have high confidence"
    print("✅ PASSED: Advanced fingerprinting works correctly")
    return True


def test_pqc_fingerprinting():
    """Test quantum-resistant fingerprinting"""
    print("\n" + "=" * 70)
    print("TEST 3: Post-Quantum Cryptography Fingerprinting")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto("Dilithium3")
    
    info = device_fingerprinting.get_crypto_info()
    print(f"✓ PQC Enabled: {info['pqc_enabled']}")
    print(f"✓ Algorithm: {info['pqc_algorithm']}")
    print(f"✓ Hybrid Mode: {info['hybrid_mode']}")
    
    fp = device_fingerprinting.generate_fingerprint(method="quantum_resistant")
    print(f"✓ Quantum-Resistant Fingerprint: {len(fp)} bytes")
    
    assert info['pqc_enabled'] == True, "PQC should be enabled"
    assert len(fp) > 1000, "PQC fingerprint should be larger"
    print("✅ PASSED: PQC fingerprinting works correctly")
    return True


def test_device_binding():
    """Test device binding without PQC"""
    print("\n" + "=" * 70)
    print("TEST 4: Device Binding (Classical Crypto)")
    print("=" * 70)
    
    # Disable PQC for this test
    device_fingerprinting.enable_post_quantum_crypto(False)
    device_fingerprinting.enable_anti_replay_protection(False)
    
    binding_data = {
        "license_key": "TEST-LICENSE-2025",
        "user_email": "test@example.com",
        "expiry": "2026-12-31"
    }
    
    binding = device_fingerprinting.create_device_binding(
        binding_data,
        security_level="high"
    )
    
    print(f"✓ Binding Created: {bool(binding.get('device_binding'))}")
    print(f"✓ Security Level: {binding['device_binding']['security_level']}")
    
    # Verify the binding
    is_valid, details = device_fingerprinting.verify_device_binding(binding)
    print(f"✓ Binding Valid: {is_valid}")
    print(f"✓ Verification Details: {details}")
    
    assert is_valid, "Binding should be valid"
    print("✅ PASSED: Device binding works correctly")
    return True


def test_device_binding_with_pqc():
    """Test device binding with PQC signatures"""
    print("\n" + "=" * 70)
    print("TEST 5: Device Binding with PQC Signatures")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto("Dilithium3")
    device_fingerprinting.enable_anti_replay_protection(False)
    
    binding_data = {
        "license_key": "PQC-LICENSE-2025",
        "product": "Device Fingerprinting Pro",
        "tier": "enterprise"
    }
    
    binding = device_fingerprinting.create_device_binding(
        binding_data,
        security_level="high"
    )
    
    print(f"✓ PQC Binding Created: {bool(binding.get('device_binding'))}")
    
    crypto_meta = binding['device_binding']['fields']['crypto_metadata']
    print(f"✓ Algorithm: {crypto_meta.get('algorithm')}")
    print(f"✓ Quantum Resistant: {crypto_meta.get('quantum_resistant')}")
    
    # Verify
    is_valid, details = device_fingerprinting.verify_device_binding(binding)
    print(f"✓ PQC Binding Valid: {is_valid}")
    
    assert is_valid, "PQC binding should be valid"
    assert crypto_meta.get('algorithm') == "Dilithium3", "Should use Dilithium3"
    print("✅ PASSED: PQC device binding works correctly")
    return True


def test_tamper_detection():
    """Test tamper detection in device binding"""
    print("\n" + "=" * 70)
    print("TEST 6: Tamper Detection")
    print("=" * 70)
    
    device_fingerprinting.enable_post_quantum_crypto("Dilithium3")
    device_fingerprinting.enable_anti_replay_protection(False)
    
    # Create valid binding
    binding_data = {"license": "TAMPER-TEST"}
    binding = device_fingerprinting.create_device_binding(
        binding_data,
        security_level="high"
    )
    
    print(f"✓ Original binding valid")
    
    # Tamper with the binding
    binding['device_binding']['fields']['license'] = "TAMPERED"
    
    # Verify tampered binding
    is_valid, details = device_fingerprinting.verify_device_binding(binding)
    print(f"✓ Tampered binding detected: {not is_valid}")
    print(f"✓ Detection details: {details}")
    
    assert not is_valid, "Tampered binding should be invalid"
    print("✅ PASSED: Tamper detection works correctly")
    return True


def test_multiple_algorithms():
    """Test multiple PQC algorithms"""
    print("\n" + "=" * 70)
    print("TEST 7: Multiple PQC Algorithms")
    print("=" * 70)
    
    algorithms = ["Dilithium3", "Dilithium5", "Falcon512"]
    
    for algo in algorithms:
        success = device_fingerprinting.enable_post_quantum_crypto(algo)
        info = device_fingerprinting.get_crypto_info()
        
        print(f"✓ {algo}: Enabled={success}, Active={info.get('pqc_algorithm')}")
        assert success, f"{algo} should be enabled"
    
    print("✅ PASSED: Multiple algorithms supported")
    return True


def test_fingerprint_stability():
    """Test that fingerprints are stable across multiple generations"""
    print("\n" + "=" * 70)
    print("TEST 8: Fingerprint Stability")
    print("=" * 70)
    
    fp = device_fingerprinting.DeviceFingerprintGenerator()
    
    # Generate multiple fingerprints
    fingerprints = [fp.generate().fingerprint for _ in range(5)]
    
    # All should be identical
    all_same = all(f == fingerprints[0] for f in fingerprints)
    print(f"✓ Generated 5 fingerprints")
    print(f"✓ All identical: {all_same}")
    
    assert all_same, "All fingerprints should be identical"
    print("✅ PASSED: Fingerprints are stable")
    return True


def test_crypto_backends():
    """Test available crypto backends"""
    print("\n" + "=" * 70)
    print("TEST 9: Crypto Backend Availability")
    print("=" * 70)
    
    backends = device_fingerprinting.get_available_crypto_backends()
    
    print(f"✓ Available backends: {len(backends['available_backends'])}")
    print(f"✓ Recommendations: {len(backends['recommendations'])}")
    
    # Show first 3 backends if available
    available = backends['available_backends']
    if isinstance(available, list):
        for backend in available[:3]:
            print(f"  - {backend.get('name', 'unknown')}")
    
    assert len(backends['available_backends']) > 0, "Should have available backends"
    print("✅ PASSED: Crypto backends available")
    return True


def test_security_levels():
    """Test different security levels"""
    print("\n" + "=" * 70)
    print("TEST 10: Security Levels")
    print("=" * 70)
    
    device_fingerprinting.enable_anti_replay_protection(False)
    
    security_levels = ["low", "medium", "high"]
    
    for level in security_levels:
        binding = device_fingerprinting.create_device_binding(
            {"test": f"level_{level}"},
            security_level=level
        )
        actual_level = binding['device_binding']['security_level']
        print(f"✓ Security level '{level}': {actual_level}")
        assert actual_level == level, f"Security level should be {level}"
    
    print("✅ PASSED: All security levels work")
    return True


def main():
    """Run all tests"""
    print("\n" + "🔬" * 35)
    print("COMPLETE DEVICE FINGERPRINTING FUNCTIONALITY TEST")
    print("🔬" * 35)
    
    tests = [
        test_basic_fingerprinting,
        test_advanced_fingerprinting,
        test_pqc_fingerprinting,
        test_device_binding,
        test_device_binding_with_pqc,
        test_tamper_detection,
        test_multiple_algorithms,
        test_fingerprint_stability,
        test_crypto_backends,
        test_security_levels,
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
            import traceback
            traceback.print_exc()
            failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("FINAL TEST SUMMARY")
    print("=" * 70)
    print(f"✅ Passed: {passed}/{len(tests)}")
    print(f"❌ Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! Device Fingerprinting is fully functional.")
        print("\n✅ Basic Fingerprinting: WORKING")
        print("✅ Advanced Fingerprinting: WORKING")
        print("✅ Post-Quantum Cryptography: WORKING")
        print("✅ Device Binding: WORKING")
        print("✅ Tamper Detection: WORKING")
        print("✅ Signature Verification: WORKING")
        print("✅ Multiple Algorithms: WORKING")
        print("✅ Deterministic Behavior: WORKING")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
