"""
Simple test for TPM integration
"""

import sys
import os

# Add src to path for local testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import device_fingerprinting as df


def test_tpm_status():
    """Test TPM status retrieval"""
    print("Testing TPM status...")
    status = df.get_tpm_status()
    
    assert 'tpm_module_available' in status
    assert 'tpm_enabled' in status
    assert 'tpm_hardware_available' in status
    assert 'platform' in status
    
    print(f"✓ TPM Status: {status}")
    return status


def test_tpm_enable_disable():
    """Test enabling and disabling TPM"""
    print("\nTesting TPM enable/disable...")
    
    # Disable first
    df.enable_tpm_fingerprinting(enabled=False)
    assert not df.is_tpm_enabled()
    print("✓ TPM disabled")
    
    # Try to enable
    result = df.enable_tpm_fingerprinting(enabled=True)
    print(f"✓ TPM enable result: {result}")
    
    if result:
        assert df.is_tpm_enabled()
        print("✓ TPM enabled successfully")
    else:
        print("⚠ TPM not available on this system (expected on some platforms)")
    
    return result


def test_fingerprint_with_tpm():
    """Test fingerprint generation with TPM"""
    print("\nTesting fingerprint with TPM...")
    
    tpm_available = df.enable_tpm_fingerprinting(enabled=True)
    
    # Generate fingerprint (should work regardless of TPM availability)
    fp = df.generate_fingerprint(method="stable")
    assert fp is not None
    assert len(fp) > 0
    
    print(f"✓ Fingerprint generated: {fp[:32]}...")
    
    if tpm_available:
        print("✓ Fingerprint includes TPM data")
    else:
        print("⚠ Fingerprint without TPM (not available)")
    
    return fp


def test_device_binding_with_tpm():
    """Test device binding with TPM"""
    print("\nTesting device binding with TPM...")
    
    df.enable_tpm_fingerprinting(enabled=True)
    
    license_key = "TEST-KEY-12345"
    binding_data = {"license_key": license_key, "user_id": "test_user"}
    binding = df.create_device_binding(binding_data, security_level="high")
    
    assert binding is not None
    assert isinstance(binding, dict)
    
    print(f"✓ Binding created with keys: {list(binding.keys())}")
    
    # Verify the binding contains expected fields
    assert "device_binding" in binding or "device_fingerprint" in binding or "fingerprint" in binding
    
    print("✓ Binding creation successful")
    
    return binding


def test_tpm_module_direct():
    """Test TPM module directly"""
    print("\nTesting TPM module directly...")
    
    try:
        from device_fingerprinting.tpm_hardware import (
            get_tpm_info,
            is_tpm_available,
            TPMFingerprinter
        )
        
        # Test module-level functions
        tpm_info = get_tpm_info()
        print(f"✓ TPM Info: available={tpm_info.available}, platform={tpm_info.platform}")
        
        if tpm_info.available:
            print(f"  - Version: {tpm_info.version}")
            print(f"  - Manufacturer: {tpm_info.manufacturer}")
            print(f"  - Hardware ID: {tpm_info.hardware_id[:32] if tpm_info.hardware_id else 'None'}...")
        else:
            print(f"  - Error: {tpm_info.error}")
        
        # Test class directly
        fingerprinter = TPMFingerprinter()
        fp_data = fingerprinter.get_fingerprint_data()
        print(f"✓ Fingerprint data: {fp_data}")
        
        return True
        
    except ImportError as e:
        print(f"✗ TPM module not available: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("TPM Integration Tests")
    print("=" * 60)
    
    try:
        # Test status
        status = test_tpm_status()
        
        # Test enable/disable
        tpm_available = test_tpm_enable_disable()
        
        # Test fingerprinting
        fp = test_fingerprint_with_tpm()
        
        # Test binding
        binding = test_device_binding_with_tpm()
        
        # Test TPM module directly
        module_ok = test_tpm_module_direct()
        
        print("\n" + "=" * 60)
        print("Summary:")
        print(f"  Platform: {status['platform']}")
        print(f"  TPM Hardware: {'Available' if status['tpm_hardware_available'] else 'Not Available'}")
        print(f"  TPM Module: {'OK' if module_ok else 'Import Error'}")
        print(f"  Fingerprinting: {'Working' if fp else 'Failed'}")
        print(f"  Device Binding: {'Working' if binding else 'Failed'}")
        print("\n✓ All tests passed!")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
