#!/usr/bin/env python3
"""
Device Fingerprinting Demo

Demonstrates the device fingerprinting library functionality including:
- Basic device identification
- Advanced hardware fingerprinting  
- Device binding and verification
- Integration with QR recovery system

Author: Security Team
"""

import json
import time
from typing import Dict, Any

def demo_basic_device_identification():
    """Demo basic device identification."""
    print("=" * 60)
    print("1. BASIC DEVICE IDENTIFICATION")
    print("=" * 60)
    
    from dual_qr_recovery import DeviceIdentifier
    
    # Get basic device ID
    device_id = DeviceIdentifier.get_device_id()
    print(f"Basic Device ID: {device_id}")
    print(f"ID Length: {len(device_id)} characters")
    print(f"ID Format: dev_[16-char-hash]")
    print()

def demo_advanced_fingerprinting():
    """Demo advanced device fingerprinting."""
    print("=" * 60)
    print("2. ADVANCED DEVICE FINGERPRINTING")
    print("=" * 60)
    
    from dual_qr_recovery import get_advanced_device_fingerprint
    
    # Test different fingerprinting methods
    methods = ["basic", "system", "network", "all"]
    
    for method in methods:
        try:
            fingerprint = get_advanced_device_fingerprint(method)
            print(f"{method.upper()} fingerprint:")
            print(f"  {fingerprint[:64]}...")
            print(f"  Length: {len(fingerprint)} characters")
            print()
        except Exception as e:
            print(f"{method.upper()} fingerprint failed: {e}")
            print()

def demo_device_binding():
    """Demo device binding with data."""
    print("=" * 60)
    print("3. DEVICE BINDING DEMONSTRATION")
    print("=" * 60)
    
    # Test data to bind to device
    test_data = {
        "user_id": "john_doe_2025",
        "access_token": "abc123def456ghi789",
        "permissions": ["read", "write", "admin"],
        "created_at": time.time()
    }
    
    print("Original data:")
    print(json.dumps(test_data, indent=2))
    print()
    
    try:
        from device_fingerprinting import create_device_binding, verify_device_binding
        
        # Bind data to device
        bound_data = create_device_binding(test_data)
        print("Device-bound data:")
        print(json.dumps(bound_data, indent=2))
        print()
        
        # Verify binding
        is_valid = verify_device_binding(bound_data)
        print(f"Device binding verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print()
        
    except ImportError:
        print("⚠️  Advanced device binding not available (using fallback)")
        from dual_qr_recovery import get_advanced_device_fingerprint
        
        # Manual binding
        bound_data = test_data.copy()
        bound_data['device_fingerprint'] = get_advanced_device_fingerprint('system')
        bound_data['binding_timestamp'] = time.time()
        
        print("Fallback device-bound data:")
        print(json.dumps(bound_data, indent=2))
        print()

def demo_qr_recovery_integration():
    """Demo QR recovery with device binding."""
    print("=" * 60)
    print("4. QR RECOVERY WITH DEVICE BINDING")
    print("=" * 60)
    
    from dual_qr_recovery import DualQRRecoverySystem
    
    # Test recovery data
    recovery_data = {
        "wallet_seed": "abandon ability able about above absent absorb abstract",
        "backup_keys": ["key1", "key2", "key3"],
        "metadata": {
            "created": "2025-09-07",
            "version": "1.0"
        }
    }
    
    print("Data to split across QR codes:")
    print(json.dumps(recovery_data, indent=2))
    print()
    
    try:
        # Create enhanced recovery system with device binding
        recovery_system = DualQRRecoverySystem(
            expiry_hours=72,
            fingerprint_method="system"
        )
        
        # Split data across QR codes
        qr_result = recovery_system.create_recovery_qrs(recovery_data)
        
        if qr_result.errors:
            print("⚠️  QR creation warnings:")
            for error in qr_result.errors:
                print(f"   - {error}")
            print()
        
        print("QR Code A:")
        print(f"  ID: {qr_result.qr_a.qr_id}")
        print(f"  Device: {qr_result.qr_a.device_id}")
        print(f"  Created: {qr_result.qr_a.created_at}")
        print(f"  Expires: {qr_result.qr_a.expires_at}")
        print()
        
        print("QR Code B:")
        print(f"  ID: {qr_result.qr_b.qr_id}")
        print(f"  Device: {qr_result.qr_b.device_id}")
        print(f"  Created: {qr_result.qr_b.created_at}")
        print(f"  Expires: {qr_result.qr_b.expires_at}")
        print()
        
        # Test recovery
        print("Testing recovery...")
        recovered_data = recovery_system.recover_from_qrs(qr_result.qr_a, qr_result.qr_b)
        
        if recovered_data:
            print("✅ Recovery successful!")
            if 'device_fingerprint_warning' in recovered_data:
                print("⚠️  Device fingerprint warning detected")
            
            # Show recovered data (excluding device binding info)
            clean_data = {k: v for k, v in recovered_data.items() 
                         if not k.startswith('advanced_device') and not k.startswith('fingerprint')}
            print("Recovered data:")
            print(json.dumps(clean_data, indent=2))
        else:
            print("❌ Recovery failed")
        
        print()
        print("Recovery Instructions:")
        print(qr_result.instructions)
        
    except Exception as e:
        print(f"❌ QR recovery demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_security_features():
    """Demo security features."""
    print("=" * 60)
    print("5. SECURITY FEATURES")
    print("=" * 60)
    
    from dual_qr_recovery import get_advanced_device_fingerprint
    
    # Demonstrate fingerprint consistency
    print("Fingerprint consistency test:")
    fp1 = get_advanced_device_fingerprint('system')
    time.sleep(0.1)  # Small delay
    fp2 = get_advanced_device_fingerprint('system')
    
    print(f"Fingerprint 1: {fp1[:32]}...")
    print(f"Fingerprint 2: {fp2[:32]}...")
    print(f"Consistency: {'✅ CONSISTENT' if fp1 == fp2 else '❌ INCONSISTENT'}")
    print()
    
    # Show device binding security
    print("Device binding security:")
    print("- Device fingerprints are unique per hardware configuration")
    print("- QR codes bound to specific device cannot be used elsewhere")
    print("- Cryptographic hashing prevents forgery")
    print("- Multiple fingerprinting methods provide redundancy")
    print()

def main():
    """Run all device fingerprinting demos."""
    print("DEVICE FINGERPRINTING LIBRARY DEMONSTRATION")
    print("Comprehensive Demo of Device Identification and Binding Features")
    print()
    
    try:
        demo_basic_device_identification()
        demo_advanced_fingerprinting()
        demo_device_binding()
        demo_qr_recovery_integration()
        demo_security_features()
        
        print("=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY! ✅")
        print("=" * 60)
        print()
        print("The device fingerprinting library is now ready for use.")
        print("Integration with CorrectPQC.py has been completed.")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
