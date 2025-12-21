"""
TPM/Secure Hardware Fingerprinting Example

Demonstrates how to use optional TPM-based device fingerprinting
for enhanced hardware-backed security.
"""

import device_fingerprinting as df


def basic_tpm_example():
    """Basic TPM fingerprinting example"""
    print("=== Basic TPM Fingerprinting Example ===\n")
    
    # Check TPM status before enabling
    status = df.get_tpm_status()
    print(f"Platform: {status['platform']}")
    print(f"TPM Module Available: {status['tpm_module_available']}")
    print(f"TPM Hardware Available: {status['tpm_hardware_available']}")
    
    if status['tpm_hardware_available']:
        print(f"TPM Version: {status['tpm_version']}")
        print(f"TPM Manufacturer: {status['tpm_manufacturer']}")
        print(f"Attestation Capable: {status['attestation_capable']}")
    else:
        print(f"TPM Not Available: {status.get('error', 'Unknown reason')}")
    
    print("\n--- Enabling TPM Fingerprinting ---")
    
    # Try to enable TPM fingerprinting
    tpm_enabled = df.enable_tpm_fingerprinting(enabled=True)
    
    if tpm_enabled:
        print("✓ TPM fingerprinting enabled successfully")
        
        # Generate fingerprint with TPM data
        fingerprint = df.generate_fingerprint(method="stable")
        print(f"\nFingerprint (with TPM): {fingerprint[:32]}...")
        
        # Create device binding with TPM
        binding_data = {"license_key": "TEST-LICENSE-KEY-001", "app": "tpm_example"}
        binding = df.create_device_binding(binding_data, security_level="high")
        print(f"Device Binding Created: {str(binding)[:60]}...")
        
    else:
        print("⚠ TPM not available - using standard fingerprinting")
        
        # Fingerprinting still works without TPM
        fingerprint = df.generate_fingerprint(method="stable")
        print(f"\nFingerprint (without TPM): {fingerprint[:32]}...")


def compare_with_without_tpm():
    """Compare fingerprints with and without TPM"""
    print("\n\n=== Comparing Fingerprints With/Without TPM ===\n")
    
    # Generate without TPM
    df.enable_tpm_fingerprinting(enabled=False)
    fp_without = df.generate_fingerprint(method="stable")
    print(f"Fingerprint WITHOUT TPM: {fp_without[:32]}...")
    
    # Generate with TPM (if available)
    tpm_enabled = df.enable_tpm_fingerprinting(enabled=True)
    if tpm_enabled:
        fp_with = df.generate_fingerprint(method="stable")
        print(f"Fingerprint WITH TPM:    {fp_with[:32]}...")
        
        if fp_with != fp_without:
            print("\n✓ TPM adds additional hardware-backed entropy")
        else:
            print("\n⚠ Fingerprints are identical (unexpected)")
    else:
        print("\n⚠ TPM not available - cannot compare")


def production_recommended_usage():
    """Recommended usage for production environments"""
    print("\n\n=== Production Recommended Configuration ===\n")
    
    # 1. Check TPM availability
    status = df.get_tpm_status()
    
    # 2. Enable TPM if available (graceful degradation)
    tpm_available = df.enable_tpm_fingerprinting(enabled=True)
    
    if tpm_available:
        print("✓ Using TPM-enhanced fingerprinting")
    else:
        print("⚠ Using standard fingerprinting (TPM not available)")
    
    # 3. Enable post-quantum cryptography for future-proofing
    pqc_enabled = df.enable_post_quantum_crypto(algorithm="Dilithium3")
    
    if pqc_enabled:
        print("✓ Post-quantum cryptography enabled")
    
    # 4. Get crypto info
    crypto_info = df.get_crypto_info()
    print(f"\nCrypto Configuration:")
    print(f"  - Algorithm: {crypto_info['algorithm']}")
    print(f"  - PQC Enabled: {crypto_info['pqc_enabled']}")
    print(f"  - Quantum Resistant: {crypto_info['quantum_resistant']}")
    
    # 5. Generate secure fingerprint
    fingerprint = df.generate_fingerprint(method="stable")
    print(f"\nSecure Fingerprint: {fingerprint[:40]}...")
    
    # 6. Create binding for license
    license_key = "PROD-LICENSE-12345"
    binding_data = {"license_key": license_key, "user": "production_user"}
    binding = df.create_device_binding(binding_data, security_level="high")
    print(f"License Binding: {str(binding)[:60]}...")
    
    print("\nConfiguration complete!")


def main():
    """Run all examples"""
    print("TPM/Secure Hardware Fingerprinting Examples")
    print("=" * 60)
    
    try:
        basic_tpm_example()
        compare_with_without_tpm()
        production_recommended_usage()
        
        print("\n" + "=" * 60)
        print("Examples completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
