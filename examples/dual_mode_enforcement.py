"""
Dual-Mode TPM Architecture Example

Demonstrates the novel cryptographic enforcement architecture:
"A cryptographic enforcement method implemented in a software library,
wherein identity derivation is conditionally permitted only upon 
hardware-attested state satisfaction."

Two modes coexist:
- Mode A (software): TPM optional, works everywhere, best-effort
- Mode B (tpm_strict): TPM mandatory, cryptographically enforced, strong guarantees
"""

import device_fingerprinting as df


def example_mode_a_software():
    """
    Mode A: Software Fingerprint (Current Behavior)
    
    Characteristics:
    - TPM optional (used if available)
    - Works on all platforms
    - Graceful fallback
    - Best-effort uniqueness
    - Backward compatible
    """
    print("=" * 70)
    print("MODE A: Software Fingerprint (Portable)")
    print("=" * 70)
    
    # Check if TPM is available (but not required)
    status = df.get_tpm_status()
    print(f"TPM Available: {status['tpm_hardware_available']}")
    
    # Enable TPM if available (optional enhancement)
    df.enable_tpm_fingerprinting(enabled=True)
    
    # Generate fingerprint - MODE A: software (default)
    try:
        fingerprint = df.generate_fingerprint(method="stable", mode="software")
        print(f"✓ Fingerprint Generated: {fingerprint[:40]}...")
        print("✓ Works with or without TPM")
        print("✓ Portable across all systems")
        return fingerprint
    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def example_mode_b_tpm_strict():
    """
    Mode B: TPM-Strict Enforcement (Novel Architecture)
    
    Characteristics:
    - TPM REQUIRED (no fallback)
    - Cryptographically enforced
    - Hardware-attested identity only
    - Strong guarantees
    - Fails explicitly if TPM unavailable
    """
    print("\n" + "=" * 70)
    print("MODE B: TPM-Strict Enforcement (Hardware-Attested)")
    print("=" * 70)
    
    # Check TPM status BEFORE attempting strict mode
    status = df.get_tpm_status()
    print(f"TPM Hardware: {status['tpm_hardware_available']}")
    
    if not status['tpm_hardware_available']:
        print("⚠ TPM not available - tpm_strict mode will fail (expected)")
        print("⚠ This is INTENTIONAL - strict mode requires hardware attestation")
    
    # Generate fingerprint - MODE B: tpm_strict (enforced)
    try:
        fingerprint = df.generate_fingerprint(method="stable", mode="tpm_strict")
        print(f"✓ Hardware-Attested Fingerprint: {fingerprint[:40]}...")
        print("✓ TPM attestation enforced")
        print("✓ Unforgeable hardware binding")
        print("✓ Cryptographic guarantee of hardware presence")
        return fingerprint
        
    except RuntimeError as e:
        print(f"✗ Expected Failure: {e}")
        print("✓ Enforcement working correctly - TPM is mandatory in strict mode")
        return None


def example_production_usage():
    """
    Production Usage: Choose mode based on requirements
    """
    print("\n" + "=" * 70)
    print("PRODUCTION USAGE PATTERNS")
    print("=" * 70)
    
    print("\n--- Use Case 1: Enterprise Software (High Security) ---")
    print("Requirement: Must run on corporate hardware with TPM")
    print("Solution: Use tpm_strict mode")
    
    try:
        # Enterprise deployment - TPM mandatory
        enterprise_fp = df.generate_fingerprint(method="stable", mode="tpm_strict")
        print(f"✓ Enterprise Fingerprint: {enterprise_fp[:40]}...")
        print("✓ Hardware attestation enforced")
    except RuntimeError as e:
        print(f"✗ Cannot deploy on this system: {str(e)[:80]}...")
    
    print("\n--- Use Case 2: Consumer Software (Wide Compatibility) ---")
    print("Requirement: Must work on all devices")
    print("Solution: Use software mode (TPM optional)")
    
    # Consumer deployment - TPM optional
    consumer_fp = df.generate_fingerprint(method="stable", mode="software")
    print(f"✓ Consumer Fingerprint: {consumer_fp[:40]}...")
    print("✓ Works on all platforms")
    
    print("\n--- Use Case 3: Hybrid Deployment (Adaptive) ---")
    print("Strategy: Use TPM if available, fallback gracefully")
    
    status = df.get_tpm_status()
    if status['tpm_hardware_available']:
        # TPM available - use strict enforcement
        try:
            hybrid_fp = df.generate_fingerprint(method="stable", mode="tpm_strict")
            print(f"✓ Using TPM-strict mode: {hybrid_fp[:40]}...")
        except RuntimeError:
            # Fallback to software mode
            hybrid_fp = df.generate_fingerprint(method="stable", mode="software")
            print(f"✓ Fallback to software mode: {hybrid_fp[:40]}...")
    else:
        # No TPM - use software mode
        hybrid_fp = df.generate_fingerprint(method="stable", mode="software")
        print(f"✓ Using software mode: {hybrid_fp[:40]}...")


def example_license_binding_strict():
    """
    License Binding with TPM-Strict Enforcement
    """
    print("\n" + "=" * 70)
    print("LICENSE BINDING: TPM-Strict Enforcement")
    print("=" * 70)
    
    # Enterprise license - must be bound to TPM hardware
    license_key = "ENT-PRO-12345"
    
    try:
        # Generate hardware-attested fingerprint
        fingerprint = df.generate_fingerprint(method="stable", mode="tpm_strict")
        
        # Create device binding with TPM attestation
        binding_data = {
            "license_key": license_key,
            "user": "enterprise_user",
            "enforcement_mode": "tpm_strict"
        }
        binding = df.create_device_binding(binding_data, security_level="high")
        
        print("✓ License bound to TPM hardware")
        print("✓ Cannot be transferred to virtual machines")
        print("✓ Cannot be cloned to different hardware")
        print("✓ Cryptographic proof of hardware presence")
        print(f"  Binding: {str(binding)[:60]}...")
        
    except RuntimeError as e:
        print(f"✗ Cannot create TPM-strict binding: {e}")
        print("  Solution: Deploy on hardware with TPM support")


def compare_modes():
    """
    Direct comparison of both modes
    """
    print("\n" + "=" * 70)
    print("MODE COMPARISON")
    print("=" * 70)
    
    print("\n| Feature                  | Software Mode      | TPM-Strict Mode     |")
    print("|--------------------------|--------------------|--------------------|")
    print("| TPM Required             | No                 | Yes (enforced)     |")
    print("| Fallback                 | Yes                | No                 |")
    print("| Portability              | High               | Limited to TPM     |")
    print("| Security Guarantee       | Best-effort        | Cryptographically  |")
    print("|                          |                    | enforced           |")
    print("| Hardware Attestation     | Optional           | Mandatory          |")
    print("| Use Case                 | Consumer/General   | Enterprise/High    |")
    print("|                          |                    | Security           |")
    print("| Backward Compatible      | Yes                | N/A (new feature)  |")
    print("| Patent Territory         | Prior art          | Novel              |")
    
    print("\nTest Both Modes:")
    
    # Mode A - Software
    try:
        fp_software = df.generate_fingerprint(method="stable", mode="software")
        print(f"  Software Mode:    ✓ {fp_software[:32]}...")
    except Exception as e:
        print(f"  Software Mode:    ✗ {e}")
    
    # Mode B - TPM-Strict
    try:
        fp_strict = df.generate_fingerprint(method="stable", mode="tpm_strict")
        print(f"  TPM-Strict Mode:  ✓ {fp_strict[:32]}...")
    except RuntimeError as e:
        print(f"  TPM-Strict Mode:  ✗ Expected failure (no TPM)")


def main():
    """Run all examples"""
    print("\n" + "=" * 70)
    print("DUAL-MODE TPM ARCHITECTURE DEMONSTRATION")
    print("Patent-Worthy Innovation:")
    print("'Cryptographic enforcement method with conditional identity derivation'")
    print("=" * 70)
    
    try:
        # Demonstrate Mode A
        example_mode_a_software()
        
        # Demonstrate Mode B
        example_mode_b_tpm_strict()
        
        # Production usage patterns
        example_production_usage()
        
        # License binding with strict enforcement
        example_license_binding_strict()
        
        # Direct comparison
        compare_modes()
        
        print("\n" + "=" * 70)
        print("KEY INNOVATION:")
        print("Both modes coexist. Only Mode B (tpm_strict) is enforced.")
        print("Users opt-in to enforcement. No breaking changes.")
        print("Novel architecture for hardware-attested cryptographic identity.")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
