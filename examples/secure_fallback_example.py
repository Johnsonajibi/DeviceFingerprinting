"""
Secure Fallback Example
======================

This example demonstrates the secure fallback implementation that prevents
automatic security degradation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from devicefingerprint import (
    AdvancedDeviceFingerprinter,
    FingerprintMethod,
    FingerprintGenerationError
)

def main():
    print("=== Secure Fallback Security Example ===\n")
    
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Example 1: Secure default - no automatic fallback
    print("1. SECURE DEFAULT BEHAVIOR:")
    print("   Attempting advanced fingerprinting without fallback...")
    
    try:
        result = fingerprinter.generate_fingerprint(FingerprintMethod.ADVANCED)
        print(f"   ✅ Success: {result.fingerprint[:16]}...")
        print(f"   Confidence: {result.confidence}")
        print(f"   Method: {result.method.value}")
    except FingerprintGenerationError as e:
        print(f"   🔒 SECURE: Fingerprinting failed without silent degradation")
        print(f"   Error: {e}")
        print("   → Application must decide how to handle this failure")
    
    print()
    
    # Example 2: Explicit security decision
    print("2. EXPLICIT SECURITY DECISIONS:")
    
    # High-security application: No fallback allowed
    print("   High-security mode (no fallback):")
    try:
        result = fingerprinter.generate_fingerprint_with_fallback(
            FingerprintMethod.QUANTUM_RESISTANT,
            allow_fallback=False
        )
        print(f"   ✅ High security maintained: {result.fingerprint[:16]}...")
        print(f"   Confidence: {result.confidence}")
    except FingerprintGenerationError as e:
        print(f"   🔒 Failed securely - no degradation")
        print(f"   → Block access or require alternative authentication")
    
    print()
    
    # Standard application: Controlled fallback
    print("   Standard mode (controlled fallback):")
    try:
        result = fingerprinter.generate_fingerprint_with_fallback(
            FingerprintMethod.ADVANCED,
            allow_fallback=True
        )
        print(f"   ✅ Result: {result.fingerprint[:16]}...")
        print(f"   Confidence: {result.confidence}")
        
        # Check if fallback was used
        fallback_used = any("Fallback" in warning for warning in result.warnings)
        if fallback_used:
            print(f"   ⚠️  FALLBACK WAS USED - Security degraded")
            print(f"   → Consider requiring additional authentication")
        else:
            print(f"   ✅ No fallback needed - Full security maintained")
            
    except FingerprintGenerationError as e:
        print(f"   ❌ Complete failure: {e}")
    
    print()
    
    # Example 3: Adaptive security policy
    print("3. ADAPTIVE SECURITY POLICY:")
    
    def get_security_recommendation(fingerprint_result, fallback_used):
        """Determine security policy based on fingerprint quality"""
        
        if fallback_used:
            return {
                "access_level": "LIMITED",
                "session_timeout": 30,  # minutes
                "require_2fa": True,
                "allow_sensitive_ops": False,
                "recommendation": "Require additional authentication due to fallback"
            }
        elif fingerprint_result.confidence >= 0.95:
            return {
                "access_level": "FULL",
                "session_timeout": 480,  # 8 hours
                "require_2fa": False,
                "allow_sensitive_ops": True,
                "recommendation": "Full access granted"
            }
        elif fingerprint_result.confidence >= 0.70:
            return {
                "access_level": "STANDARD", 
                "session_timeout": 120,  # 2 hours
                "require_2fa": True,
                "allow_sensitive_ops": True,
                "recommendation": "Standard access with 2FA"
            }
        else:
            return {
                "access_level": "RESTRICTED",
                "session_timeout": 15,  # minutes
                "require_2fa": True,
                "allow_sensitive_ops": False,
                "recommendation": "Restricted access due to low confidence"
            }
    
    try:
        result = fingerprinter.generate_fingerprint_with_fallback(
            FingerprintMethod.QUANTUM_RESISTANT,
            allow_fallback=True
        )
        
        fallback_used = any("Fallback" in warning for warning in result.warnings)
        policy = get_security_recommendation(result, fallback_used)
        
        print(f"   Fingerprint: {result.fingerprint[:16]}...")
        print(f"   Confidence: {result.confidence}")
        print(f"   Fallback used: {fallback_used}")
        print(f"   Security Policy:")
        print(f"     - Access Level: {policy['access_level']}")
        print(f"     - Session Timeout: {policy['session_timeout']} minutes")
        print(f"     - Require 2FA: {policy['require_2fa']}")
        print(f"     - Sensitive Operations: {policy['allow_sensitive_ops']}")
        print(f"     - Recommendation: {policy['recommendation']}")
        
    except FingerprintGenerationError as e:
        print(f"   ❌ Fingerprinting failed: {e}")
        print(f"   → Deny access or use alternative authentication")
    
    print()
    print("=== SECURITY BENEFITS ===")
    print("✅ No silent security degradation")
    print("✅ Explicit fallback control")
    print("✅ Clear indication when fallback is used")
    print("✅ Applications can make informed security decisions")
    print("✅ Confidence scores reflect actual security level")

if __name__ == '__main__':
    main()
