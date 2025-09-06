"""
Simple test of advanced fingerprinting methods
"""

from devicefingerprint import AdvancedDeviceFingerprinter, FingerprintMethod

def test_advanced_methods():
    print("Testing Advanced Device Fingerprinting Methods")
    print("=" * 50)
    
    fingerprinter = AdvancedDeviceFingerprinter()
    
    print(f"Available methods: {[m.value for m in fingerprinter.supported_methods]}")
    print()
    
    # Test constellation method
    try:
        print("Testing Constellation Method...")
        result = fingerprinter.generate_fingerprint(FingerprintMethod.CONSTELLATION)
        print(f"✅ Success: {result.fingerprint[:20]}... (confidence: {result.confidence})")
        if result.warnings:
            for warning in result.warnings:
                print(f"⚠️ Warning: {warning}")
    except Exception as e:
        print(f"❌ Constellation failed: {e}")
    
    print()
    
    # Test behavioral method  
    try:
        print("Testing Behavioral Method...")
        result = fingerprinter.generate_fingerprint(FingerprintMethod.BEHAVIORAL)
        print(f"✅ Success: {result.fingerprint[:20]}... (confidence: {result.confidence})")
        if result.warnings:
            for warning in result.warnings:
                print(f"⚠️ Warning: {warning}")
    except Exception as e:
        print(f"❌ Behavioral failed: {e}")
    
    print()
    
    # Test hybrid method
    try:
        print("Testing Hybrid Method...")
        result = fingerprinter.generate_fingerprint(FingerprintMethod.HYBRID)
        print(f"✅ Success: {result.fingerprint[:20]}... (confidence: {result.confidence})")
        if result.warnings:
            for warning in result.warnings:
                print(f"⚠️ Warning: {warning}")
    except Exception as e:
        print(f"❌ Hybrid failed: {e}")

if __name__ == "__main__":
    test_advanced_methods()
