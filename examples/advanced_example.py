"""
Advanced Device Fingerprinting Example
=====================================

This example demonstrates the advanced fingerprinting capabilities
with different methods and detailed results.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from device_fingerprinting import AdvancedDeviceFingerprinter, FingerprintMethod

def main():
    print("=== Advanced Device Fingerprinting Example ===\n")
    
    # Create advanced fingerprinter
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Test all three methods
    methods = [
        (FingerprintMethod.BASIC, "Basic"),
        (FingerprintMethod.ADVANCED, "Advanced"),
        (FingerprintMethod.QUANTUM_RESISTANT, "Quantum-Resistant")
    ]
    
    results = []
    
    for method, name in methods:
        print(f"=== {name} Method ===")
        result = fingerprinter.generate_fingerprint(method)
        results.append(result)
        
        print(f"Fingerprint: {result.fingerprint}")
        print(f"Method: {result.method.value}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Components: {len(result.components)}")
        print(f"Timestamp: {result.timestamp}")
        
        if result.warnings:
            print(f"Warnings: {', '.join(result.warnings)}")
        else:
            print("No warnings")
        
        print(f"Sample components: {result.components[:3]}...")
        print()
    
    # Test fingerprint stability
    print("=== Fingerprint Stability Test ===")
    quantum_result = results[2]  # Quantum-resistant result
    
    is_stable, confidence = fingerprinter.verify_fingerprint_stability(
        quantum_result.fingerprint, 
        FingerprintMethod.QUANTUM_RESISTANT
    )
    
    print(f"Fingerprint stable: {is_stable}")
    print(f"Verification confidence: {confidence:.2f}")
    
    # Compare methods
    print("\n=== Method Comparison ===")
    print(f"Basic confidence: {results[0].confidence:.2f}")
    print(f"Advanced confidence: {results[1].confidence:.2f}")
    print(f"Quantum confidence: {results[2].confidence:.2f}")
    
    print(f"\nBasic components: {len(results[0].components)}")
    print(f"Advanced components: {len(results[1].components)}")
    print(f"Quantum components: {len(results[2].components)}")

if __name__ == '__main__':
    main()
