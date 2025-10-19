"""
Basic Device Fingerprinting Example
==================================

This example shows how to use the device fingerprinting library
for basic device identification.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from device_fingerprinting import DeviceFingerprintGenerator

def main():
    print("=== Basic Device Fingerprinting Example ===\n")
    
    # Create a basic fingerprint generator
    generator = DeviceFingerprintGenerator()
    
    # Generate device fingerprint
    print("Generating device fingerprint...")
    fingerprint = generator.generate_device_fingerprint()
    
    print(f"Device fingerprint: {fingerprint}")
    print(f"Fingerprint length: {len(fingerprint)} characters")
    print(f"Starts with 'device_': {fingerprint.startswith('device_')}")
    
    # Test consistency
    print("\nTesting consistency...")
    fingerprint2 = generator.generate_device_fingerprint()
    print(f"Second fingerprint: {fingerprint2}")
    print(f"Fingerprints match: {fingerprint == fingerprint2}")
    
    # Static method usage
    print("\nUsing static method...")
    static_fingerprint = DeviceFingerprintGenerator.generate_device_fingerprint()
    print(f"Static method result: {static_fingerprint}")
    print(f"Matches instance method: {fingerprint == static_fingerprint}")

if __name__ == '__main__':
    main()
