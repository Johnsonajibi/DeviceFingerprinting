"""
Advanced Device Fingerprinting Examples
=====================================

This script demonstrates all the novel approaches implemented in the
enhanced DeviceFingerprint library, including:

1. Hardware Constellation Fingerprinting
2. Behavioral Micro-benchmark Fingerprinting  
3. Hybrid Multi-method Fingerprinting
4. Advanced Similarity-based Verification

Run this to see the cutting-edge fingerprinting techniques in action!
"""

import json
import time
import sys
import os

# Add parent directory to path to import devicefingerprint
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from devicefingerprint import (
        AdvancedDeviceFingerprinter, 
        FingerprintMethod,
        FingerprintResult
    )
except ImportError:
    # Try direct import
    import devicefingerprint
    AdvancedDeviceFingerprinter = devicefingerprint.AdvancedDeviceFingerprinter
    FingerprintMethod = devicefingerprint.FingerprintMethod
    FingerprintResult = devicefingerprint.FingerprintResult

def demonstrate_advanced_fingerprinting():
    """Demonstrate all advanced fingerprinting methods"""
    print("🚀 Advanced Device Fingerprinting Demonstration")
    print("=" * 60)
    
    # Initialize the advanced fingerprinter
    fingerprinter = AdvancedDeviceFingerprinter()
    
    print(f"📋 Supported methods: {[method.value for method in fingerprinter.supported_methods]}")
    print()
    
    # Test each method
    methods_to_test = [
        (FingerprintMethod.BASIC, "Quick & Simple"),
        (FingerprintMethod.QUANTUM_RESISTANT, "Maximum Security"), 
        (FingerprintMethod.CONSTELLATION, "Hardware Constellation (Novel)"),
        (FingerprintMethod.BEHAVIORAL, "Behavioral Timing (Novel)"),
        (FingerprintMethod.HYBRID, "Hybrid Multi-method (Ultimate)")
    ]
    
    results = {}
    
    for method, description in methods_to_test:
        print(f"🔍 Testing {description}")
        print("-" * 40)
        
        try:
            start_time = time.time()
            result = fingerprinter.generate_fingerprint(method)
            generation_time = time.time() - start_time
            
            results[method] = result
            
            print(f"  Method: {result.method.value}")
            print(f"  Fingerprint: {result.fingerprint}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Components: {len(result.components)}")
            print(f"  Generation Time: {generation_time:.3f}s")
            print(f"  Warnings: {len(result.warnings)}")
            
            if result.warnings:
                for warning in result.warnings:
                    print(f"    ⚠️ {warning}")
            
            # Show detailed info for advanced methods
            if method == FingerprintMethod.CONSTELLATION and result.constellation_data:
                print(f"  🌟 Constellation Observations: {len(result.constellation_data.observations)}")
                print(f"  🌟 Stability Prediction: {result.constellation_data.stability_prediction:.2f}")
            
            elif method == FingerprintMethod.BEHAVIORAL and result.behavioral_data:
                print(f"  ⚡ Behavioral Components: {len(result.behavioral_data.observations)}")
                print(f"  ⚡ System Load Factor: {result.behavioral_data.system_load_factor:.2f}")
                print(f"  ⚡ Reliability Score: {result.behavioral_data.reliability_score:.2f}")
            
            print("  ✅ Success!")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        print()
    
    return results

def demonstrate_advanced_verification(results):
    """Demonstrate advanced verification capabilities"""
    print("🔐 Advanced Verification Demonstration")
    print("=" * 60)
    
    fingerprinter = AdvancedDeviceFingerprinter()
    
    for method, stored_result in results.items():
        if stored_result is None:
            continue
            
        print(f"🔍 Verifying {method.value} fingerprint")
        print("-" * 40)
        
        try:
            # Test advanced verification
            is_match, similarity, details = fingerprinter.verify_advanced_fingerprint(stored_result)
            
            print(f"  Exact Match: {details['exact_match']}")
            print(f"  Similarity Score: {details['similarity_score']:.3f}")
            print(f"  Threshold Met: {details['threshold_met']}")
            print(f"  Overall Result: {'✅ MATCH' if is_match else '❌ NO MATCH'}")
            
            if 'component_analysis' in details and details['component_analysis']:
                print("  Component Analysis:")
                for component, score in details['component_analysis'].items():
                    print(f"    {component}: {score:.3f}")
            
        except Exception as e:
            print(f"  ❌ Verification Error: {e}")
        
        print()

def demonstrate_similarity_robustness():
    """Demonstrate robustness of similarity-based methods"""
    print("🎯 Similarity Robustness Test")
    print("=" * 60)
    
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Test constellation method multiple times to show consistency
    if FingerprintMethod.CONSTELLATION in fingerprinter.supported_methods:
        print("Testing Hardware Constellation consistency...")
        
        constellation_results = []
        for i in range(3):
            try:
                result = fingerprinter.generate_fingerprint(FingerprintMethod.CONSTELLATION)
                constellation_results.append(result)
                print(f"  Run {i+1}: {result.fingerprint} (confidence: {result.confidence:.2f})")
            except Exception as e:
                print(f"  Run {i+1}: Failed - {e}")
        
        # Compare consecutive runs
        if len(constellation_results) >= 2:
            for i in range(len(constellation_results) - 1):
                try:
                    is_match, similarity, details = fingerprinter.verify_advanced_fingerprint(constellation_results[i])
                    print(f"  Similarity Run {i+1} vs Current: {similarity:.3f}")
                except Exception as e:
                    print(f"  Comparison {i+1} failed: {e}")
        
        print()
    
    # Test behavioral method consistency
    if FingerprintMethod.BEHAVIORAL in fingerprinter.supported_methods:
        print("Testing Behavioral Fingerprint consistency...")
        
        behavioral_results = []
        for i in range(2):  # Fewer runs as behavioral takes longer
            try:
                result = fingerprinter.generate_fingerprint(FingerprintMethod.BEHAVIORAL)
                behavioral_results.append(result)
                print(f"  Run {i+1}: {result.fingerprint} (confidence: {result.confidence:.2f})")
            except Exception as e:
                print(f"  Run {i+1}: Failed - {e}")
        
        print()

def generate_comprehensive_report():
    """Generate a comprehensive fingerprinting report"""
    print("📊 Comprehensive Device Fingerprinting Report")
    print("=" * 60)
    
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Generate all possible fingerprints
    all_results = {}
    
    for method in fingerprinter.supported_methods:
        try:
            result = fingerprinter.generate_fingerprint(method)
            all_results[method.value] = {
                'fingerprint': result.fingerprint,
                'confidence': result.confidence,
                'components': len(result.components),
                'warnings': len(result.warnings),
                'similarity_threshold': getattr(result, 'similarity_threshold', 'N/A')
            }
        except Exception as e:
            all_results[method.value] = {'error': str(e)}
    
    # Create summary report
    report = {
        'timestamp': time.time(),
        'methods_available': len(fingerprinter.supported_methods),
        'successful_methods': len([r for r in all_results.values() if 'error' not in r]),
        'average_confidence': sum(r.get('confidence', 0) for r in all_results.values() if 'confidence' in r) / max(1, len([r for r in all_results.values() if 'confidence' in r])),
        'method_results': all_results
    }
    
    print(json.dumps(report, indent=2))
    
    return report

def main():
    """Run all demonstrations"""
    print("🎉 Welcome to Advanced Device Fingerprinting!")
    print("This demonstration showcases novel approaches that go beyond traditional fingerprinting.")
    print()
    
    # Basic demonstration
    results = demonstrate_advanced_fingerprinting()
    
    # Verification demonstration  
    demonstrate_advanced_verification(results)
    
    # Robustness testing
    demonstrate_similarity_robustness()
    
    # Comprehensive report
    generate_comprehensive_report()
    
    print("🎊 Advanced fingerprinting demonstration complete!")
    print("\nKey innovations demonstrated:")
    print("✨ Hardware Constellation - Robust to minor changes")
    print("✨ Behavioral Timing - Extremely difficult to spoof") 
    print("✨ Similarity Matching - Probabilistic verification")
    print("✨ Hybrid Approach - Maximum security and robustness")

if __name__ == "__main__":
    main()
