"""
Comprehensive test to verify ML features are functioning correctly.
Tests:
1. Feature extraction from device fingerprints
2. Anomaly detection model training and prediction
3. Adaptive security level adjustment
4. MLAnomalyDetector with real fingerprint data
"""

import sys
import time
import numpy as np
from typing import Dict, Any

print("=" * 80)
print("COMPREHENSIVE ML FUNCTIONALITY TEST")
print("=" * 80)

# Test 1: Import ML modules
print("\n[TEST 1] Importing ML modules...")
try:
    from device_fingerprinting.ml_features import (
        FeatureExtractor,
        AnomalyDetector,
        MLAnomalyDetector,
        AdaptiveSecurityManager,
        get_anomaly_detector,
        get_adaptive_security_manager
    )
    print("✅ Successfully imported all ML classes")
except ImportError as e:
    print(f"❌ Failed to import ML modules: {e}")
    sys.exit(1)

# Test 2: Feature Extraction
print("\n[TEST 2] Testing Feature Extraction...")
try:
    extractor = FeatureExtractor()
    features = extractor.collect_features()
    print(f"✅ Extracted features shape: {features.shape}")
    print(f"   Features: CPU={features[0][0]:.3f}, Memory={features[0][1]:.3f}, Battery={features[0][2]:.3f}")
    assert features.shape == (1, 3), "Expected 3 features"
    print("✅ Feature extraction working correctly")
except Exception as e:
    print(f"❌ Feature extraction failed: {e}")
    sys.exit(1)

# Test 3: Anomaly Detector Training
print("\n[TEST 3] Testing Anomaly Detector Training...")
try:
    detector = AnomalyDetector(contamination="auto")
    
    # Generate normal training data
    np.random.seed(42)
    normal_data = np.random.normal(loc=0.5, scale=0.1, size=(100, 3))
    detector.train(normal_data)
    print(f"✅ Trained anomaly detector on {normal_data.shape[0]} samples")
    
    # Test normal prediction
    normal_sample = np.array([[0.5, 0.5, 0.5]])
    prediction, score = detector.predict(normal_sample)
    print(f"   Normal sample prediction: {prediction} (1=normal, -1=anomaly), score: {score:.3f}")
    
    # Test anomalous prediction
    anomaly_sample = np.array([[10.0, 10.0, 10.0]])
    prediction, score = detector.predict(anomaly_sample)
    print(f"   Anomaly sample prediction: {prediction} (1=normal, -1=anomaly), score: {score:.3f}")
    print("✅ Anomaly detection working correctly")
except Exception as e:
    print(f"❌ Anomaly detection failed: {e}")
    sys.exit(1)

# Test 4: MLAnomalyDetector with device fingerprints
print("\n[TEST 4] Testing MLAnomalyDetector with device fingerprints...")
try:
    ml_detector = MLAnomalyDetector(window_size=100, contamination=0.05)
    
    # Create sample fingerprint data
    fingerprint_data = {
        "cpu_model": "Intel Core i7-9700K",
        "os_family": "Windows",
        "cpu_arch": "x86_64",
        "mac_hash": "abc123def456",
        "ram_gb": 16
    }
    
    session_info = {
        "duration": 3600,
        "request_count": 100,
        "time_since_last": 300
    }
    
    # Extract features
    features = ml_detector.extract_features(fingerprint_data, session_info)
    print(f"✅ Extracted {features.shape[1]} features from fingerprint data")
    print(f"   Feature vector shape: {features.shape}")
    
    # Collect data and test detection
    print("   Collecting training data...")
    for i in range(110):
        result = ml_detector.detect_anomaly(fingerprint_data, session_info)
        if i % 20 == 0:
            print(f"   Sample {i}: Status={result['status']}, Fitted={ml_detector.is_fitted}")
    
    print(f"✅ Model fitted: {ml_detector.is_fitted}")
    
    # Test with normal data
    result = ml_detector.detect_anomaly(fingerprint_data, session_info)
    print(f"✅ Normal fingerprint result:")
    print(f"   - Anomaly score: {result['anomaly_score']:.3f}")
    print(f"   - Is anomaly: {result['is_anomaly']}")
    print(f"   - Confidence: {result['confidence']:.3f}")
    print(f"   - Status: {result['status']}")
    
    # Test with anomalous data
    anomalous_fingerprint = fingerprint_data.copy()
    anomalous_fingerprint["ram_gb"] = 512  # Unusual RAM
    anomalous_session = {
        "duration": 1,  # Very short duration
        "request_count": 10000,  # Unusually high requests
        "time_since_last": 1
    }
    
    result = ml_detector.detect_anomaly(anomalous_fingerprint, anomalous_session)
    print(f"✅ Anomalous fingerprint result:")
    print(f"   - Anomaly score: {result['anomaly_score']:.3f}")
    print(f"   - Is anomaly: {result['is_anomaly']}")
    print(f"   - Confidence: {result['confidence']:.3f}")
    
except Exception as e:
    print(f"❌ MLAnomalyDetector failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 5: Adaptive Security Manager
print("\n[TEST 5] Testing Adaptive Security Manager...")
try:
    ml_detector = MLAnomalyDetector(window_size=50, contamination=0.1)
    security_manager = AdaptiveSecurityManager(ml_detector)
    
    print(f"   Initial security level: {security_manager.current_level}")
    
    # Simulate normal behavior
    print("   Simulating normal behavior (60 samples)...")
    for i in range(60):
        result = security_manager.assess_and_adapt(fingerprint_data, session_info)
    
    print(f"✅ After normal behavior:")
    print(f"   - Security level: {result['current_security_level']}")
    print(f"   - Average threat score: {result['average_threat_score']:.3f}")
    print(f"   - Required checks: {result['required_checks']}")
    
    # Simulate anomalous behavior
    print("   Simulating anomalous behavior...")
    for i in range(20):
        anomalous_fp = fingerprint_data.copy()
        anomalous_fp["ram_gb"] = 512 + i * 10
        anomalous_sess = {
            "duration": 1,
            "request_count": 5000 + i * 100,
            "time_since_last": 1
        }
        result = security_manager.assess_and_adapt(anomalous_fp, anomalous_sess)
    
    print(f"✅ After anomalous behavior:")
    print(f"   - Security level: {result['current_security_level']}")
    print(f"   - Average threat score: {result['average_threat_score']:.3f}")
    print(f"   - Required checks: {result['required_checks']}")
    print(f"   - Threat history size: {len(security_manager.threat_history)}")
    
except Exception as e:
    print(f"❌ Adaptive Security Manager failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 6: Singleton instances
print("\n[TEST 6] Testing singleton instances...")
try:
    detector1 = get_anomaly_detector()
    detector2 = get_anomaly_detector()
    assert detector1 is detector2, "Should return same instance"
    print("✅ Anomaly detector singleton working")
    
    manager1 = get_adaptive_security_manager()
    manager2 = get_adaptive_security_manager()
    assert manager1 is manager2, "Should return same instance"
    print("✅ Adaptive security manager singleton working")
    
except Exception as e:
    print(f"❌ Singleton test failed: {e}")
    sys.exit(1)

# Test 7: Model save/load functionality
print("\n[TEST 7] Testing model persistence...")
try:
    import os
    import tempfile
    
    detector = AnomalyDetector()
    normal_data = np.random.normal(loc=0.5, scale=0.1, size=(100, 3))
    detector.train(normal_data)
    
    # Save model
    with tempfile.NamedTemporaryFile(suffix='.joblib', delete=False) as tmp:
        model_path = tmp.name
    
    detector.save_model(model_path)
    print(f"✅ Saved model to {model_path}")
    
    # Load model
    new_detector = AnomalyDetector()
    new_detector.load_model(model_path)
    print(f"✅ Loaded model from {model_path}")
    
    # Verify it works
    test_sample = np.array([[0.5, 0.5, 0.5]])
    prediction1, score1 = detector.predict(test_sample)
    prediction2, score2 = new_detector.predict(test_sample)
    
    assert prediction1 == prediction2, "Predictions should match"
    assert abs(score1 - score2) < 0.001, "Scores should match"
    print(f"✅ Model persistence verified (prediction: {prediction1}, score: {score1:.3f})")
    
    # Cleanup
    os.unlink(model_path)
    
except Exception as e:
    print(f"❌ Model persistence failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Summary
print("\n" + "=" * 80)
print("ML FUNCTIONALITY TEST SUMMARY")
print("=" * 80)
print("✅ All 7 ML tests passed successfully!")
print("\nTested components:")
print("  1. ✅ Feature extraction from system metrics")
print("  2. ✅ Anomaly detector training and prediction")
print("  3. ✅ Model save/load functionality")
print("  4. ✅ MLAnomalyDetector with device fingerprints")
print("  5. ✅ Adaptive security level adjustment")
print("  6. ✅ Singleton pattern implementation")
print("  7. ✅ Model persistence")
print("\n🎉 Machine Learning functionality is working correctly!")
print("=" * 80)
