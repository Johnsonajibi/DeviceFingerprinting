"""
Enterprise Usage Examples for DeviceFingerprint Library v2.0

This file demonstrates advanced enterprise features including:
- Performance optimization with caching
- Security monitoring and alerts
- Hardware change detection
- Enterprise system integration
- Machine learning device classification
- Compliance reporting
"""

import json
import time
from datetime import datetime, timedelta

# Core fingerprinting
from devicefingerprint import (
    AdvancedDeviceFingerprinter,
    FingerprintMethod
)

# Performance enhancements
from devicefingerprint.performance_enhancements import (
    FingerprintCache,
    AsyncDeviceFingerprinter,
    BenchmarkProfiler
)

# Security monitoring
from devicefingerprint.security_monitoring import (
    SecurityMonitor,
    SecurityAlert,
    TamperDetector
)

# Hardware monitoring
from devicefingerprint.hardware_monitoring import (
    HardwareChangeDetector,
    ChangeType
)

# Enterprise integration
from devicefingerprint.enterprise_integration import (
    EnterpriseIntegrator,
    IntegrationType,
    IntegrationConfig,
    FingerprintEvent,
    ComplianceReporter
)

# Machine learning
from devicefingerprint.machine_learning import (
    IntelligentFingerprintManager,
    DeviceClassifier,
    AnomalyDetector
)

def example_1_performance_optimization():
    """Example 1: Performance optimization with caching and profiling"""
    print("=" * 60)
    print("Example 1: Performance Optimization")
    print("=" * 60)
    
    # Initialize components
    fingerprinter = AdvancedDeviceFingerprinter()
    cache = FingerprintCache(max_age_seconds=300)  # 5-minute cache
    profiler = BenchmarkProfiler()
    
    # Benchmark different methods
    methods_to_test = [
        FingerprintMethod.BASIC,
        FingerprintMethod.ADVANCED,
        FingerprintMethod.QUANTUM_RESISTANT
    ]
    
    for method in methods_to_test:
        print(f"\nTesting {method.value} method:")
        
        # Profile the method
        with profiler.profile_method(method):
            result = fingerprinter.generate_fingerprint(method)
        
        # Cache the result
        cache_key = f"device_001_{method.value}"
        cache.put(cache_key, result.fingerprint)
        
        print(f"  Fingerprint: {result.fingerprint[:32]}...")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Cached: {cache.get(cache_key) is not None}")
    
    # Display performance summary
    print(f"\nPerformance Summary:")
    summary = profiler.get_summary()
    for method, stats in summary.items():
        print(f"  {method}: {stats['average_time']:.3f}s avg, {stats['total_calls']} calls")

def example_2_security_monitoring():
    """Example 2: Security monitoring and threat detection"""
    print("=" * 60)
    print("Example 2: Security Monitoring")
    print("=" * 60)
    
    # Security alert callback
    def security_alert_handler(event):
        print(f"🚨 SECURITY ALERT: {event.alert_type.value}")
        print(f"   Device: {event.device_id}")
        print(f"   Risk Level: {event.risk_level}")
        print(f"   Confidence: {event.confidence_score:.2f}")
        print(f"   Timestamp: {event.timestamp}")
        print()
    
    # Initialize security monitor
    monitor = SecurityMonitor(alert_callback=security_alert_handler)
    tamper_detector = TamperDetector()
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Simulate device monitoring
    device_id = "enterprise_workstation_001"
    
    # Initial fingerprint registration
    result1 = fingerprinter.generate_fingerprint(FingerprintMethod.ADVANCED)
    monitor.register_fingerprint(
        device_id=device_id,
        fingerprint=result1.fingerprint,
        components=result1.detected_components,
        confidence=result1.confidence
    )
    print(f"Initial fingerprint registered for {device_id}")
    
    # Simulate time passage and hardware change
    time.sleep(1)
    
    # Simulate changed fingerprint (hardware modification)
    result2 = fingerprinter.generate_fingerprint(FingerprintMethod.ADVANCED)
    # Artificially modify fingerprint to simulate hardware change
    modified_fingerprint = result2.fingerprint[:-4] + "ABCD"
    
    monitor.register_fingerprint(
        device_id=device_id,
        fingerprint=modified_fingerprint,
        components=result2.detected_components,
        confidence=result2.confidence * 0.8  # Lower confidence due to change
    )
    
    # Get device risk profile
    risk_profile = monitor.get_device_risk_profile(device_id)
    print(f"Device Risk Profile:")
    print(f"  Status: {risk_profile['status']}")
    print(f"  Risk Score: {risk_profile['risk_score']:.2f}")
    print(f"  Change Frequency: {risk_profile['change_frequency']:.4f}")
    print(f"  Total Changes: {risk_profile['total_changes']}")

def example_3_hardware_change_detection():
    """Example 3: Hardware change detection and analysis"""
    print("=" * 60)
    print("Example 3: Hardware Change Detection")
    print("=" * 60)
    
    # Initialize change detector
    change_detector = HardwareChangeDetector()
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Get current hardware info
    result = fingerprinter.generate_fingerprint(FingerprintMethod.ADVANCED)
    
    # Simulate baseline registration
    baseline_components = {
        'cpu': 'Intel Core i7-11700K @ 3.60GHz',
        'memory': '32GB DDR4-3200',
        'storage': 'Samsung 980 PRO 1TB NVMe SSD',
        'platform': 'Windows-10-10.0.19043-SP0',
        'network': '00:1B:63:84:45:E6'
    }
    
    change_detector.register_baseline(baseline_components)
    print("Hardware baseline registered")
    
    # Simulate hardware changes
    modified_components = baseline_components.copy()
    modified_components['memory'] = '64GB DDR4-3200'  # Memory upgrade
    modified_components['storage'] = 'Samsung 980 PRO 2TB NVMe SSD'  # Storage upgrade
    
    # Detect changes
    changes = change_detector.detect_changes(modified_components)
    
    print(f"\nDetected {len(changes)} hardware changes:")
    for change in changes:
        print(f"  Change Type: {change.change_type.value}")
        print(f"  Component: {change.component_name}")
        print(f"  Old Value: {change.old_value}")
        print(f"  New Value: {change.new_value}")
        print(f"  Impact Level: {change.impact_level}")
        print(f"  Confidence: {change.detection_confidence:.2f}")
        print(f"  Context: {change.additional_context}")
        print()
    
    # Get change summary
    summary = change_detector.get_change_summary("workstation_001")
    print(f"Change Summary:")
    print(f"  Stability Score: {summary['stability_score']:.2f}")
    print(f"  Components Tracked: {summary['total_components_tracked']}")
    print(f"  Components Changed: {summary['components_with_changes']}")

def example_4_enterprise_integration():
    """Example 4: Enterprise system integration"""
    print("=" * 60)
    print("Example 4: Enterprise Integration")
    print("=" * 60)
    
    # Create sample integration configurations
    integrations = {
        "splunk_siem": IntegrationConfig(
            integration_type=IntegrationType.SIEM,
            endpoint_url="https://splunk.company.com:8088",
            api_key="sample-hec-token-12345",
            batch_size=50,
            enabled=False  # Disabled for demo
        ),
        "azure_ad": IntegrationConfig(
            integration_type=IntegrationType.IDENTITY_PROVIDER,
            endpoint_url="https://graph.microsoft.com",
            api_key="sample-azure-token-67890",
            custom_headers={"Content-Type": "application/json"},
            enabled=False  # Disabled for demo
        ),
        "asset_mgmt": IntegrationConfig(
            integration_type=IntegrationType.ASSET_MANAGEMENT,
            endpoint_url="https://cmdb.company.com/api",
            api_key="sample-cmdb-key-abcdef",
            secret_key="sample-secret-key",
            enabled=False  # Disabled for demo
        )
    }
    
    # Initialize enterprise integrator
    integrator = EnterpriseIntegrator()
    
    # Add integrations
    for name, config in integrations.items():
        integrator.add_integration(name, config)
        print(f"Added integration: {name} ({config.integration_type.value})")
    
    # Create sample fingerprint event
    fingerprint_event = FingerprintEvent(
        event_id="evt_001",
        device_id="enterprise_laptop_042",
        fingerprint="a1b2c3d4e5f6789012345678901234567890abcd",
        event_type="new_device",
        timestamp=datetime.utcnow(),
        user_context={"user_id": "john.doe", "department": "engineering"},
        risk_score=0.2,
        metadata={"location": "headquarters", "asset_tag": "LT-042"}
    )
    
    # Send event to integrations (would normally send HTTP requests)
    print(f"\nSending fingerprint event to enterprise systems:")
    print(f"  Event ID: {fingerprint_event.event_id}")
    print(f"  Device ID: {fingerprint_event.device_id}")
    print(f"  Event Type: {fingerprint_event.event_type}")
    print(f"  Risk Score: {fingerprint_event.risk_score}")
    print(f"  User Context: {fingerprint_event.user_context}")
    
    # Note: Actual sending is disabled for demo (enabled=False)
    # integrator.send_fingerprint_event(fingerprint_event)
    
    # Generate compliance report
    compliance_reporter = ComplianceReporter(integrator)
    
    # GDPR compliance report
    gdpr_report = compliance_reporter.generate_gdpr_report(
        device_id="enterprise_laptop_042",
        date_range=(datetime.utcnow() - timedelta(days=30), datetime.utcnow())
    )
    
    print(f"\nGDPR Compliance Report Generated:")
    print(f"  Device ID: {gdpr_report['device_id']}")
    print(f"  Reporting Period: {gdpr_report['reporting_period']['start'][:10]} to {gdpr_report['reporting_period']['end'][:10]}")
    print(f"  Data Processing Lawfulness: {gdpr_report['data_processing_lawfulness']}")
    print(f"  Security Measures: {len(gdpr_report['security_measures'])} implemented")

def example_5_machine_learning_analysis():
    """Example 5: Machine learning device analysis"""
    print("=" * 60)
    print("Example 5: Machine Learning Analysis")
    print("=" * 60)
    
    # Initialize ML components
    ml_manager = IntelligentFingerprintManager()
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Generate fingerprint for analysis
    result = fingerprinter.generate_fingerprint(FingerprintMethod.ADVANCED)
    
    # Create sample fingerprint data for ML analysis
    fingerprint_data = {
        'cpu': 'Intel Core i7-11700K @ 3.60GHz 8-Core',
        'memory': '32GB DDR4-3200',
        'platform': 'Windows-10-x86_64',
        'network': '00:1B:63:84:45:E6',
        'storage': 'NVMe SSD 1TB',
        'graphics': 'NVIDIA GeForce RTX 3070'
    }
    
    # Create sample history for baseline establishment
    fingerprint_history = [
        fingerprint_data,
        {**fingerprint_data, 'memory': '32GB DDR4-3200'},  # Slight variation
        {**fingerprint_data, 'storage': 'NVMe SSD 1TB Samsung'},  # Minor change
    ]
    
    # Perform comprehensive ML analysis
    device_id = "ml_analysis_device_001"
    analysis = ml_manager.analyze_device(
        device_id=device_id,
        fingerprint_data=fingerprint_data,
        fingerprint_history=fingerprint_history
    )
    
    print(f"ML Analysis Results for {device_id}:")
    print(f"  Device Class: {analysis['device_class']} (confidence: {analysis['classification_confidence']:.2f})")
    print(f"  Intelligence Score: {analysis['intelligence_score']:.2f}")
    print(f"  Anomalies Detected: {len(analysis['anomalies'])}")
    
    # Display anomalies
    if analysis['anomalies']:
        print(f"\n  Detected Anomalies:")
        for anomaly in analysis['anomalies']:
            print(f"    - {anomaly['anomaly_type']}: {anomaly['description']}")
            print(f"      Severity: {anomaly['severity']:.2f}, Confidence: {anomaly['confidence']:.2f}")
    
    # Display recommendations
    print(f"\n  Recommendations:")
    for rec in analysis['recommendations']:
        print(f"    - {rec}")
    
    # Risk assessment
    risk = analysis['risk_assessment']
    print(f"\n  Risk Assessment:")
    print(f"    Level: {risk['risk_level']} (score: {risk['risk_score']:.2f})")
    print(f"    Confidence Factor: {risk['confidence_factor']:.2f}")
    
    # Test device classification separately
    print(f"\nDevice Classification Examples:")
    
    test_devices = [
        {'cpu': 'Intel Xeon E5-2670 @ 2.60GHz 16-Core', 'memory': '128GB DDR4', 'platform': 'Linux-x86_64'},
        {'cpu': 'Apple M1 Pro 8-Core', 'memory': '16GB LPDDR5', 'platform': 'Darwin-arm64'},
        {'cpu': 'AMD Ryzen 5 5600X @ 3.70GHz 6-Core', 'memory': '16GB DDR4', 'platform': 'Windows-10-x86_64'},
        {'cpu': 'Virtual CPU @ 2.40GHz 2-Core', 'memory': '4GB', 'platform': 'Linux-x86_64', 'network': '52:54:00:12:34:56'}
    ]
    
    classifier = DeviceClassifier()
    
    for i, device_data in enumerate(test_devices):
        device_class, confidence = classifier.classify_device(device_data)
        print(f"  Device {i+1}: {device_class.value} (confidence: {confidence:.2f})")

def example_6_async_performance():
    """Example 6: Asynchronous fingerprinting for high-performance scenarios"""
    print("=" * 60)
    print("Example 6: Async Performance")
    print("=" * 60)
    
    import asyncio
    
    async def async_fingerprinting_demo():
        # Initialize async fingerprinter
        async_fingerprinter = AsyncDeviceFingerprinter()
        
        # Generate multiple fingerprints concurrently
        tasks = []
        methods = [FingerprintMethod.BASIC, FingerprintMethod.ADVANCED, FingerprintMethod.QUANTUM_RESISTANT]
        
        start_time = time.time()
        
        # Create async tasks
        for i, method in enumerate(methods):
            task = async_fingerprinter.generate_fingerprint_async(method)
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        
        print(f"Generated {len(results)} fingerprints concurrently in {end_time - start_time:.3f} seconds")
        
        for i, result in enumerate(results):
            print(f"  Method {methods[i].value}: {result.fingerprint[:32]}... (confidence: {result.confidence:.2f})")
    
    # Run async demo
    try:
        asyncio.run(async_fingerprinting_demo())
    except Exception as e:
        print(f"Async demo requires proper async environment: {e}")
        print("Async fingerprinting is available for integration into async applications")

def main():
    """Run all enterprise examples"""
    print("DeviceFingerprint Library v2.0 - Enterprise Examples")
    print("=" * 60)
    print("Demonstrating advanced enterprise features...")
    print()
    
    try:
        example_1_performance_optimization()
        print("\n")
        
        example_2_security_monitoring()
        print("\n")
        
        example_3_hardware_change_detection()
        print("\n")
        
        example_4_enterprise_integration()
        print("\n")
        
        example_5_machine_learning_analysis()
        print("\n")
        
        example_6_async_performance()
        print("\n")
        
        print("=" * 60)
        print("All enterprise examples completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error running examples: {e}")
        print("Note: Some features may require additional dependencies or configurations")

if __name__ == "__main__":
    main()
