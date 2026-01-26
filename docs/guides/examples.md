---
layout: default
title: Usage Examples
---

# Usage Examples

Practical examples demonstrating common use cases for the Device Fingerprinting Library.

## Example 1: Basic Device Fingerprinting

Generate a unique identifier for a device:

```python
from device_fingerprinting import DeviceFingerprintGenerator

def get_device_id():
    """Generate a unique device fingerprint."""
    generator = DeviceFingerprintGenerator()
    fingerprint = generator.generate_device_fingerprint()
    return fingerprint

# Usage
device_id = get_device_id()
print(f"Your device ID: {device_id}")
```

**Key Points**:
- Fingerprint is deterministic (same result every time)
- Works without network connectivity
- Fast execution (~50ms)
- Cross-platform compatible

---

## Example 2: Verifying Device Consistency

Ensure a device hasn't been tampered with:

```python
from device_fingerprinting import DeviceFingerprintGenerator

def verify_device_consistency(stored_fingerprint):
    """
    Verify that the current device matches a stored fingerprint.
    
    Returns:
        bool: True if device matches, False otherwise
    """
    generator = DeviceFingerprintGenerator()
    current_fingerprint = generator.generate_device_fingerprint()
    
    if current_fingerprint == stored_fingerprint:
        return True
    else:
        return False

# Usage
stored_fp = "device_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
if verify_device_consistency(stored_fp):
    print("Device verified - no tampering detected")
else:
    print("WARNING: Device does not match stored fingerprint")
```

**Use Cases**:
- Software license verification
- Security checkpoint validation
- Device integrity checks

---

## Example 3: Secure Storage of Sensitive Data

Store and retrieve encrypted data tied to a device:

```python
from device_fingerprinting import ProductionFingerprintGenerator

def secure_store_api_key(api_key, key_name="default"):
    """Securely store an API key."""
    generator = ProductionFingerprintGenerator()
    
    # Encrypt and store
    generator.store_fingerprint(
        key=f"api_key_{key_name}",
        value=api_key
    )
    print(f"API key stored securely as '{key_name}'")

def secure_retrieve_api_key(key_name="default"):
    """Retrieve a stored API key."""
    generator = ProductionFingerprintGenerator()
    
    try:
        api_key = generator.retrieve_fingerprint(f"api_key_{key_name}")
        return api_key
    except KeyError:
        print(f"No API key found for '{key_name}'")
        return None

# Usage
secure_store_api_key("sk-project-abc123xyz789")
api_key = secure_retrieve_api_key()
print(f"Retrieved API key: {api_key[:10]}...")
```

**Security Features**:
- AES-256-GCM encryption
- OS keyring integration
- Scrypt key derivation
- Tampering detection

---

## Example 4: Anomaly Detection

Monitor system behavior for suspicious activity:

```python
from device_fingerprinting import ProductionFingerprintGenerator
import time

def monitor_system_health(duration_seconds=300, check_interval=30):
    """
    Monitor system for anomalous behavior.
    
    Args:
        duration_seconds: How long to monitor
        check_interval: Check interval in seconds
    """
    generator = ProductionFingerprintGenerator()
    anomalies_detected = 0
    checks_performed = 0
    
    print(f"Monitoring system for {duration_seconds} seconds...\n")
    
    start_time = time.time()
    while time.time() - start_time < duration_seconds:
        # Get current system metrics
        metrics = generator.get_system_metrics()
        
        # Check for anomalies
        is_anomalous, confidence = generator.detect_anomaly(metrics)
        checks_performed += 1
        
        # Report results
        status = "ANOMALY" if is_anomalous else "NORMAL"
        print(f"[{checks_performed}] Status: {status} "
              f"(Confidence: {confidence:.2%})")
        
        if is_anomalous:
            anomalies_detected += 1
            # In production, take action here
            # - Log event
            # - Alert security team
            # - Disconnect user
            # - Restrict operations
        
        time.sleep(check_interval)
    
    print(f"\n=== Summary ===")
    print(f"Total checks: {checks_performed}")
    print(f"Anomalies detected: {anomalies_detected}")
    print(f"Anomaly rate: {anomalies_detected/checks_performed:.2%}")

# Usage
monitor_system_health(duration_seconds=60, check_interval=10)
```

**Detection Metrics**:
- CPU usage patterns
- Memory consumption
- Disk I/O activity
- Network statistics
- Process behavior

---

## Example 5: Software Licensing

Implement device-bound licensing:

```python
from device_fingerprinting import ProductionFingerprintGenerator
from datetime import datetime, timedelta

class SoftwareLicense:
    def __init__(self):
        self.generator = ProductionFingerprintGenerator()
    
    def create_license(self, product_name, license_type, duration_days=365):
        """
        Create a device-bound license.
        
        Args:
            product_name: Name of the licensed product
            license_type: Type of license (basic, professional, enterprise)
            duration_days: License validity in days
        
        Returns:
            str: License key bound to this device
        """
        fingerprint = self.generator.generate_device_fingerprint()
        expiry_date = datetime.now() + timedelta(days=duration_days)
        
        license_data = {
            "product": product_name,
            "type": license_type,
            "device_fingerprint": fingerprint,
            "created": datetime.now().isoformat(),
            "expires": expiry_date.isoformat()
        }
        
        # Store license securely
        license_key = f"license_{product_name}_{license_type}"
        self.generator.store_fingerprint(license_key, str(license_data))
        
        return license_key
    
    def verify_license(self, product_name, license_type):
        """
        Verify that a license is valid on this device.
        
        Returns:
            tuple: (is_valid, reason)
        """
        try:
            # Retrieve license
            license_key = f"license_{product_name}_{license_type}"
            license_data = self.generator.retrieve_fingerprint(license_key)
            
            # Verify device fingerprint matches
            current_fp = self.generator.generate_device_fingerprint()
            license_dict = eval(license_data)
            
            if license_dict["device_fingerprint"] != current_fp:
                return False, "Device fingerprint does not match"
            
            # Verify expiry date
            expiry = datetime.fromisoformat(license_dict["expires"])
            if datetime.now() > expiry:
                return False, "License has expired"
            
            return True, "License is valid"
        
        except Exception as e:
            return False, f"License verification failed: {str(e)}"

# Usage
license = SoftwareLicense()

# Create license
print("Creating license...")
license_key = license.create_license(
    product_name="MyApp",
    license_type="professional",
    duration_days=365
)

# Verify license
print("Verifying license...")
is_valid, reason = license.verify_license("MyApp", "professional")
print(f"License valid: {is_valid} ({reason})")
```

---

## Example 6: Multi-Device Account Management

Manage trusted devices for a user account:

```python
from device_fingerprinting import DeviceFingerprintGenerator
import json
from datetime import datetime

class UserDeviceManager:
    def __init__(self, user_id):
        self.user_id = user_id
        self.generator = DeviceFingerprintGenerator()
        self.storage_key = f"user_{user_id}_devices"
    
    def register_device(self, device_name):
        """Register current device as trusted."""
        fingerprint = self.generator.generate_device_fingerprint()
        
        # Load existing devices
        try:
            devices_json = self.generator.retrieve_fingerprint(self.storage_key)
            devices = json.loads(devices_json)
        except:
            devices = {}
        
        # Add new device
        devices[device_name] = {
            "fingerprint": fingerprint,
            "registered": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat()
        }
        
        # Store updated list
        self.generator.store_fingerprint(
            self.storage_key,
            json.dumps(devices)
        )
        
        print(f"Device '{device_name}' registered")
        return fingerprint
    
    def verify_device(self, device_name=None):
        """Check if current device is registered."""
        current_fp = self.generator.generate_device_fingerprint()
        
        try:
            devices_json = self.generator.retrieve_fingerprint(self.storage_key)
            devices = json.loads(devices_json)
        except:
            return False, "No registered devices found"
        
        # Check all registered devices
        for name, data in devices.items():
            if data["fingerprint"] == current_fp:
                # Update last used
                data["last_used"] = datetime.now().isoformat()
                self.generator.store_fingerprint(
                    self.storage_key,
                    json.dumps(devices)
                )
                return True, f"Recognized as '{name}'"
        
        return False, "Device not registered"
    
    def list_devices(self):
        """List all registered devices for this user."""
        try:
            devices_json = self.generator.retrieve_fingerprint(self.storage_key)
            devices = json.loads(devices_json)
            return devices
        except:
            return {}
    
    def remove_device(self, device_name):
        """Unregister a device."""
        try:
            devices_json = self.generator.retrieve_fingerprint(self.storage_key)
            devices = json.loads(devices_json)
            
            if device_name in devices:
                del devices[device_name]
                self.generator.store_fingerprint(
                    self.storage_key,
                    json.dumps(devices)
                )
                print(f"Device '{device_name}' removed")
                return True
        except:
            pass
        
        return False

# Usage
manager = UserDeviceManager("user@example.com")

# Register current device
print("Registering device...")
manager.register_device("work_laptop")

# Verify device
is_registered, message = manager.verify_device()
print(f"Device verification: {is_registered} - {message}")

# List all devices
devices = manager.list_devices()
print(f"Registered devices: {json.dumps(devices, indent=2)}")
```

---

## Example 7: Risk Assessment

Assess login risk based on device history:

```python
from device_fingerprinting import ProductionFingerprintGenerator
from datetime import datetime, timedelta

class LoginRiskAssessment:
    def __init__(self):
        self.generator = ProductionFingerprintGenerator()
    
    def assess_login_risk(self, user_id, known_devices):
        """
        Assess risk level of a login attempt.
        
        Args:
            user_id: User identifier
            known_devices: List of known device fingerprints
        
        Returns:
            dict: Risk assessment results
        """
        current_fp = self.generator.generate_device_fingerprint()
        metrics = self.generator.get_system_metrics()
        is_anomalous, anomaly_confidence = self.generator.detect_anomaly(metrics)
        
        risk_score = 0.0
        risk_factors = []
        
        # Factor 1: Unknown device
        if current_fp not in known_devices:
            risk_score += 0.4
            risk_factors.append("Unknown device")
        
        # Factor 2: System anomalies
        if is_anomalous:
            risk_score += 0.3 * anomaly_confidence
            risk_factors.append(f"System anomaly detected ({anomaly_confidence:.2%})")
        
        # Factor 3: Unusual time/location could be added
        # (requires additional context)
        
        # Clamp risk score to 0-1
        risk_score = min(1.0, risk_score)
        
        # Determine risk level
        if risk_score < 0.3:
            risk_level = "LOW"
            action = "Allow login"
        elif risk_score < 0.6:
            risk_level = "MEDIUM"
            action = "Request additional verification"
        elif risk_score < 0.8:
            risk_level = "HIGH"
            action = "Require strong authentication"
        else:
            risk_level = "CRITICAL"
            action = "Block login, investigate"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommended_action": action,
            "timestamp": datetime.now().isoformat()
        }

# Usage
assessment = LoginRiskAssessment()
known_devices = [
    "device_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "device_f6g7h8i9j0k1l2m3n4o5p6a1b2c3d4e5"
]

risk = assessment.assess_login_risk("user@example.com", known_devices)
print(f"Login Risk Assessment:")
print(f"  Risk Level: {risk['risk_level']}")
print(f"  Risk Score: {risk['risk_score']:.2%}")
print(f"  Factors: {', '.join(risk['risk_factors'])}")
print(f"  Action: {risk['recommended_action']}")
```

---

## Example 8: Advanced - Custom Fingerprint Method

Create a specialized fingerprinting method for specific needs:

```python
from device_fingerprinting import AdvancedDeviceFingerprinter, FingerprintMethod

def create_container_fingerprint():
    """
    Generate fingerprints for containerized environments.
    Useful for Docker, Kubernetes, and cloud deployments.
    """
    fingerprinter = AdvancedDeviceFingerprinter()
    
    # Generate multiple method results
    results = {}
    
    for method in [FingerprintMethod.BASIC, FingerprintMethod.ADVANCED]:
        result = fingerprinter.generate_fingerprint(method)
        results[method.value] = {
            "fingerprint": result.fingerprint,
            "confidence": result.confidence,
            "components": result.components[:5]  # First 5 components
        }
    
    return results

# Usage
container_fingerprints = create_container_fingerprint()
for method, data in container_fingerprints.items():
    print(f"\n{method} Method:")
    print(f"  Confidence: {data['confidence']:.2%}")
    print(f"  Components: {len(data['components'])} detected")
```

---

## Example 9: Batch Processing

Process multiple devices efficiently:

```python
from device_fingerprinting import DeviceFingerprintGenerator
from concurrent.futures import ThreadPoolExecutor
import time

def process_device_list(device_list):
    """
    Generate fingerprints for multiple devices.
    Demonstrates batch processing and threading.
    """
    def get_device_info(device_id):
        """Get fingerprint for a single device."""
        generator = DeviceFingerprintGenerator()
        fingerprint = generator.generate_device_fingerprint()
        return {
            "device_id": device_id,
            "fingerprint": fingerprint,
            "timestamp": time.time()
        }
    
    # Process with thread pool for efficiency
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(get_device_info, d) for d in device_list]
        
        for future in futures:
            results.append(future.result())
    
    return results

# Usage
devices = [f"device_{i}" for i in range(10)]
fingerprints = process_device_list(devices)

print(f"Processed {len(fingerprints)} devices")
for fp in fingerprints[:3]:
    print(f"  {fp['device_id']}: {fp['fingerprint'][:16]}...")
```

---

## Example 10: Integration with Web Framework

Integrate with a Flask web application:

```python
from flask import Flask, request, jsonify
from device_fingerprinting import ProductionFingerprintGenerator
from functools import wraps

app = Flask(__name__)
generator = ProductionFingerprintGenerator()

def require_device_verification(f):
    """Decorator to require device verification."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get device fingerprint from request
        device_fp = request.headers.get('X-Device-Fingerprint')
        
        if not device_fp:
            return jsonify({"error": "Missing device fingerprint"}), 400
        
        # Verify device
        current_fp = generator.generate_device_fingerprint()
        if device_fp != current_fp:
            return jsonify({"error": "Device verification failed"}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/register-device', methods=['POST'])
def register_device():
    """Register a device."""
    fingerprint = generator.generate_device_fingerprint()
    
    # Store device fingerprint
    device_name = request.json.get('device_name', 'unknown')
    generator.store_fingerprint(f"device_{device_name}", fingerprint)
    
    return jsonify({
        "device_fingerprint": fingerprint,
        "device_name": device_name
    })

@app.route('/api/protected', methods=['GET'])
@require_device_verification
def protected_endpoint():
    """Protected endpoint requiring device verification."""
    return jsonify({
        "message": "Access granted",
        "data": "Sensitive information"
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check system health and detect anomalies."""
    metrics = generator.get_system_metrics()
    is_anomalous, confidence = generator.detect_anomaly(metrics)
    
    return jsonify({
        "status": "healthy" if not is_anomalous else "anomaly_detected",
        "anomaly_confidence": confidence
    })

# Run app
if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc')
```

---

## Summary

These examples demonstrate:

1. **Basic Operations**: Generating and verifying fingerprints
2. **Security**: Secure storage and encryption
3. **Monitoring**: Anomaly detection and system health
4. **Integration**: Real-world application scenarios
5. **Best Practices**: Error handling and efficiency

For more detailed API documentation, see the [API Reference](../api/reference.md).
