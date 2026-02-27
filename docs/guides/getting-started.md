---
layout: default
title: Getting Started
---

# Getting Started with Device Fingerprinting

This guide introduces the fundamental concepts and helps you get up and running with the Device Fingerprinting Library.

## What is Device Fingerprinting?

Device fingerprinting is the process of generating a unique identifier for a computing device based on its hardware and software characteristics. Unlike traditional identifiers such as IP addresses or cookies, device fingerprints are:

- **Persistent**: Remain stable across reboots and system updates
- **Unique**: Extremely difficult to forge or duplicate
- **Hardware-based**: Derived from immutable hardware properties
- **Cross-platform**: Consistent across different operating systems

## Key Concepts

### 1. Fingerprint Generation

The library collects information from various hardware components and system settings to create a fingerprint:

```
Hardware Collection
    ├── CPU Information
    ├── Disk Serial Numbers
    ├── MAC Addresses
    ├── BIOS/UEFI Details
    └── System Board Information
         │
         ▼
    Processing & Hashing
    ├── Normalize data
    ├── Apply cryptographic hash
    └── Validate consistency
         │
         ▼
    Fingerprint Result
    └── Unique device identifier
```

### 2. Cryptographic Protection

All data is protected using modern cryptography:

**Encryption at Rest**: Sensitive data stored on disk is encrypted using AES-256-GCM
```
Plaintext → AES-256-GCM → Ciphertext (stored)
```

**Key Derivation**: Passwords are converted to cryptographic keys using Scrypt
```
Password → Scrypt(N=32768) → Encryption Key
```

### 3. Anomaly Detection

The library continuously monitors system behavior and identifies unusual patterns:

```
System Metrics Collection
    ├── CPU usage
    ├── Memory consumption
    ├── Disk I/O patterns
    ├── Network statistics
    └── Process information
         │
         ▼
    Machine Learning Analysis
    └── Isolation Forest Algorithm
         │
         ▼
    Anomaly Score
    └── 0 = Normal, 1 = Anomaly
```

### 4. Secure Storage

Fingerprints and sensitive data are stored securely:

```
Application Data
    │
    ├─→ Encrypt with AES-256-GCM
    │
    ├─→ Derive key from password using Scrypt
    │
    ├─→ Store in OS keyring or encrypted file
    │
    └─→ Verify integrity on retrieval
```

## Installation

### Basic Installation

```bash
pip install device-fingerprinting-pro
```

### Platform-Specific Requirements

**Windows**:
```bash
pip install device-fingerprinting-pro
# Requires Windows 7+ with .NET Framework for full features
```

**macOS**:
```bash
pip install device-fingerprinting-pro
# Requires macOS 10.13+ for TPM features on Apple Silicon
```

**Linux**:
```bash
pip install device-fingerprinting-pro
# May require additional packages: python3-dev, build-essential
# For TPM support: libtss2-dev, libtpm2-pytss-dev
```

## Basic Usage

### Generating Your First Fingerprint

```python
from device_fingerprinting import DeviceFingerprintGenerator

# Create a generator instance
generator = DeviceFingerprintGenerator()

# Generate a device fingerprint
fingerprint = generator.generate()

# The fingerprint is a unique identifier for this device
print(f"Device fingerprint: {fingerprint}")
```

**Output**:
```
Device fingerprint: device_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Verifying Consistency

A key property of device fingerprints is that they remain stable:

```python
# Generate fingerprint multiple times
fp1 = generator.generate()
fp2 = generator.generate()
fp3 = generator.generate()

# All should be identical
assert fp1 == fp2 == fp3
print("Fingerprints are consistent!")
```

### Detecting Anomalies

```python
from device_fingerprinting import ProductionFingerprintGenerator

# Initialize production generator with anomaly detection
generator = ProductionFingerprintGenerator()

# Get current system metrics
metrics = generator.get_system_metrics()

# Check for anomalies
is_anomalous, confidence = generator.detect_anomaly(metrics)

if is_anomalous:
    print(f"Anomaly detected! Confidence: {confidence:.2%}")
else:
    print("System behavior is normal")
```

### Secure Storage

```python
# Generate and store a fingerprint securely
fingerprint = generator.generate()

# Store with encryption
generator.store_fingerprint("my_device", fingerprint)

# Retrieve and verify
retrieved = generator.retrieve_fingerprint("my_device")
assert retrieved == fingerprint
print("Fingerprint securely stored and retrieved!")
```

## Understanding Fingerprint Methods

The library supports multiple fingerprinting methods with different characteristics:

### Basic Method

- **Speed**: Very fast (<50ms)
- **Components**: 5-10 hardware identifiers
- **Stability**: Very stable
- **Security**: Good for most use cases

```python
from device_fingerprinting import FingerprintMethod

result = generator.generate_fingerprint(method=FingerprintMethod.BASIC)
print(f"Fingerprint: {result.fingerprint}")
print(f"Confidence: {result.confidence:.2%}")
```

### Advanced Method

- **Speed**: Moderate (50-150ms)
- **Components**: 20-30 hardware and system identifiers
- **Stability**: Highly stable
- **Security**: Enhanced security for sensitive applications

```python
result = generator.generate_fingerprint(method=FingerprintMethod.ADVANCED)
```

### Quantum-Resistant Method

- **Speed**: Slower (150-300ms)
- **Components**: 30+ identifiers with PQC
- **Stability**: Maximum stability
- **Security**: Protected against quantum computing threats

```python
result = generator.generate_fingerprint(method=FingerprintMethod.QUANTUM_RESISTANT)
```

## Common Patterns

### Pattern 1: Device Registration

Register a device for later verification:

```python
def register_device(user_id, device_name):
    generator = DeviceFingerprintGenerator()
    fingerprint = generator.generate()
    
    # Store with user context
    storage_key = f"user_{user_id}_device_{device_name}"
    generator.store_fingerprint(storage_key, fingerprint)
    
    return fingerprint

# Usage
device_id = register_device("user123", "work_laptop")
```

### Pattern 2: Device Verification

Verify that a request comes from a known device:

```python
def verify_device(user_id, device_name):
    generator = DeviceFingerprintGenerator()
    current_fingerprint = generator.generate()
    
    # Retrieve stored fingerprint
    storage_key = f"user_{user_id}_device_{device_name}"
    stored_fingerprint = generator.retrieve_fingerprint(storage_key)
    
    # Check if they match
    if current_fingerprint == stored_fingerprint:
        return True
    else:
        return False

# Usage
if verify_device("user123", "work_laptop"):
    print("Device recognized!")
else:
    print("Unknown device - require additional verification")
```

### Pattern 3: Continuous Monitoring

Monitor a device for suspicious behavior:

```python
import time

def monitor_device(check_interval_seconds=60):
    generator = ProductionFingerprintGenerator()
    
    while True:
        # Get current metrics
        metrics = generator.get_system_metrics()
        
        # Check for anomalies
        is_anomalous, confidence = generator.detect_anomaly(metrics)
        
        if is_anomalous:
            print(f"ALERT: Anomalous behavior detected ({confidence:.2%})")
            # Take action: log, alert, disconnect, etc.
        
        time.sleep(check_interval_seconds)

# Usage
monitor_device()
```

### Pattern 4: Device Binding

Create device-bound secrets that only work on the original device:

```python
def create_bound_secret(secret_data):
    generator = ProductionFingerprintGenerator()
    fingerprint = generator.generate()
    
    # Bind secret to device
    bound_token = generator.create_device_binding({
        "data": secret_data,
        "device_fingerprint": fingerprint
    })
    
    return bound_token

def verify_bound_secret(bound_token):
    generator = ProductionFingerprintGenerator()
    current_fingerprint = generator.generate()
    
    # Verify on the same device
    is_valid = generator.verify_device_binding(bound_token, current_fingerprint)
    
    return is_valid
```

## Configuration

### Basic Configuration

```python
from device_fingerprinting import DeviceFingerprintGenerator

# Create with default settings
generator = DeviceFingerprintGenerator()

# Or with custom settings
config = {
    "include_network": True,
    "include_system_uuid": True,
    "hash_algorithm": "sha3_256"
}
generator = DeviceFingerprintGenerator(**config)
```

### Advanced Configuration

```python
from device_fingerprinting import ProductionFingerprintGenerator

generator = ProductionFingerprintGenerator()

# Configure storage backend
generator.set_storage_backend("encrypted_filesystem")

# Configure anomaly detection sensitivity
generator.set_anomaly_threshold(0.7)  # 0.0-1.0, higher = less sensitive

# Configure TPM usage
generator.enable_tpm_features(enabled=True)
```

## Next Steps

Now that you understand the basics, explore more advanced topics:

1. **[Installation Guide](installation.md)**: Detailed setup for different platforms
2. **[Usage Examples](examples.md)**: Practical examples for common scenarios
3. **[API Reference](../api/reference.md)**: Complete API documentation
4. **[Security Architecture](security-architecture.md)**: How security is implemented
5. **[FAQ](faq.md)**: Common questions and answers

## Troubleshooting

### Issue: "TPM module not available"

This is normal on systems without TPM hardware. The library falls back to software-based fingerprinting.

```python
status = generator.get_tpm_status()
print(f"TPM available: {status.get('tpm_hardware_available', False)}")
```

### Issue: "Fingerprint changed between runs"

Fingerprints should be consistent. If they change:

1. Check for recent hardware changes
2. Ensure system wasn't in hibernation
3. Verify BIOS/firmware hasn't been updated

```python
# Debug: get detailed fingerprint components
result = generator.generate_fingerprint(include_debug_info=True)
print(f"Components: {result.components}")
```

### Issue: "Permission denied" when accessing TPM

Ensure your user has appropriate permissions:

```bash
# Linux: Add user to tpm group
sudo usermod -a -G tpm $USER

# Windows: Run as Administrator
```

## Additional Resources

- [API Reference](../api/reference.md)
- [Security Whitepaper](../assets/security-whitepaper.md)
- [GitHub Repository](https://github.com/yourusername/device-fingerprinting)
- [Issue Tracker](https://github.com/yourusername/device-fingerprinting/issues)
