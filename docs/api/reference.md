---
layout: default
title: API Reference
---

# API Reference

Complete documentation for the Device Fingerprinting Library API.

## Table of Contents

1. [Core Classes](#core-classes)
2. [Fingerprint Generation](#fingerprint-generation)
3. [Cryptography](#cryptography)
4. [Secure Storage](#secure-storage)
5. [Anomaly Detection](#anomaly-detection)
6. [TPM Integration](#tpm-integration)
7. [Utility Functions](#utility-functions)
8. [Data Types](#data-types)
9. [Exceptions](#exceptions)

---

## Core Classes

### DeviceFingerprintGenerator

Basic device fingerprint generator for simple use cases.

**Usage**:

```python
from device_fingerprinting import DeviceFingerprintGenerator

generator = DeviceFingerprintGenerator()
fingerprint = generator.generate_device_fingerprint()
```

**Methods**:

#### `generate_device_fingerprint() -> str`

Generate a stable device fingerprint.

**Returns**: Unique device identifier string

**Example**:
```python
fp = generator.generate_device_fingerprint()
print(f"Fingerprint: {fp}")
# Output: device_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

#### `verify_fingerprint_stability(fingerprint: str) -> tuple[bool, float]`

Verify that a fingerprint is still valid for this device.

**Parameters**:
- `fingerprint`: Previously generated fingerprint to verify

**Returns**: Tuple of (is_valid, confidence_score)

**Example**:
```python
is_valid, confidence = generator.verify_fingerprint_stability(stored_fp)
if is_valid:
    print(f"Fingerprint valid with {confidence:.2%} confidence")
```

#### `get_system_info() -> dict`

Get detailed system information used in fingerprinting.

**Returns**: Dictionary with hardware and system details

**Example**:
```python
info = generator.get_system_info()
print(f"CPU: {info.get('cpu')}")
print(f"Motherboard: {info.get('motherboard')}")
print(f"Disk serial: {info.get('disk_serial')}")
```

---

### ProductionFingerprintGenerator

Advanced generator with encryption, storage, and anomaly detection.

**Usage**:

```python
from device_fingerprinting import ProductionFingerprintGenerator

generator = ProductionFingerprintGenerator()
fingerprint = generator.generate_fingerprint()
```

**Methods**:

#### `generate_fingerprint(method: str = "stable") -> FingerprintResult`

Generate fingerprint with optional method selection.

**Parameters**:
- `method`: "stable" (default), "fast", or "comprehensive"

**Returns**: `FingerprintResult` object

**Example**:
```python
result = generator.generate_fingerprint(method="stable")
print(f"Fingerprint: {result.fingerprint}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Components: {len(result.components)}")
```

#### `store_fingerprint(key: str, value: str) -> None`

Securely store a fingerprint or data.

**Parameters**:
- `key`: Storage key identifier
- `value`: Data to store (automatically encrypted)

**Raises**: `StorageError` if storage fails

**Example**:
```python
generator.store_fingerprint("user_device", fingerprint)
```

#### `retrieve_fingerprint(key: str) -> str`

Retrieve previously stored fingerprint.

**Parameters**:
- `key`: Storage key identifier

**Returns**: Decrypted fingerprint value

**Raises**: 
- `KeyError` if key not found
- `StorageError` if decryption fails

**Example**:
```python
retrieved = generator.retrieve_fingerprint("user_device")
```

#### `detect_anomaly(metrics: dict = None, baseline: dict = None) -> tuple[bool, float]`

Detect anomalous system behavior.

**Parameters**:
- `metrics`: Current system metrics (auto-collected if None)
- `baseline`: Baseline metrics for comparison (optional)

**Returns**: Tuple of (is_anomalous, confidence_score)

**Example**:
```python
is_anomalous, confidence = generator.detect_anomaly()
if is_anomalous:
    print(f"Anomaly detected: {confidence:.2%}")
```

#### `get_system_metrics() -> dict`

Get current system performance metrics.

**Returns**: Dictionary with CPU, memory, disk metrics

**Example**:
```python
metrics = generator.get_system_metrics()
print(f"CPU usage: {metrics['cpu_percent']}%")
print(f"Memory: {metrics['memory_percent']}%")
```

#### `create_device_binding(data: dict) -> str`

Create a device-bound secret.

**Parameters**:
- `data`: Dictionary to bind to device

**Returns**: Device-bound token

**Example**:
```python
token = generator.create_device_binding({
    "api_key": "secret",
    "user_id": "user123"
})
```

#### `verify_device_binding(token: str) -> bool`

Verify a device-bound token.

**Parameters**:
- `token`: Device-bound token to verify

**Returns**: True if valid on this device

**Example**:
```python
is_valid = generator.verify_device_binding(token)
```

#### `set_anomaly_threshold(threshold: float) -> None`

Configure anomaly detection sensitivity.

**Parameters**:
- `threshold`: 0.0-1.0 (higher = less sensitive)

**Example**:
```python
generator.set_anomaly_threshold(0.7)  # Less sensitive
```

#### `use_tpm(enabled: bool) -> bool`

Enable or disable TPM features.

**Parameters**:
- `enabled`: True to enable TPM

**Returns**: True if TPM is available and enabled

**Example**:
```python
if generator.use_tpm(True):
    print("TPM enabled")
else:
    print("TPM not available, using software fallback")
```

---

### AdvancedDeviceFingerprinter

Professional-grade fingerprinter with multiple methods.

**Usage**:

```python
from device_fingerprinting import AdvancedDeviceFingerprinter
from device_fingerprinting import FingerprintMethod

fingerprinter = AdvancedDeviceFingerprinter()
result = fingerprinter.generate_fingerprint(FingerprintMethod.QUANTUM_RESISTANT)
```

**Methods**:

#### `generate_fingerprint(method: FingerprintMethod, include_debug_info: bool = False) -> AdvancedFingerprintResult`

Generate fingerprint with specific method.

**Parameters**:
- `method`: `FingerprintMethod.BASIC`, `.ADVANCED`, or `.QUANTUM_RESISTANT`
- `include_debug_info`: Include component details in result

**Returns**: `AdvancedFingerprintResult` object

**Example**:
```python
result = fingerprinter.generate_fingerprint(
    FingerprintMethod.QUANTUM_RESISTANT,
    include_debug_info=True
)
print(f"Components: {result.components}")
```

#### `verify_fingerprint_stability(fingerprint: str, method: FingerprintMethod) -> tuple[bool, float]`

Verify fingerprint with specific method.

**Parameters**:
- `fingerprint`: Fingerprint to verify
- `method`: Method used to generate

**Returns**: Tuple of (is_stable, confidence)

**Example**:
```python
is_stable, confidence = fingerprinter.verify_fingerprint_stability(
    fingerprint,
    FingerprintMethod.ADVANCED
)
```

#### `compare_methods() -> dict`

Compare all fingerprint methods.

**Returns**: Dictionary with results for all methods

**Example**:
```python
comparison = fingerprinter.compare_methods()
for method, result in comparison.items():
    print(f"{method}: confidence={result.confidence:.2%}")
```

---

## Fingerprint Generation

### FingerprintMethod

Enumeration of fingerprinting methods.

```python
from device_fingerprinting import FingerprintMethod

# Available methods
FingerprintMethod.BASIC  # Fast, ~50ms
FingerprintMethod.ADVANCED  # Balanced, ~150ms
FingerprintMethod.QUANTUM_RESISTANT  # Secure, ~300ms
```

---

### FingerprintResult

Result object from fingerprint generation.

**Attributes**:

```python
result.fingerprint: str  # The generated fingerprint
result.confidence: float  # Confidence score 0.0-1.0
result.method: str  # Method used
result.timestamp: datetime  # Generation time
result.components: list[str]  # Hardware components used (if debug enabled)
result.warnings: list[str]  # Any warnings during generation
```

**Example**:
```python
result = generator.generate_fingerprint()
print(f"Fingerprint: {result.fingerprint}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Method: {result.method}")
print(f"Generated: {result.timestamp}")
```

---

### AdvancedFingerprintResult

Extended result object with more details.

**Attributes**:

```python
result.fingerprint: str  # The generated fingerprint
result.confidence: float  # Confidence score
result.method: FingerprintMethod  # Enumerated method
result.timestamp: datetime  # Generation time
result.components: list[str]  # All components collected
result.component_hashes: dict  # Hash of each component
result.warnings: list[str]  # Warnings
result.performance_metrics: dict  # Generation performance
result.platform_info: dict  # Detailed platform info
```

---

## Cryptography

### CryptoEngine

Cryptographic operations.

**Usage**:

```python
from device_fingerprinting.crypto import CryptoEngine

engine = CryptoEngine()
encrypted = engine.encrypt(plaintext, key)
decrypted = engine.decrypt(encrypted, key)
```

**Methods**:

#### `encrypt(plaintext: bytes, key: bytes, nonce: bytes = None) -> bytes`

Encrypt data using AES-256-GCM.

**Parameters**:
- `plaintext`: Data to encrypt
- `key`: 32-byte encryption key
- `nonce`: 12-byte nonce (generated if None)

**Returns**: Encrypted ciphertext with nonce and auth tag

**Example**:
```python
import os
key = os.urandom(32)  # 32 bytes for AES-256
encrypted = engine.encrypt(b"secret data", key)
```

#### `decrypt(ciphertext: bytes, key: bytes) -> bytes`

Decrypt AES-256-GCM encrypted data.

**Parameters**:
- `ciphertext`: Encrypted data from encrypt()
- `key`: Same key used for encryption

**Returns**: Decrypted plaintext

**Raises**: `ValueError` if authentication fails (tampering detected)

**Example**:
```python
try:
    plaintext = engine.decrypt(encrypted, key)
except ValueError:
    print("Decryption failed - data may be corrupted or tampered")
```

#### `hash_data(data: bytes) -> str`

Generate SHA-3-256 hash of data.

**Parameters**:
- `data`: Data to hash

**Returns**: Hexadecimal hash string

**Example**:
```python
fingerprint = engine.hash_data(hardware_data)
```

#### `derive_key(password: bytes, salt: bytes = None) -> tuple[bytes, bytes]`

Derive cryptographic key from password using Scrypt.

**Parameters**:
- `password`: Password bytes
- `salt`: 32-byte salt (generated if None)

**Returns**: Tuple of (key, salt)

**Example**:
```python
key, salt = engine.derive_key(b"user_password")
# Save salt with encrypted data
```

---

## Secure Storage

### SecureStorage

Encrypted data storage backend.

**Usage**:

```python
from device_fingerprinting.secure_storage import SecureStorage

storage = SecureStorage()
storage.set("user_id", "user123", "value")
value = storage.get("user_id", "user123")
```

**Methods**:

#### `set(category: str, key: str, value: str) -> None`

Store encrypted value.

**Parameters**:
- `category`: Storage category (user_id, app_id)
- `key`: Key identifier
- `value`: Value to store

**Example**:
```python
storage.set("user_123", "api_key", "sk_secret_key")
```

#### `get(category: str, key: str) -> str`

Retrieve encrypted value.

**Parameters**:
- `category`: Storage category
- `key`: Key identifier

**Returns**: Decrypted value

**Raises**: `KeyError` if key not found

**Example**:
```python
api_key = storage.get("user_123", "api_key")
```

#### `delete(category: str, key: str) -> bool`

Delete stored value.

**Parameters**:
- `category`: Storage category
- `key`: Key identifier

**Returns**: True if deleted, False if not found

**Example**:
```python
if storage.delete("user_123", "api_key"):
    print("Deleted")
```

#### `exists(category: str, key: str) -> bool`

Check if key exists in storage.

**Parameters**:
- `category`: Storage category
- `key`: Key identifier

**Returns**: True if exists

**Example**:
```python
if storage.exists("user_123", "api_key"):
    value = storage.get("user_123", "api_key")
```

#### `list_keys(category: str) -> list[str]`

List all keys in a category.

**Parameters**:
- `category`: Storage category

**Returns**: List of key names

**Example**:
```python
keys = storage.list_keys("user_123")
for key in keys:
    print(key)
```

---

## Anomaly Detection

### MLAnomalyDetector

Machine learning-based anomaly detection.

**Usage**:

```python
from device_fingerprinting.ml_features import MLAnomalyDetector

detector = MLAnomalyDetector()
is_anomalous, score = detector.detect(metrics)
```

**Methods**:

#### `detect(metrics: dict, baseline: dict = None) -> tuple[bool, float]`

Detect anomalies in system metrics.

**Parameters**:
- `metrics`: Current system metrics dictionary
- `baseline`: Baseline metrics for comparison

**Returns**: Tuple of (is_anomalous, anomaly_score)

**Example**:
```python
metrics = {
    "cpu_percent": 45.2,
    "memory_percent": 62.1,
    "disk_percent": 78.3,
    "network_io": {"bytes_sent": 1024000, "bytes_recv": 2048000}
}
is_anomalous, score = detector.detect(metrics)
```

#### `set_threshold(threshold: float) -> None`

Set anomaly detection threshold.

**Parameters**:
- `threshold`: 0.0-1.0 (higher = less sensitive)

**Example**:
```python
detector.set_threshold(0.75)  # Less sensitive
```

#### `get_contributing_features(metrics: dict) -> dict`

Get which features contributed to anomaly score.

**Parameters**:
- `metrics`: System metrics

**Returns**: Dictionary with feature contributions

**Example**:
```python
contributions = detector.get_contributing_features(metrics)
for feature, score in contributions.items():
    print(f"{feature}: {score:.2%}")
```

---

## TPM Integration

### TPMFingerprintProvider

TPM-based fingerprinting.

**Usage**:

```python
from device_fingerprinting.tpm_hardware import get_tpm_status, enable_tpm_fingerprinting

# Check TPM availability
status = get_tpm_status()

# Enable TPM features
success = enable_tpm_fingerprinting(True)
```

**Functions**:

#### `get_tpm_status() -> dict`

Get TPM availability and details.

**Returns**: Dictionary with TPM status

**Example**:
```python
status = get_tpm_status()
print(f"Platform: {status['platform']}")
print(f"TPM available: {status['tpm_hardware_available']}")
print(f"TPM version: {status.get('tpm_version', 'Unknown')}")
print(f"Manufacturer: {status.get('tpm_manufacturer', 'Unknown')}")
```

#### `enable_tpm_fingerprinting(enabled: bool) -> bool`

Enable or disable TPM fingerprinting.

**Parameters**:
- `enabled`: True to enable TPM

**Returns**: True if TPM is available and enabled

**Example**:
```python
if enable_tpm_fingerprinting(True):
    print("TPM enabled for fingerprinting")
else:
    print("TPM not available - using software mode")
```

---

## Utility Functions

### Standalone Functions

#### `generate_fingerprint(method: str = "stable") -> str`

Quick standalone fingerprint generation.

**Parameters**:
- `method`: "stable" (default), "fast", or "comprehensive"

**Returns**: Device fingerprint string

**Example**:
```python
from device_fingerprinting import generate_fingerprint

fp = generate_fingerprint()
```

#### `get_system_info() -> dict`

Get system and hardware information.

**Returns**: Dictionary with hardware details

**Example**:
```python
from device_fingerprinting import get_system_info

info = get_system_info()
```

---

## Data Types

### SystemMetrics

Dictionary with system metrics keys:

```python
{
    "cpu_percent": float,  # CPU usage 0-100
    "cpu_count": int,  # Number of CPUs
    "memory_percent": float,  # Memory usage 0-100
    "memory_available": int,  # Available memory bytes
    "disk_percent": float,  # Disk usage 0-100
    "disk_free": int,  # Free disk bytes
    "process_count": int,  # Number of processes
    "boot_time": float,  # System boot timestamp
    "uptime": float,  # Seconds since boot
    "network_io": {
        "bytes_sent": int,
        "bytes_recv": int,
        "packets_sent": int,
        "packets_recv": int
    }
}
```

---

## Exceptions

### FingerprintError

Base exception for fingerprinting errors.

```python
from device_fingerprinting.exceptions import FingerprintError

try:
    fingerprint = generator.generate_device_fingerprint()
except FingerprintError as e:
    print(f"Fingerprinting failed: {e}")
```

### StorageError

Storage operation error.

```python
from device_fingerprinting.exceptions import StorageError

try:
    generator.store_fingerprint("key", value)
except StorageError as e:
    print(f"Storage failed: {e}")
```

### CryptoError

Cryptographic operation error.

```python
from device_fingerprinting.exceptions import CryptoError

try:
    decrypted = engine.decrypt(ciphertext, key)
except CryptoError as e:
    print(f"Crypto operation failed: {e}")
```

### AnomalyDetectionError

Anomaly detection error.

```python
from device_fingerprinting.exceptions import AnomalyDetectionError

try:
    is_anomalous, score = detector.detect(metrics)
except AnomalyDetectionError as e:
    print(f"Anomaly detection failed: {e}")
```

### TPMError

TPM-related error.

```python
from device_fingerprinting.exceptions import TPMError

try:
    enable_tpm_fingerprinting(True)
except TPMError as e:
    print(f"TPM operation failed: {e}")
```

---

## Version Information

### Getting Version

```python
from device_fingerprinting import __version__

print(f"Library version: {__version__}")
# Output: 2.2.3
```

### Compatibility

```python
import device_fingerprinting
import sys

print(f"Python: {sys.version}")
print(f"Library: {device_fingerprinting.__version__}")

# Ensure compatibility
assert sys.version_info >= (3, 9), "Python 3.9+ required"
```

---

## Complete Example

```python
from device_fingerprinting import ProductionFingerprintGenerator
from device_fingerprinting import get_tpm_status
import json

# Initialize generator
generator = ProductionFingerprintGenerator()

# Check TPM
tpm_status = get_tpm_status()
print(f"TPM Available: {tpm_status['tpm_hardware_available']}")

# Enable TPM if available
generator.use_tpm(True)

# Generate fingerprint
fingerprint = generator.generate_fingerprint()
print(f"Fingerprint: {fingerprint}")
print(f"Confidence: {fingerprint.confidence:.2%}")

# Store securely
generator.store_fingerprint("device_id", fingerprint.fingerprint)

# Monitor for anomalies
metrics = generator.get_system_metrics()
is_anomalous, confidence = generator.detect_anomaly(metrics)
print(f"System normal: {not is_anomalous}")

# Create device binding
token = generator.create_device_binding({"user_id": "user123"})
is_valid = generator.verify_device_binding(token)
print(f"Token valid: {is_valid}")
```

---

For more examples, see the [Usage Examples](../guides/examples.md) guide.
