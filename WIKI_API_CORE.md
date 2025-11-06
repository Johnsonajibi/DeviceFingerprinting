# API Reference - Core

Complete API reference for core Device Fingerprinting functionality.

## 📋 Table of Contents

- [DeviceFingerprinter Class](#devicefingerprinter-class)
- [FingerprintResult Class](#fingerprintresult-class)
- [Methods](#methods)
- [Exceptions](#exceptions)

---

## DeviceFingerprinter Class

The main class for generating and verifying device fingerprints.

### Constructor

```python
DeviceFingerprinter(
    include_network: bool = True,
    include_usb: bool = False,
    enable_ml: bool = False,
    advanced_mode: bool = False,
    cache_duration: int = 300,
    crypto_backend: Optional[CryptoBackend] = None,
    storage_backend: Optional[StorageBackend] = None,
    security_backend: Optional[SecurityBackend] = None
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_network` | `bool` | `True` | Include network adapter MAC addresses |
| `include_usb` | `bool` | `False` | Include USB device information |
| `enable_ml` | `bool` | `False` | Enable ML-based anomaly detection |
| `advanced_mode` | `bool` | `False` | Use advanced fingerprinting (more components) |
| `cache_duration` | `int` | `300` | Cache duration in seconds (0 to disable) |
| `crypto_backend` | `CryptoBackend` | `None` | Custom cryptography backend |
| `storage_backend` | `StorageBackend` | `None` | Custom storage backend |
| `security_backend` | `SecurityBackend` | `None` | Custom security backend |

#### Example

```python
from device_fingerprinting import DeviceFingerprinter

# Basic usage
fp = DeviceFingerprinter()

# Advanced configuration
fp = DeviceFingerprinter(
    include_network=True,
    include_usb=False,
    enable_ml=True,
    advanced_mode=True,
    cache_duration=3600  # 1 hour cache
)
```

---

## Methods

### generate()

Generate a device fingerprint.

```python
def generate(
    self,
    force_refresh: bool = False
) -> FingerprintResult
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `force_refresh` | `bool` | `False` | Bypass cache and regenerate |

#### Returns

`FingerprintResult` - Object containing fingerprint and metadata

#### Raises

- `HardwareError` - Cannot access hardware information
- `FingerprintError` - Fingerprint generation failed

#### Example

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# Generate with cache
result = fp.generate()
print(f"Fingerprint: {result.fingerprint}")

# Force refresh (bypass cache)
result = fp.generate(force_refresh=True)
```

---

### bind_token()

Bind a token to the current device.

```python
def bind_token(
    self,
    token: str,
    metadata: Optional[Dict[str, Any]] = None
) -> str
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `token` | `str` | Required | Token to bind (license key, session ID, etc.) |
| `metadata` | `dict` | `None` | Additional metadata to include |

#### Returns

`str` - Bound token (encrypted and signed)

#### Example

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# Basic binding
license_key = "ABC-123-XYZ-789"
bound_token = fp.bind_token(license_key)

# With metadata
bound_token = fp.bind_token(
    license_key,
    metadata={
        'user_id': '12345',
        'activated_at': '2025-11-05T10:30:00Z',
        'plan': 'premium'
    }
)
```

---

### verify_token()

Verify a bound token on the current device.

```python
def verify_token(
    self,
    bound_token: str,
    strict: bool = True
) -> bool
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `bound_token` | `str` | Required | Bound token to verify |
| `strict` | `bool` | `True` | Strict verification (exact match required) |

#### Returns

`bool` - `True` if token is valid for this device, `False` otherwise

#### Example

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# Bind token
bound_token = fp.bind_token("LICENSE-KEY")

# Verify (strict mode)
if fp.verify_token(bound_token):
    print("✅ Valid license")
else:
    print("❌ Invalid or different device")

# Verify (lenient mode - allows minor hardware changes)
if fp.verify_token(bound_token, strict=False):
    print("✅ Valid with minor changes")
```

---

### get_hardware_info()

Get detailed hardware information.

```python
def get_hardware_info(self) -> Dict[str, Any]
```

#### Returns

`dict` - Hardware information dictionary

#### Example

```python
from device_fingerprinting import DeviceFingerprinter
import json

fp = DeviceFingerprinter()
hw_info = fp.get_hardware_info()

print(json.dumps(hw_info, indent=2))
```

**Output:**
```json
{
  "cpu": {
    "brand": "Intel(R) Core(TM) i7-9700K",
    "physical_cores": 8,
    "logical_cores": 8,
    "frequency": 3600
  },
  "ram": {
    "total": 17179869184,
    "total_gb": 16.0
  },
  "storage": [
    {
      "device": "C:",
      "total": 1000204886016,
      "total_gb": 931.5
    }
  ],
  "network": [
    {
      "name": "Ethernet",
      "mac": "XX:XX:XX:XX:XX:XX"
    }
  ]
}
```

---

### clear_cache()

Clear the fingerprint cache.

```python
def clear_cache(self) -> None
```

#### Example

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter(cache_duration=3600)

# Generate (cached)
result1 = fp.generate()

# Clear cache
fp.clear_cache()

# Generate (fresh)
result2 = fp.generate()
```

---

## FingerprintResult Class

Result object returned by `generate()`.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `fingerprint` | `str` | The device fingerprint (hex string) |
| `confidence_score` | `float` | Confidence score (0.0 to 1.0) |
| `components_used` | `List[str]` | Hardware components used |
| `timestamp` | `str` | ISO 8601 timestamp |
| `metadata` | `Dict` | Additional metadata |
| `cached` | `bool` | Whether result was cached |

### Properties

#### fingerprint

```python
@property
def fingerprint(self) -> str
```

The device fingerprint as a hex string.

**Example:**
```python
result = fp.generate()
print(result.fingerprint)
# Output: "a1b2c3d4e5f6789..."
```

#### confidence_score

```python
@property
def confidence_score(self) -> float
```

Confidence score between 0.0 and 1.0.

- `1.0` - Perfect confidence (all components available)
- `0.9+` - High confidence (minor components missing)
- `0.7-0.9` - Medium confidence (some components unavailable)
- `<0.7` - Low confidence (significant hardware changes)

**Example:**
```python
result = fp.generate()
if result.confidence_score < 0.7:
    print("⚠️ Warning: Low confidence score")
```

#### components_used

```python
@property
def components_used(self) -> List[str]
```

List of hardware components used in fingerprint.

**Example:**
```python
result = fp.generate()
print("Components:", ", ".join(result.components_used))
# Output: "Components: cpu, ram, storage, network"
```

#### metadata

```python
@property
def metadata(self) -> Dict[str, Any]
```

Additional metadata about fingerprint generation.

**Example:**
```python
result = fp.generate()
print(f"Generated at: {result.metadata['timestamp']}")
print(f"Platform: {result.metadata['platform']}")
print(f"Python version: {result.metadata['python_version']}")
```

### Methods

#### to_dict()

```python
def to_dict(self) -> Dict[str, Any]
```

Convert result to dictionary.

**Example:**
```python
result = fp.generate()
data = result.to_dict()
print(data)
```

#### to_json()

```python
def to_json(self, indent: Optional[int] = None) -> str
```

Convert result to JSON string.

**Example:**
```python
result = fp.generate()
json_str = result.to_json(indent=2)
print(json_str)
```

---

## Exceptions

### FingerprintError

Base exception for fingerprint-related errors.

```python
from device_fingerprinting.exceptions import FingerprintError

try:
    result = fp.generate()
except FingerprintError as e:
    print(f"Error: {e}")
```

### HardwareError

Exception raised when hardware information cannot be accessed.

```python
from device_fingerprinting.exceptions import HardwareError

try:
    result = fp.generate()
except HardwareError as e:
    print(f"Hardware access error: {e}")
    # Fallback to basic fingerprinting
```

### VerificationError

Exception raised during token verification.

```python
from device_fingerprinting.exceptions import VerificationError

try:
    is_valid = fp.verify_token(bound_token)
except VerificationError as e:
    print(f"Verification error: {e}")
```

### CryptoError

Exception raised for cryptographic operations.

```python
from device_fingerprinting.exceptions import CryptoError

try:
    bound_token = fp.bind_token(license_key)
except CryptoError as e:
    print(f"Crypto error: {e}")
```

---

## Usage Patterns

### Pattern 1: Simple License Check

```python
from device_fingerprinting import DeviceFingerprinter

def check_license():
    fp = DeviceFingerprinter()
    
    # Load stored bound token
    with open('license.dat', 'r') as f:
        bound_token = f.read()
    
    return fp.verify_token(bound_token)

if check_license():
    print("✅ License valid")
else:
    print("❌ License invalid")
```

### Pattern 2: Hardware Change Detection

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# First run - store fingerprint
result = fp.generate()
original_fp = result.fingerprint
save_to_file(original_fp)

# Later runs - compare
current_result = fp.generate()
if current_result.fingerprint != original_fp:
    if current_result.confidence_score < 0.8:
        print("⚠️ Significant hardware change detected")
    else:
        print("Minor hardware change (acceptable)")
```

### Pattern 3: Multi-Device Support

```python
from device_fingerprinting import DeviceFingerprinter

class MultiDeviceLicense:
    def __init__(self, max_devices=3):
        self.fp = DeviceFingerprinter()
        self.max_devices = max_devices
        self.registered_devices = []
    
    def register_device(self, license_key):
        if len(self.registered_devices) >= self.max_devices:
            return False, "Maximum devices reached"
        
        result = self.fp.generate()
        bound_token = self.fp.bind_token(license_key)
        
        self.registered_devices.append({
            'fingerprint': result.fingerprint,
            'bound_token': bound_token
        })
        
        return True, bound_token
    
    def verify_any_device(self, license_key):
        current = self.fp.generate()
        
        for device in self.registered_devices:
            if current.fingerprint == device['fingerprint']:
                return self.fp.verify_token(device['bound_token'])
        
        return False

# Usage
manager = MultiDeviceLicense(max_devices=3)

# Register devices
success, token = manager.register_device("LICENSE-KEY")
if success:
    print(f"✅ Device registered: {token[:20]}...")
```

---

## Type Hints

```python
from typing import Optional, Dict, Any, List
from device_fingerprinting import DeviceFingerprinter, FingerprintResult

def activate_license(
    license_key: str,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """Activate license with type hints."""
    fp: DeviceFingerprinter = DeviceFingerprinter()
    
    result: FingerprintResult = fp.generate()
    
    bound_token: str = fp.bind_token(
        license_key,
        metadata={'user_id': user_id} if user_id else None
    )
    
    return {
        'success': True,
        'fingerprint': result.fingerprint,
        'bound_token': bound_token,
        'confidence': result.confidence_score
    }
```

---

## Best Practices

### ✅ Do's

```python
# ✅ Handle exceptions
try:
    result = fp.generate()
except Exception as e:
    # Graceful fallback
    pass

# ✅ Check confidence scores
result = fp.generate()
if result.confidence_score < 0.8:
    # Request additional verification
    pass

# ✅ Use appropriate cache duration
fp = DeviceFingerprinter(cache_duration=3600)  # 1 hour

# ✅ Clear cache when needed
fp.clear_cache()

# ✅ Use strict verification for security
is_valid = fp.verify_token(token, strict=True)
```

### ❌ Don'ts

```python
# ❌ Don't ignore confidence scores
result = fp.generate()
# Bad: use result.fingerprint without checking confidence

# ❌ Don't generate too frequently
for i in range(1000):
    fp.generate()  # Wasteful without cache

# ❌ Don't expose raw hardware info
hw_info = fp.get_hardware_info()
# Bad: log or transmit hw_info (may contain sensitive data)

# ❌ Don't store unbound tokens
# Bad: save license_key in plain text
# Good: save bound_token
```

---

## Next Steps

- **Configuration API**: [Configuration Reference →](WIKI_API_CONFIG.md)
- **Advanced API**: [Advanced Reference →](WIKI_API_ADVANCED.md)
- **Backends**: [Backend Configuration →](WIKI_BACKENDS.md)
- **Examples**: [Usage Examples →](WIKI_BASIC_EXAMPLES.md)

---

**Navigation**: [← Home](WIKI_HOME.md) | [Configuration API →](WIKI_API_CONFIG.md)
