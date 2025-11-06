# Quick Start Guide

Get up and running with Device Fingerprinting in 5 minutes.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Common Patterns](#common-patterns)
- [Configuration](#configuration)
- [Next Steps](#next-steps)

---

## Basic Usage

### Simple Fingerprint Generation

```python
from device_fingerprinting import DeviceFingerprinter

# Create instance
fingerprinter = DeviceFingerprinter()

# Generate fingerprint
result = fingerprinter.generate()

# Access results
print(f"Fingerprint: {result.fingerprint}")
print(f"Confidence: {result.confidence_score}")
print(f"Components: {result.components_used}")
```

**Output:**
```
Fingerprint: a1b2c3d4e5f6...
Confidence: 0.95
Components: ['cpu', 'ram', 'storage', 'network']
```

### Device Binding

```python
from device_fingerprinting import DeviceFingerprinter

fingerprinter = DeviceFingerprinter()

# Generate and bind license
license_token = "YOUR-LICENSE-KEY-12345"
bound_token = fingerprinter.bind_token(license_token)

# Store bound token securely
print(f"Bound Token: {bound_token}")

# Later: Verify device
is_valid = fingerprinter.verify_token(bound_token)
print(f"Valid: {is_valid}")  # True on same device
```

---

## Common Patterns

### 1. Software Licensing

```python
from device_fingerprinting import DeviceFingerprinter

class LicenseManager:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
    
    def activate_license(self, license_key):
        """Bind license to this device"""
        bound_token = self.fingerprinter.bind_token(license_key)
        # Store in database or config file
        return bound_token
    
    def verify_license(self, bound_token):
        """Check if license is valid on this device"""
        return self.fingerprinter.verify_token(bound_token)

# Usage
manager = LicenseManager()

# On first activation
token = manager.activate_license("ABC-123-XYZ")
print(f"License activated: {token}")

# On each app startup
if manager.verify_license(token):
    print("✅ License valid!")
else:
    print("❌ License invalid or different device!")
```

### 2. User Authentication

```python
from device_fingerprinting import DeviceFingerprinter
import json

class DeviceAuth:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
    
    def register_device(self, user_id):
        """Register current device for user"""
        result = self.fingerprinter.generate()
        
        device_data = {
            'user_id': user_id,
            'fingerprint': result.fingerprint,
            'confidence': result.confidence_score,
            'registered_at': result.metadata['timestamp']
        }
        return device_data
    
    def verify_device(self, user_id, stored_fingerprint):
        """Verify if current device matches registered device"""
        current = self.fingerprinter.generate()
        
        # Simple comparison (production should use verify_token)
        return current.fingerprint == stored_fingerprint

# Usage
auth = DeviceAuth()

# Registration
device_info = auth.register_device(user_id="user123")
print(f"Device registered: {device_info['fingerprint'][:20]}...")

# Verification
is_same_device = auth.verify_device("user123", device_info['fingerprint'])
print(f"Same device: {is_same_device}")
```

### 3. Fraud Detection

```python
from device_fingerprinting import DeviceFingerprinter

class FraudDetector:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter(
            enable_ml=True,  # Enable ML detection
            advanced_mode=True
        )
        self.known_devices = {}
    
    def check_transaction(self, user_id, transaction_id):
        """Check if transaction is from known device"""
        result = self.fingerprinter.generate()
        
        risk_score = 0.0
        
        # Check against known devices
        if user_id in self.known_devices:
            known_fp = self.known_devices[user_id]
            if result.fingerprint != known_fp:
                risk_score += 0.5
        
        # Low confidence = higher risk
        if result.confidence_score < 0.8:
            risk_score += 0.3
        
        # Check anomalies (if ML enabled)
        if hasattr(result, 'anomaly_score'):
            risk_score += result.anomaly_score
        
        return {
            'transaction_id': transaction_id,
            'risk_score': min(risk_score, 1.0),
            'fingerprint': result.fingerprint,
            'allow': risk_score < 0.7
        }
    
    def add_trusted_device(self, user_id):
        """Add current device as trusted"""
        result = self.fingerprinter.generate()
        self.known_devices[user_id] = result.fingerprint

# Usage
detector = FraudDetector()

# Add trusted device
detector.add_trusted_device("user123")

# Check transaction
fraud_check = detector.check_transaction("user123", "txn_001")
print(f"Risk Score: {fraud_check['risk_score']}")
print(f"Allow: {fraud_check['allow']}")
```

---

## Configuration

### Basic Configuration

```python
from device_fingerprinting import DeviceFingerprinter

# Create with custom settings
fingerprinter = DeviceFingerprinter(
    include_network=True,      # Include network adapters
    include_usb=False,         # Exclude USB devices
    enable_ml=True,            # Enable ML anomaly detection
    advanced_mode=True,        # Use advanced fingerprinting
    cache_duration=3600        # Cache for 1 hour
)
```

### Backend Configuration

```python
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.backends import CryptoBackend, StorageBackend

# Custom crypto backend
class MyCustomCrypto(CryptoBackend):
    def hash(self, data: str) -> str:
        # Custom hashing logic
        return hashlib.sha256(data.encode()).hexdigest()

# Use custom backend
fingerprinter = DeviceFingerprinter(
    crypto_backend=MyCustomCrypto()
)
```

### Post-Quantum Cryptography

```python
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.hybrid_pqc import HybridPQC

# Enable PQC protection
fingerprinter = DeviceFingerprinter()

# Create PQC backend
pqc = HybridPQC()

# Bind token with PQC signatures
license_key = "ABC-123-XYZ"
bound_token = fingerprinter.bind_token(license_key)

# Add PQC signature
data = f"{license_key}:{fingerprinter.generate().fingerprint}"
signature = pqc.sign(data)

# Verify with PQC
is_valid = pqc.verify(data, signature)
print(f"PQC Verification: {is_valid}")
```

---

## Error Handling

### Basic Error Handling

```python
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.exceptions import (
    FingerprintError,
    VerificationError,
    HardwareError
)

fingerprinter = DeviceFingerprinter()

try:
    result = fingerprinter.generate()
    print(f"Success: {result.fingerprint}")
    
except HardwareError as e:
    print(f"Hardware access error: {e}")
    # Fallback to basic fingerprinting
    
except FingerprintError as e:
    print(f"Fingerprint generation failed: {e}")
    # Handle gracefully
    
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Verification Error Handling

```python
try:
    is_valid = fingerprinter.verify_token(bound_token)
    
    if not is_valid:
        print("⚠️ Device mismatch detected")
        # Log security event
        # Request re-authentication
    else:
        print("✅ Device verified")
        
except VerificationError as e:
    print(f"Verification failed: {e}")
    # Token corrupted or invalid
```

---

## Best Practices

### ✅ Do's

```python
# ✅ Cache fingerprints appropriately
fingerprinter = DeviceFingerprinter(cache_duration=3600)

# ✅ Use token binding for security
bound_token = fingerprinter.bind_token(license_key)

# ✅ Check confidence scores
result = fingerprinter.generate()
if result.confidence_score < 0.7:
    print("⚠️ Low confidence, hardware may have changed")

# ✅ Handle errors gracefully
try:
    result = fingerprinter.generate()
except Exception:
    # Fallback logic
    pass

# ✅ Store bound tokens securely
# Use encrypted storage, not plain text
```

### ❌ Don'ts

```python
# ❌ Don't store raw fingerprints in plain text
# BAD: open('fingerprint.txt', 'w').write(fingerprint)

# ❌ Don't compare fingerprints directly
# BAD: if fp1 == fp2:
# GOOD: if fingerprinter.verify_token(bound_token):

# ❌ Don't ignore confidence scores
# BAD: result = fingerprinter.generate()  # and use blindly

# ❌ Don't generate fingerprints too frequently
# BAD: for i in range(1000): fingerprinter.generate()
# GOOD: Use caching

# ❌ Don't expose internal hardware details
# BAD: print(result.raw_components)  # May leak sensitive info
```

---

## Performance Tips

### Caching

```python
# Enable caching for better performance
fingerprinter = DeviceFingerprinter(cache_duration=3600)

# First call: ~200-500ms
result1 = fingerprinter.generate()

# Subsequent calls: ~1-5ms (cached)
result2 = fingerprinter.generate()
```

### Async Usage

```python
import asyncio
from device_fingerprinting import DeviceFingerprinter

async def verify_multiple_devices(tokens):
    fingerprinter = DeviceFingerprinter()
    
    tasks = [
        asyncio.to_thread(fingerprinter.verify_token, token)
        for token in tokens
    ]
    
    results = await asyncio.gather(*tasks)
    return results

# Usage
tokens = ["token1", "token2", "token3"]
results = asyncio.run(verify_multiple_devices(tokens))
```

---

## Testing Your Integration

### Unit Test Example

```python
import unittest
from device_fingerprinting import DeviceFingerprinter

class TestFingerprinting(unittest.TestCase):
    def setUp(self):
        self.fingerprinter = DeviceFingerprinter()
    
    def test_generate_fingerprint(self):
        result = self.fingerprinter.generate()
        self.assertIsNotNone(result.fingerprint)
        self.assertGreater(result.confidence_score, 0)
    
    def test_token_binding(self):
        token = "test-token-123"
        bound = self.fingerprinter.bind_token(token)
        self.assertTrue(self.fingerprinter.verify_token(bound))
    
    def test_verification_fails_on_invalid(self):
        invalid_token = "invalid-token-xyz"
        self.assertFalse(self.fingerprinter.verify_token(invalid_token))

if __name__ == '__main__':
    unittest.main()
```

---

## Next Steps

Now that you have the basics:

1. **Explore Examples**: [Basic Examples →](WIKI_BASIC_EXAMPLES.md)
2. **Learn About Backends**: [Backend Configuration →](WIKI_BACKENDS.md)
3. **Security Setup**: [Security Guide →](WIKI_SECURITY.md)
4. **Enable PQC**: [Post-Quantum Crypto →](WIKI_PQC.md)
5. **Production Deploy**: [Deployment Guide →](WIKI_DEPLOYMENT.md)

---

## Common Questions

**Q: How stable are fingerprints?**  
A: Fingerprints remain consistent across reboots and minor system changes. Major hardware modifications (CPU or RAM replacement) will change the fingerprint.

**Q: Can users bypass fingerprinting?**  
A: Determined users with virtualization or emulation tools may attempt to circumvent fingerprinting. Implement additional verification layers for sensitive applications.

**Q: Does this work in virtual machines?**  
A: Yes, but VM fingerprints may be less distinctive than physical hardware. Enable `advanced_mode=True` for improved differentiation.

**Q: What is the performance impact?**  
A: Initial fingerprint generation typically takes 200-500ms. Cached results return in 1-5ms. CPU and memory overhead is minimal.

**Q: Is this GDPR compliant?**  
A: Fingerprints are hashed hardware identifiers and don't contain personal data. However, consult legal counsel regarding your specific implementation and jurisdiction.

---

**Navigation**: [← Installation](WIKI_INSTALLATION.md) | [Home](WIKI_HOME.md) | [Examples →](WIKI_BASIC_EXAMPLES.md)
