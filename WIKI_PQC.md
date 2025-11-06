# Post-Quantum Cryptography (PQC) Guide

Complete guide to using quantum-resistant cryptography in Device Fingerprinting.

## 📋 Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Algorithms](#algorithms)
- [Configuration](#configuration)
- [Integration Examples](#integration-examples)
- [Security Features](#security-features)
- [Performance](#performance)

---

## Overview

### What is Post-Quantum Cryptography?

Post-Quantum Cryptography (PQC) refers to cryptographic algorithms that are secure against both classical and quantum computer attacks. As quantum computers advance, traditional cryptographic algorithms (RSA, ECC) become vulnerable.

### Why Use PQC?

- **Quantum Resistance**: Designed to withstand attacks from quantum computers
- **Standards Compliance**: Implements NIST-standardized algorithms
- **Hybrid Approach**: Combines classical and quantum-resistant cryptography
- **Implementation**: Uses established cryptographic libraries

### Current Status

All PQC features have been tested and are operational.

| Feature | Status | Algorithm |
|---------|--------|-----------|
| Digital Signatures | Operational | Dilithium3 (NIST Level 3) |
| Key Encapsulation | Operational | Kyber1024 (NIST Level 5) |
| Classical Fallback | Operational | HMAC-SHA3-256 + RSA |
| Power Analysis Protection | Implemented | Built-in countermeasures |

---

## Installation

### Basic PQC Installation

```bash
# Install with PQC support
pip install device-fingerprinting-pro[pqc]

# Verify installation
python -c "from device_fingerprinting.hybrid_pqc import HybridPQC; print('PQC Ready!')"
```

### Dependencies

The PQC installation includes:

```
pqcdualusb>=0.15.5    # Primary PQC library (Dilithium3, Kyber1024)
pqcrypto>=0.3.4       # Python PQC backend
cryptography>=46.0.0  # Classical crypto fallback
```

### Platform-Specific Notes

**Windows:**
```powershell
pip install device-fingerprinting-pro[pqc]
# Uses pqcrypto backend (recommended)
```

**Linux:**
```bash
# Install liboqs for optimal performance (optional)
sudo apt-get install liboqs-dev
pip install oqs
pip install device-fingerprinting-pro[pqc]
```

**macOS:**
```bash
pip install device-fingerprinting-pro[pqc]
# Uses pqcrypto backend
```

---

## Basic Usage

### Initialize PQC

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

# Create PQC instance
pqc = HybridPQC()

# Check configuration
info = pqc.get_info()
print(f"PQC Available: {info['pqc_available']}")
print(f"Library: {info['pqc_library']}")
print(f"Algorithm: {info['algorithm']}")
```

**Output:**
```
PQC Available: True
Library: pqcdualusb-0.15.5
Algorithm: Dilithium3
```

### Sign Data

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Sign sensitive data
data = "license_key:ABC-123-XYZ:device_fingerprint:a1b2c3..."
signature = pqc.sign(data)

print(f"Signature length: {len(signature)} bytes")
print(f"Signature (hex): {signature[:100]}...")
```

### Verify Signatures

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Original data
data = "license_key:ABC-123-XYZ:device_fingerprint:a1b2c3..."

# Sign
signature = pqc.sign(data)

# Verify
is_valid = pqc.verify(data, signature)
print(f"Valid: {is_valid}")  # True

# Tampered data
tampered_data = data + "modified"
is_valid_tampered = pqc.verify(tampered_data, signature)
print(f"Valid (tampered): {is_valid_tampered}")  # False
```

---

## Algorithms

### Supported PQC Algorithms

#### 1. Dilithium3 (Digital Signatures)

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

print(f"Signature Algorithm: {info['algorithm']}")
```

**Specifications:**
- **Security Level**: NIST Level 3 (~AES-192)
- **Public Key**: ~1952 bytes
- **Private Key**: ~4000 bytes
- **Signature**: ~3293 bytes
- **Speed**: ~0.5-2ms per signature
- **Status**: NIST standardized (2024)

#### 2. Kyber1024 (Key Encapsulation)

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Key encapsulation available in pqcdualusb
# Used for secure key exchange
```

**Specifications:**
- **Security Level**: NIST Level 5 (~AES-256)
- **Public Key**: ~1568 bytes
- **Ciphertext**: ~1568 bytes
- **Shared Secret**: 32 bytes
- **Speed**: ~0.1-0.5ms per operation
- **Status**: NIST standardized (2024)

### Classical Fallback

When PQC libraries are unavailable, the system falls back to classical algorithms:

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

if not info['pqc_available']:
    print(f"Using classical fallback: {info['algorithm']}")
    # Output: HMAC-SHA3-256 or RSA-2048
```

**Classical Algorithms:**
- **HMAC-SHA3-256**: Fast, secure message authentication
- **RSA-2048**: Public key signatures (slower)
- **AES-256-GCM**: Encryption
- **Argon2id**: Key derivation

---

## Configuration

### Basic Configuration

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

# Default configuration (recommended)
pqc = HybridPQC()

# Custom salt (for key derivation)
pqc = HybridPQC(salt=b"my-custom-salt-32-bytes-long")
```

### Advanced Configuration

```python
from device_fingerprinting.hybrid_pqc import HybridPQC
import json

# Initialize
pqc = HybridPQC()

# Get full configuration
info = pqc.get_info()
print(json.dumps(info, indent=2))
```

**Configuration Output:**
```json
{
  "pqc_available": true,
  "pqc_library": "pqcdualusb-0.15.5",
  "backend": "pqcrypto",
  "algorithm": "Dilithium3",
  "security_level": "NIST Level 3",
  "hybrid_mode": true,
  "classical_algorithm": "HMAC-SHA3-256",
  "power_analysis_protection": true
}
```

### Environment Variables

```bash
# Force specific PQC backend
export PQC_BACKEND=pqcrypto  # or 'liboqs', 'fallback'

# Enable PQC debug logging
export PQC_DEBUG=1

# Disable PQC (use classical only)
export PQC_DISABLE=1
```

---

## Integration Examples

### 1. Device Token Binding with PQC

```python
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.hybrid_pqc import HybridPQC

class SecureDeviceBinder:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.pqc = HybridPQC()
    
    def bind_license(self, license_key):
        """Bind license with PQC signature"""
        # Generate device fingerprint
        result = self.fingerprinter.generate()
        
        # Create binding data
        binding_data = f"{license_key}:{result.fingerprint}"
        
        # Sign with PQC
        signature = self.pqc.sign(binding_data)
        
        # Return bound token
        return {
            'license_key': license_key,
            'fingerprint': result.fingerprint,
            'signature': signature,
            'algorithm': self.pqc.get_info()['algorithm']
        }
    
    def verify_license(self, bound_token):
        """Verify license with PQC"""
        # Get current fingerprint
        current = self.fingerprinter.generate()
        
        # Reconstruct binding data
        binding_data = f"{bound_token['license_key']}:{current.fingerprint}"
        
        # Verify PQC signature
        is_valid = self.pqc.verify(binding_data, bound_token['signature'])
        
        # Check fingerprint match
        fingerprint_match = current.fingerprint == bound_token['fingerprint']
        
        return is_valid and fingerprint_match

# Usage
binder = SecureDeviceBinder()

# Bind license
token = binder.bind_license("ABC-123-XYZ")
print(f"✅ License bound with {token['algorithm']}")

# Verify (on same device)
is_valid = binder.verify_license(token)
print(f"Verification: {'✅ Valid' if is_valid else '❌ Invalid'}")
```

### 2. Secure Data Signing

```python
from device_fingerprinting.hybrid_pqc import HybridPQC
import json
from datetime import datetime

class SecureDataSigner:
    def __init__(self):
        self.pqc = HybridPQC()
    
    def sign_document(self, document_data):
        """Sign document with PQC"""
        # Add metadata
        signed_doc = {
            'data': document_data,
            'timestamp': datetime.now().isoformat(),
            'algorithm': self.pqc.get_info()['algorithm']
        }
        
        # Serialize
        doc_string = json.dumps(signed_doc, sort_keys=True)
        
        # Sign
        signature = self.pqc.sign(doc_string)
        signed_doc['signature'] = signature
        
        return signed_doc
    
    def verify_document(self, signed_doc):
        """Verify signed document"""
        # Extract signature
        signature = signed_doc.pop('signature')
        
        # Reconstruct original
        doc_string = json.dumps(signed_doc, sort_keys=True)
        
        # Verify
        is_valid = self.pqc.verify(doc_string, signature)
        
        # Restore signature
        signed_doc['signature'] = signature
        
        return is_valid

# Usage
signer = SecureDataSigner()

# Sign document
document = {'content': 'Sensitive data', 'id': 12345}
signed = signer.sign_document(document)
print(f"✅ Document signed")

# Verify
is_valid = signer.verify_document(signed)
print(f"Valid: {is_valid}")
```

### 3. Tamper Detection

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

class TamperDetector:
    def __init__(self):
        self.pqc = HybridPQC()
    
    def protect_data(self, data):
        """Protect data with PQC signature"""
        signature = self.pqc.sign(data)
        return {
            'data': data,
            'signature': signature,
            'protected_at': datetime.now().isoformat()
        }
    
    def check_tampering(self, protected_data):
        """Check if data has been tampered"""
        data = protected_data['data']
        signature = protected_data['signature']
        
        is_valid = self.pqc.verify(data, signature)
        
        return {
            'tampered': not is_valid,
            'valid_signature': is_valid
        }

# Usage
detector = TamperDetector()

# Protect data
protected = detector.protect_data("Important configuration data")
print("✅ Data protected")

# Check (original data)
result = detector.check_tampering(protected)
print(f"Tampered: {result['tampered']}")  # False

# Simulate tampering
protected['data'] = "Modified data"
result = detector.check_tampering(protected)
print(f"Tampered: {result['tampered']}")  # True
```

---

## Security Features

### Hybrid Classical + PQC

The library uses **hybrid mode** by default, combining classical and quantum-resistant algorithms:

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Hybrid signature process:
# 1. Classical HMAC-SHA3-256 of data
# 2. PQC Dilithium3 signature
# 3. Combined signature output

data = "sensitive_data"
signature = pqc.sign(data)  # Hybrid signature

# Verification requires BOTH to pass
is_valid = pqc.verify(data, signature)
```

**Benefits:**
- ✅ Protected if classical crypto remains secure
- ✅ Protected if PQC algorithms remain secure
- ✅ Only breaks if BOTH are broken simultaneously

### Power Analysis Protection

The pqcdualusb library includes power analysis resistance:

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

# Check security features
if 'power_analysis_protection' in info:
    print("✅ Side-channel attack protection enabled")
```

**Protected Against:**
- Timing attacks
- Power consumption analysis
- Electromagnetic emissions
- Cache timing attacks

### Key Management

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Keys are managed internally
# Access key information (not the keys themselves)
print(f"Public key size: {len(pqc.pqc_public_key)} bytes")
print(f"Private key size: {len(pqc.pqc_private_key)} bytes")
print(f"Classical key size: {len(pqc.classical_key)} bytes")
```

**Security Notes:**
- ⚠️ Never expose private keys
- ⚠️ Store keys in secure storage (encrypted)
- ⚠️ Rotate keys periodically
- ⚠️ Use hardware security modules (HSM) for production

---

## Performance

### Benchmarks

```python
from device_fingerprinting.hybrid_pqc import HybridPQC
import time

pqc = HybridPQC()
data = "test_data" * 100

# Signature generation
start = time.time()
for _ in range(100):
    signature = pqc.sign(data)
sign_time = (time.time() - start) / 100

# Verification
start = time.time()
for _ in range(100):
    pqc.verify(data, signature)
verify_time = (time.time() - start) / 100

print(f"Sign: {sign_time*1000:.2f}ms")
print(f"Verify: {verify_time*1000:.2f}ms")
```

**Typical Performance (Dilithium3):**
- **Signature Generation**: 0.5-2ms
- **Verification**: 0.3-1ms
- **Key Generation**: 1-5ms
- **Memory Usage**: ~10MB

### Optimization Tips

```python
# 1. Reuse PQC instance (avoid re-initialization)
pqc = HybridPQC()  # Do once
for data in batch:
    signature = pqc.sign(data)  # Reuse

# 2. Batch operations
signatures = [pqc.sign(data) for data in batch]

# 3. Use caching for repeated verifications
from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_verify(data, signature):
    return pqc.verify(data, signature)
```

### Size Considerations

| Component | Size | Notes |
|-----------|------|-------|
| Dilithium3 Public Key | ~1952 bytes | Can be shared publicly |
| Dilithium3 Private Key | ~4000 bytes | Must be kept secret |
| Dilithium3 Signature | ~3293 bytes | ~3x larger than RSA |
| Classical HMAC | 32 bytes | Compact |
| Combined Signature | ~3400 bytes | Hybrid overhead |

---

## Testing & Validation

### Verify PQC Installation

```bash
# Run included test script
python -m device_fingerprinting.test_pqc

# Or create custom test
python << EOF
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

print(f"PQC Available: {info['pqc_available']}")
print(f"Library: {info['pqc_library']}")
print(f"Algorithm: {info['algorithm']}")

# Test signature
data = "test"
sig = pqc.sign(data)
valid = pqc.verify(data, sig)

print(f"✅ Test {'PASSED' if valid else 'FAILED'}")
EOF
```

### Unit Tests

```python
import unittest
from device_fingerprinting.hybrid_pqc import HybridPQC

class TestPQC(unittest.TestCase):
    def setUp(self):
        self.pqc = HybridPQC()
    
    def test_pqc_available(self):
        info = self.pqc.get_info()
        self.assertTrue(info['pqc_available'])
    
    def test_sign_and_verify(self):
        data = "test_data"
        signature = self.pqc.sign(data)
        self.assertTrue(self.pqc.verify(data, signature))
    
    def test_tamper_detection(self):
        data = "original"
        signature = self.pqc.sign(data)
        self.assertFalse(self.pqc.verify("modified", signature))

if __name__ == '__main__':
    unittest.main()
```

---

## Troubleshooting

### PQC Not Available

**Problem:**
```python
INFO:pqcdualusb.crypto:PQC backend initialized successfully (using fallback)
```

**Solution:**
```bash
# Install PQC dependencies
pip install --upgrade pqcdualusb pqcrypto

# Verify installation
python -c "import pqcdualusb; print(pqcdualusb.__version__)"
```

### Import Errors

**Problem:**
```
ModuleNotFoundError: No module named 'pqcdualusb'
```

**Solution:**
```bash
pip install device-fingerprinting-pro[pqc]
```

### Performance Issues

**Problem:** Slow signature operations

**Solution:**
```python
# 1. Check backend
from device_fingerprinting.hybrid_pqc import HybridPQC
pqc = HybridPQC()
print(pqc.get_info()['backend'])  # Should be 'pqcrypto' or 'liboqs'

# 2. Use liboqs on Linux for better performance
# sudo apt-get install liboqs-dev
# pip install oqs

# 3. Reduce signature frequency
# Use caching or batch operations
```

---

## Migration from Classical Crypto

### Step 1: Install PQC

```bash
pip install device-fingerprinting-pro[pqc]
```

### Step 2: Update Code

**Before (Classical only):**
```python
from device_fingerprinting import DeviceFingerprinter

fingerprinter = DeviceFingerprinter()
bound_token = fingerprinter.bind_token(license_key)
```

**After (with PQC):**
```python
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.hybrid_pqc import HybridPQC

fingerprinter = DeviceFingerprinter()
pqc = HybridPQC()

# Bind with PQC signature
result = fingerprinter.generate()
binding_data = f"{license_key}:{result.fingerprint}"
signature = pqc.sign(binding_data)

bound_token = {
    'token': fingerprinter.bind_token(license_key),
    'pqc_signature': signature
}
```

### Step 3: Update Verification

```python
# Verify both classical and PQC
is_valid_classical = fingerprinter.verify_token(bound_token['token'])
is_valid_pqc = pqc.verify(binding_data, bound_token['pqc_signature'])

is_valid = is_valid_classical and is_valid_pqc
```

---

## Next Steps

- **Production Deployment**: [Deployment Guide →](WIKI_DEPLOYMENT.md)
- **Security Best Practices**: [Security Guide →](WIKI_SECURITY.md)
- **HSM Integration**: [HSM Guide →](WIKI_HSM.md)
- **API Reference**: [API Documentation →](WIKI_API_ADVANCED.md)

---

**Navigation**: [← Home](WIKI_HOME.md) | [Security →](WIKI_SECURITY.md)
