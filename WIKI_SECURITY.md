# Security Architecture

Comprehensive guide to the security architecture and best practices.

## 📋 Table of Contents

- [Security Overview](#security-overview)
- [Cryptographic Architecture](#cryptographic-architecture)
- [Threat Model](#threat-model)
- [Security Features](#security-features)
- [Best Practices](#best-practices)
- [Compliance](#compliance)

---

## Security Overview

### Security Layers

The Device Fingerprinting library implements multiple security layers:

```
┌─────────────────────────────────────────┐
│     Application Layer                   │
│  (Your application using the library)   │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│     API Layer                           │
│  (DeviceFingerprinter, HybridPQC)       │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│     Security Layer                      │
│  • Token Binding                        │
│  • Signature Verification               │
│  • Tamper Detection                     │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│     Cryptographic Layer                 │
│  • PQC (Dilithium3, Kyber1024)         │
│  • Classical (SHA3-256, AES-256-GCM)   │
│  • Hybrid Mode                          │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│     Storage Layer                       │
│  • Encrypted Storage                    │
│  • Secure Key Management                │
│  • HSM Support (optional)               │
└─────────────────────────────────────────┘
```

### Security Assessment

| Component | Status | Notes |
|-----------|--------|-------|
| **Cryptography** | Compliant | Uses NIST-approved algorithms |
| **Code Security** | Verified | Analyzed with Bandit and CodeQL |
| **Dependency Security** | Current | No known vulnerabilities as of Nov 2025 |
| **Input Validation** | Implemented | Validates all user inputs |
| **Error Handling** | Secure | Prevents information disclosure |

---

## Cryptographic Architecture

### Algorithms Used

#### Post-Quantum Cryptography (PQC)

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

print(f"Algorithm: {info['algorithm']}")
# Output: Dilithium3 (NIST Level 3)
```

**PQC Algorithms:**
- **Dilithium3**: Digital signatures (NIST Level 3 = AES-192)
- **Kyber1024**: Key encapsulation (NIST Level 5 = AES-256)
- **Status**: NIST standardized (2024)
- **Quantum Resistance**: Protected against Shor's algorithm

#### Classical Cryptography

**Hashing:**
- SHA3-256 (primary)
- SHA-256 (compatibility)
- BLAKE2b (performance)

**Encryption:**
- AES-256-GCM (authenticated encryption)
- ChaCha20-Poly1305 (alternative)

**Key Derivation:**
- Argon2id (password-based)
- HKDF-SHA256 (key expansion)

**MACs:**
- HMAC-SHA3-256 (primary)
- HMAC-SHA256 (compatibility)

### Hybrid Mode

The library uses **hybrid cryptography** by default:

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Hybrid signature combines:
# 1. Classical HMAC-SHA3-256
# 2. PQC Dilithium3
# Both must verify for signature to be valid

data = "sensitive_data"
signature = pqc.sign(data)  # Hybrid signature

# Verification requires BOTH classical AND PQC to pass
is_valid = pqc.verify(data, signature)
```

**Benefits:**
- ✅ Protected if classical crypto remains secure
- ✅ Protected if PQC remains secure  
- ✅ Only vulnerable if BOTH are broken
- ✅ Future-proof security

---

## Threat Model

### Threats Protected Against

#### ✅ 1. License Piracy

**Threat:** User copies license to different device

**Protection:**
```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# Bind license to device
bound_token = fp.bind_token("LICENSE-KEY")

# Verification fails on different device
is_valid = fp.verify_token(bound_token)  # False on different device
```

**Security Level:** High effectiveness

#### 2. Token Tampering

**Threat:** Attacker modifies bound token

**Protection:**
```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Cryptographic signature
data = "license:ABC-123"
signature = pqc.sign(data)

# Tampering detected
tampered_data = "license:ABC-999"
is_valid = pqc.verify(tampered_data, signature)  # False
```

**Security Level:** Enhanced with hybrid cryptography

#### 3. Replay Attacks

**Threat:** Attacker intercepts and reuses valid token

**Protection:**
```python
from device_fingerprinting import DeviceFingerprinter
from datetime import datetime, timedelta

fp = DeviceFingerprinter()

# Include timestamp in binding
metadata = {
    'timestamp': datetime.now().isoformat(),
    'expires_at': (datetime.now() + timedelta(days=365)).isoformat()
}

bound_token = fp.bind_token("LICENSE", metadata=metadata)

# Verify timestamp on each check
# (implement in your application logic)
```

**Security Level:** Effective when combined with timestamp validation

#### 4. Quantum Computing Attacks

**Threat:** Future quantum computers break classical crypto

**Protection:**
```python
from device_fingerprinting.hybrid_pqc import HybridPQC

# PQC protection enabled by default
pqc = HybridPQC()

# Dilithium3 is quantum-resistant
signature = pqc.sign(data)
```

**Security Level:** NIST Level 3 security strength

#### 5. VM Cloning

**Threat:** User clones virtual machine

**Protection:**
```python
from device_fingerprinting import DeviceFingerprinter

# Use advanced mode + network + USB
fp = DeviceFingerprinter(
    advanced_mode=True,
    include_network=True,
    include_usb=True
)

result = fp.generate()

# Check confidence - VM clones may have lower scores
if result.confidence_score < 0.8:
    print("⚠️ Possible VM clone detected")
```

**Security Level:** Moderate - determined attackers may bypass

#### 6. Hardware Emulation

**Threat:** Attacker emulates hardware characteristics

**Protection:**
```python
from device_fingerprinting import DeviceFingerprinter

# Enable ML-based anomaly detection
fp = DeviceFingerprinter(
    enable_ml=True,
    advanced_mode=True
)

result = fp.generate()

# ML can detect suspicious patterns
if hasattr(result, 'anomaly_score') and result.anomaly_score > 0.7:
    print("⚠️ Anomaly detected - possible emulation")
```

**Security Level:** Moderate - effectiveness depends on ML model training

### Known Limitations

#### 1. Physical Hardware Access

The library cannot prevent:
- Physical theft of device
- Hardware modifications by expert technicians
- Direct memory access attacks

**Mitigation:** Implement additional security layers such as HSM, TPM, or secure boot

#### 2. Root/Admin Compromise

If attacker has root/admin access:
- Can modify system to spoof hardware IDs
- Can extract keys from memory
- Can disable security features

**Mitigation:** Apply code obfuscation, anti-debugging techniques, and runtime integrity checks

#### 3. Side-Channel Attacks

Advanced attacks like:
- Timing attacks (partially mitigated)
- Power analysis (PQC has protection)
- Cache attacks

**Mitigation:** Use HSM for critical operations

---

## Security Features

### 1. Token Binding

```python
from device_fingerprinting import DeviceFingerprinter

fp = DeviceFingerprinter()

# Cryptographically bind token to device
license_key = "ABC-123-XYZ"
bound_token = fp.bind_token(license_key)

# Token includes:
# - Device fingerprint (hashed)
# - License key (encrypted)
# - HMAC signature
# - Timestamp
# - Random salt

# Verification requires:
# 1. Correct device (fingerprint match)
# 2. Valid signature (not tampered)
# 3. Correct decryption (authentic token)
```

### 2. Signature Verification

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Multi-layer signature
data = "sensitive_data"
signature = pqc.sign(data)

# Verification process:
# 1. Classical HMAC-SHA3-256 verification
# 2. PQC Dilithium3 verification
# 3. Timestamp validation (if included)
# 4. Metadata integrity check

is_valid = pqc.verify(data, signature)
```

### 3. Tamper Detection

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()

# Protect critical data
config_data = '{"max_devices": 1, "features": ["premium"]}'
signature = pqc.sign(config_data)

# Store both
save_config(config_data, signature)

# Later: verify integrity
loaded_config = load_config()
loaded_signature = load_signature()

if pqc.verify(loaded_config, loaded_signature):
    print("✅ Configuration intact")
else:
    print("❌ TAMPERING DETECTED - Configuration modified!")
    # Take action: reset to defaults, alert admin, etc.
```

### 4. Secure Storage

```python
from device_fingerprinting.secure_storage import SecureStorage

# Encrypted storage for sensitive data
storage = SecureStorage()

# Store encrypted
storage.store('license_token', bound_token)
storage.store('fingerprint', fingerprint)

# Retrieve encrypted
token = storage.retrieve('license_token')

# Data is encrypted at rest with:
# - AES-256-GCM encryption
# - Unique per-installation key
# - IV/nonce for each entry
```

### 5. Key Rotation

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

class KeyRotationManager:
    def __init__(self):
        self.current_pqc = HybridPQC()
        self.rotation_interval = 90 * 24 * 3600  # 90 days
    
    def rotate_keys(self):
        """Generate new PQC keys"""
        # Create new PQC instance (new keys)
        new_pqc = HybridPQC()
        
        # Re-sign all critical data with new keys
        # ...
        
        self.current_pqc = new_pqc
        return new_pqc.get_info()
```

---

## Best Practices

### Secure Implementation

#### ✅ 1. Always Use Token Binding

```python
# ❌ BAD: Store raw license key
license_key = "ABC-123"
save_to_file(license_key)  # Insecure!

# ✅ GOOD: Bind to device
fp = DeviceFingerprinter()
bound_token = fp.bind_token(license_key)
save_to_file(bound_token)  # Secure!
```

#### ✅ 2. Enable PQC Protection

```python
# ❌ BAD: Classical crypto only
fp = DeviceFingerprinter()
bound_token = fp.bind_token(license_key)

# ✅ GOOD: Add PQC signature
from device_fingerprinting.hybrid_pqc import HybridPQC

fp = DeviceFingerprinter()
pqc = HybridPQC()

result = fp.generate()
binding_data = f"{license_key}:{result.fingerprint}"
signature = pqc.sign(binding_data)

# Store both
save_license({
    'bound_token': fp.bind_token(license_key),
    'pqc_signature': signature
})
```

#### ✅ 3. Validate Confidence Scores

```python
# ✅ Check confidence before trusting fingerprint
result = fp.generate()

if result.confidence_score < 0.7:
    print("⚠️ Low confidence - hardware may have changed")
    # Request additional verification
    # Log security event
    # Or deny access
elif result.confidence_score < 0.9:
    print("⚠️ Medium confidence - minor changes detected")
    # Allow but log for review
else:
    print("✅ High confidence")
```

#### ✅ 4. Implement Rate Limiting

```python
from datetime import datetime, timedelta
from collections import defaultdict

class RateLimiter:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.max_attempts = 5
        self.window = 300  # 5 minutes
    
    def check_rate_limit(self, identifier):
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window)
        
        # Remove old attempts
        self.attempts[identifier] = [
            t for t in self.attempts[identifier]
            if t > cutoff
        ]
        
        # Check limit
        if len(self.attempts[identifier]) >= self.max_attempts:
            return False
        
        self.attempts[identifier].append(now)
        return True

# Usage
limiter = RateLimiter()

def verify_license(license_key):
    if not limiter.check_rate_limit(license_key):
        print("❌ Rate limit exceeded - possible attack")
        return False
    
    # Proceed with verification
    # ...
```

#### ✅ 5. Secure Error Handling

```python
# ❌ BAD: Expose internal details
try:
    is_valid = fp.verify_token(bound_token)
except Exception as e:
    print(f"Error: {e}")  # May leak sensitive info!

# ✅ GOOD: Generic error messages
try:
    is_valid = fp.verify_token(bound_token)
except Exception as e:
    # Log detailed error internally
    logger.error(f"Verification failed: {e}", exc_info=True)
    
    # Show generic message to user
    print("Verification failed. Please contact support.")
```

#### ✅ 6. Use Encrypted Storage

```python
from device_fingerprinting.secure_storage import SecureStorage

# ✅ Store sensitive data encrypted
storage = SecureStorage()

storage.store('license_token', bound_token)
storage.store('activation_date', datetime.now().isoformat())

# Later retrieval
token = storage.retrieve('license_token')
```

#### ✅ 7. Implement Audit Logging

```python
import logging
from datetime import datetime

# Configure secure logging
logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def verify_with_audit(bound_token):
    fp = DeviceFingerprinter()
    
    try:
        is_valid = fp.verify_token(bound_token)
        
        # Log verification attempt
        logging.info(
            f"License verification: "
            f"valid={is_valid}, "
            f"timestamp={datetime.now().isoformat()}"
        )
        
        if not is_valid:
            logging.warning("Invalid license verification attempt")
        
        return is_valid
        
    except Exception as e:
        logging.error(f"Verification error: {e}", exc_info=True)
        return False
```

### Deployment Security

#### ✅ 1. Code Obfuscation

```python
# Use PyArmor or similar to obfuscate production code
# pyarmor pack -e "--onefile" your_app.py
```

#### ✅ 2. Secure Distribution

- Sign your application packages
- Use HTTPS for downloads
- Implement code signing certificates
- Verify integrity on first run

#### ✅ 3. Update Mechanism

```python
import hashlib
import requests

def secure_update_check():
    """Check for updates with signature verification"""
    # Download update info
    response = requests.get('https://your-server.com/update.json')
    update_info = response.json()
    
    # Verify signature
    pqc = HybridPQC()
    if not pqc.verify(
        update_info['version_data'],
        update_info['signature']
    ):
        print("❌ Invalid update signature!")
        return False
    
    # Proceed with update
    # ...
```

---

## Compliance

### GDPR Compliance

**Personal Data Considerations:**

The library **does not collect or transmit** personal data by default:

- ✅ Fingerprints are hashed (not reversible)
- ✅ No user identification information included
- ✅ Hardware IDs are anonymized
- ✅ Data stays on local device

**Your Responsibilities:**
- Inform users about device fingerprinting in privacy policy
- Obtain consent if required by your jurisdiction
- Allow users to request data deletion
- Don't combine fingerprints with personal data without consent

```python
# Example: Privacy-compliant implementation
def generate_anonymous_fingerprint():
    """Generate fingerprint without personal data"""
    fp = DeviceFingerprinter(
        include_network=False,  # Don't include MAC addresses
        include_usb=False       # Don't include USB devices
    )
    
    result = fp.generate()
    
    # Only use hashed fingerprint
    return result.fingerprint  # Already hashed
```

### SOC 2 / ISO 27001

**Security Controls:**

**Access Control**
- Cryptographic key protection mechanisms
- Secure storage implementation
- Role-based access control (implemented at application level)

**Data Protection**
- Encryption at rest using AES-256-GCM
- Encryption in transit (application's responsibility)
- Secure key derivation with Argon2id

**Audit Logging**
```python
# Implement audit trail
def audit_log(event, details):
    logging.info(
        json.dumps({
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'details': details,
            'user': get_current_user()  # Your implementation
        })
    )
```

**Vulnerability Management**
- Regular dependency updates recommended
- Security scanning with Bandit and CodeQL
- No known vulnerabilities as of November 2025

### PCI DSS (Payment Card Industry)

When implementing for payment security:

**Requirement 3**: Protect stored data
- Encrypted storage available
- Key management features provided

**Requirement 6**: Secure development
- Follows secure coding practices
- Regular security testing conducted

**Requirement 8**: Access control
- Device binding capabilities
- Multi-factor authentication support

**Requirement 10**: Audit logging
- Application must implement logging

---

## Security Checklist

### Pre-Deployment Checklist

- [ ] Install PQC libraries (`pqcdualusb`)
- [ ] Implement token binding instead of storing raw keys
- [ ] Configure encrypted storage using `SecureStorage`
- [ ] Add rate limiting to prevent brute force attacks
- [ ] Implement audit logging for security events
- [ ] Validate confidence scores before accepting results
- [ ] Review error handling to prevent information disclosure
- [ ] Consider code obfuscation for sensitive deployments
- [ ] Conduct security testing and vulnerability scans
- [ ] Update all dependencies to current versions

### Runtime Security Checklist

- [ ] Monitor and log failed verification attempts
- [ ] Maintain comprehensive security event logs
- [ ] Configure alerts for anomalous behavior
- [ ] Enforce rate limiting on API requests
- [ ] Validate and sanitize all user inputs
- [ ] Use HTTPS for all network communications
- [ ] Establish key rotation schedule
- [ ] Implement secure backup procedures

---

## Next Steps

- **Deployment Guide**: [Production Deployment →](WIKI_DEPLOYMENT.md)
- **PQC Guide**: [Post-Quantum Cryptography →](WIKI_PQC.md)
- **HSM Integration**: [HSM Guide →](WIKI_HSM.md)
- **Monitoring**: [Analytics Dashboard →](WIKI_MONITORING.md)

---

**Navigation**: [← Home](WIKI_HOME.md) | [Deployment →](WIKI_DEPLOYMENT.md)
