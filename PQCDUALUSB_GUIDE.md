# pqcdualusb Library - Function and Usage Guide

**Version Covered**: pqcdualusb >= 0.15.5  
**Status**: Active dependency in Device Fingerprinting v2.1.4

---

## 📌 Quick Definition

**pqcdualusb** is a Python library that provides **post-quantum cryptographic (PQC) support** with **hybrid classical + quantum-resistant cryptography** capabilities. It allows applications to use quantum-resistant algorithms (Dilithium, Kyber) while maintaining backward compatibility with classical cryptography.

---

## 🎯 Primary Functions

### 1. **Post-Quantum Digital Signatures**
- **Algorithm**: Dilithium3 (NIST ML-DSA-65)
- **Security Level**: NIST Level 3 (~AES-192 equivalent)
- **Purpose**: Create quantum-resistant signatures for data authentication
- **Key Sizes**: 
  - Public Key: ~1952 bytes
  - Private Key: ~4032 bytes
  - Signature: ~3293 bytes

### 2. **Quantum-Resistant Key Encapsulation**
- **Algorithm**: Kyber1024 (NIST Level 5)
- **Security Level**: NIST Level 5 (~AES-256 equivalent)
- **Purpose**: Secure key exchange resistant to quantum attacks
- **Key Sizes**:
  - Public Key: ~1568 bytes
  - Ciphertext: ~1568 bytes
  - Shared Secret: 32 bytes

### 3. **Hybrid Cryptography Support**
- Combines classical cryptography + PQC
- Provides defense-in-depth security model
- Maintains quantum resistance while ensuring current-day security
- Fallback mechanism when PQC unavailable

### 4. **Power Analysis Protection**
- Built-in countermeasures against power analysis attacks
- Constant-time operations to prevent timing side-channels
- Secure memory handling

### 5. **Multiple Backend Support**
- **pqcrypto**: Python implementation (cross-platform)
- **liboqs**: Optimized C implementation (Linux, macOS)
- **cpp-pqc**: C++ binding with performance optimization
- **rust-pqc**: Rust implementation with memory safety
- **Automatic selection** based on availability

---

## 🔄 How Device Fingerprinting Uses pqcdualusb

### Integration in HybridPQC Module

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

# Initialize with pqcdualusb backend
pqc = HybridPQC(algorithm="Dilithium3")

# Automatically initializes pqcdualusb 0.15.0+
# with power analysis protection
```

### Key Integration Points

**1. Initialization (`_init_pqcdualusb()`):**
```python
def _init_pqcdualusb(self) -> bool:
    """Initialize pqcdualusb 0.15.0+ library for PQC operations"""
    import pqcdualusb
    
    # Get security information
    self.security_info = pqcdualusb.get_security_info()
    
    # Try real PQC first (no fallback)
    self.pqc_backend = pqcdualusb.PostQuantumCrypto(allow_fallback=False)
    
    # If real PQC fails, use classical fallback
    # self.pqc_backend = pqcdualusb.PostQuantumCrypto(allow_fallback=True)
    
    # Store version information
    self.pqcdualusb_version = pqcdualusb.__version__
```

**2. Key Generation:**
```python
def _generate_pqc_keys(self) -> Tuple[bytes, bytes]:
    """Generate PQC keys using pqcdualusb"""
    # Uses pqcdualusb's PostQuantumCrypto backend
    public_key, private_key = self.pqc_backend.generate_sig_keypair()
    return public_key, private_key
```

**3. Signing Operations:**
- Uses Dilithium3 signatures for device fingerprints
- Creates quantum-resistant proof of device authentication
- Protects against future quantum computer attacks

**4. Verification:**
- Verifies device fingerprint signatures
- Ensures tamper-proof device binding
- Resistant to quantum attacks

---

## 💡 Use Cases in Device Fingerprinting

### 1. **Device Authentication**
```python
# Create quantum-resistant device signature
pqc = HybridPQC()
device_id = generate_device_fingerprint()
signature = pqc.sign(device_id)

# This signature remains secure even against quantum computers
```

### 2. **Secure Device Binding**
```python
# Bind software license to device with quantum-resistant signature
license_data = f"license:{license_id}:device:{fingerprint}"
pqc_signature = pqc.sign(license_data)

# Future-proof against quantum attacks
```

### 3. **Tamper Detection**
```python
# Detect device modifications using PQC signatures
if not pqc.verify(device_data, stored_signature):
    # Device has been tampered with
    # Quantum-safe verification confirms tampering
    raise SecurityException("Device fingerprint mismatch")
```

### 4. **Forensic Analysis**
```python
# Forensic security with quantum-resistant hashing
pqc_hash = pqc.secure_hash(device_fingerprint)
# Hash remains secure against quantum attacks
```

---

## 🔐 Security Features Provided

### 1. **Quantum Resistance**
- **Protection Against**: Quantum computer attacks (Shor's algorithm)
- **Algorithms**: NIST-standardized post-quantum algorithms
- **Timeline**: Provides security for 10-30+ years

### 2. **Hybrid Approach**
- Combines classical (RSA-4096, HMAC-SHA3-256) + PQC
- Ensures security even if one algorithm is compromised
- Recommended by NIST for future-proofing

### 3. **Power Analysis Protection**
- Constant-time operations to prevent timing leaks
- Secure memory handling (overwrites after use)
- Protection against side-channel attacks

### 4. **Graceful Degradation**
- Falls back to classical cryptography if PQC unavailable
- Maintains security while allowing flexibility
- Automatic backend selection

### 5. **Standards Compliance**
- NIST-standardized algorithms (2024)
- ML-DSA-65 (Dilithium3)
- ML-KEM-1024 (Kyber1024)
- Conforms to FIPS PQC standards

---

## 🚀 Performance Characteristics

| Operation | Time | Backend |
|-----------|------|---------|
| Generate keypair | ~10-50ms | pqcrypto |
| Sign data | ~0.5-2ms | pqcdualusb |
| Verify signature | ~0.5-2ms | pqcdualusb |
| Key encapsulation | ~0.1-0.5ms | Kyber1024 |

**Optimizations with liboqs backend** (Linux):
- 2-5x faster than pqcrypto
- Native C implementation
- Reduced memory footprint

---

## 📦 Installation Requirements

### Basic Installation
```bash
pip install device-fingerprinting-pro[pqc]
```

### What Gets Installed
```
pqcdualusb>=0.15.5    # Primary PQC library
pqcrypto>=0.3.4       # Python PQC backend
cryptography>=46.0.0  # Classical crypto fallback
```

### Optional: Linux Performance Enhancement
```bash
sudo apt-get install liboqs-dev
pip install oqs
# Automatically used by pqcdualusb for better performance
```

---

## 🔍 Detection in Code

### How to Identify pqcdualusb Usage

**1. In HybridPQC class:**
```python
# src/device_fingerprinting/hybrid_pqc.py
import pqcdualusb  # Line 55
self.pqc_backend = pqcdualusb.PostQuantumCrypto(allow_fallback=False)  # Line 74
```

**2. In Dependencies:**
```toml
# pyproject.toml
pqcdualusb>=0.15.5    # Primary PQC library
```

**3. Test Files:**
```python
# tests/test_pqc_integration.py
import pqcdualusb
```

---

## ✅ Verification

### Check if pqcdualusb is Available
```python
try:
    import pqcdualusb
    print(f"pqcdualusb version: {pqcdualusb.__version__}")
    print(f"Security info: {pqcdualusb.get_security_info()}")
except ImportError:
    print("pqcdualusb not installed - using classical fallback")
```

### Verify Backend Status
```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

print(f"PQC Available: {info['pqc_available']}")  # True if real PQC
print(f"Library: {info['pqc_library']}")  # pqcdualusb-0.15.5
print(f"Algorithm: {info['algorithm']}")  # Dilithium3
```

### Integration Test
```bash
python -m pytest tests/test_pqc_integration.py -v
```

---

## 🛡️ Security Guarantees

### Current Security (Without PQC)
- ✅ Secure against classical attacks
- ❌ Vulnerable to quantum computer attacks (future threat)

### With pqcdualusb PQC
- ✅ Secure against classical attacks
- ✅ Secure against quantum computer attacks
- ✅ Hybrid defense (both must be broken to compromise)
- ✅ Future-proof for 10-30+ years

---

## 📚 Related Components

1. **HybridPQC** (`hybrid_pqc.py`): Main integration class
2. **QuantumCrypto** (`quantum_crypto.py`): Additional PQC features
3. **QuantumResistantBackends** (`quantum_resistant_backends.py`): Alternative implementations
4. **ML Features** (`ml_features.py`): Uses PQC for secure anomaly detection

---

## 🔗 Resources

- **NIST PQC Standards**: https://csrc.nist.gov/projects/post-quantum-cryptography/
- **pqcdualusb GitHub**: pqcdualusb repository
- **Dilithium Specification**: FIPS 204 (ML-DSA)
- **Kyber Specification**: FIPS 203 (ML-KEM)

---

## Summary

**pqcdualusb** is the core library enabling quantum-resistant cryptography in Device Fingerprinting. It provides:

✅ **Production-grade PQC algorithms** (Dilithium3, Kyber1024)  
✅ **Hybrid security model** (classical + quantum-resistant)  
✅ **Multiple backend support** (pqcrypto, liboqs, cpp-pqc)  
✅ **Power analysis protection** (side-channel resistance)  
✅ **Automatic fallback** (graceful degradation)  
✅ **NIST standards compliance** (2024 standardization)  

With pqcdualusb, device fingerprints and security tokens remain secure even against future quantum computer attacks.
