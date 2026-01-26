---
layout: default
title: Architecture Overview
---

# Architecture Overview

Comprehensive visual guide to the Device Fingerprinting Library architecture.

## System-Level Architecture

### High-Level Component Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                        Your Application                        │
│                   (Web App, Desktop, Mobile)                   │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────────┐
│              Device Fingerprinting Library API                 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Fingerprinting │  │ Cryptography │  │ Storage Engine │  │
│  │    Engine       │  │    Module    │  │                │  │
│  └────────┬────────┘  └──────┬───────┘  └────────┬───────┘  │
│           │                  │                   │           │
│  ┌────────┴──────────────────┴───────────────────┴───────┐  │
│  │                                                        │  │
│  │  ┌──────────────────┐      ┌──────────────────────┐  │  │
│  │  │   ML Engine      │      │  TPM Interface      │  │  │
│  │  │  (Anomaly Det.)  │      │  (Hardware Crypto)  │  │  │
│  │  └──────────────────┘      └──────────────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┬─────────────────┐
        │                │                │                 │
        ▼                ▼                ▼                 ▼
   ┌─────────┐    ┌──────────┐     ┌────────┐      ┌────────────┐
   │Hardware │    │    OS    │     │ Disk   │      │   TPM      │
   │  Info   │    │ Keyring  │     │Storage │      │  Hardware  │
   └─────────┘    └──────────┘     └────────┘      └────────────┘
```

---

## Data Flow Architecture

### Fingerprint Generation Flow

```
START
  │
  ├─────────────────────────────────────────┐
  │                                         │
  ▼                                         ▼
Collect Hardware          Collect System
Information              Information
  │                         │
  ├─ CPU Details            ├─ OS Type
  ├─ Disk Serial            ├─ Kernel Version
  ├─ MAC Addresses          ├─ System UUID
  ├─ BIOS/UEFI              └─ Hostname
  └─ Motherboard Board         │
  │                         │
  └─────────────────────────┘
  │
  ▼
Normalize Data
  │
  ├─ Remove whitespace
  ├─ Standardize formats
  ├─ Handle missing values
  └─ Validate input
  │
  ▼
Apply Cryptographic Hash (SHA-3-256)
  │
  ├─ Create stable fingerprint
  ├─ Ensure deterministic output
  └─ Support collision detection
  │
  ▼
Return FingerprintResult
  │
  ├─ Fingerprint (hex string)
  ├─ Confidence score
  ├─ Components used
  └─ Timestamp
  │
  ▼
END
```

### Secure Storage Flow

```
START (Store Encrypted Data)
  │
  ▼
Validate Input
  │
  ├─ Check key format
  ├─ Verify value type
  └─ Sanitize data
  │
  ▼
Derive Encryption Key
  │
  ├─ Get password from user/config
  ├─ Generate random salt (256 bits)
  ├─ Apply Scrypt KDF
  │  ├─ N=32768 (CPU cost)
  │  ├─ r=8 (block size)
  │  └─ p=1 (parallelization)
  └─ Output: 256-bit key
  │
  ▼
Generate Random Nonce
  │
  └─ 96 bits for GCM mode
  │
  ▼
Encrypt with AES-256-GCM
  │
  ├─ Mode: Galois/Counter Mode
  ├─ Key: 256 bits
  ├─ Authentication: Enabled
  └─ Produces: ciphertext + auth tag
  │
  ▼
Format Storage Entry
  │
  └─ [nonce | ciphertext | auth_tag]
  │
  ▼
Store to Backend
  │
  ├─ Option 1: OS Keyring
  │  ├─ Windows Credential Manager
  │  ├─ macOS Keychain
  │  └─ Linux Secret Service
  │
  ├─ Option 2: Encrypted Filesystem
  │  ├─ ~/.config/device-fingerprinting/
  │  └─ Additional filesystem encryption
  │
  └─ Option 3: Memory (temporary)
     └─ Cleared on exit
  │
  ▼
END (Store Encryption, Success)
```

### Retrieval and Decryption Flow

```
START (Retrieve Encrypted Data)
  │
  ▼
Read from Backend
  │
  ├─ Fetch from OS Keyring
  ├─ Read from filesystem
  └─ Extract from memory
  │
  ▼
Parse Storage Entry
  │
  └─ Extract: [nonce | ciphertext | auth_tag]
  │
  ▼
Derive Encryption Key (Same Process)
  │
  ├─ Get password from user/config
  ├─ Use stored salt
  ├─ Apply Scrypt KDF with same parameters
  └─ Output: Same 256-bit key
  │
  ▼
Decrypt with AES-256-GCM
  │
  ├─ Verify authentication tag
  ├─ Check for tampering
  ├─ Decrypt ciphertext
  └─ Returns: plaintext or error
  │
  ▼
Validation
  │
  ├─ Verify plaintext format
  ├─ Check content integrity
  └─ Sanitize output
  │
  ▼
Return Plaintext
  │
  ▼
END (Retrieval, Success)
```

---

## Anomaly Detection Architecture

### ML Pipeline

```
System Metrics Collection
      │
      ├─ CPU metrics
      │  ├─ Usage percentage
      │  ├─ Load average
      │  └─ Context switches
      │
      ├─ Memory metrics
      │  ├─ Usage percentage
      │  ├─ Available memory
      │  └─ Swap usage
      │
      ├─ Disk metrics
      │  ├─ I/O read/write
      │  ├─ Usage percentage
      │  └─ Free space
      │
      ├─ Network metrics
      │  ├─ Bytes sent/received
      │  ├─ Packets sent/received
      │  └─ Connection count
      │
      └─ Process metrics
         ├─ Process count
         ├─ Top processes
         └─ Memory consumers
      │
      ▼
Feature Normalization
      │
      ├─ Z-score normalization
      │  └─ (value - mean) / std_dev
      │
      └─ Min-max scaling
         └─ (value - min) / (max - min)
      │
      ▼
Isolation Forest Algorithm
      │
      ├─ Build random decision trees
      ├─ Calculate anomaly score
      │  └─ Path length analysis
      └─ Generate confidence metric
      │
      ▼
Anomaly Classification
      │
      ├─ Score < 0.3: Normal
      ├─ Score 0.3-0.7: Suspicious
      └─ Score > 0.7: Anomalous
      │
      ▼
Return Detection Result
      │
      ├─ is_anomalous: boolean
      ├─ confidence: 0.0-1.0
      └─ contributing_features: dict
      │
      ▼
END (Anomaly Detection)
```

---

## Security Architecture

### Cryptographic Layers

```
┌─────────────────────────────────────────────┐
│        Application Layer                    │
│   (Input validation, access control)        │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│     API Security Layer                      │
│   (Rate limiting, authentication)           │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│   Cryptographic Layer                       │
│                                             │
│  ┌─────────────────────────────────────┐  │
│  │ Hashing Layer (SHA-3)              │  │
│  │ └─ Fingerprint generation          │  │
│  └─────────────────────────────────────┘  │
│                                            │
│  ┌─────────────────────────────────────┐  │
│  │ Key Derivation Layer (Scrypt)      │  │
│  │ └─ Password → Key conversion       │  │
│  └─────────────────────────────────────┘  │
│                                            │
│  ┌─────────────────────────────────────┐  │
│  │ Encryption Layer (AES-256-GCM)     │  │
│  │ ├─ Symmetric encryption            │  │
│  │ └─ Authenticated encryption        │  │
│  └─────────────────────────────────────┘  │
│                                            │
│  ┌─────────────────────────────────────┐  │
│  │ Post-Quantum Layer (optional)      │  │
│  │ ├─ Kyber (key exchange)            │  │
│  │ └─ Dilithium (signatures)          │  │
│  └─────────────────────────────────────┘  │
└────────────────────┬──────────────────────┘
                     │
┌────────────────────▼──────────────────────┐
│    Storage Layer                          │
│  ├─ OS Keyring (Windows/macOS/Linux)     │
│  ├─ Encrypted Filesystem                 │
│  └─ In-Memory (temporary)                │
└────────────────────┬──────────────────────┘
                     │
┌────────────────────▼──────────────────────┐
│    Hardware Layer                         │
│  ├─ TPM 2.0                              │
│  ├─ Secure Enclave (macOS)               │
│  └─ Hardware Security Modules            │
└──────────────────────────────────────────┘
```

---

## TPM Integration Architecture

### TPM-Based Fingerprinting

```
START (TPM-Based Fingerprint)
  │
  ▼
Check TPM Availability
  │
  ├─ Is TPM hardware present?
  ├─ Is TPM initialized?
  └─ Can user access TPM?
  │
  ├─ YES──────────────┐
  │                  │
  │                  ▼
  │            Create TPM Key
  │              │
  │              ├─ Create primary key
  │              ├─ Define key parameters
  │              └─ Derive child key
  │              │
  │              ▼
  │            Extend PCR (Platform Config Reg)
  │              │
  │              ├─ Add hardware measurements
  │              ├─ Add system state
  │              └─ Create attestation evidence
  │              │
  │              ▼
  │            Sign with TPM Key
  │              │
  │              ├─ Use TPM attestation key
  │              ├─ Create hardware signature
  │              └─ Generate proof
  │              │
  │              ▼
  │            TPM Fingerprint
  │              │
  │              ├─ Hardware-backed
  │              ├─ Cryptographically signed
  │              └─ Tamper-evident
  │
  └─ NO───────────────┐
                     │
                     ▼
            Software Fallback
              │
              ├─ Use standard hashing
              ├─ No hardware attestation
              └─ Software-based only
              │
              ▼
            Software Fingerprint
              │
              ├─ Still cryptographically secure
              ├─ Deterministic
              └─ Hardware-derived
  │
  ▼
END (Fingerprint Generated)
```

---

## Module Dependencies

### Core Dependencies

```
device_fingerprinting/
│
├─ device_fingerprinting.py
│  └─ Main API (imports below modules)
│
├─ crypto.py
│  ├─ cryptography (AES-GCM, SHA-3, Scrypt)
│  └─ Implementation: CryptoEngine
│
├─ secure_storage.py
│  ├─ crypto.py
│  ├─ keyring (OS integration)
│  └─ Implementation: SecureStorage
│
├─ ml_features.py
│  ├─ scikit-learn (ML algorithms)
│  ├─ numpy (numerical operations)
│  └─ Implementation: MLAnomalyDetector
│
├─ production_fingerprint.py
│  ├─ device_fingerprinting.py
│  ├─ crypto.py
│  ├─ secure_storage.py
│  ├─ ml_features.py
│  └─ Implementation: ProductionFingerprintGenerator
│
├─ tpm_hardware.py (optional)
│  ├─ tpm2-pytss (TPM interface)
│  └─ Implementation: TPM integration
│
├─ quantum_resistant_backends.py (optional)
│  ├─ liboqs or tpm2-pytss
│  └─ Implementation: PQC algorithms
│
└─ exceptions.py
   └─ Custom exception classes
```

---

## Request/Response Flow

### Typical Fingerprint Request

```
User Code
   │
   │  generator.generate_fingerprint()
   │
   ▼
ProductionFingerprintGenerator.generate_fingerprint()
   │
   ├─ Validate parameters
   │
   ├─ Check TPM status
   │
   ├─ Collect hardware info
   │  ├─ DeviceFingerprinter.collect_hardware()
   │  └─ Get CPU, disk, MAC, etc.
   │
   ├─ Collect system info
   │  ├─ DeviceFingerprinter.collect_system()
   │  └─ Get OS, memory, UUID, etc.
   │
   ├─ Normalize data
   │  └─ StandardizeFormat() for each component
   │
   ├─ Hash components
   │  ├─ CryptoEngine.hash_data()
   │  └─ SHA-3-256
   │
   ├─ Apply algorithm-specific processing
   │  ├─ BASIC: Simple concatenation
   │  ├─ ADVANCED: Extended feature set
   │  └─ QUANTUM_RESISTANT: PQC signatures
   │
   ├─ Calculate confidence
   │  └─ Based on component stability
   │
   └─ Return FingerprintResult
   │
   └─ fingerprint: str
      confidence: float
      timestamp: datetime
      components: list
      warnings: list
   │
   ▼
User Code
```

---

## Error Handling Architecture

### Error Flow

```
Operation (fingerprint, encrypt, store, etc.)
   │
   ▼
Input Validation
   │
   ├─ Format check
   ├─ Type check
   └─ Value range check
   │
   ├─ INVALID ──────┐
   │               │
   │               ▼
   │        Validation Error
   │               │
   │               └─> Return error
   │
   ▼
   VALID
   │
   ├─ Execute operation
   │
   ├─ FAILED ──────┐
   │              │
   │              ▼
   │        Specific Error
   │        ├─ FingerprintError
   │        ├─ StorageError
   │        ├─ CryptoError
   │        ├─ AnomalyDetectionError
   │        └─ TPMError
   │              │
   │              ├─ Log error (sanitized)
   │              ├─ Attempt recovery
   │              └─ Return error to user
   │
   ▼
   SUCCESS
   │
   ├─ Return result
   ├─ Optional: Log success (non-sensitive)
   └─ Cleanup resources
   │
   ▼
Operation Complete
```

---

## Deployment Architecture

### Single Machine Deployment

```
┌──────────────────────────────┐
│   User Application           │
└────────────┬─────────────────┘
             │
             ▼
┌──────────────────────────────┐
│  Device Fingerprinting Lib   │
├──────────────────────────────┤
│ • Fingerprint generation     │
│ • Anomaly detection          │
│ • Secure storage             │
└────────────┬─────────────────┘
             │
    ┌────────┼────────┬────────┐
    │        │        │        │
    ▼        ▼        ▼        ▼
 OS Keyring Disk    Memory    TPM
 Storage   Storage  Storage  Hardware
```

### Distributed Deployment

```
┌─────────────────┐
│  Client App 1   │
└────────┬────────┘
         │ fingerprint request
         │
┌────────▼──────────────┐
│ Central Verification  │
│ Service               │
├──────────────────────┤
│ • Verify fingerprint │
│ • Check device known │
│ • Detect anomalies   │
└────────┬──────────────┘
         │
    ┌────┴────┬─────────┐
    │         │         │
    ▼         ▼         ▼
  Database  Logs    Alert System
```

---

## Performance Characteristics

### Timing Profile

```
Operation               Typical Time    Range
─────────────────────────────────────────────
Fingerprint (Basic)     ~50ms          40-80ms
Fingerprint (Advanced)  ~150ms         100-200ms
Fingerprint (QR)        ~250ms         200-350ms
Anomaly Detection       ~30ms          20-50ms
Encryption (AES)        ~5ms           2-10ms
Decryption (AES)        ~5ms           2-10ms
Storage (write)         <5ms           0-10ms
Storage (read)          <5ms           0-10ms
Key Derivation (Scrypt) ~250ms         150-400ms
```

### Memory Profile

```
Component                   Memory
─────────────────────────────────
Library loaded              ~10 MB
Fingerprint generator       ~5 MB
ML model (in-memory)        ~20 MB
Storage backend             ~5 MB
Total (idle)                ~40 MB
```

---

## Scalability Considerations

### Horizontal Scaling

- **Stateless design**: Each instance can operate independently
- **Multiple devices**: No limit on concurrent devices
- **Distributed storage**: Can use remote backends

### Vertical Scaling

- **Single machine**: Handles 1000+ operations/sec
- **Memory**: Linear with connected devices
- **CPU**: Minor impact from ML processing

---

For more details on specific components, see [API Reference](api/reference.md).
