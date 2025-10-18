# Device Fingerprinting Library

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-57_passing-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/security-hardened-red.svg)](SECURITY.md)

A production-ready Python library for **hardware-based device fingerprinting**. It is designed to be robust, secure, and easy to integrate, providing a reliable way to identify and verify devices.

This library has been hardened with a comprehensive test suite, ensuring that all core components are validated and function as expected.

## 📖 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Core Concepts Explained](#-core-concepts-explained)
  - [1. The Fingerprinting Process](#1-the-fingerprinting-process)
  - [2. The Cryptographic Engine](#2-the-cryptographic-engine)
  - [3. Secure Storage](#3-secure-storage)
  - [4. ML Anomaly Detection](#4-ml-anomaly-detection)
- [Testing & Validation](#-testing--validation)
- [Dependencies](#-dependencies)
- [Contributing](#-contributing)
- [License](#️-license)

## 🏛️ Architectural Overview

This library is built on a modular architecture that separates concerns, making it robust and easy to maintain. The diagram below illustrates the high-level interaction between the main components.

```
+---------------------------------+
|      Application / Your Code    |
+---------------------------------+
              |
              v
+---------------------------------+
| ProductionFingerprintGenerator  |
|       (Primary Public API)      |
+---------------------------------+
|      |            |             |
|      v            v             v
| +----------+ +-----------+ +-----------------+
| |  Crypto  | |MLFeatures | |  SecureStorage  |
| |(Hashing, | | (Anomaly  | |  (Encrypted     |
| |Encrypting)| | Detection)| |   Data Store)   |
| +----------+ +-----------+ +-----------------+
|      |             |
|      v             v
| +----------+ +-----------+
| | Hardware | |  System   |
| |(CPU, MAC)| |(OS, etc.) |
| +----------+ +-----------+
```

-   **ProductionFingerprintGenerator**: The main entry point for generating device fingerprints.
-   **Crypto**: A module providing cryptographic primitives like hashing (SHA3) and encryption (AES-GCM).
-   **MLFeatures**: A component that uses machine learning (`IsolationForest`) to detect anomalies in system behavior.
-   **SecureStorage**: A class for securely storing and retrieving encrypted data, using the system's keyring or a password-derived key.
-   **Hardware/System Collectors**: Internal functions that gather the raw data used to generate the fingerprint.

## ✨ Features

-   **Stable Device Fingerprinting**: Generates a consistent identifier from hardware and software attributes.
-   **Robust Security**:
    -   **Strong Encryption**: Uses AES-GCM for encrypting sensitive data.
    -   **Secure Key Derivation**: Employs Scrypt (a memory-hard KDF) to protect against brute-force attacks on passwords.
-   **Machine Learning Anomaly Detection**:
    -   Monitors system behavior (CPU, memory, etc.).
    -   Uses an `IsolationForest` model to detect deviations from a normal baseline.
-   **Secure Encrypted Storage**:
    -   Stores data in an encrypted format at rest.
    -   Integrates with system keyrings (`Windows Credential Locker`, `macOS Keychain`, etc.) for enhanced security.
-   **Production-Ready & Tested**: Comes with a comprehensive suite of 57 passing `pytest` tests, ensuring reliability and correctness.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Johnsonajibi/DeviceFingerprinting.git
cd DeviceFingerprinting/device_fingerprinting

# Install dependencies
pip install -r requirements.txt

# Install the package in editable mode
pip install -e .
```

## 🚀 Quick Start

The following example demonstrates how to generate a fingerprint and use the anomaly detector.

```python
from device_fingerprinting.production_fingerprint import ProductionFingerprintGenerator
from device_fingerprinting.ml_features import FeatureExtractor, AnomalyDetector
import numpy as np

# --- 1. Generate a Device Fingerprint ---
print("--- Generating Device Fingerprint ---")
fp_generator = ProductionFingerprintGenerator()
fingerprint_data = fp_generator.generate_fingerprint()
print(f"Fingerprint Hash: {fingerprint_data['fingerprint_hash']}")
print(f"Platform: {fingerprint_data['system_info']['platform']}")
print("-" * 20)

# --- 2. Use the ML Anomaly Detector ---
print("\n--- ML Anomaly Detection ---")
# In a real application, you would train the model on data from a known-good state.
# For this demo, we'll train it on random "normal" data.
normal_data = np.random.rand(100, 3)
detector = AnomalyDetector()
detector.train(normal_data)
print("Anomaly detector trained on baseline data.")

# Collect current system features
feature_extractor = FeatureExtractor()
current_features = feature_extractor.collect_features()
prediction, score = detector.predict(current_features)

if prediction == 1:
    print(f"System behavior is NORMAL (Score: {score:.2f})")
else:
    print(f"System behavior is ANOMALOUS (Score: {score:.2f})")

# Now, test with a clear anomaly
anomalous_data = np.array([[10.0, -5.0, 100.0]])
prediction, score = detector.predict(anomalous_data)
print(f"Prediction for outlier data: {'ANOMALY' if prediction == -1 else 'NORMAL'} (Score: {score:.2f})")
print("-" * 20)
```

## 🔬 Core Concepts Explained

### 1. The Fingerprinting Process

The device fingerprint is a unique hash generated from a collection of system attributes. This process is designed to be deterministic, meaning the same device will consistently produce the same fingerprint.

```
+-----------------------+    +-----------------------+    +---------------------+
|  Collect Hardware     |    |  Collect Software     |    |  Collect Security   |
|  Info (CPU, RAM, MAC) |    |  Info (OS, Python Ver)|    |  Info (Is Admin?)   |
+-----------------------+    +-----------------------+    +---------------------+
           |                           |                            |
           +---------------------------+----------------------------+
                                       |
                                       v
                          +--------------------------+
                          |  Combine into a single   |
                          |      JSON object         |
                          +--------------------------+
                                       |
                                       v
                          +--------------------------+
                          |  Serialize to a stable,  |
                          |     sorted JSON string   |
                          +--------------------------+
                                       |
                                       v
                          +--------------------------+
                          |   Hash with SHA3-512     |
                          +--------------------------+
                                       |
                                       v
                          +--------------------------+
                          |   Final Fingerprint Hash |
                          +--------------------------+
```

### 2. The Cryptographic Engine

Security is a core design principle. The library uses strong, modern cryptographic primitives for hashing, key derivation, and encryption.

```
+--------------------------+                             +--------------------------+
|         Password         |---- (generates) ---->       |      Encryption Key      |
|   (e.g., "my-secret")    |                             |       (32 bytes)         |
+--------------------------+                             +--------------------------+
             |                                                         |
             v                                                         v
+--------------------------+                             +--------------------------+
| Plaintext Data (JSON)    |---- (encrypts with) ---->   |      AES-GCM Encrypted   |
+--------------------------+                             |           Blob           |
                                                         +--------------------------+
```

-   **Scrypt**: We use Scrypt to derive the encryption key from a user-provided password. Because it is memory-hard, it is highly resistant to custom hardware attacks and brute-forcing.
-   **AES-GCM**: All sensitive data is encrypted using AES in Galois/Counter Mode. This provides both confidentiality and authenticity, protecting against tampering.

### 3. Secure Storage

The `SecureStorage` class provides a simple, dictionary-like interface for storing encrypted data on disk. It automatically handles encryption and decryption.

For enhanced security, it will first attempt to use the operating system's native keyring (like Windows Credential Locker or macOS Keychain) to store the encryption password. This is more secure than leaving the password in code. If a keyring is not available, it falls back to using the password directly.

### 4. ML Anomaly Detection

The library includes a machine learning component to detect unusual system behavior. This can be used as an additional layer of security to flag if a fingerprinting attempt is happening in a suspicious environment (e.g., under heavy CPU load that might indicate a debugger is attached).

```
+------------------------+    +------------------------+    +------------------------+
|  Collect CPU Usage     |    | Collect Memory Usage   |    | Collect Battery Level  |
+------------------------+    +------------------------+    +------------------------+
            |                          |                           |
            +--------------------------+---------------------------+
                                       |
                                       v
                          +--------------------------+
                          |  Create Feature Vector   |
                          |      (NumPy Array)       |
                          +--------------------------+
                                       |
                                       v
                          +--------------------------+
                          |     AnomalyDetector      |
                          |   (IsolationForest Model)|
