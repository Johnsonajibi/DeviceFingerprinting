# QuantumVault Innovation Libraries - Quick Start Guide

This document provides a comprehensive guide on how to use all the innovative libraries extracted from the QuantumVault password manager system.

## 📚 Available Libraries

### 1. **dual_qr_recovery.py** - Dual QR Recovery System
Revolutionary dual QR code system for secure password recovery with cryptographic isolation.

### 2. **quantum_resistant_crypto.py** - Quantum-Resistant Cryptography  
SHA3-512 based cryptography with quantum resistance and timing attack protection.

### 3. **forward_secure_encryption.py** - Forward-Secure Page Encryption
Page-based encryption with epoch counters for forward security and selective re-encryption.

### 4. **steganographic_qr.py** - Steganographic QR System (Patent Pending)
Reed-Solomon error correction steganography for hiding data in QR codes.

### 5. **dynamic_page_sizing.py** - Dynamic Page Sizing Optimization
Automatic page size optimization based on vault characteristics.

### 6. **security_testing.py** - Security Testing Framework
Comprehensive security testing framework for cryptographic operations.

### 7. **__init__.py** - Integration Library
Main integration point with demo functionality and library availability checking.

---

## 🚀 Quick Start Examples

### Basic Usage: Dual QR Recovery System

```python
from dual_qr_recovery import DualQRRecoverySystem
from datetime import datetime

# Initialize the system
qr_system = DualQRRecoverySystem()

# Prepare recovery data
master_data = {
    "master_password_hash": "your_hash_here",
    "encryption_salt": "your_salt_here",
    "vault_key_encrypted": "your_encrypted_key_here"
}

security_data = {
    "question_1": "What was your first pet's name?",
    "answer_1_hash": "hash_of_answer_1",
    "question_2": "In what city were you born?", 
    "answer_2_hash": "hash_of_answer_2"
}

# Create dual QR system
dual_qr = qr_system.create_dual_qr_system(
    master_recovery_data=master_data,
    security_questions_data=security_data,
    expiry_hours=72
)

print(f"Primary QR ID: {dual_qr.primary_qr.qr_id}")
print(f"Secondary QR ID: {dual_qr.secondary_qr.qr_id}")
```

### Basic Usage: Quantum-Resistant Cryptography

```python
from quantum_resistant_crypto import QuantumResistantCrypto

# Initialize quantum-resistant crypto
crypto = QuantumResistantCrypto(
    salt_length=64,
    pbkdf2_iterations=600000,
    min_password_length=30
)

# Hash a password
password = "MyVerySecurePassword123!@#ForQuantumResistance2025"
hash_result = crypto.hash_password(password)

print(f"Algorithm: {hash_result.algorithm}")
print(f"Iterations: {hash_result.iterations:,}")

# Verify password
is_valid = crypto.verify_password(password, hash_result)
print(f"Password verified: {is_valid}")

# Derive encryption keys
vault_key, salt = crypto.derive_key(password, purpose="vault_encryption")
print(f"Vault key length: {len(vault_key)} bytes")
```

### Basic Usage: Forward-Secure Encryption

```python
from forward_secure_encryption import ForwardSecurePageManager
import os

# Initialize for 150-entry vault
fs_manager = ForwardSecurePageManager(vault_size=150)

# Prepare vault data
vault_data = [
    {"service": "gmail", "password": "secure_password_1"},
    {"service": "github", "password": "secure_password_2"}
]

# Generate encryption keys
old_key = os.urandom(32)
new_key = os.urandom(32)

# Perform forward-secure rotation
result = fs_manager.perform_forward_secure_rotation(
    vault_data=vault_data,
    old_key=old_key,
    new_key=new_key
)

print(f"Rotation success: {result.success}")
print(f"Pages rotated: {result.pages_rotated}")
print(f"Pages skipped: {result.pages_skipped}")
```

### Basic Usage: Steganographic QR System

```python
from steganographic_qr import SteganographicQRSystem

# Initialize steganographic QR system
steg_qr = SteganographicQRSystem()

# Prepare data
visible_data = "This is visible QR data"
hidden_data = "SECRET: Hidden recovery data"
master_key = "steganographic_encryption_key"

# Embed hidden data in QR error correction space
steg_result = steg_qr.embed_steganographic_data(
    qr_data=visible_data,
    hidden_data=hidden_data,
    master_key=master_key,
    error_level='M'
)

if steg_result:
    print(f"Steganographic QR created successfully!")
    print(f"Utilization: {steg_result['utilization_percent']:.1f}%")
    
    # Extract hidden data
    extracted = steg_qr.extract_steganographic_data(steg_result, master_key)
    print(f"Hidden data extracted: {extracted == hidden_data}")
```

### Basic Usage: Dynamic Page Sizing

```python
from dynamic_page_sizing import DynamicPageSizer

# Initialize page sizer
sizer = DynamicPageSizer()

# Calculate optimal page size for different vault sizes
vault_sizes = [50, 200, 1000, 5000]

for size in vault_sizes:
    result = sizer.calculate_optimal_page_size(size)
    print(f"{size:4d} entries: {result.optimal_page_size_kb}KB pages, "
          f"{result.expected_pages} pages, {result.memory_efficiency}% efficiency")

# Optimize for specific operations
vault_size = 300
operations = ['read', 'write', 'rotation', 'backup']

for operation in operations:
    result = sizer.optimize_for_operation(vault_size, operation)
    print(f"{operation:8s}: {result.optimal_page_size_kb}KB (efficiency: {result.memory_efficiency}%)")
```

### Basic Usage: Security Testing Framework

```python
from security_testing import SecurityTestFramework
from quantum_resistant_crypto import QuantumResistantCrypto

# Initialize components
framework = SecurityTestFramework()
crypto = QuantumResistantCrypto()

# Prepare test functions
crypto_functions = {
    'hash_function': lambda x: crypto.hash_password(x + "A" * 10).hash,
    'salt_generator': crypto.generate_salt,
    'verify_function': crypto.verify_password
}

# Prepare test data
test_password = "SecureTestPassword123!@#ForSecurityValidation"
hash_result = crypto.hash_password(test_password)

test_data = {
    'test_passwords': {'strong': test_password},
    'test_credentials': {
        'correct_password': test_password,
        'incorrect_password': 'wrong_password',
        'hash_data': hash_result
    }
}

# Run comprehensive security tests
test_suite = framework.run_comprehensive_tests(crypto_functions, test_data)

print(f"Tests run: {test_suite.total_tests}")
print(f"Passed: {test_suite.passed}")
print(f"Failed: {test_suite.failed}")
print(f"Success rate: {(test_suite.passed/test_suite.total_tests)*100:.1f}%")
```

---

## 🔧 Integration Usage

### Complete System Integration

```python
from __init__ import (
    get_innovation_summary,
    create_complete_quantum_vault_system,
    run_innovation_demo
)

# Get overview of all innovations
innovations = get_innovation_summary()
print("Available innovations:")
for name, desc in innovations.items():
    print(f"  • {name}: {desc}")

# Create complete integrated system
vault_system = create_complete_quantum_vault_system(
    master_password="MyQuantumResistantPassword123!@#",
    vault_size=200
)

if vault_system['success']:
    print("✓ Complete quantum vault system created successfully!")
    print(f"  Crypto system: {vault_system['crypto_system'] is not None}")
    print(f"  Page manager: {vault_system['page_manager'] is not None}")
    print(f"  QR recovery: {vault_system['qr_recovery'] is not None}")
    print(f"  Steganographic QR: {vault_system['steganographic_qr'] is not None}")

# Run complete demonstration
demo_result = run_innovation_demo()
print(f"Demo completed with {demo_result['tests_run']} tests")
```

---

## 📖 Running Examples

### Method 1: Run Individual Examples
```bash
# Run the comprehensive usage examples
python usage_examples.py
```

### Method 2: Interactive Testing
```python
# Import and test individual components
from dual_qr_recovery import DualQRRecoverySystem
from quantum_resistant_crypto import QuantumResistantCrypto

# Test components interactively
qr_system = DualQRRecoverySystem()
crypto = QuantumResistantCrypto()

# Your testing code here...
```

### Method 3: Integration Demo
```python
# Run the complete integration demo
from __init__ import run_innovation_demo

result = run_innovation_demo()
print(f"Demo completed: {result}")
```

---

## 📁 File Structure

After running the examples, you'll see these generated files:

```
CorrectOne/
├── dual_qr_recovery.py           # Dual QR Recovery System
├── quantum_resistant_crypto.py   # Quantum-Resistant Cryptography
├── forward_secure_encryption.py  # Forward-Secure Page Encryption
├── steganographic_qr.py          # Steganographic QR System
├── dynamic_page_sizing.py        # Dynamic Page Sizing
├── security_testing.py           # Security Testing Framework
├── __init__.py                   # Integration Library
├── usage_examples.py             # This examples file
├── security_test_report.txt      # Generated security report
└── quantum_vault_system_report.json  # Generated system report
```

---

## 🛡️ Security Features

### Quantum Resistance
- SHA3-512 hashing algorithm
- 600,000+ PBKDF2 iterations
- Timing attack protection
- Secure random generation

### Forward Security
- Epoch-based encryption rotation
- Selective page re-encryption
- Zero-knowledge architecture
- Cryptographic isolation

### Steganography (Patent Pending)
- Reed-Solomon error correction embedding
- Invisible data hiding in QR codes
- Dual-layer security
- Advanced capacity optimization

### Recovery Systems
- Dual QR code architecture
- Device fingerprint binding
- Time-limited credentials
- Cryptographic validation

---

## 🚨 Important Notes

1. **Dependencies**: Some features require optional dependencies (qrcode, PIL)
2. **Security**: All libraries implement production-grade security
3. **Performance**: Optimized for different vault sizes and operations
4. **Patents**: Steganographic QR system has patent pending status
5. **Testing**: Comprehensive security testing included

---

## 💡 Need Help?

1. Check the generated reports for detailed analysis
2. Review the usage_examples.py for comprehensive demonstrations
3. Each library has detailed docstrings and type hints
4. Security testing framework validates all operations

**Start with `usage_examples.py` to see everything in action!**
