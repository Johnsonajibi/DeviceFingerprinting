# QuantumVault Innovation Libraries

A collection of revolutionary cryptographic libraries implementing cutting-edge innovations for password vault security and quantum-resistant cryptography.

## 🚀 Library Overview

This repository contains 6 innovative libraries, each in its own dedicated folder:

### 📁 [`dual_qr_recovery/`](./dual_qr_recovery/) - Dual QR Recovery System
Revolutionary dual QR code system for secure password recovery with cryptographic isolation.

**Key Innovation**: First dual QR system with cryptographic isolation, preventing single point of failure.

### 📁 [`quantum_resistant_crypto/`](./quantum_resistant_crypto/) - Quantum-Resistant Cryptography  
SHA3-512 based cryptography with quantum resistance and timing attack protection.

**Key Innovation**: Post-quantum cryptographic implementation with 600,000+ PBKDF2 iterations.

### 📁 [`forward_secure_encryption/`](./forward_secure_encryption/) - Forward-Secure Page Encryption
Page-based encryption with epoch counters for forward security and selective re-encryption.

**Key Innovation**: Selective re-encryption algorithm that only updates changed pages during key rotation.

### 📁 [`steganographic_qr/`](./steganographic_qr/) - Steganographic QR System ⚖️ Patent Pending
Reed-Solomon error correction steganography for hiding data in QR codes.

**Key Innovation**: Patent-pending technique for invisible data hiding in QR error correction space.

### 📁 [`dynamic_page_sizing/`](./dynamic_page_sizing/) - Dynamic Page Sizing Optimization
Automatic page size optimization based on vault characteristics.

**Key Innovation**: Intelligent page size calculation that adapts to vault size and operation types.

### 📁 [`security_testing/`](./security_testing/) - Security Testing Framework
Comprehensive security testing framework for cryptographic operations.

**Key Innovation**: Automated timing attack detection and comprehensive cryptographic validation.
- **Data Import/Export**: CSV and Excel file support
- **Forward-Secure Key Rotation**: Advanced page-based encryption system

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Quick Start

1. Run the password manager:
```bash
python CorrectPQC.py
```

2. Follow the setup wizard to:
   - Choose token storage location (local or USB)
   - Create a strong master password (30+ characters recommended)
   - Configure security questions

3. Access your vault and start managing passwords securely

## Usage

### Basic Operations

- **Add Password**: Store new credentials securely
- **Retrieve Password**: Access stored credentials
- **Update Password**: Modify existing entries
- **Delete Password**: Remove credentials
- **Import/Export**: Backup and restore data

### Security Features

- **Master Password**: Primary authentication layer
- **USB Token**: Optional hardware authentication
- **Security Questions**: Additional verification layer
- **Automatic Lockout**: Protection against brute force attacks

## Security Architecture

### Cryptographic Specifications

- **Hash Algorithm**: SHA3-512 with 600,000 iterations
- **Key Derivation**: PBKDF2-HMAC-SHA512
- **Encryption**: AES-256-GCM with authenticated encryption
- **Salt Length**: 64 bytes of cryptographically secure random data
- **Key Length**: 256-bit encryption keys

### Security Properties

- **Timing Attack Resistance**: Constant-time password verification
- **Rainbow Table Protection**: Unique salts for each password
- **Forward Security**: Key rotation without full plaintext exposure
- **Memory Safety**: Secure memory management for sensitive data

## Configuration

The password manager creates several configuration files:

- `vault.enc`: Encrypted password database
- `vault_config.json`: System configuration
- `vault_master.hash`: Master password hash
- `vault_salt.json`: Cryptographic salts

## Dependencies

### Required
- `cryptography`: Core cryptographic operations
- Standard Python libraries (json, hashlib, secrets, etc.)

### Optional
- `pandas`: Excel import/export functionality
- `qrcode`: QR code recovery system
- `Pillow`: Image processing for QR codes

## Contributing

This is a security-critical application. Please follow these guidelines:

1. All changes must maintain or improve security properties
2. Add comprehensive tests for new functionality
3. Follow Python PEP 8 coding standards
4. Document security implications of changes

## License

This project is released under a commercial license. See LICENSE file for details.

## Security Considerations

⚠️ **Important Security Notes**:

- Use a strong master password (30+ characters)
- Store USB tokens separately from backup files
- Regularly update the application for security patches
- Do not share master passwords or tokens
- Always exit the application properly to save changes

## Support

For security issues or questions:
- Review the documentation thoroughly
- Check that all dependencies are properly installed
- Ensure proper file permissions on configuration files

## Version

Current Version: 1.0.0
Cryptographic Version: SHA3-512-Enhanced
