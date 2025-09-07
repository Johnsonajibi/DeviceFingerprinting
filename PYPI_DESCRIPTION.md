# QuantumVault Password Manager

[![PyPI version](https://badge.fury.io/py/quantumvault-password-manager.svg)](https://badge.fury.io/py/quantumvault-password-manager)
[![PyPI downloads](https://img.shields.io/pypi/dm/quantumvault-password-manager.svg)](https://pypi.org/project/quantumvault-password-manager/)
[![PyPI downloads total](https://static.pepy.tech/badge/quantumvault-password-manager)](https://pepy.tech/project/quantumvault-password-manager)
[![Python versions](https://img.shields.io/pypi/pyversions/quantumvault-password-manager.svg)](https://pypi.org/project/quantumvault-password-manager/)
[![License](https://img.shields.io/pypi/l/quantumvault-password-manager.svg)](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/blob/master/LICENSE)

**A quantum-resistant password manager with advanced cryptographic features designed for the post-quantum era.**

QuantumVault implements cutting-edge cryptographic libraries and quantum-resistant algorithms to protect your sensitive data against both classical and quantum computer attacks.

## 🔐 Key Features

- **🛡️ Quantum-Resistant Cryptography**: SHA3-512 hashing with PBKDF2 key derivation
- **🔒 AES-256-GCM Encryption**: Authenticated encryption with associated data
- **📱 Dual QR Recovery**: Split recovery system across two independent QR codes
- **🕵️ Steganographic QR**: Hidden data embedding in error correction space
- **⏭️ Forward Secure Encryption**: Epoch-based key rotation with perfect forward secrecy
- **💾 Dynamic Memory Management**: Adaptive page sizing for optimal performance
- **🖥️ Device Binding**: Hardware fingerprint integration for device-specific security

## 🚀 Quick Installation

```bash
# Install the latest stable version
pip install quantumvault-password-manager

# Install with full features (pandas, QR codes, plotting)
pip install quantumvault-password-manager[full]

# Install for development with testing tools
pip install quantumvault-password-manager[dev]
```

## 🎯 Quick Start

```bash
# Start the interactive password manager
quantumvault

# Show help and available commands
quantumvault --help

# Alternative command alias
qvault
```

## 📋 Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, Linux
- **Memory**: Minimum 512 MB RAM

## 🔧 Core Dependencies

- `cryptography>=41.0.0` - Cryptographic operations
- `click>=8.0.0` - Command line interface
- `rich>=13.0.0` - Rich text and beautiful formatting
- `pydantic>=2.0.0` - Data validation

## 📦 Optional Dependencies

### Full Feature Set (`[full]`)
- `pandas>=2.0.0` - Data manipulation and CSV/Excel import/export
- `qrcode[pil]>=7.4.0` - QR code generation
- `Pillow>=10.0.0` - Image processing
- `matplotlib>=3.7.0` - Plotting and visualization
- `numpy>=1.24.0` - Numerical operations

### Development Tools (`[dev]`)
- `pytest>=7.0.0` - Testing framework
- `pytest-cov>=4.0.0` - Coverage reporting
- `black>=23.0.0` - Code formatting
- `flake8>=6.0.0` - Linting
- `mypy>=1.5.0` - Type checking

### Security Analysis (`[security]`)
- `bandit>=1.7.0` - Security vulnerability scanner
- `safety>=3.0.0` - Dependency vulnerability checker
- `semgrep>=1.45.0` - Static analysis for security

## 🛡️ Security Features

### Cryptographic Standards
- **Hash Function**: SHA3-512 (NIST approved, quantum-resistant)
- **Key Derivation**: PBKDF2 with 100,000+ iterations
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Random Generation**: Cryptographically secure PRNG

### Advanced Security
- **Input Validation**: Prevents injection attacks
- **Memory Protection**: Secure allocation and deletion
- **Audit Logging**: Comprehensive security event logging
- **Device Binding**: Hardware-specific cryptographic binding
- **Forward Secrecy**: Time-bounded compromise isolation

## 📚 Usage Examples

### Basic Password Management
```python
from quantumvault import QuantumVault

# Initialize the vault
vault = QuantumVault()

# Add a password
vault.add_password("example.com", "user@example.com", "secure_password")

# Search for passwords
results = vault.search_passwords("example")

# Generate QR recovery codes
vault.generate_dual_qr_recovery()
```

### Advanced Features
```python
# Enable forward secure encryption
vault.enable_forward_secure_encryption(epoch_duration_hours=24)

# Create steganographic QR code
hidden_qr = vault.create_steganographic_qr(
    public_data="https://example.com",
    hidden_data="secret_recovery_key"
)

# Configure dynamic page sizing
vault.configure_dynamic_sizing(
    min_page_size=4096,
    max_page_size=65536,
    auto_optimize=True
)
```

## 🔗 Links

- **Homepage**: [https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager)
- **Documentation**: [Wiki](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/wiki)
- **Bug Reports**: [Issues](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/issues)
- **Security**: [Security Policy](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/security)
- **Changelog**: [CHANGELOG.md](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/blob/master/CHANGELOG.md)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/blob/master/LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and feel free to submit pull requests.

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/issues)
- **Security Issues**: Please see our [security policy](https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/security)

---

**Made with ❤️ for quantum-safe security**
