# Installation Guide

Complete guide for installing and setting up the Device Fingerprinting library.

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Basic Installation](#basic-installation)
- [Optional Dependencies](#optional-dependencies)
- [Development Installation](#development-installation)
- [Platform-Specific Setup](#platform-specific-setup)
- [Verification](#verification)

---

## System Requirements

### Minimum Requirements
- **Python**: 3.9 or higher
- **RAM**: 512 MB minimum (1 GB recommended)
- **Storage**: 100 MB for base installation
- **OS**: Windows, Linux, or macOS

### Supported Platforms
| Platform | Status | Notes |
|----------|--------|-------|
| Windows 10/11 | ✅ Full Support | All features available |
| Ubuntu 20.04+ | ✅ Full Support | All features available |
| macOS 11+ | ✅ Full Support | All features available |
| Other Linux | ⚠️ Limited Testing | Should work |

---

## Basic Installation

### Using pip (Recommended)

```bash
# Install from PyPI
pip install device-fingerprinting-pro

# Verify installation
python -c "import device_fingerprinting; print(device_fingerprinting.__version__)"
```

### Using pip with virtual environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install package
pip install device-fingerprinting-pro
```

### From Source

```bash
# Clone repository
git clone https://github.com/Johnsonajibi/DeviceFingerprinting.git
cd DeviceFingerprinting

# Install in development mode
pip install -e .
```

---

## Optional Dependencies

### Post-Quantum Cryptography (PQC)

For quantum-resistant cryptography features:

```bash
pip install device-fingerprinting-pro[pqc]
```

**Includes:**
- `pqcdualusb>=0.15.5` - Dilithium3, Kyber1024

### Cloud Integration

For AWS S3 and Azure Blob Storage support:

```bash
pip install device-fingerprinting-pro[cloud]
```

**Includes:**
- `boto3>=1.28.0` - AWS S3
- `azure-storage-blob>=12.17.0` - Azure Blob

### Development Tools

For development and testing:

```bash
pip install device-fingerprinting-pro[dev]
```

**Includes:**
- `pytest>=7.0.0` - Testing framework
- `pytest-cov>=4.0.0` - Coverage reporting
- `black>=23.0.0` - Code formatter
- `flake8>=6.0.0` - Linter
- `mypy>=1.0.0` - Type checker

### All Optional Features

Install everything:

```bash
pip install device-fingerprinting-pro[pqc,cloud,dev]
```

---

## Development Installation

### Complete Development Setup

```bash
# Clone repository
git clone https://github.com/Johnsonajibi/DeviceFingerprinting.git
cd DeviceFingerprinting

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install with all dependencies
pip install -e .[pqc,cloud,dev,test]

# Run tests to verify
pytest tests/
```

### Building from Source

```bash
# Install build tools
pip install build wheel

# Build distribution packages
python -m build

# Install built package
pip install dist/device_fingerprinting_pro-*.whl
```

---

## Platform-Specific Setup

### Windows

```powershell
# Install with all features
pip install device-fingerprinting-pro[pqc,cloud]

# For HSM support, install additional packages
pip install PyKCS11
```

**Note**: Some PQC backends require Microsoft Visual C++ 14.0 or greater.

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3-dev build-essential

# Install package
pip install device-fingerprinting-pro[pqc,cloud]

# For liboqs backend (optional)
sudo apt-get install liboqs-dev
pip install oqs
```

### macOS

```bash
# Install with Homebrew (if needed)
brew install python@3.11

# Install package
pip3 install device-fingerprinting-pro[pqc,cloud]

# For optimal performance
pip3 install cryptography --no-binary cryptography
```

---

## Verification

### Basic Verification

```python
import device_fingerprinting

# Check version
print(f"Version: {device_fingerprinting.__version__}")

# Test basic functionality
from device_fingerprinting import DeviceFingerprinter

fingerprinter = DeviceFingerprinter()
result = fingerprinter.generate()
print(f"✅ Installation successful!")
print(f"Fingerprint: {result.fingerprint[:50]}...")
```

### Verify PQC Support

```python
from device_fingerprinting.hybrid_pqc import HybridPQC

pqc = HybridPQC()
info = pqc.get_info()

print(f"PQC Available: {info['pqc_available']}")
print(f"Library: {info['pqc_library']}")
print(f"Algorithm: {info['algorithm']}")
```

### Run Test Suite

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=device_fingerprinting --cov-report=html
```

### Check Dependencies

```bash
# List installed packages
pip list | grep -E "device-fingerprinting|pqc|crypto"

# Check for security vulnerabilities
pip install pip-audit
pip-audit
```

---

## Common Installation Issues

### Issue: Import Error

**Problem:**
```
ImportError: No module named 'device_fingerprinting'
```

**Solution:**
```bash
# Verify installation
pip list | grep device-fingerprinting

# Reinstall if necessary
pip install --force-reinstall device-fingerprinting-pro
```

### Issue: PQC Not Available

**Problem:**
```
WARNING: pqcdualusb not available
```

**Solution:**
```bash
# Install PQC dependencies
pip install device-fingerprinting-pro[pqc]

# Or install manually
pip install pqcdualusb pqcrypto
```

### Issue: Cryptography Build Errors

**Problem:**
```
ERROR: Failed building wheel for cryptography
```

**Solution:**

**Windows:**
```powershell
# Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
```

**Linux:**
```bash
sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
pip install --upgrade pip setuptools wheel
pip install cryptography
```

### Issue: Permission Denied

**Problem:**
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
```bash
# Install for user only (no sudo needed)
pip install --user device-fingerprinting-pro

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install device-fingerprinting-pro
```

---

## Upgrade Guide

### Upgrading from Previous Version

```bash
# Upgrade to latest version
pip install --upgrade device-fingerprinting-pro

# Upgrade with all features
pip install --upgrade device-fingerprinting-pro[pqc,cloud]

# Check new version
python -c "import device_fingerprinting; print(device_fingerprinting.__version__)"
```

### Breaking Changes

See [CHANGELOG.md](CHANGELOG.md) for version-specific breaking changes.

---

## Uninstallation

```bash
# Uninstall package
pip uninstall device-fingerprinting-pro

# Remove all dependencies (optional)
pip uninstall pqcdualusb pqcrypto boto3 azure-storage-blob
```

---

## Next Steps

After successful installation:

1. **Read Quick Start**: [Quick Start Guide →](WIKI_QUICK_START.md)
2. **Try Examples**: [Basic Examples →](WIKI_BASIC_EXAMPLES.md)
3. **Configure Backends**: [Backend Configuration →](WIKI_BACKENDS.md)
4. **Security Setup**: [Security Guide →](WIKI_SECURITY.md)

---

**Navigation**: [← Home](WIKI_HOME.md) | [Quick Start →](WIKI_QUICK_START.md)
