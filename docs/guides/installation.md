---
layout: default
title: Installation Guide
---

# Installation Guide

Comprehensive installation instructions for all platforms and configurations.

## System Requirements

### Minimum Requirements

- **Python**: 3.9 or higher
- **Operating System**: Windows 7+, macOS 10.13+, or modern Linux distribution
- **Memory**: 512 MB minimum
- **Disk Space**: 50 MB for installation

### Recommended Requirements

- **Python**: 3.11 or higher
- **Operating System**: Windows 10+, macOS 11+, or recent Linux (Ubuntu 20.04+, CentOS 8+)
- **Memory**: 2 GB or more
- **Disk Space**: 100 MB including dependencies
- **Network**: Internet connection for initial setup and dependency resolution

## Basic Installation

### Step 1: Verify Python Installation

```bash
python --version
# Output should be Python 3.9 or higher
```

If Python is not installed, download from [python.org](https://www.python.org/downloads/).

### Step 2: Install from PyPI

```bash
pip install device-fingerprinting-pro
```

### Step 3: Verify Installation

```bash
python -c "import device_fingerprinting; print(device_fingerprinting.__version__)"
# Output: 2.2.3
```

## Platform-Specific Installation

### Windows Installation

#### Prerequisites

- Windows 7 or later
- Python 3.9+
- Visual C++ 14.0 or greater (for building some dependencies)

#### Installation Steps

```bash
# 1. Update pip, setuptools, and wheel
python -m pip install --upgrade pip setuptools wheel

# 2. Install the library
pip install device-fingerprinting-pro

# 3. Verify installation
python -c "from device_fingerprinting import DeviceFingerprintGenerator; print('Installation successful!')"
```

#### TPM Support on Windows

For TPM 2.0 support on Windows 10+:

```bash
# Additional package for TPM support
pip install device-fingerprinting-pro[tpm]

# Verify TPM availability
python -c "from device_fingerprinting import get_tpm_status; import json; print(json.dumps(get_tpm_status(), indent=2))"
```

#### Windows Troubleshooting

If you encounter build errors:

1. **Missing C++ compiler**: Install Microsoft C++ Build Tools
   ```
   https://visualstudio.microsoft.com/visual-cpp-build-tools/
   ```

2. **Permission errors**: Run Command Prompt as Administrator
   ```bash
   python -m pip install --user device-fingerprinting-pro
   ```

### macOS Installation

#### Prerequisites

- macOS 10.13 or later
- Python 3.9+ (via Homebrew or python.org)
- Xcode Command Line Tools

#### Installation Steps

```bash
# 1. Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# 2. Update pip
python3 -m pip install --upgrade pip

# 3. Install the library
pip3 install device-fingerprinting-pro

# 4. Verify installation
python3 -c "from device_fingerprinting import DeviceFingerprintGenerator; print('Installation successful!')"
```

#### Apple Silicon (M1/M2/M3) Support

For optimal performance on Apple Silicon:

```bash
# The library includes native ARM64 bindings
pip3 install device-fingerprinting-pro

# Verify architecture
python3 -c "import platform; print(platform.machine())"
# Output should be: arm64
```

#### macOS TPM Support

TPM support on macOS is limited, but the library supports Secure Enclave:

```bash
pip3 install device-fingerprinting-pro[secure-enclave]
```

### Linux Installation

#### Debian/Ubuntu

```bash
# 1. Install build dependencies
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip build-essential

# 2. Install the library
pip install device-fingerprinting-pro

# 3. For TPM support
sudo apt-get install -y libtss2-dev tpm2-tools
pip install device-fingerprinting-pro[tpm]
```

#### Red Hat/CentOS

```bash
# 1. Install build dependencies
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel

# 2. Install the library
pip install device-fingerprinting-pro

# 3. For TPM support
sudo yum install -y tpm2-tools tpm2-tss-devel
pip install device-fingerprinting-pro[tpm]
```

#### Arch Linux

```bash
# 1. Install build dependencies
sudo pacman -S base-devel python-pip

# 2. Install the library
pip install device-fingerprinting-pro

# 3. For TPM support
sudo pacman -S tpm2-tools tpm2-tss
pip install device-fingerprinting-pro[tpm]
```

#### Linux TPM Permissions

For TPM functionality, add your user to the tpm group:

```bash
# Check TPM device
ls -la /dev/tpm*

# Add user to tpm group
sudo usermod -a -G tpm $(whoami)

# Apply group membership (log out and back in, or use)
newgrp tpm
```

## Installation Options

### Core Installation

```bash
pip install device-fingerprinting-pro
```

Includes:
- Basic device fingerprinting
- Cryptographic operations
- Secure storage
- ML-based anomaly detection

### Post-Quantum Cryptography (PQC)

For quantum-resistant algorithms:

```bash
pip install device-fingerprinting-pro[pqc]
```

Additional packages:
- Kyber key encapsulation
- Dilithium digital signatures
- Other NIST-standardized PQC algorithms

### TPM Support

For Trusted Platform Module features:

```bash
pip install device-fingerprinting-pro[tpm]
```

Additional packages:
- TPM 2.0 interface
- Hardware attestation
- Secure key storage

### Development Installation

For contributing to the project:

```bash
# Clone the repository
git clone https://github.com/yourusername/device-fingerprinting.git
cd device-fingerprinting

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install in development mode
pip install -e .[dev,test,pqc,tpm]
```

### Complete Installation

Install all optional features:

```bash
pip install device-fingerprinting-pro[all]
```

Equivalent to:

```bash
pip install device-fingerprinting-pro[pqc,tpm,dev,test,docs]
```

## Virtual Environment Setup

Recommended: Use a virtual environment to avoid dependency conflicts.

### Using venv

```bash
# Create virtual environment
python -m venv df_env

# Activate virtual environment
# Windows:
df_env\Scripts\activate
# macOS/Linux:
source df_env/bin/activate

# Install library
pip install device-fingerprinting-pro

# Verify
python -c "import device_fingerprinting; print(device_fingerprinting.__version__)"

# Deactivate when done
deactivate
```

### Using Poetry

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Create project directory
mkdir my_fingerprinting_project
cd my_fingerprinting_project

# Initialize with Poetry
poetry init

# Add dependency
poetry add device-fingerprinting-pro

# Activate environment
poetry shell
```

### Using Conda

```bash
# Create environment
conda create -n df_env python=3.11

# Activate environment
conda activate df_env

# Install from PyPI
pip install device-fingerprinting-pro
```

## Dependency Management

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| cryptography | >=43.0.0 | Cryptographic primitives |
| numpy | >=1.21.0 | Numerical operations |
| scikit-learn | >=1.0.0 | Machine learning |
| psutil | >=5.8.0 | System metrics |

### Optional Dependencies

| Package | Version | Purpose | Feature |
|---------|---------|---------|---------|
| liboqs | >=0.8.0 | Post-quantum cryptography | [pqc] |
| tpm2-pytss | >=0.4.0 | TPM interface | [tpm] |
| pytest | >=7.0.0 | Testing framework | [test] |
| sphinx | >=5.0.0 | Documentation | [docs] |

## Upgrading

### Upgrade to Latest Version

```bash
pip install --upgrade device-fingerprinting-pro
```

### Upgrade with Options

```bash
# Upgrade with PQC support
pip install --upgrade device-fingerprinting-pro[pqc]

# Upgrade all optional features
pip install --upgrade device-fingerprinting-pro[all]
```

## Verify Installation

### Quick Verification

```python
import device_fingerprinting as df

# Check version
print(f"Version: {df.__version__}")

# Generate fingerprint
generator = df.DeviceFingerprintGenerator()
fingerprint = generator.generate_device_fingerprint()
print(f"Fingerprint: {fingerprint[:32]}...")

# Check TPM availability
status = df.get_tpm_status()
print(f"TPM Available: {status.get('tpm_hardware_available', 'Unknown')}")
```

### Comprehensive Verification

```python
import device_fingerprinting as df
import json

print("=== Device Fingerprinting Library Verification ===\n")

# 1. Version and basic info
print(f"Version: {df.__version__}")
print(f"Installation location: {df.__file__}\n")

# 2. Core functionality
try:
    generator = df.DeviceFingerprintGenerator()
    fp = generator.generate_device_fingerprint()
    print("Core fingerprinting: OK")
except Exception as e:
    print(f"Core fingerprinting: FAILED ({e})")

# 3. Cryptography
try:
    from device_fingerprinting.crypto import CryptoEngine
    engine = CryptoEngine()
    print("Cryptography module: OK")
except Exception as e:
    print(f"Cryptography module: FAILED ({e})")

# 4. ML/Anomaly Detection
try:
    from device_fingerprinting.ml_features import MLAnomalyDetector
    detector = MLAnomalyDetector()
    print("ML anomaly detection: OK")
except Exception as e:
    print(f"ML anomaly detection: FAILED ({e})")

# 5. Secure Storage
try:
    from device_fingerprinting.secure_storage import SecureStorage
    storage = SecureStorage()
    print("Secure storage: OK")
except Exception as e:
    print(f"Secure storage: FAILED ({e})")

# 6. TPM Support
try:
    status = df.get_tpm_status()
    tpm_available = status.get('tpm_hardware_available', False)
    if tpm_available:
        print("TPM support: Available")
    else:
        print("TPM support: Not available (software fallback active)")
except Exception as e:
    print(f"TPM support: ERROR ({e})")

print("\n=== Verification Complete ===")
```

## Uninstallation

To remove the library:

```bash
pip uninstall device-fingerprinting-pro
```

To remove with all optional dependencies:

```bash
pip uninstall device-fingerprinting-pro liboqs tpm2-pytss
```

## Troubleshooting Installation

### Issue: "No module named 'device_fingerprinting'"

**Causes**: 
- Installation failed silently
- Wrong Python interpreter
- Virtual environment not activated

**Solutions**:

```bash
# 1. Verify installation
pip show device-fingerprinting-pro

# 2. Check Python version
python --version  # Should be 3.9+

# 3. Try reinstalling
pip uninstall device-fingerprinting-pro
pip install device-fingerprinting-pro

# 4. Check PATH
python -m site
```

### Issue: "Permission denied" errors

**Causes**: 
- Insufficient file permissions
- Writing to protected directories

**Solutions**:

```bash
# Option 1: Use --user flag
pip install --user device-fingerprinting-pro

# Option 2: Use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install device-fingerprinting-pro
```

### Issue: Dependency conflicts

**Causes**: 
- Incompatible versions with existing packages
- Python version mismatch

**Solutions**:

```bash
# 1. Check Python version
python --version  # Must be 3.9+

# 2. Update pip
python -m pip install --upgrade pip

# 3. Install with specific version
pip install device-fingerprinting-pro==2.2.3

# 4. Use virtual environment
python -m venv venv
source venv/bin/activate
pip install device-fingerprinting-pro
```

### Issue: Build failures on Linux

**Causes**: 
- Missing build tools
- Incompatible compiler

**Solutions**:

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential python3-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel

# Then retry
pip install device-fingerprinting-pro
```

## Getting Help

If you encounter installation issues:

1. **Check the FAQ**: [FAQ](faq.md)
2. **Review Troubleshooting**: [Troubleshooting Guide](troubleshooting.md)
3. **Search Issues**: [GitHub Issues](https://github.com/yourusername/device-fingerprinting/issues)
4. **Create Issue**: Provide Python version, OS, and error message
5. **Email Support**: ajibijohnson@jtnetsolutions.com

## Next Steps

After successful installation:

1. **Quick Start**: [Getting Started Guide](getting-started.md)
2. **Examples**: [Usage Examples](examples.md)
3. **API Reference**: [Complete API Documentation](../api/reference.md)
