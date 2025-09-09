# Device Fingerprinting Library

[![Python versions](https://img.shields.io/pypi/pyversions/device-fingerprinting-pro.svg)](https://pypi.org/project/device-fingerprinting-pro/)
[![License](https://img.shields.io/pypi/l/device-fingerprinting-pro.svg)](https://github.com/Johnsonajibi/DeviceFingerprinting/blob/main/LICENSE)

A Python library for generating unique device fingerprints based on hardware characteristics.

## Overview

The Device Fingerprinting library provides a robust method for identifying devices based on their hardware characteristics. It generates unique fingerprints by combining various system properties including CPU information, memory details, disk characteristics, and network interfaces.

## Features

- **Hardware-based identification**: Uses CPU, memory, disk, and network characteristics
- **Cross-platform support**: Works on Windows, macOS, and Linux
- **Unique fingerprinting**: Generates consistent, unique identifiers per device
- **Lightweight**: Minimal dependencies and fast execution
- **Privacy-focused**: No personally identifiable information collected

## Installation

```bash
pip install device-fingerprinting-pro
```

Or install from source:

```bash
git clone https://github.com/Johnsonajibi/DeviceFingerprinting.git
cd DeviceFingerprinting
pip install -r requirements.txt
```

## Quick Start

```python
from device_fingerprinting import DeviceFingerprint

# Create a device fingerprint
fingerprint = DeviceFingerprint()
device_id = fingerprint.generate()

print(f"Device ID: {device_id}")
```

## API Reference

### DeviceFingerprint Class

#### `generate()`
Generates a unique device fingerprint based on hardware characteristics.

**Returns:**
- `str`: A unique device identifier

**Example:**
```python
from device_fingerprinting import DeviceFingerprint

fingerprint = DeviceFingerprint()
device_id = fingerprint.generate()
print(device_id)  # Output: unique device identifier string
```

## How It Works

The library collects the following system information to create a unique fingerprint:

1. **CPU Information**: Processor name, core count, architecture
2. **Memory Details**: Total RAM, available memory
3. **Disk Information**: Storage device characteristics
4. **Network Interfaces**: MAC addresses and network adapter info
5. **System Properties**: OS version, hostname, and other system identifiers

All collected data is hashed to create a consistent, unique identifier while protecting privacy.

## Requirements

- Python 3.7 or higher
- `psutil` for system information
- `hashlib` for fingerprint generation (included in Python standard library)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## Support

For support, please open an issue on GitHub.