# DeviceFingerprint Pro

[![PyPI version](https://badge.fury.io/py/device-fingerprinting-pro.svg)](https://badge.fury.io/py/device-fingerprinting-pro)
[![PyPI downloads](https://img.shields.io/pypi/dm/device-fingerprinting-pro.svg)](https://pypi.org/project/device-fingerprinting-pro/)
[![PyPI downloads total](https://static.pepy.tech/badge/device-fingerprinting-pro)](https://pepy.tech/project/device-fingerprinting-pro)
[![Python versions](https://img.shields.io/pypi/pyversions/device-fingerprinting-pro.svg)](https://pypi.org/project/device-fingerprinting-pro/)
[![License](https://img.shields.io/pypi/l/device-fingerprinting-pro.svg)](https://github.com/Johnsonajibi/DeviceFingerprinting/blob/main/LICENSE)

**Professional-grade hardware-based device identification for Python applications**

DeviceFingerprint Pro is a comprehensive security library that creates unique, stable identifiers for computing devices by analyzing their hardware characteristics. Built for enterprise security applications, fraud prevention systems, and authentication workflows that demand reliable device recognition.

## 🚀 Quick Installation

```bash
# Install the latest stable version
pip install device-fingerprinting-pro

# Install with development tools
pip install device-fingerprinting-pro[dev]
```

## 🔐 Key Features

- **🛡️ Quantum-Resistant Cryptography**: SHA3-512 hashing provides protection against future quantum threats
- **🖥️ Hardware-Based Identification**: Multi-component analysis of CPU, memory, storage, and network hardware
- **🌐 Cross-Platform Support**: Consistent behavior across Windows, Linux, and macOS
- **🔒 Security Token Binding**: Secure device-specific token validation for authentication
- **⚡ Zero Dependencies**: Built entirely on Python's standard library
- **🎯 Multiple Confidence Levels**: Choose between Basic (0.7), Advanced (0.9), and Quantum-Resistant (0.95)
- **🔄 Stable Across Reboots**: Generates identical fingerprints for the same hardware
- **🛡️ Privacy-Aware**: Sensitive information is cryptographically hashed, never stored plaintext

## 🎯 Quick Start

### Basic Device Identification
```python
from devicefingerprint import generate_device_fingerprint

# Generate a unique identifier for this device
device_id = generate_device_fingerprint()
print(f"Device ID: {device_id}")
```

### Advanced Fingerprinting
```python
from devicefingerprint import AdvancedDeviceFingerprinter, FingerprintMethod

# Initialize advanced fingerprinter
fingerprinter = AdvancedDeviceFingerprinter()

# Generate quantum-resistant fingerprint
result = fingerprinter.generate_fingerprint(FingerprintMethod.QUANTUM_RESISTANT)

print(f"Fingerprint: {result.fingerprint}")
print(f"Confidence: {result.confidence}")
print(f"Components: {len(result.components)} hardware components")
```

### Security Token Binding
```python
from devicefingerprint import bind_token_to_device, verify_device_binding

# Bind security token to current device
user_token = {"user_id": "john.doe", "permissions": ["read", "write"]}
bound_token = bind_token_to_device(user_token)

# Later: verify token is on the same device
if verify_device_binding(bound_token):
    print("✅ Token verification successful - same device")
else:
    print("❌ Security alert: Token on different device")
```

## 📋 Requirements

- **Python**: 3.8 or higher
- **Dependencies**: None (built on standard library)
- **Platforms**: Windows, Linux, macOS
- **Environments**: Virtual environments, containers, cloud instances

## 🔧 Fingerprinting Methods

| Method | Security Level | Confidence | Use Case |
|--------|---------------|------------|----------|
| **Basic** | Standard | 0.7 | General device identification |
| **Advanced** | High | 0.9 | Security-sensitive applications |
| **Quantum-Resistant** | Maximum | 0.95 | Enterprise, quantum-safe requirements |

## 🏗️ Hardware Components Analyzed

- **CPU**: Processor ID, architecture, cores
- **Memory**: Total RAM, configuration
- **Storage**: Disk serials, mount points
- **Network**: MAC addresses, interfaces
- **System**: Machine ID, OS version, platform

## 🛡️ Security Features

### Enterprise-Ready Security
- **Constant-Time Operations**: Timing attack protection
- **Secure Random Generation**: Cryptographically secure entropy
- **No Silent Degradation**: Explicit error handling
- **Collision Detection**: Built-in collision handling

### Privacy Protection
- **Hash-Only Storage**: No plaintext hardware IDs
- **Minimal Data Exposure**: Only necessary information processed
- **Local Processing**: No external network calls
- **Secure Comparison**: Timing-safe fingerprint verification

## 🎯 Use Cases

### Security Applications
- **Multi-Factor Authentication**: Device binding as additional factor
- **Token Security**: Prevent theft and unauthorized token use
- **Session Management**: Tie user sessions to specific devices
- **Fraud Detection**: Detect unusual device access patterns

### Enterprise Applications
- **License Enforcement**: Bind software licenses to hardware
- **Compliance Monitoring**: Track device changes and access
- **Inventory Management**: Unique device identification
- **Deployment Tracking**: Monitor software installations

## 📊 Performance Benchmarks

| Method | Avg Time | Memory | Components |
|--------|----------|--------|------------|
| Basic | ~50ms | <1MB | 4-5 |
| Advanced | ~150ms | <2MB | 6-8 |
| Quantum-Resistant | ~200ms | <3MB | 8-10 |

*Benchmarks on modern hardware (Intel i7, 16GB RAM, SSD)*

## 🌐 Platform Support

| Platform | CPU | Memory | Storage | Network | System ID |
|----------|-----|--------|---------|---------|-----------|
| **Windows** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Linux** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **macOS** | ✅ | ✅ | ✅ | ✅ | ✅ |

## 📚 API Reference

### Core Classes

#### `AdvancedDeviceFingerprinter`
Main class for device fingerprinting operations.

#### `FingerprintMethod` (Enum)
- `BASIC`: Fast, moderate security (0.7 confidence)
- `ADVANCED`: Balanced performance (0.9 confidence)  
- `QUANTUM_RESISTANT`: Maximum security (0.95 confidence)

#### `FingerprintResult` (Dataclass)
```python
@dataclass
class FingerprintResult:
    fingerprint: str          # Generated fingerprint
    method: FingerprintMethod # Method used
    components: List[str]     # Hardware components
    timestamp: str           # Generation time
    confidence: float        # Confidence score
    warnings: List[str]      # Any warnings
```

### Core Functions

- `generate_device_fingerprint() -> str`: Simple fingerprint generation
- `bind_token_to_device(token: Dict) -> Dict`: Bind token to device
- `verify_device_binding(token: Dict) -> bool`: Verify device binding

## 🔧 Advanced Usage

### Enterprise Integration
```python
from devicefingerprint import AdvancedDeviceFingerprinter, FingerprintMethod
import logging

class EnterpriseDeviceManager:
    def __init__(self):
        self.fingerprinter = AdvancedDeviceFingerprinter()
        self.logger = logging.getLogger(__name__)
    
    def register_device(self, user_id: str) -> dict:
        """Register device for enterprise user"""
        result = self.fingerprinter.generate_fingerprint(
            FingerprintMethod.QUANTUM_RESISTANT
        )
        
        return {
            "device_id": result.fingerprint,
            "user_id": user_id,
            "confidence": result.confidence,
            "registered_at": datetime.utcnow().isoformat()
        }
    
    def verify_device_access(self, user_id: str, stored_id: str) -> bool:
        """Verify device access for security"""
        current = self.fingerprinter.generate_fingerprint(
            FingerprintMethod.QUANTUM_RESISTANT
        )
        return stored_id == current.fingerprint

# Usage
manager = EnterpriseDeviceManager()
device_record = manager.register_device("employee@company.com")
is_authorized = manager.verify_device_access(
    "employee@company.com", 
    device_record["device_id"]
)
```

### Adaptive Security
```python
def adaptive_fingerprinting(risk_level: str):
    """Implement risk-based fingerprinting"""
    fingerprinter = AdvancedDeviceFingerprinter()
    
    method_map = {
        "low": FingerprintMethod.BASIC,
        "medium": FingerprintMethod.ADVANCED,
        "high": FingerprintMethod.QUANTUM_RESISTANT
    }
    
    method = method_map.get(risk_level, FingerprintMethod.ADVANCED)
    return fingerprinter.generate_fingerprint(method)

# Risk-based fingerprinting
low_risk_fp = adaptive_fingerprinting("low")
high_risk_fp = adaptive_fingerprinting("high")
```

## 🛠️ Development & Testing

```bash
# Clone repository
git clone https://github.com/Johnsonajibi/DeviceFingerprinting.git
cd DeviceFingerprinting

# Install development dependencies
pip install -e .[dev]

# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=devicefingerprint
```

## 🔗 Links

- **Homepage**: [GitHub Repository](https://github.com/Johnsonajibi/DeviceFingerprinting)
- **Documentation**: [Full Documentation](https://github.com/Johnsonajibi/DeviceFingerprinting#readme)
- **Bug Reports**: [GitHub Issues](https://github.com/Johnsonajibi/DeviceFingerprinting/issues)
- **Release Notes**: [Changelog](https://github.com/Johnsonajibi/DeviceFingerprinting/blob/main/RELEASE_NOTES.md)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Johnsonajibi/DeviceFingerprinting/blob/main/LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Johnsonajibi/DeviceFingerprinting/issues)
- **Email**: johnson@devicefingerprint.dev

---

**DeviceFingerprint Pro** - Secure, reliable, quantum-resistant device identification for Python applications.
