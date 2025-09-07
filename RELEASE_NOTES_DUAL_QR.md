# Dual QR Recovery System v1.0.0

## Release Date: September 4, 2025

### Overview
Initial release of the Dual QR Recovery System - a Python library that splits recovery data across two QR codes for improved security and reliability.

### What's New
- **Dual QR Code Generation**: Splits sensitive recovery data across two separate QR codes
- **Device Fingerprinting**: Binds recovery credentials to specific hardware
- **Time-Limited Recovery**: Recovery codes expire after configurable time periods
- **Data Compression**: Efficient compression for large recovery datasets
- **AES-256-GCM Encryption**: Military-grade encryption for recovery data

### Key Features
- Split recovery secrets across multiple QR codes to prevent single points of failure
- Hardware-bound recovery prevents unauthorized use on different devices
- Configurable expiration times for security
- Support for both text and binary data recovery
- Built-in integrity verification

### Installation
```bash
pip install dual-qr-recovery
```

### Basic Usage
```python
from dual_qr_recovery import DualQRRecoverySystem

# Create recovery system
recovery = DualQRRecoverySystem()

# Generate dual QR codes
result = recovery.create_dual_qr_system(
    recovery_data="sensitive_backup_data",
    device_fingerprint="unique_device_id"
)

print(f"Primary QR: {result.primary_qr}")
print(f"Secondary QR: {result.secondary_qr}")
```

### Technical Details
- Written in Python 3.8+
- Dependencies: cryptography, qrcode, pillow
- Tested on Windows, Linux, and macOS
- Thread-safe implementation
- Memory-efficient processing

### Use Cases
- Password manager backup systems
- Cryptocurrency wallet recovery
- Secure document archival
- Multi-factor authentication backup
- Enterprise credential recovery

### Security Notes
- Recovery data is encrypted before QR generation
- Device fingerprints prevent cross-device recovery
- No recovery data is stored in plaintext
- Uses secure random generation for all cryptographic operations

### Known Limitations
- QR code size limits maximum recovery data to ~2KB per code
- Requires both QR codes for successful recovery
- Device fingerprinting may fail on virtual machines

### Documentation
Full documentation available at: docs/dual_qr_recovery.md

### Support
Report issues at: https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/issues

---
*Dual QR Recovery System - Secure, reliable recovery through distributed QR codes*
