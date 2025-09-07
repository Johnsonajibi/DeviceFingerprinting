# Steganographic QR System v1.0.0

## Release Date: September 4, 2025

### Overview
First release of the Steganographic QR System - a Python library that hides encrypted data within QR code error correction space using Reed-Solomon steganography.

### What's New
- **Error Correction Steganography**: Embeds hidden data in QR code error correction bits
- **Reed-Solomon Integration**: Uses existing error correction infrastructure for data hiding
- **Capacity Calculation**: Automatically calculates available hiding space
- **LSB Manipulation**: Modifies least significant bits in error correction data
- **Dual Functionality**: Maintains normal QR operation while hiding data

### Key Features
- Hide up to 50% of error correction capacity for steganographic data
- Invisible to standard QR code readers and analyzers
- Maintains full QR code error recovery capability
- Support for multiple error correction levels (L/M/Q/H)
- Cryptographic binding between hidden data and QR content

### Installation
```bash
pip install steganographic-qr
```

### Basic Usage
```python
from steganographic_qr import SteganographicQRSystem

# Create steganographic system
stego = SteganographicQRSystem()

# Calculate hiding capacity
capacity = stego.calculate_steganographic_capacity(qr_size=1000, error_level='M')
print(f"Can hide {capacity} bytes")

# Embed hidden data
result = stego.embed_steganographic_data(
    secret_data="hidden_message",
    cover_message="visible_qr_content"
)

# Extract hidden data
extracted = stego.extract_steganographic_data(result)
```

### Technical Details
- Supports QR code versions 1-40
- Error correction levels: L (7%), M (15%), Q (25%), H (30%)
- Maximum hidden payload varies by QR size and error level
- Uses AES-256 encryption for hidden data
- Compatible with standard QR readers for cover data

### Algorithm Features
- **50/50 Split**: 50% error correction, 50% steganographic space
- **Adaptive Capacity**: Adjusts to QR size and error level
- **Integrity Verification**: Built-in verification of hidden data
- **Format Preservation**: QR codes remain standard-compliant

### Use Cases
- Covert communication channels
- Digital watermarking
- Secure data transmission
- Anti-counterfeiting measures
- Research in steganography

### Security Considerations
- Hidden data is encrypted before embedding
- Steganographic presence is not detectable by casual inspection
- Requires knowledge of embedding algorithm for extraction
- Error correction capability is reduced but maintained

### Performance
- Embedding: ~100ms for typical QR codes
- Extraction: ~50ms for typical QR codes
- Memory usage: <10MB for largest QR codes
- CPU usage: Minimal during operation

### Documentation
Complete API documentation: docs/steganographic_qr.md

### Contributing
Contributions welcome. Please read CONTRIBUTING.md for guidelines.

---
*Steganographic QR System - Hide in plain sight with Reed-Solomon steganography*
