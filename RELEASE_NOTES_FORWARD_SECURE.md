# Forward Secure Encryption v1.0.0

## Release Date: September 4, 2025

### Overview
First release of the Forward Secure Encryption library - implementing forward-secure key rotation through page-based encryption with epoch counters.

### What's New
- **Epoch-Based Encryption**: Pages encrypted with version-specific keys
- **Forward Security**: Old keys cannot decrypt new data after rotation
- **Selective Re-encryption**: Only stale pages are re-encrypted during rotation
- **Page Metadata Tracking**: Detailed epoch tracking for each encrypted page
- **Minimal Plaintext Exposure**: Reduces data exposure during key rotation

### Key Features
- Forward security guarantees through epoch-based key management
- Efficient key rotation with minimal computational overhead
- Page-level encryption granularity for large datasets
- Comprehensive metadata tracking and statistics
- Thread-safe operations for concurrent access

### Installation
```bash
pip install forward-secure-encryption
```

### Basic Usage
```python
from forward_secure_encryption import ForwardSecurePageManager

# Initialize page manager
manager = ForwardSecurePageManager(vault_size=100)

# Perform forward-secure key rotation
rotation_result = manager.perform_forward_secure_rotation(
    vault_data=data,
    old_key=old_encryption_key,
    new_key=new_encryption_key
)

print(f"Rotated {rotation_result.pages_rotated} pages")
print(f"Skipped {rotation_result.pages_skipped} current pages")
```

### Core Concepts

#### Epochs
- Each page has an epoch counter
- Global epoch increments with each rotation
- Only pages with `page_epoch < current_epoch` are re-encrypted

#### Page Management
- Data divided into configurable page sizes
- Individual page encryption with AES-256-GCM
- Metadata tracking for each page
- Efficient large dataset handling

#### Forward Security
- Previous keys cannot decrypt data encrypted with newer keys
- Compromised old keys don't affect current data security
- Time-based security guarantees

### Configuration Options
- **Page Size**: Configurable page sizes (0.5KB to 4KB)
- **Epoch Strategy**: Automatic or manual epoch incrementing
- **Metadata Storage**: JSON-based metadata persistence
- **Performance Tuning**: Optimizable for different use cases

### Performance Characteristics
- **Key Rotation Time**: Linear with number of stale pages
- **Memory Usage**: Constant, independent of total data size
- **Storage Overhead**: ~5% for metadata
- **Encryption Speed**: ~50MB/s typical throughput

### Use Cases
- Database encryption with key rotation
- File system encryption
- Backup system security
- Long-term data archival
- Compliance with data retention policies

### Security Properties
- **Forward Security**: ✓ Old keys cannot decrypt new data
- **Selective Exposure**: ✓ Only stale pages exposed during rotation
- **Metadata Protection**: ✓ Epoch metadata is integrity-protected
- **Key Separation**: ✓ Different keys for different epochs

### API Documentation

#### Main Classes
- `ForwardSecurePageManager` - Core page management and rotation
- `PageEpoch` - Metadata for individual pages
- `EpochRotationResult` - Results and statistics from rotation

#### Key Methods
- `perform_forward_secure_rotation()` - Execute key rotation
- `update_vault_size()` - Update page size optimization
- `get_rotation_statistics()` - Get detailed statistics

### Integration Examples
Works well with:
- Database encryption layers
- File encryption systems
- Backup and archival tools
- Key management systems

### Limitations
- Requires metadata storage for page tracking
- Initial setup overhead for large datasets
- Page size affects performance characteristics

### Future Enhancements
- Hardware acceleration support
- Additional encryption algorithms
- Improved page size optimization
- Enhanced metadata compression

---
*Forward Secure Encryption - Protecting your future from your past*
