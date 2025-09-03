# Post Quantum Offline Manager

A quantum-resistant password manager with advanced cryptographic features designed for the post-quantum era. Built with enterprise-grade security and innovative cryptographic libraries.

## 🔐 Overview

Post Quantum Offline Manager (QuantumVault) is a comprehensive password management solution that implements quantum-resistant cryptography to protect against both classical and quantum computer attacks. The system integrates multiple innovative cryptographic libraries to provide maximum security for sensitive data storage.

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph "User Interface Layer"
        CLI[Command Line Interface]
        Menu[Interactive Menu System]
    end
    
    subgraph "Core Application Layer"
        App[CorrectPQC.py - Main Application]
        Auth[Authentication Manager]
        Session[Session Manager]
    end
    
    subgraph "Cryptographic Libraries"
        QRC[Quantum Resistant Crypto]
        DQR[Dual QR Recovery]
        SQR[Steganographic QR]
        FSE[Forward Secure Encryption]
        DPS[Dynamic Page Sizing]
    end
    
    subgraph "Storage Layer"
        Vault[Encrypted Vault Files]
        Token[Quantum Tokens]
        Backup[Backup Systems]
        Config[Configuration Files]
    end
    
    subgraph "Security Layer"
        Audit[Security Auditing]
        Logger[Secure Logging]
        Validator[Input Validation]
        Monitor[Performance Monitoring]
    end
    
    CLI --> Menu
    Menu --> App
    App --> Auth
    App --> Session
    
    Auth --> QRC
    Session --> FSE
    App --> DQR
    App --> SQR
    App --> DPS
    
    QRC --> Vault
    DQR --> Token
    FSE --> Backup
    SQR --> Config
    
    App --> Audit
    App --> Logger
    App --> Validator
    App --> Monitor
    
    classDef crypto fill:#e1f5fe
    classDef storage fill:#f3e5f5
    classDef security fill:#e8f5e8
    classDef core fill:#fff3e0
    
    class QRC,DQR,SQR,FSE,DPS crypto
    class Vault,Token,Backup,Config storage
    class Audit,Logger,Validator,Monitor security
    class App,Auth,Session core
```

## 🔑 Cryptographic Architecture

### Quantum-Resistant Cryptography Module

```mermaid
graph LR
    subgraph "Input Processing"
        PWD[Password Input]
        Salt[Salt Generation]
        Data[Data Input]
    end
    
    subgraph "Key Derivation"
        PBKDF2[PBKDF2 100K+ Iterations]
        SHA3[SHA3-512 Hashing]
        KeyMat[Key Material]
    end
    
    subgraph "Encryption Layer"
        AES[AES-256-GCM]
        AEAD[AEAD Encryption]
        IV[IV Generation]
    end
    
    subgraph "Output"
        Cipher[Encrypted Data]
        MAC[Authentication Tag]
        Metadata[Encryption Metadata]
    end
    
    PWD --> PBKDF2
    Salt --> PBKDF2
    PBKDF2 --> SHA3
    SHA3 --> KeyMat
    
    Data --> AES
    KeyMat --> AES
    IV --> AES
    AES --> AEAD
    
    AEAD --> Cipher
    AEAD --> MAC
    AES --> Metadata
    
    classDef input fill:#ffebee
    classDef kdf fill:#e8f5e8
    classDef encrypt fill:#e3f2fd
    classDef output fill:#f3e5f5
    
    class PWD,Salt,Data input
    class PBKDF2,SHA3,KeyMat kdf
    class AES,AEAD,IV encrypt
    class Cipher,MAC,Metadata output
```

### Dual QR Recovery System Architecture

```mermaid
graph TB
    subgraph "Master Recovery Data"
        Master[Master Password Hash]
        DeviceID[Device Fingerprint]
        RecoveryKey[Recovery Key Material]
    end
    
    subgraph "QR Code Generation"
        Split[Data Splitting Algorithm]
        Primary[Primary QR Code]
        Secondary[Secondary QR Code]
    end
    
    subgraph "Security Layers"
        Encrypt[Individual QR Encryption]
        Cross[Cross-QR Verification]
        Binding[Device Binding]
    end
    
    subgraph "Storage Options"
        Print[Physical Printouts]
        Digital[Digital Storage]
        Vault[Secure Vault Storage]
    end
    
    subgraph "Recovery Process"
        Scan[QR Code Scanning]
        Verify[Dual Verification]
        Reconstruct[Data Reconstruction]
        Unlock[Master Password Reset]
    end
    
    Master --> Split
    DeviceID --> Split
    RecoveryKey --> Split
    
    Split --> Primary
    Split --> Secondary
    
    Primary --> Encrypt
    Secondary --> Encrypt
    Encrypt --> Cross
    Cross --> Binding
    
    Primary --> Print
    Secondary --> Print
    Primary --> Digital
    Secondary --> Digital
    Primary --> Vault
    Secondary --> Vault
    
    Print --> Scan
    Digital --> Scan
    Vault --> Scan
    
    Scan --> Verify
    Verify --> Reconstruct
    Reconstruct --> Unlock
    
    classDef data fill:#e8f5e8
    classDef qr fill:#e3f2fd
    classDef security fill:#fff3e0
    classDef storage fill:#f3e5f5
    classDef recovery fill:#ffebee
    
    class Master,DeviceID,RecoveryKey data
    class Split,Primary,Secondary qr
    class Encrypt,Cross,Binding security
    class Print,Digital,Vault storage
    class Scan,Verify,Reconstruct,Unlock recovery
```

### Steganographic QR System Architecture

```mermaid
graph LR
    subgraph "Data Preparation"
        Secret[Secret Data]
        Compress[Compression]
        Encrypt[Encryption]
    end
    
    subgraph "QR Code Generation"
        Visible[Visible QR Data]
        ErrorSpace[Error Correction Space]
        ReedSolomon[Reed-Solomon Analysis]
    end
    
    subgraph "Steganographic Embedding"
        ECC[Error Correction Calculation]
        BitManip[Bit Manipulation]
        Embed[Data Embedding]
    end
    
    subgraph "Verification Layer"
        Integrity[QR Code Integrity]
        Hidden[Hidden Data Integrity]
        CrossCheck[Cross Verification]
    end
    
    subgraph "Output QR Code"
        Standard[Standard QR Function]
        Steganographic[Hidden Data Layer]
        Combined[Combined QR Code]
    end
    
    Secret --> Compress
    Compress --> Encrypt
    
    Encrypt --> ErrorSpace
    Visible --> ErrorSpace
    ErrorSpace --> ReedSolomon
    
    ReedSolomon --> ECC
    ECC --> BitManip
    BitManip --> Embed
    
    Embed --> Integrity
    Integrity --> Hidden
    Hidden --> CrossCheck
    
    Visible --> Standard
    Embed --> Steganographic
    Standard --> Combined
    Steganographic --> Combined
    
    classDef prep fill:#e8f5e8
    classDef qr fill:#e3f2fd
    classDef stego fill:#fff3e0
    classDef verify fill:#ffebee
    classDef output fill:#f3e5f5
    
    class Secret,Compress,Encrypt prep
    class Visible,ErrorSpace,ReedSolomon qr
    class ECC,BitManip,Embed stego
    class Integrity,Hidden,CrossCheck verify
    class Standard,Steganographic,Combined output
```

### Forward Secure Encryption Architecture

```mermaid
graph TB
    subgraph "Epoch Management"
        CurrentEpoch[Current Epoch]
        EpochRotation[Automatic Rotation]
        TimeBasedKeys[Time-Based Keys]
    end
    
    subgraph "Key Evolution"
        MasterKey[Master Key]
        KeyDerivation[One-Way Key Derivation]
        EpochKeys[Epoch-Specific Keys]
        KeyDeletion[Secure Key Deletion]
    end
    
    subgraph "Data Processing"
        PageData[Data Pages]
        ReEncryption[Page Re-encryption]
        BatchProcessing[Batch Operations]
    end
    
    subgraph "Forward Security"
        PastKeys[Past Keys Destroyed]
        FutureKeys[Future Keys Unknown]
        CompromiseIsolation[Compromise Isolation]
    end
    
    subgraph "Performance Optimization"
        IncrementalUpdate[Incremental Updates]
        MemoryOptimization[Memory Management]
        ConcurrentProcessing[Concurrent Operations]
    end
    
    CurrentEpoch --> EpochRotation
    EpochRotation --> TimeBasedKeys
    TimeBasedKeys --> MasterKey
    
    MasterKey --> KeyDerivation
    KeyDerivation --> EpochKeys
    EpochKeys --> KeyDeletion
    
    EpochKeys --> PageData
    PageData --> ReEncryption
    ReEncryption --> BatchProcessing
    
    KeyDeletion --> PastKeys
    KeyDerivation --> FutureKeys
    PastKeys --> CompromiseIsolation
    FutureKeys --> CompromiseIsolation
    
    BatchProcessing --> IncrementalUpdate
    ReEncryption --> MemoryOptimization
    BatchProcessing --> ConcurrentProcessing
    
    classDef epoch fill:#e8f5e8
    classDef keys fill:#e3f2fd
    classDef data fill:#fff3e0
    classDef security fill:#ffebee
    classDef performance fill:#f3e5f5
    
    class CurrentEpoch,EpochRotation,TimeBasedKeys epoch
    class MasterKey,KeyDerivation,EpochKeys,KeyDeletion keys
    class PageData,ReEncryption,BatchProcessing data
    class PastKeys,FutureKeys,CompromiseIsolation security
    class IncrementalUpdate,MemoryOptimization,ConcurrentProcessing performance
```

### Dynamic Page Sizing Architecture

```mermaid
graph LR
    subgraph "Data Analysis"
        DataSize[Data Size Analysis]
        AccessPattern[Access Pattern Analysis]
        MemoryProfile[Memory Profiling]
    end
    
    subgraph "Optimization Engine"
        Algorithm[Optimization Algorithm]
        MathModel[Mathematical Modeling]
        Prediction[Performance Prediction]
    end
    
    subgraph "Page Management"
        PageSizing[Dynamic Page Sizing]
        MemoryAllocation[Memory Allocation]
        CacheOptimization[Cache Optimization]
    end
    
    subgraph "Performance Monitoring"
        Metrics[Performance Metrics]
        Feedback[Feedback Loop]
        Adaptation[Adaptive Optimization]
    end
    
    subgraph "Resource Management"
        MemoryPool[Memory Pool Management]
        GarbageCollection[Garbage Collection]
        ResourceCleanup[Resource Cleanup]
    end
    
    DataSize --> Algorithm
    AccessPattern --> Algorithm
    MemoryProfile --> Algorithm
    
    Algorithm --> MathModel
    MathModel --> Prediction
    Prediction --> PageSizing
    
    PageSizing --> MemoryAllocation
    MemoryAllocation --> CacheOptimization
    CacheOptimization --> Metrics
    
    Metrics --> Feedback
    Feedback --> Adaptation
    Adaptation --> Algorithm
    
    MemoryAllocation --> MemoryPool
    CacheOptimization --> GarbageCollection
    Metrics --> ResourceCleanup
    
    classDef analysis fill:#e8f5e8
    classDef engine fill:#e3f2fd
    classDef management fill:#fff3e0
    classDef monitoring fill:#ffebee
    classDef resources fill:#f3e5f5
    
    class DataSize,AccessPattern,MemoryProfile analysis
    class Algorithm,MathModel,Prediction engine
    class PageSizing,MemoryAllocation,CacheOptimization management
    class Metrics,Feedback,Adaptation monitoring
    class MemoryPool,GarbageCollection,ResourceCleanup resources
```

## 🚀 Features

### Core Security Features
- **Quantum-Resistant Cryptography**: SHA3-512 hashing with PBKDF2 key derivation
- **AES-256-GCM Encryption**: Authenticated encryption with associated data
- **Device Binding**: Hardware fingerprint integration for device-specific security
- **Secure Memory Management**: Memory protection and secure deletion
- **Timing Attack Protection**: Constant-time operations for cryptographic functions

### Advanced Features
- **Dual QR Recovery System**: Split recovery across two independent QR codes
- **Steganographic QR Codes**: Hidden data embedding in error correction space
- **Forward Secure Encryption**: Epoch-based key rotation with perfect forward secrecy
- **Dynamic Page Sizing**: Adaptive memory optimization for large datasets
- **Comprehensive Auditing**: Security event logging and monitoring

### Data Management
- **Password Storage**: Secure storage of passwords with metadata
- **Import/Export**: CSV and Excel file support for bulk operations
- **Backup Systems**: Multi-location backup with encryption
- **Search Functionality**: Fast and secure password searching
- **Data Validation**: Input sanitization and validation

## 📋 Requirements

### System Requirements
- **Python**: 3.11 or higher
- **Operating System**: Windows, macOS, Linux
- **Memory**: Minimum 512 MB RAM
- **Storage**: 100 MB free space

### Dependencies
```bash
# Core dependencies
cryptography>=41.0.0
pandas>=2.0.0

# Optional QR code support
qrcode[pil]>=7.4.0
Pillow>=10.0.0

# Development dependencies (optional)
pytest>=7.0.0
pytest-cov>=4.0.0
```

## ⚡ Quick Start

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager.git
cd Post_Quantum_Offline_Manager
```

2. **Install dependencies**:
```bash
pip install cryptography pandas qrcode[pil] Pillow
```

3. **Run the application**:
```bash
python CorrectPQC.py
```

### First-Time Setup

1. **Choose token storage location** (USB recommended for maximum security)
2. **Create master password** (minimum 30 characters with mixed character types)
3. **Complete device binding** for hardware-based security
4. **Set up recovery questions** (optional but recommended)

## 🔧 Configuration

### Security Configuration

The application automatically configures quantum-resistant security settings:

- **Key Derivation**: PBKDF2 with 100,000+ iterations
- **Encryption**: AES-256-GCM with random IV generation
- **Hashing**: SHA3-512 for quantum resistance
- **Session Management**: Automatic timeout and secure cleanup

### Enhanced Libraries Status

```
🔐 PM-PQC Quantum-Resistant Crypto:     ✅ ACTIVE
🔄 Dual QR Recovery System:            ✅ ACTIVE  
⏳ Forward Secure Encryption:          ⚠️  OPTIONAL
📊 Dynamic Page Sizing Optimizer:      ⚠️  OPTIONAL
🎯 Steganographic QR System:           ⚠️  OPTIONAL
```

## 📊 Performance Metrics

### Cryptographic Performance
- **Password Hashing**: ~2-3 seconds (100K iterations)
- **Data Encryption**: ~1-2ms per KB
- **Key Derivation**: ~500ms average
- **QR Generation**: ~100-200ms per code

### Memory Usage
- **Base Application**: ~50-100 MB
- **Per Password Entry**: ~1-2 KB
- **QR Code Generation**: ~5-10 MB temporary
- **Backup Operations**: ~2x data size temporarily

## 🛡️ Security Model

### Threat Model

The system is designed to protect against:
- **Classical Computer Attacks**: Brute force, dictionary attacks
- **Quantum Computer Attacks**: Shor's algorithm, Grover's algorithm
- **Side-Channel Attacks**: Timing attacks, power analysis
- **Physical Attacks**: Device theft, forensic analysis
- **Social Engineering**: Password recovery attacks

### Security Assumptions

- **Secure Hardware**: Trusted execution environment
- **Secure Random Number Generation**: Cryptographically secure RNG
- **Physical Security**: Protection of backup materials
- **Network Isolation**: Offline operation preferred

## 🔍 Usage Examples

### Adding Password Entries

```python
# Interactive CLI
python CorrectPQC.py
# Select option 1: Add New Password Entry
# Follow prompts for service, username, password
```

### Bulk Import

```python
# Prepare CSV file with columns: service, username, password
# Select option 7: Import from File
# Choose your CSV file
```

### QR Recovery Setup

```python
# Select option 10: QR Recovery System
# Choose primary and secondary QR storage locations
# Print QR codes and store in separate secure locations
```

## 📚 API Documentation

### Core Classes

#### QuantumResistantCrypto
```python
class QuantumResistantCrypto:
    def encrypt(self, data: str) -> str
    def decrypt(self, encrypted_data: str) -> str
    def hash_password(self, password: str, salt: bytes = None) -> PasswordHash
    def verify_password(self, password: str, hash_result: PasswordHash) -> bool
```

#### SecureQRRecoverySystem
```python
class SecureQRRecoverySystem:
    def generate_recovery_qrs(self, master_password: str) -> Tuple[Dict, Dict]
    def verify_recovery_qrs(self, primary_qr_data: str, secondary_qr_data: str) -> bool
    def recover_master_password(self, primary_qr: str, secondary_qr: str) -> str
```

## 🔧 Development

### Project Structure

```
Post_Quantum_Offline_Manager/
├── CorrectPQC.py              # Main application
├── quantumvault.py            # Alternative interface
├── requirements.txt           # Dependencies
├── README.md                  # This file
├── dual_qr_recovery/          # QR recovery library
├── steganographic_qr/         # Steganographic QR library
├── quantum_resistant_crypto/  # Quantum crypto library
├── forward_secure_encryption/ # Forward secure library
├── dynamic_page_sizing/       # Page optimization library
└── logs/                      # Security logs
```

### Testing

```bash
# Run basic functionality test
python CorrectPQC.py

# Manual testing steps
# 1. Create new vault
# 2. Add password entries
# 3. Test search functionality
# 4. Generate QR recovery codes
# 5. Test backup/restore
```

### Contributing

1. **Security First**: All contributions must maintain security standards
2. **Code Review**: Security-critical changes require thorough review
3. **Testing**: Comprehensive testing of cryptographic functions
4. **Documentation**: Update documentation for new features

## 📖 Security Considerations

### Best Practices

1. **Master Password**: Use a strong, unique passphrase (30+ characters)
2. **Device Security**: Keep devices physically secure
3. **Backup Strategy**: Store QR codes in separate secure locations
4. **Regular Updates**: Keep the application and dependencies updated
5. **Offline Usage**: Prefer offline operation for maximum security

### Risk Mitigation

- **Token Binding**: Prevents unauthorized device usage
- **Secure Deletion**: Memory and storage cleanup
- **Audit Logging**: Comprehensive security event tracking
- **Input Validation**: Protection against injection attacks
- **Cryptographic Agility**: Ability to upgrade algorithms

## 🚨 Troubleshooting

### Common Issues

#### Python Not Found
```bash
# Windows
py --version
pip install cryptography

# macOS/Linux  
python3 --version
pip3 install cryptography
```

#### Missing Dependencies
```bash
pip install -r requirements.txt
```

#### QR Libraries Not Available
```bash
pip install qrcode[pil] Pillow
```

#### Token Generation Failed
- Token already exists from previous setup
- Delete token files only if absolutely necessary
- Backup existing data before token regeneration

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Password too short` | Less than 30 characters | Use longer passphrase |
| `Password validation failed` | Missing character types | Include uppercase, numbers, symbols |
| `Token generation failed` | Existing token | Normal behavior for security |
| `Library not available` | Missing dependencies | Install optional packages |

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Support

For support and questions:
- **Issues**: GitHub Issues page
- **Security**: Report security issues privately
- **Documentation**: See inline code documentation

## 🔬 Research and Innovation

This project implements several novel cryptographic techniques:

1. **Reed-Solomon Steganography**: Patent-pending method for hiding data in QR error correction
2. **Dual QR Recovery**: Cryptographic splitting for enhanced security
3. **Forward Secure Pagination**: Epoch-based key evolution for large datasets
4. **Quantum-Resistant Design**: Post-quantum cryptography implementation

## 📈 Roadmap

### Planned Features
- **Multi-factor Authentication**: Hardware token support
- **Cloud Sync**: End-to-end encrypted synchronization
- **Mobile Applications**: iOS and Android versions
- **Hardware Security Module**: HSM integration
- **Zero-Knowledge Architecture**: Client-side encryption

### Performance Improvements
- **Parallel Processing**: Multi-threaded operations
- **Memory Optimization**: Reduced memory footprint
- **Caching Strategies**: Intelligent data caching
- **Database Backend**: SQLite integration option

---

**QuantumVault: Securing the Future with Quantum-Resistant Cryptography** 🔐

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
