# Post Quantum Offline Manager

A quantum-resistant password manager with advanced cryptographic features designed for the post-quantum era. Built with enterprise-grade security and innovative cryptographic libraries.

## 🔐 Overview

Post Quantum Offline Manager (QuantumVault) is a comprehensive password management solution that implements quantum-resistant cryptography to protect against both classical and quantum computer attacks. The system integrates multiple innovative cryptographic libraries to provide maximum security for sensitive data storage.

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph "User Interface Layer"
        UI[Command Line Interface]
        Menu[Interactive Menu System]
        Input[User Input Handler]
    end
    
    subgraph "Application Core"
        App[CorrectPQC Main Application]
        Auth[Authentication Manager]
        Session[Session Controller]
        Router[Command Router]
    end
    
    subgraph "Cryptographic Engine"
        QRC[Quantum-Resistant Crypto<br/>SHA3-512 + PBKDF2]
        DQR[Dual QR Recovery<br/>Split Key Architecture]
        SQR[Steganographic QR<br/>Hidden Data in ECC]
        FSE[Forward Secure Encryption<br/>Epoch-Based Key Rotation]
        DPS[Dynamic Page Sizing<br/>Memory Optimization]
    end
    
    subgraph "Data Storage Layer"
        Vault[Encrypted Password Vault<br/>AES-256-GCM]
        Backup[Secure Backup System<br/>Multi-Location Storage]
        Config[Configuration Files<br/>JSON + Encryption]
        Logs[Security Audit Logs<br/>Tamper-Proof]
    end
    
    subgraph "Security Framework"
        Validator[Input Validation<br/>SQL Injection Prevention]
        Monitor[Security Monitoring<br/>Anomaly Detection]
        Auditor[Security Auditing<br/>Event Logging]
        MemProtect[Memory Protection<br/>Secure Deletion]
    end
    
    %% User Interface Flow
    UI --> Menu
    Menu --> Input
    Input --> Router
    Router --> App
    
    %% Core Application Flow
    App --> Auth
    App --> Session
    Auth --> QRC
    Session --> FSE
    
    %% Cryptographic Integration
    App --> DQR
    App --> SQR
    App --> DPS
    QRC --> Vault
    DQR --> Backup
    FSE --> Config
    
    %% Security Integration
    App --> Validator
    App --> Monitor
    App --> Auditor
    App --> MemProtect
    Auditor --> Logs
    
    classDef uiLayer fill:#e3f2fd,stroke:#1976d2,stroke-width:2px,color:#000000
    classDef coreLayer fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000000
    classDef cryptoLayer fill:#e8f5e8,stroke:#388e3c,stroke-width:2px,color:#000000
    classDef storageLayer fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000000
    classDef securityLayer fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#000000
    
    class UI,Menu,Input uiLayer
    class App,Auth,Session,Router coreLayer
    class QRC,DQR,SQR,FSE,DPS cryptoLayer
    class Vault,Backup,Config,Logs storageLayer
    class Validator,Monitor,Auditor,MemProtect securityLayer
```

## 🔑 Cryptographic Architecture

### Quantum-Resistant Cryptography Module

```mermaid
sequenceDiagram
    participant U as User
    participant A as Application
    participant K as Key Derivation
    participant E as Encryption Engine
    participant S as Secure Storage
    
    U->>A: Password Input
    A->>K: Generate Salt (256-bit)
    K->>K: PBKDF2 (100,000+ iterations)
    K->>K: SHA3-512 Hashing
    K->>E: Derived Key (256-bit)
    
    U->>A: Data to Encrypt
    A->>E: Plain Data + Key
    E->>E: AES-256-GCM Encryption
    E->>E: Generate Authentication Tag
    E->>S: Encrypted Data + MAC
    
    Note over K,E: Quantum-Resistant Algorithms
    Note over E,S: Perfect Forward Secrecy
```

### Dual QR Recovery System Architecture

```mermaid
graph LR
    subgraph "Data Preparation"
        MasterData[Master Recovery Data<br/>Password Hash + Device ID]
        Entropy[Additional Entropy<br/>Timestamp + Random]
    end
    
    subgraph "Cryptographic Splitting"
        Combine[Combine Data Elements]
        Split[Shamir Secret Sharing<br/>2-of-2 Threshold]
        Encrypt[Individual QR Encryption<br/>AES-256 per fragment]
    end
    
    subgraph "QR Generation"
        QR1[QR Code Fragment 1<br/>Base64 Encoded]
        QR2[QR Code Fragment 2<br/>Base64 Encoded]
        Verify[Cross-Verification<br/>Checksums]
    end
    
    subgraph "Recovery Process"
        Scan[Scan Both QR Codes]
        Validate[Validate Checksums]
        Reconstruct[Reconstruct Secret]
        Decrypt[Decrypt with Device ID]
    end
    
    MasterData --> Combine
    Entropy --> Combine
    Combine --> Split
    Split --> Encrypt
    Encrypt --> QR1
    Encrypt --> QR2
    QR1 --> Verify
    QR2 --> Verify
    
    QR1 --> Scan
    QR2 --> Scan
    Scan --> Validate
    Validate --> Reconstruct
    Reconstruct --> Decrypt
    
    classDef dataPrep fill:#e8f5e8,stroke:#4caf50,stroke-width:2px,color:#000000
    classDef cryptoSplit fill:#e3f2fd,stroke:#2196f3,stroke-width:2px,color:#000000
    classDef qrGen fill:#fff3e0,stroke:#ff9800,stroke-width:2px,color:#000000
    classDef recovery fill:#ffebee,stroke:#f44336,stroke-width:2px,color:#000000
    
    class MasterData,Entropy dataPrep
    class Combine,Split,Encrypt cryptoSplit
    class QR1,QR2,Verify qrGen
    class Scan,Validate,Reconstruct,Decrypt recovery
```

### Steganographic QR System Architecture

```mermaid
flowchart TD
    subgraph "Data Processing Pipeline"
        Secret[Secret Data Input]
        Compress[ZLIB Compression<br/>Reduce Size]
        Encrypt[AES-256 Encryption<br/>With Random IV]
        Format[Base64 Encoding]
    end
    
    subgraph "QR Code Analysis"
        Public[Public QR Data]
        Generate[Generate Standard QR]
        Analyze[Reed-Solomon Analysis<br/>Error Correction Capacity]
        Calculate[Calculate Available<br/>Steganographic Space]
    end
    
    subgraph "Steganographic Embedding"
        BitLevel[Bit-Level Manipulation]
        ECCSpace[ECC Space Utilization]
        Embed[Embed Hidden Data]
        Integrity[Dual Integrity Check<br/>Visible + Hidden]
    end
    
    subgraph "Verification & Output"
        StandardTest[Standard QR Test<br/>Functionality Preserved]
        HiddenTest[Hidden Data Test<br/>Extraction Verification]
        FinalQR[Final Steganographic QR<br/>Dual-Purpose Code]
    end
    
    Secret --> Compress
    Compress --> Encrypt
    Encrypt --> Format
    
    Public --> Generate
    Generate --> Analyze
    Analyze --> Calculate
    
    Format --> BitLevel
    Calculate --> BitLevel
    BitLevel --> ECCSpace
    ECCSpace --> Embed
    Embed --> Integrity
    
    Integrity --> StandardTest
    Integrity --> HiddenTest
    StandardTest --> FinalQR
    HiddenTest --> FinalQR
    
    classDef processing fill:#e8f5e8,stroke:#4caf50,stroke-width:2px,color:#000000
    classDef analysis fill:#e3f2fd,stroke:#2196f3,stroke-width:2px,color:#000000
    classDef embedding fill:#fff3e0,stroke:#ff9800,stroke-width:2px,color:#000000
    classDef verification fill:#ffebee,stroke:#f44336,stroke-width:2px,color:#000000
    
    class Secret,Compress,Encrypt,Format processing
    class Public,Generate,Analyze,Calculate analysis
    class BitLevel,ECCSpace,Embed,Integrity embedding
    class StandardTest,HiddenTest,FinalQR verification
```

### Forward Secure Encryption Architecture

```mermaid
graph TB
    subgraph "Epoch Management"
        Timer[Time-Based Epochs<br/>Configurable Intervals]
        Current[Current Epoch State]
        Trigger[Automatic Rotation Triggers]
    end
    
    subgraph "Key Evolution Chain"
        MasterSeed[Master Seed Key<br/>256-bit Entropy]
        KDF[One-Way Key Derivation<br/>HKDF-SHA256]
        EpochKey[Current Epoch Key]
        NextKey[Next Epoch Key]
    end
    
    subgraph "Data Operations"
        Encrypt[Data Encryption<br/>AES-256-GCM]
        Decrypt[Data Decryption<br/>Historical Keys]
        ReEncrypt[Batch Re-encryption<br/>Background Process]
    end
    
    subgraph "Security Guarantees"
        Delete[Secure Key Deletion<br/>Memory Wiping]
        Isolate[Compromise Isolation<br/>Time-Bounded Impact]
        Forward[Forward Secrecy<br/>Past Data Protection]
    end
    
    Timer --> Current
    Current --> Trigger
    Trigger --> Timer
    
    MasterSeed --> KDF
    Current --> KDF
    KDF --> EpochKey
    KDF --> NextKey
    
    EpochKey --> Encrypt
    EpochKey --> Decrypt
    NextKey --> ReEncrypt
    
    Trigger --> Delete
    Delete --> Isolate
    Isolate --> Forward
    
    classDef epoch fill:#e8f5e8,stroke:#4caf50,stroke-width:2px,color:#000000
    classDef keychain fill:#e3f2fd,stroke:#2196f3,stroke-width:2px,color:#000000
    classDef operations fill:#fff3e0,stroke:#ff9800,stroke-width:2px,color:#000000
    classDef security fill:#ffebee,stroke:#f44336,stroke-width:2px,color:#000000
    
    class Timer,Current,Trigger epoch
    class MasterSeed,KDF,EpochKey,NextKey keychain
    class Encrypt,Decrypt,ReEncrypt operations
    class Delete,Isolate,Forward security
```

### Dynamic Page Sizing Architecture

```mermaid
graph TD
    subgraph "Data Intelligence"
        Profile[Data Profiling<br/>Size & Pattern Analysis]
        Entropy[Entropy Calculation<br/>Compression Potential]
        Access[Access Pattern Detection<br/>Hot/Cold Data]
    end
    
    subgraph "Optimization Engine"
        Calculate[Optimal Size Calculator<br/>Mathematical Modeling]
        Predict[Performance Prediction<br/>Machine Learning]
        Threshold[Threshold Management<br/>Dynamic Adjustment]
    end
    
    subgraph "Memory Management"
        Allocate[Page Allocation<br/>Variable Size Pages]
        Fragment[Fragmentation Control<br/>Memory Defragmentation]
        Pool[Memory Pool Management<br/>Efficient Allocation]
    end
    
    subgraph "Performance Monitoring"
        Metrics[Performance Metrics<br/>Throughput & Latency]
        Feedback[Feedback Loop<br/>Continuous Optimization]
        Adapt[Adaptive Tuning<br/>Real-Time Adjustment]
    end
    
    Profile --> Calculate
    Entropy --> Calculate
    Access --> Predict
    
    Calculate --> Threshold
    Predict --> Threshold
    Threshold --> Allocate
    
    Allocate --> Fragment
    Fragment --> Pool
    Pool --> Metrics
    
    Metrics --> Feedback
    Feedback --> Adapt
    Adapt --> Profile
    
    classDef intelligence fill:#e8f5e8,stroke:#4caf50,stroke-width:2px,color:#000000
    classDef optimization fill:#e3f2fd,stroke:#2196f3,stroke-width:2px,color:#000000
    classDef memory fill:#fff3e0,stroke:#ff9800,stroke-width:2px,color:#000000
    classDef monitoring fill:#ffebee,stroke:#f44336,stroke-width:2px,color:#000000
    
    class Profile,Entropy,Access intelligence
    class Calculate,Predict,Threshold optimization
    class Allocate,Fragment,Pool memory
    class Metrics,Feedback,Adapt monitoring
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
pip install cryptography pandas qrcode[pil] hashlib secrets
```

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager.git
cd Post_Quantum_Offline_Manager
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Run the application**:
```bash
python CorrectPQC.py
```

## 🎯 Usage

### Basic Operations
```bash
# Start the application
python CorrectPQC.py

# Follow the interactive menu to:
# 1. Add new passwords
# 2. Search for passwords
# 3. Generate QR recovery codes
# 4. Import/export data
# 5. Configure security settings
```

### Advanced Features
```bash
# Generate dual QR recovery codes
# Navigate to: Security → QR Recovery → Generate Dual QR

# Create steganographic QR codes
# Navigate to: Advanced → Steganographic QR → Create Hidden QR

# Configure forward secure encryption
# Navigate to: Security → Forward Secure → Configure Epochs
```

## 🛡️ Security

### Cryptographic Standards
- **Hash Function**: SHA3-512 (NIST approved, quantum-resistant)
- **Key Derivation**: PBKDF2 with 100,000+ iterations
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Random Number Generation**: Cryptographically secure PRNG

### Security Measures
- **Input Validation**: Prevents injection attacks
- **Memory Protection**: Secure memory allocation and deletion
- **Audit Logging**: Comprehensive security event logging
- **Device Binding**: Hardware-specific cryptographic binding
- **Forward Secrecy**: Time-bounded compromise isolation

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support, please open an issue on GitHub or contact the development team.

## 🔮 Future Roadmap

- **GUI Interface**: Desktop application with modern UI
- **Mobile Integration**: iOS and Android companion apps
- **Cloud Sync**: Optional encrypted cloud synchronization
- **Hardware Security Module**: HSM integration for enterprise use
- **Multi-Factor Authentication**: TOTP and hardware token support
