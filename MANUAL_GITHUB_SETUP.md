# 🚀 Manual GitHub Repository Setup Guide

## Prerequisites

1. **Install GitHub CLI**:
   ```powershell
   winget install GitHub.cli
   ```
   Or download from: https://cli.github.com/

2. **Authenticate with GitHub**:
   ```powershell
   gh auth login
   ```

## Repository Setup Commands

### 1. Dual QR Password Recovery

```powershell
cd dual_qr_recovery
git init
git add .
git commit -m "Initial commit: Revolutionary dual QR code recovery system with cryptographic isolation"
gh repo create dual-qr-password-recovery --description "Revolutionary dual QR code recovery system with cryptographic isolation" --private --source . --remote origin --push
gh repo edit dual-qr-password-recovery --add-topic cryptography
gh repo edit dual-qr-password-recovery --add-topic qr-codes
gh repo edit dual-qr-password-recovery --add-topic security
gh repo edit dual-qr-password-recovery --add-topic recovery
gh repo edit dual-qr-password-recovery --add-topic dual-factor
cd ..
```

### 2. Post-Quantum Crypto Library

```powershell
cd quantum_resistant_crypto
git init
git add .
git commit -m "Initial commit: Post-quantum cryptographic library with SHA3-512 and timing attack protection"
gh repo create post-quantum-crypto-library --description "Post-quantum cryptographic library with SHA3-512 and timing attack protection" --private --source . --remote origin --push
gh repo edit post-quantum-crypto-library --add-topic post-quantum
gh repo edit post-quantum-crypto-library --add-topic cryptography
gh repo edit post-quantum-crypto-library --add-topic sha3
gh repo edit post-quantum-crypto-library --add-topic pbkdf2
gh repo edit post-quantum-crypto-library --add-topic quantum-resistant
cd ..
```

### 3. Forward-Secure Encryption

```powershell
cd forward_secure_encryption
git init
git add .
git commit -m "Initial commit: Forward-secure page encryption with epoch counters and selective re-encryption"
gh repo create forward-secure-encryption --description "Forward-secure page encryption with epoch counters and selective re-encryption" --private --source . --remote origin --push
gh repo edit forward-secure-encryption --add-topic forward-security
gh repo edit forward-secure-encryption --add-topic encryption
gh repo edit forward-secure-encryption --add-topic epoch-based
gh repo edit forward-secure-encryption --add-topic aes-256
gh repo edit forward-secure-encryption --add-topic temporal-security
cd ..
```

### 4. Encrypted Data in QR Codes

```powershell
cd steganographic_qr
git init
git add .
git commit -m "Initial commit: Patent-pending steganographic QR system using Reed-Solomon error correction"
gh repo create encrypted-data-in-qr-codes --description "Patent-pending steganographic QR system using Reed-Solomon error correction" --private --source . --remote origin --push
gh repo edit encrypted-data-in-qr-codes --add-topic steganography
gh repo edit encrypted-data-in-qr-codes --add-topic qr-codes
gh repo edit encrypted-data-in-qr-codes --add-topic reed-solomon
gh repo edit encrypted-data-in-qr-codes --add-topic patent-pending
gh repo edit encrypted-data-in-qr-codes --add-topic encrypted-data
cd ..
```

### 5. Dynamic Data Storage Optimizer

```powershell
cd dynamic_page_sizing
git init
git add .
git commit -m "Initial commit: Intelligent page size optimization for cryptographic vault systems"
gh repo create dynamic-data-storage-optimizer --description "Intelligent page size optimization for cryptographic vault systems" --private --source . --remote origin --push
gh repo edit dynamic-data-storage-optimizer --add-topic optimization
gh repo edit dynamic-data-storage-optimizer --add-topic page-sizing
gh repo edit dynamic-data-storage-optimizer --add-topic performance
gh repo edit dynamic-data-storage-optimizer --add-topic vault-management
gh repo edit dynamic-data-storage-optimizer --add-topic adaptive-algorithms
cd ..
```

### 6. Crypto Security Testing

```powershell
cd security_testing
git init
git add .
git commit -m "Initial commit: Comprehensive security testing framework for cryptographic operations"
gh repo create crypto-security-testing --description "Comprehensive security testing framework for cryptographic operations" --private --source . --remote origin --push
gh repo edit crypto-security-testing --add-topic security-testing
gh repo edit crypto-security-testing --add-topic timing-attacks
gh repo edit crypto-security-testing --add-topic cryptography
gh repo edit crypto-security-testing --add-topic validation
gh repo edit crypto-security-testing --add-topic test-framework
cd ..
```

## Verification

After running the commands, verify your repositories:

```powershell
gh repo list --private
```

## Repository URLs

Your private repositories will be available at:

1. https://github.com/YOUR_USERNAME/dual-qr-password-recovery
2. https://github.com/YOUR_USERNAME/post-quantum-crypto-library
3. https://github.com/YOUR_USERNAME/forward-secure-encryption
4. https://github.com/YOUR_USERNAME/encrypted-data-in-qr-codes
5. https://github.com/YOUR_USERNAME/dynamic-data-storage-optimizer
6. https://github.com/YOUR_USERNAME/crypto-security-testing

## Common Git Commands for Updates

```powershell
# To update a repository after changes
cd FOLDER_NAME
git add .
git commit -m "Update: description of changes"
git push origin main

# To clone a repository elsewhere
git clone https://github.com/YOUR_USERNAME/REPO_NAME.git

# To check repository status
git status
```

## Repository Settings

After creation, consider configuring:

1. **Branch Protection Rules**
2. **Collaborators** (if working with a team)
3. **Repository Secrets** (for CI/CD)
4. **Issues and Projects** (for project management)
5. **Wiki** (for additional documentation)

All repositories are created as **PRIVATE** by default for security.
