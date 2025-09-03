# QuantumVault Production Deployment Guide

## Overview

QuantumVault is a quantum-resistant password manager with advanced security features including forward-secure key rotation, multi-factor authentication, and post-quantum cryptography.

## Prerequisites

### System Requirements
- Python 3.8+ (recommended: Python 3.11+)
- Minimum 4GB RAM
- 1GB free disk space
- USB ports (for USB token authentication)

### Supported Platforms
- Windows 10/11
- macOS 10.15+
- Linux (Ubuntu 20.04+, CentOS 8+)

## Installation

### 1. Environment Setup

```bash
# Create virtual environment
python -m venv quantumvault_env

# Activate environment
# Windows:
quantumvault_env\Scripts\activate
# Linux/macOS:
source quantumvault_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Production Configuration

Create production environment file:

```bash
# Copy template
cp .env.template .env

# Edit configuration
nano .env  # or your preferred editor
```

### Required Environment Variables

```bash
# Security Configuration
QVAULT_MIN_PASSWORD_LENGTH=20
QVAULT_MAX_LOGIN_ATTEMPTS=3
QVAULT_PBKDF2_ITERATIONS=600000
QVAULT_SALT_LENGTH=64
QVAULT_LOCKOUT_DURATION=900

# Storage Configuration
QVAULT_DATA_DIR=/secure/data/quantumvault
QVAULT_BACKUP_DIR=/secure/backups/quantumvault
QVAULT_BACKUP_COUNT=10

# Cryptographic Settings
QVAULT_PAGE_SIZE_KB=2
QVAULT_KYBER_KEY_SIZE=1568

# Security Features
QVAULT_FORWARD_SECURE_ENABLED=true
QVAULT_DYNAMIC_PAGE_SIZING=true
QVAULT_COERCION_RESISTANCE=true
QVAULT_DURESS_CODE_ENABLED=true

# Multi-Factor Authentication
QVAULT_REQUIRE_SECURITY_QUESTIONS=true
QVAULT_MIN_SECURITY_QUESTIONS=3
QVAULT_QR_RECOVERY_EXPIRY_DAYS=365

# USB Token Configuration
QVAULT_USB_PIN_LENGTH=12
QVAULT_USB_PIN_MAX_ATTEMPTS=3
```

### 3. Directory Structure

```bash
# Create secure directories
mkdir -p /secure/data/quantumvault
mkdir -p /secure/backups/quantumvault
mkdir -p /secure/logs/quantumvault

# Set secure permissions (Linux/macOS)
chmod 700 /secure/data/quantumvault
chmod 700 /secure/backups/quantumvault
chmod 750 /secure/logs/quantumvault

# Windows equivalent
icacls "C:\Secure\Data\QuantumVault" /inheritance:d
icacls "C:\Secure\Data\QuantumVault" /grant:r "%USERNAME%:(OI)(CI)F"
```

## Security Hardening

### 1. File System Security

```bash
# Linux/macOS: Set restrictive permissions
find /secure/data/quantumvault -type f -exec chmod 600 {} \;
find /secure/data/quantumvault -type d -exec chmod 700 {} \;

# Create secure temporary directory
export TMPDIR=/secure/tmp
mkdir -p $TMPDIR
chmod 700 $TMPDIR
```

### 2. Network Security

- Run QuantumVault in an air-gapped environment when possible
- If network access is required, use firewall rules to restrict connections
- Consider running in a containerized environment for isolation

### 3. Memory Security

Add to environment configuration:

```bash
# Memory protection
QVAULT_SECURE_MEMORY=true
QVAULT_CLEAR_MEMORY_ON_EXIT=true
```

## Running the Application

### 1. Security Audit

Before first run, perform security audit:

```bash
python security_audit.py
```

Expected output should show a security score of 90+ for production readiness.

### 2. Application Start

```bash
# Start QuantumVault
python CorrectPQC.py

# Or with logging
python CorrectPQC.py --log-level INFO --log-file /secure/logs/quantumvault/app.log
```

### 3. First Time Setup

1. **Master Password**: Create a strong master password (minimum 20 characters)
2. **Security Questions**: Configure at least 3 security questions
3. **USB Token**: Initialize USB authentication token
4. **Backup Configuration**: Set up automated backups
5. **Recovery Codes**: Generate and securely store recovery codes

## Backup and Recovery

### 1. Automated Backups

QuantumVault automatically creates encrypted backups in the configured backup directory.

Backup files include:
- `vault_backup_YYYYMMDD_HHMMSS.enc` - Encrypted vault data
- `config_backup_YYYYMMDD_HHMMSS.enc` - Encrypted configuration
- `metadata_backup_YYYYMMDD_HHMMSS.json` - Backup metadata

### 2. Manual Backup

```bash
# Create manual backup
python -c "
from CorrectPQC import QuantumVaultManager
manager = QuantumVaultManager()
manager.create_emergency_backup()
"
```

### 3. Recovery Process

1. **Vault Recovery**: Use master password + security questions
2. **USB Token Recovery**: Use backup recovery codes
3. **Emergency Access**: Use QR recovery codes (if configured)
4. **Full System Recovery**: Restore from encrypted backups

## Monitoring and Maintenance

### 1. Log Monitoring

Monitor these log files:
- `/secure/logs/quantumvault/app.log` - Application logs
- `/secure/logs/quantaumvault/security.log` - Security events
- `/secure/logs/quantumvault/audit.log` - Access audit trail

### 2. Security Monitoring

Key security events to monitor:
- Failed login attempts
- USB token events
- Key rotation operations
- Emergency access usage
- Configuration changes

### 3. Maintenance Tasks

**Daily:**
- Check log files for security events
- Verify backup creation
- Monitor disk space

**Weekly:**
- Run security audit
- Test backup recovery
- Update security configurations if needed

**Monthly:**
- Rotate master encryption keys
- Review access logs
- Update security questions
- Test emergency recovery procedures

## Troubleshooting

### Common Issues

1. **Configuration Not Loading**
   ```bash
   # Check environment variables
   python -c "from secure_config import config_manager; print(config_manager.validate_configuration())"
   ```

2. **USB Token Issues**
   ```bash
   # List detected USB devices
   python -c "from CorrectPQC import list_removable_drives; print(list_removable_drives())"
   ```

3. **Backup Failures**
   ```bash
   # Check backup directory permissions
   ls -la /secure/backups/quantumvault
   ```

4. **Memory Issues**
   ```bash
   # Check memory usage
   python -c "import psutil; print(f'Memory: {psutil.virtual_memory().percent}%')"
   ```

### Performance Optimization

1. **Large Vaults**: Increase `QVAULT_PAGE_SIZE_KB` for vaults with 500+ passwords
2. **Slow Encryption**: Reduce `QVAULT_PBKDF2_ITERATIONS` (minimum 100000)
3. **Storage Issues**: Enable compression in backup configuration

## Security Best Practices

### 1. Operational Security

- Use dedicated hardware for QuantumVault
- Keep system offline when possible
- Regularly update cryptographic libraries
- Use hardware security modules (HSMs) if available

### 2. Access Control

- Limit system administrator access
- Use principle of least privilege
- Implement proper user authentication
- Regular access reviews

### 3. Incident Response

- Have incident response procedures ready
- Know how to quickly revoke access
- Understand emergency recovery options
- Test disaster recovery procedures

## Compliance and Auditing

### 1. Audit Logging

QuantumVault logs all security-relevant events:
- Authentication attempts
- Vault access
- Configuration changes
- Key rotations
- Backup operations

### 2. Compliance Features

- **Forward Secrecy**: Compromised keys cannot decrypt future data
- **Post-Quantum Cryptography**: Resistance to quantum computer attacks
- **Multi-Factor Authentication**: Defense in depth
- **Audit Trail**: Complete activity logging
- **Data Encryption**: All data encrypted at rest and in transit

### 3. Regular Security Assessments

- Run monthly security audits
- Perform penetration testing
- Review cryptographic implementations
- Update security configurations based on threat landscape

## Support and Updates

### 1. Security Updates

Monitor for:
- Cryptographic library updates
- Python security patches
- Operating system security updates

### 2. Configuration Updates

Keep configuration current with:
- New threat intelligence
- Regulatory requirements
- Organizational security policies

### 3. Documentation

Maintain documentation for:
- Deployment procedures
- Backup and recovery processes
- Incident response plans
- User training materials

---

**Important**: This is production-grade security software. Improper configuration or deployment may compromise security. Ensure proper testing in a non-production environment before deployment.

For additional support, consult the security_audit.py output and system logs for specific guidance on your deployment.
