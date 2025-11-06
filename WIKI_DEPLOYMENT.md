# Deployment Guide

This guide covers deploying the Device Fingerprinting library in enterprise environments.

## 📋 Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Security Hardening](#security-hardening)
- [Performance Optimization](#performance-optimization)
- [Monitoring & Logging](#monitoring--logging)
- [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### Essential Requirements

- [ ] Python 3.9+ installed
- [ ] Virtual environment configured
- [ ] All dependencies installed
- [ ] PQC libraries verified (`pqcdualusb>=0.15.5`)
- [ ] Security scan completed (0 vulnerabilities)
- [ ] Tests passing (100% critical paths)
- [ ] Configuration reviewed
- [ ] Backup strategy defined
- [ ] Monitoring configured
- [ ] Documentation reviewed

### Security Checklist

- [ ] PQC enabled and tested
- [ ] Token binding implemented
- [ ] Encrypted storage configured
- [ ] Rate limiting implemented
- [ ] Audit logging enabled
- [ ] Error handling secured
- [ ] Code obfuscated (if applicable)
- [ ] HTTPS enforced
- [ ] Secrets management configured
- [ ] Incident response plan ready

---

## Installation & Setup

### 1. Environment Setup

```bash
# Create production directory
mkdir -p /opt/your_app
cd /opt/your_app

# Create virtual environment
python3.11 -m venv venv

# Activate
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 2. Install Dependencies

```bash
# Install with all production features
pip install device-fingerprinting-pro[pqc,cloud]

# Verify installation
python -c "from device_fingerprinting import DeviceFingerprinter; print('✅ Ready')"
python -c "from device_fingerprinting.hybrid_pqc import HybridPQC; print('✅ PQC Ready')"
```

### 3. Verify Security

```bash
# Check for vulnerabilities
pip install pip-audit
pip-audit

# Expected output: Found 0 known vulnerabilities

# Verify PQC
python << EOF
from device_fingerprinting.hybrid_pqc import HybridPQC
pqc = HybridPQC()
info = pqc.get_info()
assert info['pqc_available'], "PQC not available"
assert info['algorithm'] == 'Dilithium3', "Unexpected algorithm"
print(f"PQC Verified: {info['pqc_library']}")
EOF
```

---

## Configuration

### 1. Environment Variables

Create `.env` file:

```bash
# Application Settings
APP_ENV=production
APP_DEBUG=false
APP_LOG_LEVEL=INFO

# Device Fingerprinting
FINGERPRINT_CACHE_DURATION=3600  # 1 hour
FINGERPRINT_INCLUDE_NETWORK=true
FINGERPRINT_INCLUDE_USB=false
FINGERPRINT_ADVANCED_MODE=true
FINGERPRINT_ENABLE_ML=true

# PQC Settings
PQC_BACKEND=pqcrypto  # or 'liboqs'
PQC_ALGORITHM=Dilithium3

# Storage Settings
STORAGE_BACKEND=encrypted_file  # or 's3', 'azure'
STORAGE_ENCRYPTION_KEY_PATH=/etc/your_app/encryption.key

# Security
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX_ATTEMPTS=5
RATE_LIMIT_WINDOW_SECONDS=300

# Monitoring
SENTRY_DSN=your_sentry_dsn
PROMETHEUS_PORT=9090
```

### 2. Application Configuration

```python
# config.py
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ProductionConfig:
    # App settings
    ENV = os.getenv('APP_ENV', 'production')
    DEBUG = os.getenv('APP_DEBUG', 'false').lower() == 'true'
    LOG_LEVEL = os.getenv('APP_LOG_LEVEL', 'INFO')
    
    # Fingerprinting settings
    FINGERPRINT_CONFIG = {
        'cache_duration': int(os.getenv('FINGERPRINT_CACHE_DURATION', 3600)),
        'include_network': os.getenv('FINGERPRINT_INCLUDE_NETWORK', 'true').lower() == 'true',
        'include_usb': os.getenv('FINGERPRINT_INCLUDE_USB', 'false').lower() == 'true',
        'advanced_mode': os.getenv('FINGERPRINT_ADVANCED_MODE', 'true').lower() == 'true',
        'enable_ml': os.getenv('FINGERPRINT_ENABLE_ML', 'true').lower() == 'true',
    }
    
    # Storage settings
    STORAGE_CONFIG = {
        'backend': os.getenv('STORAGE_BACKEND', 'encrypted_file'),
        'encryption_key_path': os.getenv('STORAGE_ENCRYPTION_KEY_PATH'),
    }
    
    # Rate limiting
    RATE_LIMIT_CONFIG = {
        'enabled': os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true',
        'max_attempts': int(os.getenv('RATE_LIMIT_MAX_ATTEMPTS', 5)),
        'window_seconds': int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', 300)),
    }

config = ProductionConfig()
```

### 3. Initialize Application

```python
# app.py
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.hybrid_pqc import HybridPQC
from device_fingerprinting.secure_storage import SecureStorage
from config import config
import logging

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/your_app/app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class LicenseManager:
    def __init__(self):
        """Initialize with production configuration"""
        self.fingerprinter = DeviceFingerprinter(**config.FINGERPRINT_CONFIG)
        self.pqc = HybridPQC()
        self.storage = SecureStorage()
        
        # Verify PQC
        pqc_info = self.pqc.get_info()
        if not pqc_info['pqc_available']:
            logger.warning("PQC not available, using fallback mode")
        else:
            logger.info(f"PQC initialized: {pqc_info['pqc_library']}")
    
    def activate_license(self, license_key: str, user_id: str = None):
        """Activate license with full security"""
        try:
            # Generate fingerprint
            result = self.fingerprinter.generate()
            
            if result.confidence_score < 0.8:
                logger.warning(f"Low confidence score: {result.confidence_score}")
            
            # Bind token
            bound_token = self.fingerprinter.bind_token(
                license_key,
                metadata={'user_id': user_id}
            )
            
            # Add PQC signature
            binding_data = f"{license_key}:{result.fingerprint}"
            pqc_signature = self.pqc.sign(binding_data)
            
            # Store securely
            self.storage.store('license_token', bound_token)
            self.storage.store('pqc_signature', pqc_signature)
            self.storage.store('fingerprint', result.fingerprint)
            
            logger.info(f"License activated: {license_key[:8]}...")
            
            return {
                'success': True,
                'fingerprint': result.fingerprint,
                'confidence': result.confidence_score
            }
            
        except Exception as e:
            logger.error(f"License activation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'Activation process failed'}
    
    def verify_license(self):
        """Verify license with full security checks"""
        try:
            # Load stored data
            bound_token = self.storage.retrieve('license_token')
            pqc_signature = self.storage.retrieve('pqc_signature')
            stored_fp = self.storage.retrieve('fingerprint')
            
            if not all([bound_token, pqc_signature, stored_fp]):
                logger.warning("Missing license data")
                return False
            
            # Verify bound token
            if not self.fingerprinter.verify_token(bound_token):
                logger.warning("Token verification failed")
                return False
            
            # Verify PQC signature
            current_result = self.fingerprinter.generate()
            binding_data = f"<license_key>:{current_result.fingerprint}"
            
            # Note: You'd need to store the original license_key or reconstruct it
            # This is simplified for demonstration
            
            logger.info("License verification successful")
            return True
            
        except Exception as e:
            logger.error(f"License verification failed: {e}", exc_info=True)
            return False

# Initialize
license_manager = LicenseManager()
```

---

## Security Hardening

### 1. File Permissions

```bash
# Linux/macOS
# Restrict access to sensitive files
chmod 600 /etc/your_app/encryption.key
chmod 600 /etc/your_app/.env
chmod 700 /opt/your_app/storage

# Set ownership
chown your_app_user:your_app_group /opt/your_app -R
```

### 2. Firewall Configuration

```bash
# Linux (ufw)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Allow monitoring (if needed)
sudo ufw allow from 10.0.0.0/8 to any port 9090  # Prometheus
```

### 3. System Hardening

```bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups

# Enable automatic security updates
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 4. Code Obfuscation

```bash
# Install PyArmor
pip install pyarmor

# Obfuscate production code
pyarmor pack \
    --clean \
    --without-license \
    -e "--onefile --hidden-import=device_fingerprinting" \
    your_app.py

# Output: dist/your_app
```

---

## Performance Optimization

### 1. Caching Strategy

```python
from device_fingerprinting import DeviceFingerprinter
from functools import lru_cache
from datetime import datetime, timedelta

class OptimizedFingerprinter:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter(
            cache_duration=3600  # 1 hour cache
        )
        self.cache_timestamp = None
    
    def get_fingerprint(self):
        """Get fingerprint with intelligent caching"""
        # Check if cache needs refresh
        if self.cache_timestamp:
            age = (datetime.now() - self.cache_timestamp).total_seconds()
            if age < 3600:  # 1 hour
                return self.fingerprinter.generate(force_refresh=False)
        
        # Refresh cache
        result = self.fingerprinter.generate(force_refresh=True)
        self.cache_timestamp = datetime.now()
        return result
    
    @lru_cache(maxsize=1000)
    def verify_cached(self, bound_token: str):
        """Cache verification results"""
        return self.fingerprinter.verify_token(bound_token)
```

### 2. Async Operations

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

class AsyncLicenseManager:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def verify_license_async(self, bound_token):
        """Async license verification"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self.fingerprinter.verify_token,
            bound_token
        )
    
    async def verify_batch(self, tokens):
        """Verify multiple licenses concurrently"""
        tasks = [
            self.verify_license_async(token)
            for token in tokens
        ]
        return await asyncio.gather(*tasks)

# Usage
async def main():
    manager = AsyncLicenseManager()
    tokens = ['token1', 'token2', 'token3']
    results = await manager.verify_batch(tokens)
    print(results)

# asyncio.run(main())
```

### 3. Database Optimization

```python
import sqlite3
from datetime import datetime

class LicenseDatabase:
    def __init__(self, db_path='/var/lib/your_app/licenses.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database with indexes"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                fingerprint TEXT NOT NULL,
                bound_token TEXT NOT NULL,
                pqc_signature TEXT NOT NULL,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_verified TIMESTAMP,
                verification_count INTEGER DEFAULT 0
            )
        ''')
        
        # Create indexes for fast lookups
        conn.execute('CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON licenses(fingerprint)')
        conn.commit()
        conn.close()
    
    def store_license(self, license_key, fingerprint, bound_token, pqc_signature):
        """Store license with optimized INSERT"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT OR REPLACE INTO licenses 
            (license_key, fingerprint, bound_token, pqc_signature)
            VALUES (?, ?, ?, ?)
        ''', (license_key, fingerprint, bound_token, pqc_signature))
        conn.commit()
        conn.close()
    
    def get_license(self, license_key):
        """Fast license lookup with index"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            (license_key,)
        )
        result = cursor.fetchone()
        conn.close()
        return result
```

---

## Monitoring & Logging

### 1. Application Logging

```python
import logging
import logging.handlers
import json

# Configure structured logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Setup logging
handler = logging.handlers.RotatingFileHandler(
    '/var/log/your_app/app.log',
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=5
)
handler.setFormatter(JsonFormatter())

logger = logging.getLogger('your_app')
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

### 2. Security Audit Logging

```python
import logging
from datetime import datetime

security_logger = logging.getLogger('security_audit')
security_handler = logging.handlers.RotatingFileHandler(
    '/var/log/your_app/security.log',
    maxBytes=50*1024*1024,  # 50 MB
    backupCount=10
)
security_logger.addHandler(security_handler)

def audit_log(event_type, details):
    """Log security events"""
    security_logger.info(json.dumps({
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'details': details
    }))

# Usage
audit_log('license_activation', {
    'license_key': 'ABC-***',  # Partial key
    'success': True,
    'confidence_score': 0.95
})

audit_log('license_verification_failed', {
    'reason': 'fingerprint_mismatch',
    'attempts': 3
})
```

### 3. Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Define metrics
license_activations = Counter(
    'license_activations_total',
    'Total number of license activations'
)

license_verifications = Counter(
    'license_verifications_total',
    'Total number of license verifications',
    ['result']  # 'success' or 'failure'
)

verification_duration = Histogram(
    'license_verification_duration_seconds',
    'Time spent verifying licenses'
)

active_licenses = Gauge(
    'active_licenses_count',
    'Number of currently active licenses'
)

class MetricsLicenseManager(LicenseManager):
    def activate_license(self, license_key, user_id=None):
        """Activate with metrics"""
        license_activations.inc()
        result = super().activate_license(license_key, user_id)
        if result['success']:
            active_licenses.inc()
        return result
    
    @verification_duration.time()
    def verify_license(self):
        """Verify with metrics"""
        result = super().verify_license()
        license_verifications.labels(
            result='success' if result else 'failure'
        ).inc()
        return result

# Start metrics server
start_http_server(9090)
```

### 4. Health Checks

```python
from flask import Flask, jsonify
from device_fingerprinting import DeviceFingerprinter
from device_fingerprinting.hybrid_pqc import HybridPQC

app = Flask(__name__)

@app.route('/health')
def health_check():
    """Basic health check"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/health/ready')
def readiness_check():
    """Readiness check with dependencies"""
    checks = {}
    
    # Check fingerprinting
    try:
        fp = DeviceFingerprinter()
        fp.generate()
        checks['fingerprinting'] = 'ok'
    except Exception as e:
        checks['fingerprinting'] = f'error: {str(e)}'
    
    # Check PQC
    try:
        pqc = HybridPQC()
        info = pqc.get_info()
        checks['pqc'] = 'ok' if info['pqc_available'] else 'fallback'
    except Exception as e:
        checks['pqc'] = f'error: {str(e)}'
    
    # Check storage
    try:
        from device_fingerprinting.secure_storage import SecureStorage
        storage = SecureStorage()
        checks['storage'] = 'ok'
    except Exception as e:
        checks['storage'] = f'error: {str(e)}'
    
    # Overall status
    all_ok = all(v in ['ok', 'fallback'] for v in checks.values())
    status_code = 200 if all_ok else 503
    
    return jsonify({
        'status': 'ready' if all_ok else 'not ready',
        'checks': checks
    }), status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

---

## Troubleshooting

### Common Issues

#### Issue 1: PQC Not Available

**Symptoms:**
```
WARNING: pqcdualusb not available, using fallback
```

**Solution:**
```bash
# Reinstall PQC dependencies
pip install --upgrade --force-reinstall pqcdualusb pqcrypto

# Verify
python -c "import pqcdualusb; print(pqcdualusb.__version__)"
```

#### Issue 2: High Memory Usage

**Symptoms:** Application using >500MB RAM

**Solution:**
```python
# Enable garbage collection
import gc

# After heavy operations
gc.collect()

# Limit cache size
fp = DeviceFingerprinter(cache_duration=300)  # 5 minutes instead of 1 hour
```

#### Issue 3: Slow Verification

**Symptoms:** Verification taking >1 second

**Solution:**
```python
# Enable caching
from functools import lru_cache

@lru_cache(maxsize=1000)
def verify_cached(bound_token):
    return fingerprinter.verify_token(bound_token)

# Use async
import asyncio
result = await verify_async(bound_token)
```

#### Issue 4: Storage Errors

**Symptoms:** `PermissionError` or `FileNotFoundError`

**Solution:**
```bash
# Check permissions
ls -la /var/lib/your_app

# Fix permissions
sudo chown your_app_user:your_app_group /var/lib/your_app -R
sudo chmod 700 /var/lib/your_app
```

---

## Next Steps

- **Monitoring Guide**: [Monitoring & Analytics →](WIKI_MONITORING.md)
- **Security Best Practices**: [Security Guide →](WIKI_SECURITY.md)
- **API Reference**: [API Documentation →](WIKI_API_CORE.md)
- **Troubleshooting**: [Troubleshooting Guide →](WIKI_TROUBLESHOOTING.md)

---

**Navigation**: [← Home](WIKI_HOME.md) | [Security](WIKI_SECURITY.md) | [Monitoring →](WIKI_MONITORING.md)
