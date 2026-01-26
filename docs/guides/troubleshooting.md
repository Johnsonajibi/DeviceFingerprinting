---
layout: default
title: Troubleshooting Guide
---

# Troubleshooting Guide

Solutions for common issues and error messages.

## Installation Issues

### Error: "No module named setuptools"

**Cause**: setuptools not installed

**Solution**:
```bash
python -m pip install --upgrade pip setuptools wheel
pip install device-fingerprinting-pro
```

### Error: "Microsoft Visual C++ 14.0 is required" (Windows)

**Cause**: Missing C++ compiler

**Solution**:
1. Download Microsoft C++ Build Tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Run installer and select "Desktop development with C++"
3. Restart and retry installation

Or use pre-built wheel:
```bash
pip install device-fingerprinting-pro --only-binary :all:
```

### Error: "pip: command not found"

**Cause**: Python not in PATH or pip not installed

**Solution**:
```bash
# Use Python module runner
python -m pip install device-fingerprinting-pro

# Or upgrade pip
python -m pip install --upgrade pip
```

### Error: "Permission denied" during installation

**Cause**: Insufficient file permissions

**Solution**:

Option 1 - Use --user flag:
```bash
pip install --user device-fingerprinting-pro
```

Option 2 - Use virtual environment (recommended):
```bash
python -m venv fingerprint_env
source fingerprint_env/bin/activate  # Windows: fingerprint_env\Scripts\activate
pip install device-fingerprinting-pro
```

Option 3 - Use sudo (Linux/macOS, not recommended):
```bash
sudo pip install device-fingerprinting-pro
```

### Error: "Wheel building failed"

**Cause**: Missing build dependencies

**Solution**:

**Ubuntu/Debian**:
```bash
sudo apt-get install -y python3-dev build-essential
pip install device-fingerprinting-pro
```

**CentOS/RHEL**:
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel
pip install device-fingerprinting-pro
```

**macOS**:
```bash
xcode-select --install
pip install device-fingerprinting-pro
```

---

## Import Issues

### Error: "ModuleNotFoundError: No module named 'device_fingerprinting'"

**Cause 1**: Library not installed

**Solution**:
```bash
pip install device-fingerprinting-pro
```

**Cause 2**: Wrong Python interpreter

**Solution**:
```bash
# Check Python version
python --version  # Must be 3.9+

# Check where device-fingerprinting is installed
python -m pip show device-fingerprinting-pro

# Use explicit Python
python3.11 -m pip install device-fingerprinting-pro
```

**Cause 3**: Virtual environment not activated

**Solution**:
```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate  # Windows
```

### Error: "ImportError: DLL load failed" (Windows)

**Cause**: Missing runtime dependencies

**Solution**:
```bash
# Install Visual C++ Redistributable
# https://support.microsoft.com/en-us/help/2977003

# Or reinstall the library
pip uninstall device-fingerprinting-pro
pip install device-fingerprinting-pro
```

### Error: "cannot import name 'ProductionFingerprintGenerator'"

**Cause**: Using old version or wrong import

**Solution**:
```python
# Check version
import device_fingerprinting
print(device_fingerprinting.__version__)

# Correct import
from device_fingerprinting import ProductionFingerprintGenerator
```

---

## Fingerprint Generation Issues

### Issue: Fingerprint changes between runs

**This should not happen**. Fingerprints are deterministic.

**Causes & Solutions**:

**1. Hardware changes detected**:
```bash
# Check system information
python -c "from device_fingerprinting import DeviceFingerprintGenerator; g = DeviceFingerprintGenerator(); print(g.get_system_info())"
```

**2. BIOS/UEFI updated**:
- Fingerprints may change after BIOS updates
- This is expected behavior
- Update stored fingerprints accordingly

**3. Disk replaced**:
- New disk = new fingerprint component
- Register device again

**4. Network interface changed**:
- New network adapter = different MAC address
- Update fingerprint

**Debug - Compare components**:

```python
from device_fingerprinting import AdvancedDeviceFingerprinter

fingerprinter = AdvancedDeviceFingerprinter()

# Get first set of components
result1 = fingerprinter.generate_fingerprint(include_debug_info=True)
components1 = set(result1.components)

# Get second set
result2 = fingerprinter.generate_fingerprint(include_debug_info=True)
components2 = set(result2.components)

# Compare
added = components2 - components1
removed = components1 - components2

if added or removed:
    print(f"Added: {added}")
    print(f"Removed: {removed}")
else:
    print("Components are consistent")
```

### Issue: Fingerprint generation is very slow

**Typical times**:
- Basic: 50ms
- Advanced: 150ms
- Quantum-resistant: 300ms

**If slower**:

**1. Check system load**:
```bash
# Linux/macOS
uptime

# Windows
wmic os get systemuptime
```

**2. Check disk speed**:
- SSDs are faster than HDDs
- Stop background processes

**3. Use faster method**:
```python
from device_fingerprinting import FingerprintMethod

# Use faster method
result = generator.generate_fingerprint(method=FingerprintMethod.BASIC)
```

**4. Cache fingerprint**:
```python
import time

class FingerprintCache:
    def __init__(self):
        self.fingerprint = None
        self.last_generated = 0
        self.cache_duration = 3600  # 1 hour
    
    def get(self, generator):
        if (self.fingerprint is None or 
            time.time() - self.last_generated > self.cache_duration):
            self.fingerprint = generator.generate_device_fingerprint()
            self.last_generated = time.time()
        return self.fingerprint
```

### Issue: "Permission denied" accessing hardware info

**Cause**: Insufficient permissions

**Solution**:

**Linux**:
```bash
# Run with appropriate permissions
sudo python script.py

# Or add user to required groups
sudo usermod -a -G disk,video,input $(whoami)
```

**Windows**:
- Run Command Prompt as Administrator

**macOS**:
```bash
sudo python3 script.py
```

---

## Cryptography Issues

### Error: "unsupported hash type sha3_256"

**Cause**: Old OpenSSL version

**Solution**:
```bash
# Upgrade cryptography library
pip install --upgrade cryptography

# Check OpenSSL version
python -c "from cryptography.hazmat.backends import default_backend; print(default_backend())"
```

### Error: "Scrypt not available"

**Cause**: cryptography library without Scrypt support

**Solution**:
```bash
# Upgrade to latest version
pip install --upgrade 'cryptography>=43.0.0'

# Or reinstall
pip uninstall cryptography
pip install cryptography>=43.0.0
```

### Error: "AES-GCM encryption failed"

**Cause**: Data corruption or wrong key

**Solution**:
```python
# Verify data integrity
try:
    decrypted = generator.retrieve_fingerprint("key")
except ValueError as e:
    print("Data was corrupted or wrong key used")
    # Handle recovery (re-encrypt, re-store)
```

---

## Storage Issues

### Error: "Secure storage not available"

**Cause**: No keyring backend available

**Solution**:

**Linux** - Install secret service:
```bash
sudo apt-get install -y gnome-keyring
# or for KDE
sudo apt-get install -y kwalletmanager
```

**Windows**:
- Uses Windows Credential Manager (built-in)
- Should work automatically

**macOS**:
- Uses Keychain (built-in)
- Should work automatically

**Fallback** - Use filesystem storage:
```python
generator.set_storage_backend("encrypted_filesystem")
```

### Error: "Permission denied" accessing keyring

**Solution**:

**Linux**:
```bash
# Initialize keyring
sudo apt-get install -y gnome-keyring
gnome-keyring-daemon --start
```

**Windows**:
- Run as Administrator

### Error: "Storage file corrupted"

**Cause**: File corruption or tamper detection

**Solution**:
```python
# Delete corrupted storage
import os
storage_path = os.path.expanduser("~/.config/device-fingerprinting")
shutil.rmtree(storage_path)

# Regenerate
generator = ProductionFingerprintGenerator()
fingerprint = generator.generate_device_fingerprint()
generator.store_fingerprint("backup", fingerprint)
```

---

## TPM Issues

### Error: "TPM not available"

**Cause**: Device without TPM or TPM disabled

**Solution**:
```python
# Check TPM status
from device_fingerprinting import get_tpm_status
status = get_tpm_status()
print(f"TPM available: {status['tpm_hardware_available']}")

# Enable software fallback (automatic)
# Library uses software fingerprinting if TPM unavailable
```

### Error: "Permission denied accessing /dev/tpm0" (Linux)

**Cause**: User not in tpm group

**Solution**:
```bash
# Add user to tpm group
sudo usermod -a -G tpm $(whoami)

# Apply group membership (logout/login, or use)
newgrp tpm

# Verify
groups  # Should include 'tpm'
```

### Error: "TPM initialization failed"

**Cause**: TPM in bad state or disabled in BIOS

**Solution**:

1. **Check BIOS Settings**:
   - Restart computer
   - Enter BIOS setup (F2, DEL, or F10 depending on manufacturer)
   - Look for "Security", "TPM", or "PTT" settings
   - Ensure TPM is enabled

2. **Clear TPM**:
   ```bash
   # Windows
   tpm.msc  # Open TPM Management Console, Clear TPM
   
   # Linux
   tpm2_clear -c p
   ```

3. **Disable TPM temporarily**:
   ```python
   generator.use_tpm(enabled=False)
   ```

---

## Anomaly Detection Issues

### Issue: Too many false positives

**Cause**: Sensitivity threshold too low

**Solution**:
```python
generator = ProductionFingerprintGenerator()

# Increase threshold (less sensitive)
generator.set_anomaly_threshold(0.8)  # Higher = less sensitive

# Or provide baseline
baseline = generator.get_system_metrics()

# Compare against baseline
is_anomalous, _ = generator.detect_anomaly(
    current_metrics,
    baseline=baseline
)
```

### Issue: Not detecting actual anomalies

**Cause**: Sensitivity threshold too high

**Solution**:
```python
# Decrease threshold (more sensitive)
generator.set_anomaly_threshold(0.4)  # Lower = more sensitive
```

### Issue: Anomaly detection is slow

**Solution**:
```python
# Use minimal feature set
generator.set_feature_set("minimal")

# Or increase check interval
generator.set_anomaly_check_interval(60)  # Every 60 seconds
```

---

## Performance Issues

### Issue: High CPU usage during fingerprint generation

**Solution**:

**1. Check system load**:
```bash
# See what's using CPU
top  # Linux/macOS
tasklist  # Windows
```

**2. Use caching**:
```python
# Cache fingerprint instead of regenerating
fingerprint = generator.generate_device_fingerprint()
# Reuse instead of regenerating
```

**3. Use simpler method**:
```python
# Use Basic method instead of Quantum-Resistant
from device_fingerprinting import FingerprintMethod
result = generator.generate_fingerprint(method=FingerprintMethod.BASIC)
```

### Issue: High memory usage

**Solution**:

**1. Limit ML features**:
```python
generator.set_feature_set("minimal")
```

**2. Use memory storage backend**:
```python
generator.set_storage_backend("memory")
```

**3. Clear caches periodically**:
```python
generator.clear_caches()
```

---

## Platform-Specific Issues

### Windows-Specific

**Issue**: "Powershell execution policy prevented script**

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Issue**: Antivirus blocking installation

**Solution**:
- Temporarily disable antivirus
- Add Python and pip to antivirus whitelist
- Or use --user installation

### macOS-Specific

**Issue**: "Cannot verify developer" error

**Solution**:
```bash
# For downloaded binaries
sudo spctl --add /path/to/binary

# Or allow in Security & Privacy settings
# System Preferences > Security & Privacy > App Store and identified developers
```

**Issue**: Apple Silicon (M1/M2) incompatibility

**Solution**:
```bash
# Ensure using native Python (not Intel emulation)
file /usr/local/bin/python3  # Should show "Mach-O 64-bit executable arm64"

# Or use architecture-specific Python
conda install -c conda-forge python=3.11 arm64
```

### Linux-Specific

**Issue**: SELinux blocking access

**Solution**:
```bash
# Temporarily disable
sudo setenforce 0

# Or adjust policy
sudo setsebool -P allow_execstacks on
```

**Issue**: AppArmor preventing access

**Solution**:
```bash
# Check AppArmor status
sudo aa-status

# Disable for Python
sudo aa-disable /etc/apparmor.d/usr.bin.python*
```

---

## Network/Connectivity Issues

### Issue: Cannot download dependencies

**Cause**: Network issue or pip index down

**Solution**:

```bash
# Use different pip index
pip install -i https://pypi.org/simple device-fingerprinting-pro

# Or use proxy
pip install --proxy "[user:passwd@]proxy.server:port" device-fingerprinting-pro

# Or download offline
pip download device-fingerprinting-pro
pip install --no-index --find-links . device-fingerprinting-pro
```

---

## Getting Help

If you can't find a solution:

1. **Check FAQ**: [Frequently Asked Questions](faq.md)
2. **Review Examples**: [Usage Examples](examples.md)
3. **Check Issues**: https://github.com/yourusername/device-fingerprinting/issues
4. **Search Stack Overflow**: Tag: device-fingerprinting-pro
5. **Email Support**: ajibijohnson@jtnetsolutions.com

When reporting issues, include:

- Python version: `python --version`
- Library version: `pip show device-fingerprinting-pro`
- Operating system and version
- Complete error traceback
- Steps to reproduce
- Attempted solutions

---

## Debug Mode

Enable debug logging for detailed information:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('device_fingerprinting')
logger.setLevel(logging.DEBUG)

# Now use library
from device_fingerprinting import ProductionFingerprintGenerator
generator = ProductionFingerprintGenerator()
fingerprint = generator.generate_device_fingerprint()
```

This will show detailed information about each operation, which helps with troubleshooting.
