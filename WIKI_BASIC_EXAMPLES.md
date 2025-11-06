# Basic Examples

Practical examples for common use cases of Device Fingerprinting.

## 📋 Table of Contents

- [Software Licensing](#software-licensing)
- [User Authentication](#user-authentication)
- [Session Management](#session-management)
- [Fraud Detection](#fraud-detection)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Cloud Integration](#cloud-integration)

---

## Software Licensing

### Example 1: Basic License Activation

```python
from device_fingerprinting import DeviceFingerprinter
import json
from datetime import datetime, timedelta

class SimpleLicenseManager:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.license_file = 'license.json'
    
    def activate(self, license_key):
        """Activate license on current device"""
        # Generate device fingerprint
        result = self.fingerprinter.generate()
        
        # Bind license to device
        bound_token = self.fingerprinter.bind_token(license_key)
        
        # Save license data
        license_data = {
            'license_key': license_key,
            'bound_token': bound_token,
            'fingerprint': result.fingerprint,
            'activated_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=365)).isoformat()
        }
        
        with open(self.license_file, 'w') as f:
            json.dump(license_data, f, indent=2)
        
        print(f"License activated successfully")
        print(f"   Device fingerprint: {result.fingerprint[:20]}...")
        print(f"   Confidence: {result.confidence_score:.2%}")
        
        return True
    
    def verify(self):
        """Verify license on current device"""
        try:
            # Load license data
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)
            
            # Check expiration
            expires_at = datetime.fromisoformat(license_data['expires_at'])
            if datetime.now() > expires_at:
                print("❌ License expired")
                return False
            
            # Verify device binding
            is_valid = self.fingerprinter.verify_token(license_data['bound_token'])
            
            if is_valid:
                print("License valid")
                return True
            else:
                print("License invalid - device mismatch detected")
                return False
                
        except FileNotFoundError:
            print("No license file found")
            return False
        except Exception as e:
            print(f"Verification error: {e}")
            return False

# Usage
if __name__ == '__main__':
    manager = SimpleLicenseManager()
    
    # First time: Activate license
    manager.activate("ABC-123-XYZ-789")
    
    # Every time app starts: Verify license
    if manager.verify():
        print("Starting application...")
    else:
        print("Please activate your license")
```

### Example 2: Multi-Device License

```python
from device_fingerprinting import DeviceFingerprinter
import json
from datetime import datetime

class MultiDeviceLicense:
    def __init__(self, max_devices=3):
        self.fingerprinter = DeviceFingerprinter()
        self.max_devices = max_devices
        self.license_file = 'multi_device_license.json'
    
    def _load_licenses(self):
        """Load license data"""
        try:
            with open(self.license_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {'devices': [], 'license_key': None}
    
    def _save_licenses(self, data):
        """Save license data"""
        with open(self.license_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def activate(self, license_key):
        """Activate license on current device"""
        data = self._load_licenses()
        
        # Check if license key changed
        if data['license_key'] and data['license_key'] != license_key:
            print("❌ Different license key")
            return False
        
        # Get current device fingerprint
        result = self.fingerprinter.generate()
        current_fp = result.fingerprint
        
        # Check if device already registered
        for device in data['devices']:
            if device['fingerprint'] == current_fp:
                print("Device already activated")
                return True
        
        # Check device limit
        if len(data['devices']) >= self.max_devices:
            print(f"Maximum device limit reached ({self.max_devices})")
            return False
        
        # Register new device
        bound_token = self.fingerprinter.bind_token(license_key)
        
        device_info = {
            'fingerprint': current_fp,
            'bound_token': bound_token,
            'device_name': self._get_device_name(),
            'activated_at': datetime.now().isoformat()
        }
        
        data['license_key'] = license_key
        data['devices'].append(device_info)
        self._save_licenses(data)
        
        print(f"Device activated ({len(data['devices'])}/{self.max_devices} slots used)")
        return True
    
    def verify(self):
        """Verify license on current device"""
        data = self._load_licenses()
        
        if not data['devices']:
            print("❌ No devices activated")
            return False
        
        # Get current fingerprint
        result = self.fingerprinter.generate()
        current_fp = result.fingerprint
        
        # Check if current device is registered
        for device in data['devices']:
            if device['fingerprint'] == current_fp:
                # Verify bound token
                is_valid = self.fingerprinter.verify_token(device['bound_token'])
                if is_valid:
                    print(f"License verified for {device['device_name']}")
                    return True
        
        print("Device not registered")
        return False
    
    def list_devices(self):
        """List all registered devices"""
        data = self._load_licenses()
        
        if not data['devices']:
            print("No devices registered")
            return
        
        print(f"\nRegistered Devices ({len(data['devices'])}/{self.max_devices}):")
        for i, device in enumerate(data['devices'], 1):
            print(f"  {i}. {device['device_name']}")
            print(f"     Activated: {device['activated_at']}")
            print(f"     Fingerprint: {device['fingerprint'][:20]}...")
    
    def _get_device_name(self):
        """Get friendly device name"""
        import platform
        return f"{platform.system()}-{platform.node()}"
    
    def deactivate_device(self, fingerprint):
        """Remove a device"""
        data = self._load_licenses()
        
        data['devices'] = [
            d for d in data['devices']
            if d['fingerprint'] != fingerprint
        ]
        
        self._save_licenses(data)
        print("✅ Device deactivated")

# Usage
if __name__ == '__main__':
    manager = MultiDeviceLicense(max_devices=3)
    
    # Activate on current device
    manager.activate("PRO-LICENSE-KEY")
    
    # List devices
    manager.list_devices()
    
    # Verify
    if manager.verify():
        print("Application running...")
```

---

## User Authentication

### Example 3: Device-Based MFA

```python
from device_fingerprinting import DeviceFingerprinter
import json
from datetime import datetime

class DeviceMFA:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.trusted_devices_file = 'trusted_devices.json'
    
    def _load_trusted_devices(self):
        """Load trusted devices"""
        try:
            with open(self.trusted_devices_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_trusted_devices(self, data):
        """Save trusted devices"""
        with open(self.trusted_devices_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def is_trusted_device(self, user_id):
        """Check if current device is trusted"""
        devices = self._load_trusted_devices()
        user_devices = devices.get(user_id, [])
        
        # Get current device fingerprint
        result = self.fingerprinter.generate()
        current_fp = result.fingerprint
        
        # Check if device is trusted
        for device in user_devices:
            if device['fingerprint'] == current_fp:
                print(f"Trusted device: {device['device_name']}")
                return True
        
        return False
    
    def add_trusted_device(self, user_id, device_name=None):
        """Add current device as trusted"""
        devices = self._load_trusted_devices()
        
        if user_id not in devices:
            devices[user_id] = []
        
        # Get current device info
        result = self.fingerprinter.generate()
        
        # Check if already trusted
        for device in devices[user_id]:
            if device['fingerprint'] == result.fingerprint:
                print("Device already trusted")
                return False
        
        # Add device
        device_info = {
            'fingerprint': result.fingerprint,
            'device_name': device_name or 'Unknown Device',
            'added_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
        
        devices[user_id].append(device_info)
        self._save_trusted_devices(devices)
        
        print(f"Device added to trusted list")
        return True
    
    def authenticate(self, user_id, password):
        """Authenticate user with device check"""
        # Step 1: Verify password (your implementation)
        password_valid = self._verify_password(user_id, password)
        
        if not password_valid:
            print("❌ Invalid password")
            return False
        
        # Step 2: Check if device is trusted
        if self.is_trusted_device(user_id):
            print("Authentication successful (trusted device)")
            return True
        else:
            print("New device detected - additional verification required")
            # Request 2FA code, email confirmation, etc.
            return self._require_additional_verification(user_id)
    
    def _verify_password(self, user_id, password):
        """Verify password (stub)"""
        # Your password verification logic
        return True
    
    def _require_additional_verification(self, user_id):
        """Request additional verification"""
        # Send email, SMS, or prompt for 2FA code
        print("  Please check your email for verification code")
        
        # For demo, simulate user entering code
        code = input("  Enter verification code: ")
        
        if code == "123456":  # Your verification logic
            # Add device as trusted
            device_name = input("  Name this device: ")
            self.add_trusted_device(user_id, device_name)
            return True
        
        return False

# Usage
if __name__ == '__main__':
    mfa = DeviceMFA()
    
    # User login
    user_id = "user@example.com"
    password = "user_password"
    
    if mfa.authenticate(user_id, password):
        print("✅ Logged in successfully")
    else:
        print("❌ Authentication failed")
```

---

## Session Management

### Example 4: Session Binding

```python
from device_fingerprinting import DeviceFingerprinter
import secrets
from datetime import datetime, timedelta

class SessionManager:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.sessions = {}  # In production, use database
    
    def create_session(self, user_id):
        """Create session bound to device"""
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Get device fingerprint
        result = self.fingerprinter.generate()
        
        # Bind session to device
        bound_session = self.fingerprinter.bind_token(
            session_id,
            metadata={'user_id': user_id}
        )
        
        # Store session
        self.sessions[session_id] = {
            'user_id': user_id,
            'fingerprint': result.fingerprint,
            'bound_session': bound_session,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24)
        }
        
        print(f"Session created: {session_id[:16]}...")
        return session_id
    
    def validate_session(self, session_id):
        """Validate session and device"""
        if session_id not in self.sessions:
            print("❌ Session not found")
            return False
        
        session = self.sessions[session_id]
        
        # Check expiration
        if datetime.now() > session['expires_at']:
            print("❌ Session expired")
            del self.sessions[session_id]
            return False
        
        # Verify device binding
        is_valid = self.fingerprinter.verify_token(session['bound_session'])
        
        if is_valid:
            print(f"Session validated for user: {session['user_id']}")
            return True
        else:
            print("Device mismatch detected - possible session hijacking attempt")
            return False
    
    def destroy_session(self, session_id):
        """Destroy session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            print("✅ Session destroyed")

# Usage
if __name__ == '__main__':
    manager = SessionManager()
    
    # User logs in
    session_id = manager.create_session("user123")
    
    # Later: Validate session
    if manager.validate_session(session_id):
        print("Access granted")
    else:
        print("Access denied")
    
    # Logout
    manager.destroy_session(session_id)
```

---

## Fraud Detection

### Example 5: Transaction Monitoring

```python
from device_fingerprinting import DeviceFingerprinter
from datetime import datetime, timedelta
from collections import defaultdict

class FraudDetector:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter(
            enable_ml=True,
            advanced_mode=True
        )
        self.device_history = defaultdict(list)
        self.risk_threshold = 0.7
    
    def analyze_transaction(self, user_id, amount, transaction_type):
        """Analyze transaction for fraud"""
        # Generate device fingerprint
        result = self.fingerprinter.generate()
        
        # Calculate risk score
        risk_score = 0.0
        risk_factors = []
        
        # Factor 1: New/Unknown device
        known_devices = self.device_history[user_id]
        is_known_device = any(
            d['fingerprint'] == result.fingerprint
            for d in known_devices
        )
        
        if not is_known_device:
            risk_score += 0.4
            risk_factors.append("Unknown device")
        
        # Factor 2: Low confidence score
        if result.confidence_score < 0.8:
            risk_score += 0.2
            risk_factors.append("Low confidence hardware")
        
        # Factor 3: High transaction amount
        if amount > 1000:
            risk_score += 0.2
            risk_factors.append("High value transaction")
        
        # Factor 4: Unusual timing
        if self._is_unusual_time():
            risk_score += 0.1
            risk_factors.append("Unusual time")
        
        # Factor 5: Multiple devices in short time
        if self._detect_device_switching(user_id):
            risk_score += 0.3
            risk_factors.append("Multiple devices detected")
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        
        # Record device usage
        self.device_history[user_id].append({
            'fingerprint': result.fingerprint,
            'timestamp': datetime.now(),
            'amount': amount,
            'risk_score': risk_score
        })
        
        # Determine action
        if risk_score < 0.3:
            action = "ALLOW"
            print(f"Transaction allowed (Risk: {risk_score:.1%})")
        elif risk_score < self.risk_threshold:
            action = "REVIEW"
            print(f"Transaction flagged for review (Risk: {risk_score:.1%})")
        else:
            action = "BLOCK"
            print(f"Transaction blocked (Risk: {risk_score:.1%})")
        
        return {
            'action': action,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'fingerprint': result.fingerprint,
            'confidence': result.confidence_score
        }
    
    def _is_unusual_time(self):
        """Check if transaction is at unusual time"""
        current_hour = datetime.now().hour
        return current_hour < 6 or current_hour > 23
    
    def _detect_device_switching(self, user_id):
        """Detect rapid device switching"""
        devices = self.device_history[user_id]
        
        if len(devices) < 2:
            return False
        
        # Check last 10 minutes
        recent_window = datetime.now() - timedelta(minutes=10)
        recent_devices = [
            d for d in devices
            if d['timestamp'] > recent_window
        ]
        
        # Multiple different devices in short time
        unique_fps = set(d['fingerprint'] for d in recent_devices)
        return len(unique_fps) > 2

# Usage
if __name__ == '__main__':
    detector = FraudDetector()
    
    # Analyze transactions
    result1 = detector.analyze_transaction(
        user_id="user123",
        amount=50.00,
        transaction_type="purchase"
    )
    
    result2 = detector.analyze_transaction(
        user_id="user123",
        amount=1500.00,
        transaction_type="wire_transfer"
    )
    
    print(f"\nTransaction 1: {result1['action']}")
    print(f"Transaction 2: {result2['action']}")
```

---

## Multi-Factor Authentication

### Example 6: Device as Second Factor

```python
from device_fingerprinting import DeviceFingerprinter
import json

class Device2FA:
    def __init__(self):
        self.fingerprinter = DeviceFingerprinter()
        self.registered_devices_file = '2fa_devices.json'
    
    def register_device_2fa(self, user_id):
        """Register device as 2FA method"""
        # Load existing registrations
        try:
            with open(self.registered_devices_file, 'r') as f:
                registrations = json.load(f)
        except FileNotFoundError:
            registrations = {}
        
        # Generate and bind device token
        result = self.fingerprinter.generate()
        device_token = self.fingerprinter.bind_token(user_id)
        
        # Store registration
        registrations[user_id] = {
            'fingerprint': result.fingerprint,
            'device_token': device_token,
            'registered_at': datetime.now().isoformat()
        }
        
        with open(self.registered_devices_file, 'w') as f:
            json.dump(registrations, f, indent=2)
        
        print("Device registered for 2FA")
        return True
    
    def verify_2fa(self, user_id):
        """Verify using device as second factor"""
        # Load registrations
        try:
            with open(self.registered_devices_file, 'r') as f:
                registrations = json.load(f)
        except FileNotFoundError:
            print("❌ No 2FA device registered")
            return False
        
        if user_id not in registrations:
            print("❌ User not registered for device 2FA")
            return False
        
        # Verify device token
        device_token = registrations[user_id]['device_token']
        is_valid = self.fingerprinter.verify_token(device_token)
        
        if is_valid:
            print("2FA verification successful")
            return True
        else:
            print("2FA verification failed - device mismatch")
            return False

# Usage
if __name__ == '__main__':
    twofa = Device2FA()
    
    user_id = "user@example.com"
    
    # First time: Register device
    twofa.register_device_2fa(user_id)
    
    # Login: Verify 2FA
    # Step 1: Username/Password (your implementation)
    # Step 2: Device verification
    if twofa.verify_2fa(user_id):
        print("✅ Login successful")
    else:
        print("❌ 2FA failed")
```

---

## Cloud Integration

### Example 7: License Server Integration

```python
from device_fingerprinting import DeviceFingerprinter
import requests
import json

class CloudLicenseClient:
    def __init__(self, api_url):
        self.fingerprinter = DeviceFingerprinter()
        self.api_url = api_url
    
    def activate_online(self, license_key):
        """Activate license with cloud verification"""
        # Generate device fingerprint
        result = self.fingerprinter.generate()
        
        # Send activation request to server
        response = requests.post(
            f"{self.api_url}/activate",
            json={
                'license_key': license_key,
                'fingerprint': result.fingerprint,
                'hardware_info': {
                    'confidence': result.confidence_score,
                    'components': result.components_used
                }
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Store activation token
            with open('license.json', 'w') as f:
                json.dump({
                    'license_key': license_key,
                    'activation_token': data['activation_token'],
                    'fingerprint': result.fingerprint
                }, f)
            
            print("License activated successfully")
            return True
        else:
            print(f"Activation failed: {response.json().get('error')}")
            return False
    
    def verify_online(self):
        """Verify license with cloud server"""
        # Load license
        try:
            with open('license.json', 'r') as f:
                license_data = json.load(f)
        except FileNotFoundError:
            print("❌ No license found")
            return False
        
        # Get current fingerprint
        result = self.fingerprinter.generate()
        
        # Verify with server
        response = requests.post(
            f"{self.api_url}/verify",
            json={
                'activation_token': license_data['activation_token'],
                'fingerprint': result.fingerprint
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['valid']:
                print("License verified successfully")
                return True
        
        print("License verification failed")
        return False

# Usage
if __name__ == '__main__':
    client = CloudLicenseClient("https://your-license-server.com/api")
    
    # Activate
    if client.activate_online("LICENSE-KEY-HERE"):
        print("Starting application...")
    
    # Verify (e.g., on app startup)
    if client.verify_online():
        print("Application running...")
```

---

## Next Steps

- **API Reference**: [Core API →](WIKI_API_CORE.md)
- **Advanced Features**: [PQC Guide →](WIKI_PQC.md)
- **Production Deployment**: [Deployment Guide →](WIKI_DEPLOYMENT.md)

---

**Navigation**: [← Quick Start](WIKI_QUICK_START.md) | [Home](WIKI_HOME.md) | [API →](WIKI_API_CORE.md)
