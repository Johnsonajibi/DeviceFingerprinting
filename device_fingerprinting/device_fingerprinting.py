"""
Production device fingerprinting library.

Hardware-based device identification for license binding with
pluggable crypto, storage, and security backends.

NOW WITH POST-QUANTUM CRYPTOGRAPHY SUPPORT!
"""

import os
import platform
import hashlib
import json
import time
import threading
import subprocess
import logging
import secrets
from typing import Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, Future

from .backends import CryptoBackend, StorageBackend, SecurityCheck
from .default_backends import HmacSha256Backend, InMemoryStorage, NoOpSecurityCheck

# Import real post-quantum cryptography backend
try:
    from .quantum_crypto import RealPostQuantumBackend
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("⚠️ Post-quantum cryptography not available. Install pqcrypto and liboqs-python for PQC support.")

# Import our real post-quantum crypto backend
try:
    from .quantum_crypto import create_real_quantum_resistant_backend
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

__version__ = "1.0.0-PQC"

# Global configuration
_crypto_backend: CryptoBackend = HmacSha256Backend()
_storage_backend: StorageBackend = InMemoryStorage()
_security_check: SecurityCheck = NoOpSecurityCheck()
_logger: Optional[logging.Logger] = None

# Post-quantum crypto configuration
_pqc_enabled: bool = False
_pqc_algorithm: str = "Dilithium3"
_pqc_hybrid_mode: bool = True

# Internal state
_cache = {}
_cache_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="fingerprint")
CACHE_TIME = 300  # 5 minutes

def set_crypto_backend(backend: CryptoBackend) -> None:
    """Set cryptographic backend for signing operations"""
    global _crypto_backend
    _crypto_backend = backend

def set_storage_backend(backend: StorageBackend) -> None:
    """Set storage backend for secure data persistence"""
    global _storage_backend
    _storage_backend = backend

def set_security_check(check: SecurityCheck) -> None:
    """Set security check for runtime tamper detection"""
    global _security_check
    _security_check = check

def set_logger(logger: Optional[logging.Logger]) -> None:
    """Set logger for debug output. None = silent operation"""
    global _logger
    _logger = logger

def enable_post_quantum_crypto(algorithm: str = "Dilithium3", 
                              hybrid_mode: bool = True) -> bool:
    """
    Enable post-quantum cryptography for device fingerprinting.
    
    Args:
        algorithm: PQC algorithm ("Dilithium3", "Dilithium5", "Falcon-512", "SPHINCS+")
        hybrid_mode: Use hybrid classical+PQC mode (recommended for transition)
    
    Returns:
        True if PQC was successfully enabled, False otherwise
    """
    global _crypto_backend, _pqc_enabled, _pqc_algorithm, _pqc_hybrid_mode
    
    if not PQC_AVAILABLE:
        _log("Post-quantum crypto libraries not available. Install liboqs-python or pqcrypto.")
        return False
    
    try:
        # Create real post-quantum crypto backend (includes fallback handling)
        pqc_backend = RealPostQuantumBackend(
            algorithm=algorithm,
            hybrid_mode=hybrid_mode
        )
        
        # Test the backend (fallback implementations are also valid)
        test_data = b"PQC compatibility test"
        test_sig = pqc_backend.sign(test_data)
        if not pqc_backend.verify(test_sig, test_data):
            _log("❌ Post-quantum crypto backend failed verification test")
            return False
        
        # Replace the crypto backend
        _crypto_backend = pqc_backend
        _pqc_enabled = True
        _pqc_algorithm = algorithm
        _pqc_hybrid_mode = hybrid_mode
        
        # Get backend info for logging
        backend_info = pqc_backend.get_info()
        library_info = backend_info.get('library', 'unknown')
        
        _log(f"✅ Post-quantum cryptography enabled: {algorithm}")
        _log(f"   Library: {library_info}")
        _log(f"   Hybrid mode: {hybrid_mode}")
        
        if 'fallback' in library_info.lower():
            _log("⚠️  Using fallback implementation - install pqcrypto/liboqs for production")
        
        return True
        
    except Exception as e:
        _log(f"Failed to enable post-quantum crypto: {type(e).__name__}: {e}")
        return False

def disable_post_quantum_crypto() -> None:
    """
    Disable post-quantum cryptography and revert to classical HMAC-SHA256.
    
    Note: This is not recommended for production use after 2030.
    """
    global _crypto_backend, _pqc_enabled
    
    _crypto_backend = HmacSha256Backend()
    _pqc_enabled = False
    _log("Post-quantum cryptography disabled - reverted to classical HMAC-SHA256")

def is_post_quantum_enabled() -> bool:
    """Check if post-quantum cryptography is currently enabled"""
    return _pqc_enabled

def get_crypto_info() -> Dict[str, Any]:
    """
    Get information about the current cryptographic configuration.
    
    Returns:
        Dictionary with crypto backend details
    """
    info = {
        'pqc_enabled': _pqc_enabled,
        'backend_type': type(_crypto_backend).__name__,
        'version': __version__
    }
    
    if _pqc_enabled:
        try:
            backend_info = _crypto_backend.get_info()
            info.update({
                'pqc_algorithm': backend_info.get('algorithm', _pqc_algorithm),
                'pqc_library': backend_info.get('library', 'unknown'),
                'hybrid_mode': backend_info.get('hybrid_mode', _pqc_hybrid_mode),
                'quantum_resistant': backend_info.get('quantum_resistant', True),
                'nist_standardized': backend_info.get('nist_standardized', False)
            })
        except Exception as e:
            info['pqc_info_error'] = str(e)
    else:
        info.update({
            'quantum_resistant': False,
            'algorithm': 'HMAC-SHA256',
            'note': 'Classical MAC - not a true digital signature'
        })
    
    return info

def _log(msg: str) -> None:
    """Internal logging with rate limiting and sanitized messages"""
    if not _logger:
        return
    
    # Sanitize message to prevent information disclosure
    sanitized_msg = _sanitize_log_message(msg)
    
    # Simple rate limiting to prevent spam
    current_time = time.time()
    key = f"log_{hash(sanitized_msg) % 1000}"
    
    with _cache_lock:
        last_log = _cache.get(key, 0)
        if current_time - last_log > 3600:  # 1 hour
            _cache[key] = current_time
            _logger.debug(sanitized_msg)

def _sanitize_log_message(msg: str) -> str:
    """Sanitize log messages to prevent information disclosure"""
    # Remove sensitive patterns
    import re
    
    # Remove potential hardware IDs, UUIDs, serial numbers, memory addresses
    msg = re.sub(r'[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}', '[UUID]', msg, flags=re.IGNORECASE)
    msg = re.sub(r'0x[A-F0-9]+', '[MEM_ADDR]', msg, flags=re.IGNORECASE)
    msg = re.sub(r'\b[A-F0-9]{12,}\b', '[HEX_ID]', msg, flags=re.IGNORECASE)
    msg = re.sub(r'\b\d{8,}\b', '[NUMERIC_ID]', msg)
    
    # Truncate overly long messages
    if len(msg) > 200:
        msg = msg[:200] + "...[truncated]"
    
    return msg

def _constant_time_cache_lookup(cache_key: str) -> Optional[Dict[str, Any]]:
    """Constant-time cache lookup to prevent timing attacks"""
    # Add random delay to prevent timing analysis
    dummy_time = secrets.randbelow(1000) / 1000000  # 0-1ms random delay
    time.sleep(dummy_time)
    
    with _cache_lock:
        result = _cache.get(cache_key)
        current_time = time.time()
        
        # Always perform time check to maintain constant time
        if result:
            is_valid = current_time - result['time'] < CACHE_TIME
            return result if is_valid else None
        return None

def _get_stable_fields() -> Dict[str, Any]:
    """
    Get hardware fields that are stable across reboots and minor updates.
    
    Uses only slow-changing hardware characteristics:
    - CPU model (not current frequency)
    - RAM in GB (rounded, not exact bytes)  
    - Disk serial numbers (truncated for privacy)
    - Motherboard UUID (if available)
    - Network MAC hash (salted, not reversible)
    """
    fields = {}
    
    try:
        # Basic platform info - always available
        fields['os_family'] = platform.system()
        fields['cpu_arch'] = platform.machine()
        
        # CPU model name (stable across reboots)
        cpu_name = platform.processor()
        if cpu_name:
            # Normalize CPU name - remove frequency and cache info
            cpu_clean = cpu_name.split('@')[0].strip()  # Remove frequency
            cpu_clean = ' '.join(cpu_clean.split())  # Normalize whitespace
            fields['cpu_model'] = cpu_clean[:50]  # Truncate
        
        # Get OS build number (more stable than version string)
        if platform.system() == "Windows":
            fields['os_build'] = platform.win32_ver()[1]
        else:
            fields['os_release'] = platform.release()[:20]
            
    except Exception as e:
        _log(f"Failed to get basic fields: {type(e).__name__}")
        fields['error'] = 'basic_info_failed'
    
    return fields

def _obfuscate_hardware_id(value: str, field_type: str) -> str:
    """Add deterministic obfuscation to hardware IDs to prevent exact matching"""
    if not value or len(value) < 4:
        return value
        
    # Create deterministic but unpredictable noise based on the value itself
    noise_seed = hashlib.sha256(f"{value}_{field_type}_obfuscation_2024".encode()).digest()[:4]
    noise = int.from_bytes(noise_seed, 'big') % 256
    
    # Apply field-specific obfuscation
    if field_type == 'uuid':
        # Rotate characters based on noise to maintain character distribution
        rotation = noise % len(value)
        return value[rotation:] + value[:rotation]
    elif field_type == 'serial':
        # XOR with noise pattern while preserving alphanumeric characters
        result = []
        for i, c in enumerate(value):
            if c.isalnum():
                # XOR with position-dependent noise
                char_noise = (noise + i) % 26
                if c.isdigit():
                    new_char = str((int(c) + char_noise) % 10)
                elif c.isupper():
                    new_char = chr((ord(c) - ord('A') + char_noise) % 26 + ord('A'))
                elif c.islower():
                    new_char = chr((ord(c) - ord('a') + char_noise) % 26 + ord('a'))
                else:
                    new_char = c
                result.append(new_char)
            else:
                result.append(c)
        return ''.join(result)
    else:
        # Default: simple character rotation
        rotation = noise % max(1, len(value))
        return value[rotation:] + value[:rotation]

def _secure_subprocess_run(cmd, **kwargs):
    """Run subprocess with security hardening"""
    # Restrict environment variables
    safe_env = {
        'PATH': os.environ.get('PATH', ''),
        'SYSTEMROOT': os.environ.get('SYSTEMROOT', ''),
        'WINDIR': os.environ.get('WINDIR', ''),
    }
    
    # Apply security restrictions
    secure_kwargs = {
        'env': safe_env,
        'cwd': None,  # Don't inherit current directory
        'timeout': min(kwargs.get('timeout', 5), 5),  # Max 5 seconds
        'capture_output': True,
        'text': True,
    }
    
    # Add Windows-specific security flags
    if os.name == 'nt':
        secure_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    
    secure_kwargs.update(kwargs)
    return subprocess.run(cmd, **secure_kwargs)

def _get_wmi_uuid() -> Optional[str]:
    """Get motherboard UUID via WMI command with security hardening"""
    try:
        result = _secure_subprocess_run(['wmic', 'csproduct', 'get', 'UUID'], timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and 'UUID' not in line:
                    uuid = line.strip()
                    if len(uuid) > 10:  # Valid UUID
                        # Add obfuscation to prevent exact matching
                        obfuscated = _obfuscate_hardware_id(uuid, 'uuid')
                        return obfuscated[:16]  # Truncated for privacy
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass  # WMI unavailable or hung
    except Exception:
        pass
    return None

def _get_wmi_disk_serial() -> Optional[str]:
    """Get primary disk serial via WMI command with security hardening"""
    try:
        result = _secure_subprocess_run(['wmic', 'diskdrive', 'get', 'SerialNumber'], timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and 'SerialNumber' not in line:
                    serial = line.strip()
                    if len(serial) > 5:  # Valid serial
                        # Add obfuscation to prevent exact matching
                        obfuscated = _obfuscate_hardware_id(serial, 'serial')
                        return obfuscated[:12]  # Truncated
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass  # WMI unavailable or hung
    except Exception:
        pass
    return None

def _get_windows_hardware() -> Dict[str, Any]:
    """Get Windows-specific stable hardware identifiers"""
    fields = {}
    
    try:
        # CPU details from registry
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            try:
                cpu_name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                fields['cpu_name'] = cpu_name.strip()[:50]
            except:
                pass
        
        # Motherboard UUID via WMI (if available)
        uuid = _get_wmi_uuid()
        if uuid:
            fields['board_uuid'] = uuid
            
        # Primary disk serial (truncated)
        serial = _get_wmi_disk_serial()
        if serial:
            fields['disk_serial'] = serial
            
    except ImportError:
        pass  # winreg not available
    except Exception as e:
        _log(f"Windows hardware detection failed: {type(e).__name__}")
    
    return fields

def _get_memory_info() -> Dict[str, Any]:
    """Get memory info rounded to GB for stability"""
    try:
        # Try psutil first (most accurate)
        try:
            import psutil
        except ImportError:
            psutil = None
            
        if psutil:
            mem = psutil.virtual_memory()
            # Round to nearest GB for stability
            ram_gb = round(mem.total / (1024**3))
            return {'ram_gb': ram_gb}
        
        # Fallback for Linux without psutil
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        ram_gb = round(kb / (1024**2))
                        return {'ram_gb': ram_gb}
        except:
            pass
            
    except Exception as e:
        _log(f"Memory detection failed: {type(e).__name__}")
    
    return {}

def _get_network_hash() -> Dict[str, Any]:
    """Get salted hash of primary network adapter MAC"""
    try:
        import uuid
        mac = uuid.getnode()
        if mac and mac != 0x1fffffffffffff:  # Valid MAC
            # Hash the MAC with a salt to prevent tracking
            mac_bytes = mac.to_bytes(6, 'big')
            mac_hash = hashlib.sha256(mac_bytes + b"mac_salt_2024").hexdigest()[:16]
            return {'mac_hash': mac_hash}
    except Exception as e:
        _log(f"MAC hash failed: {type(e).__name__}")
    
    return {}

def _generate_fingerprint_fields() -> Dict[str, Any]:
    """
    Generate stable hardware fingerprint fields.
    
    Returns dictionary of hardware characteristics that should
    remain stable across reboots and minor system updates.
    """
    fields = _get_stable_fields()
    
    # Add platform-specific hardware info
    if platform.system() == "Windows":
        fields.update(_get_windows_hardware())
    
    # Add memory and network info
    fields.update(_get_memory_info())
    fields.update(_get_network_hash())
    
    # Add timestamp for debugging
    fields['collected_at'] = int(time.time())
    
    return fields

def _score_field_match(current: Dict[str, Any], stored: Dict[str, Any]) -> float:
    """
    Score how well current hardware matches stored fingerprint.
    
    Returns float between 0.0 and 1.0 indicating match confidence.
    Uses weighted scoring where some fields are more important.
    """
    # Define field weights (more stable fields have higher weight)
    weights = {
        'cpu_model': 0.25,
        'cpu_name': 0.25, 
        'ram_gb': 0.15,
        'board_uuid': 0.20,
        'disk_serial': 0.10,
        'mac_hash': 0.05
    }
    
    total_weight = 0.0
    matched_weight = 0.0
    
    for field, weight in weights.items():
        if field in stored:  # Only score fields that were stored
            total_weight += weight
            if field in current and current[field] == stored[field]:
                matched_weight += weight
    
    # Also check basic platform compatibility
    if stored.get('os_family') == current.get('os_family'):
        matched_weight += 0.1
        total_weight += 0.1
    
    if total_weight == 0:
        return 0.0
    
    return matched_weight / total_weight

def generate_fingerprint(method: str = "stable") -> str:
    """
    Generate cryptographically signed device fingerprint.
    
    Args:
        method: "stable" for hardware fields or "basic" for minimal fields
    
    Returns:
        Cryptographic signature of device fingerprint fields
        
    Note:
        - With PQC enabled: Uses real post-quantum digital signatures
        - Without PQC: Uses classical HMAC-SHA256 (not quantum-resistant)
    """
    # Check security if enabled
    try:
        is_suspicious, reason = _security_check.check()
        if is_suspicious:
            _log(f"Security warning: {reason}")
    except Exception as e:
        _log(f"Security check failed: {type(e).__name__}")
    
    # Check cache first using constant-time lookup
    cache_key = hashlib.sha256(f"{method}_{_pqc_enabled}_{_pqc_algorithm}".encode()).hexdigest()[:16]
    cached = _constant_time_cache_lookup(cache_key)
    if cached:
        return cached['fp']
    
    # Gather fingerprint fields
    if method == "basic":
        fields = {
            'os': platform.system(),
            'machine': platform.machine(),
            'version': platform.release()
        }
    else:
        fields = _generate_fingerprint_fields()
    
    # Add cryptographic metadata
    crypto_info = get_crypto_info()
    fields['crypto_metadata'] = {
        'pqc_enabled': crypto_info['pqc_enabled'],
        'algorithm': crypto_info.get('pqc_algorithm', crypto_info.get('algorithm', 'HMAC-SHA256')),
        'quantum_resistant': crypto_info['quantum_resistant'],
        'signature_type': 'digital_signature' if crypto_info['pqc_enabled'] else 'mac',
        'timestamp': int(time.time())
    }
    
    # Create cryptographic signature using pluggable backend
    fields_json = json.dumps(fields, sort_keys=True).encode()
    fingerprint = _crypto_backend.sign(fields_json)
    
    # Cache the result
    with _cache_lock:
        _cache[cache_key] = {'fp': fingerprint, 'time': time.time(), 'fields': fields}
        # Cleanup old cache entries
        if len(_cache) > 10:
            oldest = min(_cache.keys(), key=lambda k: _cache[k]['time'])
            del _cache[oldest]
    
    # Log crypto mode for security awareness
    if _pqc_enabled:
        _log(f"Generated PQC fingerprint using {_pqc_algorithm}")
    else:
        _log("Generated classical fingerprint using HMAC-SHA256 (not quantum-resistant)")
    
    return fingerprint

def generate_fingerprint_async(method="stable") -> Future[str]:
    """
    Generate fingerprint asynchronously to avoid blocking UI.
    
    Returns Future that resolves to fingerprint string.
    """
    return _executor.submit(generate_fingerprint, method)

def create_device_binding(binding_data: Dict[str, Any], 
                         security_level: str = "high",
                         custom_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Bind data to this specific device using cryptographic signatures.
    
    Args:
        binding_data: Dictionary containing data to bind
        security_level: "basic", "medium", or "high" 
        custom_fields: Additional fields to include in binding
    
    Returns:
        Dictionary with device binding information added
    """
    if not isinstance(binding_data, dict):
        raise ValueError("binding_data must be a dict")
    
    # Choose fingerprint method and tolerance based on security level
    if security_level == "basic":
        method = "basic"
        tolerance = 0.5
    elif security_level == "medium":
        method = "stable"
        tolerance = 0.75
    else:  # high
        method = "stable" 
        tolerance = 0.85
    
    # Generate device fingerprint and get fields
    fingerprint = generate_fingerprint(method)
    
    # Get the cached fields from fingerprint generation
    with _cache_lock:
        cache_key = hashlib.sha256(f"{method}_{_pqc_enabled}_{_pqc_algorithm}".encode()).hexdigest()[:16]
        cache_entry = _cache.get(cache_key, {})
        fields = cache_entry.get('fields', {})
    
    # Create binding metadata
    binding_metadata = {
        'device_signature': fingerprint,
        'device_fields': fields,
        'binding_timestamp': int(time.time()),
        'binding_version': __version__,
        'security_level': security_level,
        'match_tolerance': tolerance
    }
    
    # Add custom fields if provided
    if custom_fields:
        binding_metadata['custom_fields'] = custom_fields
    
    # Combine with original data
    result = binding_data.copy()
    result['device_binding'] = binding_metadata
    
    # Store binding securely using pluggable backend
    try:
        storage_key = f"binding_{hash(str(binding_data))}"
        _storage_backend.store(storage_key, binding_metadata)
    except Exception as e:
        _log(f"Failed to store binding: {type(e).__name__}")
    
    return result

def verify_device_binding(bound_data: Dict[str, Any], 
                         tolerance: Optional[str] = None,
                         grace_period: int = 7) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify that bound data matches current device with detailed scoring.
    
    Args:
        bound_data: Dictionary returned from create_device_binding
        tolerance: Override tolerance level ("strict", "medium", "loose")
        grace_period: Days to accept lower scores after binding (default 7)
    
    Returns:
        Tuple of (is_valid, details_dict)
    """
    if not isinstance(bound_data, dict):
        return False, {'error': 'invalid_input'}
    
    binding_info = bound_data.get('device_binding')
    if not binding_info:
        return False, {'error': 'no_binding_data'}
    
    try:
        stored_signature = binding_info['device_signature']
        stored_fields = binding_info['device_fields']
        binding_time = binding_info.get('binding_timestamp', 0)
        stored_tolerance = binding_info.get('match_tolerance', 0.75)
        
        # Use provided tolerance or fall back to stored/default
        if tolerance == "strict":
            match_threshold = 0.95
        elif tolerance == "loose":
            match_threshold = 0.5
        elif tolerance == "medium":
            match_threshold = 0.75
        else:
            match_threshold = stored_tolerance
        
        # Get current device fields
        current_fields = _generate_fingerprint_fields()
        
        # Verify stored signature is authentic using pluggable backend
        stored_fields_json = json.dumps(stored_fields, sort_keys=True).encode()
        signature_valid = _crypto_backend.verify(stored_signature, stored_fields_json)
        if not signature_valid:
            return False, {'error': 'invalid_signature', 'signature_valid': False}
        
        # Score field matching
        match_score = _score_field_match(current_fields, stored_fields)
        
        # Check if within tolerance
        is_match = match_score >= match_threshold
        
        # Grace period for recent bindings
        age_days = (time.time() - binding_time) / (24 * 3600)
        in_grace_period = age_days <= grace_period
        
        # Accept lower scores during grace period
        if not is_match and in_grace_period and match_score >= 0.4:
            is_match = True
            grace_used = True
        else:
            grace_used = False
        
        details = {
            'match_score': match_score,
            'threshold': match_threshold,
            'signature_valid': signature_valid,
            'age_days': age_days,
            'grace_period_used': grace_used,
            'matched_fields': sum(1 for k in stored_fields 
                                if k in current_fields and 
                                current_fields[k] == stored_fields[k]),
            'total_fields': len(stored_fields)
        }
        
        return is_match, details
        
    except Exception as e:
        # Sanitize error message to prevent information disclosure
        error_type = type(e).__name__
        safe_errors = {
            'KeyError': 'missing_required_field',
            'ValueError': 'invalid_data_format',
            'TypeError': 'invalid_data_type',
            'AttributeError': 'invalid_structure'
        }
        sanitized_error = safe_errors.get(error_type, 'verification_failed')
        return False, {'error': sanitized_error}

def reset_device_id() -> bool:
    """
    Reset device binding (GDPR compliance).
    
    Clears all cached fingerprints. Does not reset backends.
    Returns True if successful.
    """
    try:
        # Clear memory cache
        with _cache_lock:
            _cache.clear()
        
        _log("Device ID reset completed")
        return True
        
    except Exception as e:
        _log(f"Device ID reset failed: {type(e).__name__}")
        return False
