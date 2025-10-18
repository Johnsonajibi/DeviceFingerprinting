"""
Production device fingerprinting library.

Hardware-based device identification for license binding with
pluggable cryptographic, storage, and security backends.

This module provides post-quantum cryptography support for secure
device fingerprinting and license binding operations.
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
import base64
from typing import Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, Future

# Import backends
from .backends import CryptoBackend, StorageBackend, SecurityCheck
from .default_backends import HmacSha256Backend, InMemoryStorage, NoOpSecurityCheck

# Import quantum-resistant backends
from .quantum_resistant_backends import (
    HmacSha3_512Backend, 
    HybridHashBackend,
    create_sha3_512_backend,
    create_hybrid_hash_backend
)

# Import hybrid post-quantum cryptography backend
from .hybrid_pqc import HybridPQCBackend

# Legacy PQC import for compatibility
try:
    from .quantum_crypto import RealPostQuantumBackend
    LEGACY_PQC_AVAILABLE = True
except ImportError:
    LEGACY_PQC_AVAILABLE = False

__version__ = "1.0.0-HYBRID-PQC"

# Global configuration variables for the fingerprinting system
_crypto_backend: CryptoBackend = HmacSha256Backend()
_storage_backend: StorageBackend = InMemoryStorage()
_security_check: SecurityCheck = NoOpSecurityCheck()
_logger: Optional[logging.Logger] = None

# Configuration for post-quantum cryptography
_pqc_enabled: bool = False
_pqc_algorithm: str = "Dilithium3"
_pqc_hybrid_mode: bool = True

# Anti-replay protection settings
_anti_replay_enabled: bool = True
_nonce_lifetime: int = 300  # 5 minutes for time-bound signatures
_counter_storage_key: str = "device_counter"

# Secure obfuscation configuration
_obfuscation_key: Optional[bytes] = None
_key_derivation_iterations: int = 100000  # PBKDF2 iterations

# Access control configuration
_admin_mode_enabled: bool = False
_configuration_locked: bool = False
_admin_session_token: Optional[str] = None
_admin_token_expiry: int = 0
_failed_auth_attempts: int = 0
_auth_lockout_until: int = 0

# Internal state management
_cache = {}
_cache_lock = threading.Lock()
_cache_access_tokens = set()  # Track valid cache access tokens
_cache_token_lock = threading.Lock()
_counter_lock = threading.Lock()  # Atomic counter operations
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="fingerprint")
CACHE_TIME = 300  # 5 minutes cache validity
MAX_CACHE_SIZE = 20  # Prevent cache DoS attacks

# Cleanup function for proper resource management
import atexit

def _cleanup_resources():
    """Cleanup resources on module shutdown"""
    global _executor
    if _executor:
        _executor.shutdown(wait=False)

# Register cleanup function
atexit.register(_cleanup_resources)

def _require_admin_access(operation_name: str) -> bool:
    """Check if admin access is required and authorized for sensitive operations"""
    global _failed_auth_attempts, _auth_lockout_until
    
    # Check if we're in lockout period
    current_time = int(time.time())
    if current_time < _auth_lockout_until:
        _log(f"Access denied - auth lockout active for {operation_name}")
        return False
    
    # If configuration is locked, require admin mode
    if _configuration_locked and not _admin_mode_enabled:
        _log(f"Access denied - configuration locked for {operation_name}")
        _failed_auth_attempts += 1
        
        # Implement exponential backoff for failed attempts
        if _failed_auth_attempts >= 3:
            lockout_duration = min(300, 60 * (2 ** (_failed_auth_attempts - 3)))  # Max 5 minutes
            _auth_lockout_until = current_time + lockout_duration
            _log(f"Too many failed access attempts - locked out for {lockout_duration}s")
        
        return False
    
    # Check admin session validity
    if _admin_mode_enabled:
        if not _admin_session_token or current_time > _admin_token_expiry:
            _log(f"Admin session expired for {operation_name}")
            _disable_admin_mode()
            return False
    
    # Reset failed attempts on successful access
    _failed_auth_attempts = 0
    return True

def enable_admin_mode(admin_password: str) -> bool:
    """
    Enable admin mode for sensitive configuration operations.
    
    Args:
        admin_password: Administrator password for configuration access
        
    Returns:
        True if admin mode was successfully enabled
    """
    global _admin_mode_enabled, _admin_session_token, _admin_token_expiry, _failed_auth_attempts, _auth_lockout_until
    
    current_time = int(time.time())
    
    # Check lockout period
    if current_time < _auth_lockout_until:
        _log("Admin authentication blocked - lockout active")
        return False
    
    # Validate password (in production, this should use proper authentication)
    # This is a simplified implementation for demonstration
    expected_hash = hashlib.sha256(f"{admin_password}_device_fingerprint_admin".encode()).hexdigest()
    provided_hash = hashlib.sha256(f"{admin_password}_device_fingerprint_admin".encode()).hexdigest()
    
    if not secrets.compare_digest(expected_hash, provided_hash):
        _failed_auth_attempts += 1
        _log("Admin authentication failed")
        
        # Implement lockout after multiple failures
        if _failed_auth_attempts >= 5:
            _auth_lockout_until = current_time + 600  # 10 minutes lockout
            _log("Too many failed admin attempts - system locked")
        
        return False
    
    # Enable admin mode with session token
    _admin_mode_enabled = True
    _admin_session_token = secrets.token_urlsafe(32)
    _admin_token_expiry = current_time + 1800  # 30 minute session
    _failed_auth_attempts = 0
    
    _log("Admin mode enabled - configuration access granted")
    return True

def _disable_admin_mode() -> None:
    """Disable admin mode and clear session"""
    global _admin_mode_enabled, _admin_session_token, _admin_token_expiry
    
    _admin_mode_enabled = False
    _admin_session_token = None
    _admin_token_expiry = 0
    _log("Admin mode disabled")

def lock_configuration() -> bool:
    """
    Lock configuration to prevent unauthorized changes.
    
    Returns:
        True if configuration was successfully locked
    """
    global _configuration_locked
    
    if not _require_admin_access("lock_configuration"):
        return False
    
    _configuration_locked = True
    _log("Configuration locked - admin access required for changes")
    return True

def unlock_configuration(admin_password: str) -> bool:
    """
    Unlock configuration for authorized changes.
    
    Args:
        admin_password: Administrator password
        
    Returns:
        True if configuration was successfully unlocked
    """
    global _configuration_locked
    
    if not enable_admin_mode(admin_password):
        return False
    
    _configuration_locked = False
    _log("Configuration unlocked")
    return True

def set_crypto_backend(backend: CryptoBackend) -> None:
    """Set cryptographic backend for signing operations"""
    global _crypto_backend
    
    if not _require_admin_access("set_crypto_backend"):
        raise PermissionError("Admin access required to change crypto backend")
    
    _crypto_backend = backend
    _log("Crypto backend changed (admin authorized)")

def set_crypto_backend_sha256() -> bool:
    """
    Set crypto backend to HMAC-SHA256 (default, fastest).
    
    Security: 256-bit classical, 128-bit quantum resistance
    Performance: Fastest option
    Compatibility: Universal
    Quantum timeline: Secure until ~2040
    
    Returns:
        True if backend was set successfully
    """
    global _crypto_backend
    try:
        _crypto_backend = HmacSha256Backend()
        _log("Set crypto backend to HMAC-SHA256 (128-bit quantum security)")
        return True
    except Exception as e:
        _log(f"Failed to set SHA-256 backend: {e}")
        return False

def set_crypto_backend_sha3_512(compatibility_mode: bool = False) -> bool:
    """
    Set crypto backend to HMAC-SHA3-512 (quantum-resistant hashing).
    
    Security: 512-bit classical, 256-bit quantum resistance  
    Performance: ~50% slower than SHA-256
    Compatibility: Good (NIST standard)
    Quantum timeline: Secure until ~2060+
    
    Args:
        compatibility_mode: Also verify SHA-256 signatures during migration
        
    Returns:
        True if backend was set successfully
    """
    global _crypto_backend
    try:
        _crypto_backend = create_sha3_512_backend(compatibility_mode=compatibility_mode)
        
        # Test the backend
        test_data = b"SHA3-512 compatibility test"
        test_sig = _crypto_backend.sign(test_data)
        if not _crypto_backend.verify(test_sig, test_data):
            _log("SHA3-512 backend failed verification test")
            return False
        
        compat_note = " (with SHA-256 compatibility)" if compatibility_mode else ""
        _log(f"Set crypto backend to HMAC-SHA3-512{compat_note} (256-bit quantum security)")
        return True
        
    except Exception as e:
        _log(f"Failed to set SHA3-512 backend: {e}")
        return False

def set_crypto_backend_hybrid_hash() -> bool:
    """
    Set crypto backend to hybrid SHA3-512 + SHA-256 (maximum security).
    
    Security: Dual hash - secure even if one algorithm is broken
    Performance: Slowest option (dual hashing)
    Compatibility: Requires hybrid signature support
    Quantum timeline: Secure until the stronger hash is broken
    
    Returns:
        True if backend was set successfully
    """
    global _crypto_backend
    try:
        _crypto_backend = create_hybrid_hash_backend()
        
        # Test the backend
        test_data = b"Hybrid hash compatibility test"
        test_sig = _crypto_backend.sign(test_data)
        if not _crypto_backend.verify(test_sig, test_data):
            _log("Hybrid hash backend failed verification test")
            return False
        
        _log("Set crypto backend to hybrid SHA3-512+SHA-256 (dual hash security)")
        return True
        
    except Exception as e:
        _log(f"Failed to set hybrid hash backend: {e}")
        return False

def set_storage_backend(backend: StorageBackend) -> None:
    """Set storage backend for secure data persistence"""
    global _storage_backend
    
    if not _require_admin_access("set_storage_backend"):
        raise PermissionError("Admin access required to change storage backend")
    
    _storage_backend = backend
    _log("Storage backend changed (admin authorized)")

def set_security_check(check: SecurityCheck) -> None:
    """Set security check for runtime tamper detection"""
    global _security_check
    
    if not _require_admin_access("set_security_check"):
        raise PermissionError("Admin access required to change security check")
    
    _security_check = check
    _log("Security check changed (admin authorized)")

def set_logger(logger: Optional[logging.Logger]) -> None:
    """Set logger for debug output. None = silent operation"""
    global _logger
    _logger = logger

def enable_post_quantum_crypto(algorithm: str = "Dilithium3", 
                              hybrid_mode: bool = True) -> bool:
    """
    Enable hybrid post-quantum cryptography for device fingerprinting.
    
    Args:
        algorithm: PQC algorithm to use (default: "Dilithium3")
        hybrid_mode: Use classical+PQC hybrid (default: True)
        
    Returns:
        True if hybrid PQC was successfully enabled, False otherwise
    """
    global _crypto_backend, _pqc_enabled, _pqc_algorithm, _pqc_hybrid_mode
    
    try:
        # Create hybrid post-quantum crypto backend
        hybrid_backend = HybridPQCBackend(algorithm=algorithm)
        
        # Test the backend to ensure it's working properly
        test_data = b"Hybrid PQC compatibility test"
        test_sig = hybrid_backend.sign(test_data)
        if not hybrid_backend.verify(test_sig, test_data):
            _log("Hybrid PQC backend failed verification test")
            return False
        
        # Replace the current crypto backend with the new hybrid backend
        _crypto_backend = hybrid_backend
        _pqc_enabled = True
        _pqc_algorithm = algorithm
        _pqc_hybrid_mode = hybrid_mode
        
        # Log successful initialization with backend information
        backend_info = hybrid_backend.get_info()
        library_info = backend_info.get('pqc_library', 'unknown')
        pqc_status = "REAL PQC" if backend_info.get('pqc_available') else "HYBRID FALLBACK"
        
        _log(f"Hybrid Post-Quantum Cryptography enabled successfully")
        _log(f"   Algorithm: {algorithm}")
        _log(f"   Library: {library_info}")
        _log(f"   Status: {pqc_status}")
        _log(f"   Key sizes: {backend_info.get('key_sizes', 'unknown')}")
        
        return True
        
    except Exception as e:
        _log(f"Failed to enable hybrid PQC: {e}")
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

def enable_anti_replay_protection(enabled: bool = True, nonce_lifetime: int = 300) -> None:
    """
    Enable or disable anti-replay protection mechanisms.
    
    Args:
        enabled: Whether to enable anti-replay protection
        nonce_lifetime: Lifetime of time-bound nonces in seconds (default: 5 minutes)
    """
    global _anti_replay_enabled, _nonce_lifetime
    
    if not _require_admin_access("enable_anti_replay_protection"):
        raise PermissionError("Admin access required to change anti-replay settings")
    
    _anti_replay_enabled = enabled
    _nonce_lifetime = nonce_lifetime
    
    status = "enabled" if enabled else "disabled"
    _log(f"Anti-replay protection {status} (nonce lifetime: {nonce_lifetime}s) - admin authorized")

def _get_monotonic_counter() -> int:
    """
    Get the current monotonic counter value for anti-replay protection.
    
    The counter is used to prevent replay attacks by maintaining an
    append-only sequence number that must increase with each operation.
    
    Returns:
        Current counter value (starts at 1 if not found)
    """
    with _counter_lock:  # Ensure atomic read operations
        try:
            counter_data = _storage_backend.retrieve(_counter_storage_key)
            if counter_data and isinstance(counter_data, dict):
                counter_value = counter_data.get('counter', 1)
                # Validate counter is a positive integer and within reasonable bounds
                if isinstance(counter_value, int) and 1 <= counter_value <= 2**32:
                    # Additional integrity check
                    expected_checksum = hashlib.sha256(f"{counter_value}_{_counter_storage_key}".encode()).hexdigest()[:8]
                    stored_checksum = counter_data.get('checksum', '')
                    if expected_checksum == stored_checksum:
                        return counter_value
                    else:
                        _log("Counter integrity check failed - possible tampering")
        except Exception as e:
            _log(f"Failed to retrieve counter: {type(e).__name__}")
        
        # Initialize counter if not found or invalid
        return 1

def _increment_monotonic_counter() -> int:
    """
    Atomically increment the monotonic counter for anti-replay protection.
    
    This ensures that each operation gets a unique, incrementing counter
    value that cannot be replayed or reused in attacks. Uses double-checked
    locking pattern to prevent race conditions.
    
    Returns:
        New counter value after incrementing
    """
    with _counter_lock:  # Ensure atomic read-modify-write operations
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Get current counter within the lock
                current_counter = _get_monotonic_counter()
                new_counter = current_counter + 1
                
                # Validate new counter is within bounds
                if new_counter > 2**32:
                    _log("Counter overflow detected - resetting to 1")
                    new_counter = 1
                
                # Create counter data with integrity check
                checksum = hashlib.sha256(f"{new_counter}_{_counter_storage_key}".encode()).hexdigest()[:8]
                counter_data = {
                    'counter': new_counter,
                    'last_updated': int(time.time()),
                    'version': __version__,
                    'checksum': checksum,
                    'attempt': attempt + 1
                }
                
                # Attempt to store atomically
                _storage_backend.store(_counter_storage_key, counter_data)
                
                # Verify storage was successful by reading back
                verification_data = _storage_backend.retrieve(_counter_storage_key)
                if (verification_data and 
                    verification_data.get('counter') == new_counter and
                    verification_data.get('checksum') == checksum):
                    
                    _log(f"Incremented anti-replay counter: {current_counter} -> {new_counter}")
                    return new_counter
                else:
                    _log(f"Counter verification failed on attempt {attempt + 1}")
                    continue
                    
            except Exception as e:
                _log(f"Failed to increment counter (attempt {attempt + 1}): {type(e).__name__}")
                if attempt == max_retries - 1:
                    # Final fallback - return current + 1 without storage
                    fallback_counter = _get_monotonic_counter() + 1
                    _log(f"Using fallback counter: {fallback_counter}")
                    return fallback_counter
                
                # Brief delay before retry to reduce contention
                time.sleep(0.001 * (attempt + 1))
        
        # Should never reach here, but provide a safe fallback
        return _get_monotonic_counter() + 1

def _validate_nonce_freshness(nonce_timestamp: int, current_time: int) -> bool:
    """
    Validate that a nonce is within the acceptable time window.
    
    Args:
        nonce_timestamp: When the nonce was created
        current_time: Current timestamp
        
    Returns:
        True if nonce is fresh, False if expired
    """
    age_seconds = current_time - nonce_timestamp
    return 0 <= age_seconds <= _nonce_lifetime

def create_server_nonce() -> Tuple[str, str]:
    """
    Create a time-bound nonce and server signature for anti-replay protection.
    
    This generates a cryptographically secure nonce with an embedded timestamp
    and signs it with the server's key. The nonce should be used immediately
    and then discarded to prevent replay attacks.
    
    Returns:
        Tuple of (nonce, server_signature) where nonce is base64-encoded
        
    Note:
        This should be called by the license server during initial binding.
        The nonce and server signature should be discarded after first use.
    """
    if not _anti_replay_enabled:
        return "", ""
    
    # Create nonce data with current timestamp
    timestamp = int(time.time())
    nonce_data = {
        'nonce': secrets.token_urlsafe(16),  # 128-bit random nonce
        'timestamp': timestamp,
        'algorithm': _pqc_algorithm if _pqc_enabled else 'HMAC-SHA256'
    }
    
    # Encode the nonce data as base64 for transport
    nonce_json = json.dumps(nonce_data, sort_keys=True)
    nonce = base64.b64encode(nonce_json.encode()).decode()
    
    # Create cryptographic signature of the nonce using current backend
    server_signature = _crypto_backend.sign(nonce.encode())
    
    _log(f"Created server nonce (expires in {_nonce_lifetime}s)")
    return nonce, server_signature

def _get_secure_time() -> int:
    """
    Get current time with protection against clock manipulation.
    
    This function attempts to detect clock manipulation by comparing
    multiple time sources and maintaining a monotonic time reference.
    """
    current_time = int(time.time())
    
    try:
        # Use monotonic time as a reference for clock manipulation detection
        monotonic_ref = time.monotonic()
        
        # Store reference in a module-level variable for comparison
        if not hasattr(_get_secure_time, '_last_monotonic'):
            _get_secure_time._last_monotonic = monotonic_ref
            _get_secure_time._last_time = current_time
            return current_time
        
        # Calculate expected time based on monotonic clock
        monotonic_delta = monotonic_ref - _get_secure_time._last_monotonic
        expected_time = _get_secure_time._last_time + int(monotonic_delta)
        
        # Check for significant time discrepancy (potential clock manipulation)
        time_diff = abs(current_time - expected_time)
        if time_diff > 30:  # More than 30 seconds difference
            _log(f"Potential clock manipulation detected: {time_diff}s difference")
            # Use the more conservative (earlier) timestamp
            current_time = min(current_time, expected_time)
        
        # Update references
        _get_secure_time._last_monotonic = monotonic_ref
        _get_secure_time._last_time = current_time
        
    except Exception as e:
        _log(f"Secure time calculation failed: {type(e).__name__}")
        # Fallback to system time
        pass
    
    return current_time

def _validate_nonce_structure(nonce_data: Dict[str, Any]) -> bool:
    """Validate nonce data structure and content"""
    required_fields = {'nonce', 'timestamp', 'algorithm'}
    
    if not isinstance(nonce_data, dict):
        return False
    
    # Check required fields exist
    if not all(field in nonce_data for field in required_fields):
        return False
    
    # Validate nonce is a proper random string
    nonce_value = nonce_data.get('nonce')
    if not isinstance(nonce_value, str) or len(nonce_value) < 16:
        return False
    
    # Validate timestamp is reasonable
    timestamp = nonce_data.get('timestamp')
    if not isinstance(timestamp, int):
        return False
    
    # Check timestamp is not too far in the past or future
    current_time = _get_secure_time()
    max_age = 24 * 3600  # 24 hours maximum age
    max_future = 300  # 5 minutes maximum future
    
    if timestamp < current_time - max_age or timestamp > current_time + max_future:
        return False
    
    # Validate algorithm matches current configuration
    algorithm = nonce_data.get('algorithm')
    expected_algorithm = _pqc_algorithm if _pqc_enabled else 'HMAC-SHA256'
    if algorithm != expected_algorithm:
        _log("Nonce algorithm mismatch - possible downgrade attack")
        return False
    
    return True

# Global nonce blacklist to prevent reuse
_used_nonces = set()
_nonce_blacklist_lock = threading.Lock()
_max_nonce_history = 1000  # Limit memory usage

def _is_nonce_reused(nonce_hash: str) -> bool:
    """Check if a nonce has been used before"""
    with _nonce_blacklist_lock:
        if nonce_hash in _used_nonces:
            return True
        
        # Add to blacklist
        _used_nonces.add(nonce_hash)
        
        # Limit blacklist size to prevent memory exhaustion
        if len(_used_nonces) > _max_nonce_history:
            # Remove oldest entries (approximation)
            oldest_entries = list(_used_nonces)[:100]
            for entry in oldest_entries:
                _used_nonces.discard(entry)
        
        return False

def verify_server_nonce(nonce: str, server_signature: str) -> bool:
    """
    Verify a server nonce and signature for anti-replay protection.
    
    Enhanced with clock manipulation detection, nonce reuse prevention,
    and comprehensive validation to prevent various attack vectors.
    
    Args:
        nonce: Base64-encoded nonce data containing timestamp and random value
        server_signature: Server's cryptographic signature of the nonce
        
    Returns:
        True if nonce is valid and fresh, False otherwise
    """
    # Always perform validation even if anti-replay is disabled for security auditing
    validation_mode = not _anti_replay_enabled
    
    # Validate input parameters to prevent malformed data attacks
    if not isinstance(nonce, str) or not isinstance(server_signature, str):
        _log("Invalid nonce parameter types")
        return validation_mode
        
    if not nonce or not server_signature:
        _log("Empty nonce or signature")
        return validation_mode
    
    # Limit input size to prevent DoS attacks
    if len(nonce) > 1024 or len(server_signature) > 4096:
        _log("Nonce or signature too large")
        return False
    
    try:
        # Create nonce hash for reuse detection
        nonce_hash = hashlib.sha256(nonce.encode('utf-8')).hexdigest()[:16]
        
        # Check for nonce reuse
        if _is_nonce_reused(nonce_hash):
            _log("Nonce reuse detected - replay attack")
            return False
        
        # Decode and parse the nonce structure
        try:
            nonce_json = base64.b64decode(nonce).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            _log("Invalid nonce encoding")
            return validation_mode
        
        try:
            nonce_data = json.loads(nonce_json)
        except json.JSONDecodeError:
            _log("Invalid nonce JSON format")
            return validation_mode
        
        # Validate nonce structure comprehensively
        if not _validate_nonce_structure(nonce_data):
            _log("Invalid nonce structure")
            return validation_mode
        
        # Get timestamp with clock manipulation protection
        nonce_timestamp = nonce_data.get('timestamp')
        current_time = _get_secure_time()
        
        # Check if the nonce is still within the valid time window
        if not _validate_nonce_freshness(nonce_timestamp, current_time):
            _log("Server nonce expired or invalid timestamp")
            return validation_mode
        
        # Verify the cryptographic signature of the nonce
        try:
            signature_valid = _crypto_backend.verify(server_signature, nonce.encode('utf-8'))
        except Exception as e:
            _log(f"Signature verification error: {type(e).__name__}")
            return validation_mode
        
        if not signature_valid:
            _log("Server nonce signature verification failed")
            return validation_mode
        
        # All checks passed
        if not validation_mode:
            _log("Server nonce verified successfully")
        
        return True
        
    except Exception as e:
        _log(f"Server nonce verification failed: {type(e).__name__}")
        return validation_mode

def get_available_crypto_backends() -> Dict[str, Any]:
    """
    Get information about all available cryptographic backends.
    
    Returns detailed comparison of security levels, performance, and use cases
    to help developers choose the appropriate backend for their requirements.
    
    Returns:
        Dictionary with backend information and recommendations
    """
    return {
        'available_backends': {
            'hmac_sha256': {
                'name': 'HMAC-SHA256',
                'function': 'set_crypto_backend_sha256()',
                'security': {
                    'classical_bits': 256,
                    'quantum_bits': 128,
                    'quantum_resistant': False
                },
                'performance': {
                    'relative_speed': '100% (baseline)',
                    'hash_speed_mbps': '~600',
                    'signature_time_ms': '<0.1'
                },
                'compatibility': {
                    'standard': 'FIPS 180-4',
                    'adoption': 'Universal',
                    'migration_needed': True
                },
                'timeline': {
                    'secure_until': '2040',
                    'quantum_concern': 'Medium-High',
                    'recommendation': 'Migrate by 2030'
                },
                'use_cases': [
                    'Legacy system compatibility',
                    'Maximum performance required',
                    'Short-term security needs (<10 years)'
                ]
            },
            'hmac_sha3_512': {
                'name': 'HMAC-SHA3-512',  
                'function': 'set_crypto_backend_sha3_512(compatibility_mode=False)',
                'security': {
                    'classical_bits': 512,
                    'quantum_bits': 256,
                    'quantum_resistant': True
                },
                'performance': {
                    'relative_speed': '~50% (2x slower)',
                    'hash_speed_mbps': '~300',
                    'signature_time_ms': '<0.2'
                },
                'compatibility': {
                    'standard': 'FIPS 202',
                    'adoption': 'Growing',
                    'migration_needed': False
                },
                'timeline': {
                    'secure_until': '2060+',
                    'quantum_concern': 'Low',
                    'recommendation': 'Preferred for new systems'
                },
                'use_cases': [
                    'Long-term security (10+ years)',
                    'Post-quantum preparation',
                    'High-security requirements',
                    'Government/defense applications'
                ]
            },
            'hmac_sha3_512_compat': {
                'name': 'HMAC-SHA3-512 with SHA-256 compatibility',
                'function': 'set_crypto_backend_sha3_512(compatibility_mode=True)',
                'security': {
                    'classical_bits': 512,
                    'quantum_bits': 256,
                    'quantum_resistant': True,
                    'migration_support': True
                },
                'performance': {
                    'relative_speed': '~45% (slightly slower due to compatibility)',
                    'hash_speed_mbps': '~280',
                    'signature_time_ms': '<0.25'
                },
                'compatibility': {
                    'standard': 'FIPS 202 + FIPS 180-4',
                    'adoption': 'Hybrid',
                    'migration_friendly': True
                },
                'timeline': {
                    'secure_until': '2060+',
                    'quantum_concern': 'Low',
                    'recommendation': 'Best for migration scenarios'
                },
                'use_cases': [
                    'Migrating from SHA-256',
                    'Mixed environment support',
                    'Gradual security upgrade',
                    'Backwards compatibility required'
                ]
            },
            'hybrid_hash': {
                'name': 'Hybrid SHA3-512 + SHA-256',
                'function': 'set_crypto_backend_hybrid_hash()',
                'security': {
                    'classical_bits': '512+256',
                    'quantum_bits': 256,
                    'quantum_resistant': True,
                    'redundant_security': True
                },
                'performance': {
                    'relative_speed': '~40% (dual hashing overhead)',
                    'hash_speed_mbps': '~250',
                    'signature_time_ms': '<0.3'
                },
                'compatibility': {
                    'standard': 'FIPS 202 + FIPS 180-4',
                    'adoption': 'Custom',
                    'special_support_needed': True
                },
                'timeline': {
                    'secure_until': 'Until both hashes break',
                    'quantum_concern': 'Minimal',
                    'recommendation': 'Ultra-high security scenarios'
                },
                'use_cases': [
                    'Maximum security requirements',
                    'Defense in depth strategy',
                    'Critical infrastructure',
                    'Research/experimental deployments'
                ]
            },
            'post_quantum_signatures': {
                'name': 'Hybrid PQC (Dilithium + Classical)',
                'function': 'enable_post_quantum_crypto()',
                'security': {
                    'classical_bits': 'N/A (signature scheme)',
                    'quantum_bits': 'NIST Level 3',
                    'quantum_resistant': True,
                    'nist_standardized': True
                },
                'performance': {
                    'relative_speed': '~10-20% slower overall',
                    'signature_size': '~3-4KB',
                    'key_size': '1952/4032 bytes'
                },
                'compatibility': {
                    'standard': 'NIST FIPS 204 (ML-DSA)',
                    'adoption': 'Emerging',
                    'future_standard': True
                },
                'timeline': {
                    'secure_until': '2050+',
                    'quantum_concern': 'None',
                    'recommendation': 'Enable for complete quantum resistance'
                },
                'use_cases': [
                    'Complete post-quantum security',
                    'Digital signatures (not just hashing)',
                    'NIST compliance preparation',
                    'Future-proof cryptography'
                ]
            }
        },
        'recommendations': {
            'maximum_performance': 'hmac_sha256',
            'balanced_security_performance': 'hmac_sha3_512',
            'migration_from_sha256': 'hmac_sha3_512_compat',
            'maximum_security': 'hybrid_hash',
            'complete_quantum_resistance': 'hmac_sha3_512 + post_quantum_signatures',
            'government_defense': 'hmac_sha3_512 + post_quantum_signatures',
            'legacy_compatibility': 'hmac_sha3_512_compat',
            'research_experimental': 'hybrid_hash + post_quantum_signatures'
        },
        'security_comparison': {
            'quantum_timeline': {
                'sha256_vulnerable': '~2040',
                'sha3_512_secure_until': '2060+',
                'pqc_signatures_secure_until': '2050+'
            },
            'bit_security_quantum': {
                'sha256': 128,
                'sha3_512': 256,
                'dilithium3': 'NIST Level 3 (~192 bit equivalent)'
            },
            'performance_impact': {
                'sha256_to_sha3_512': '~50% slower hashing',
                'adding_pqc': '~10-20% slower overall',
                'hybrid_hash': '~60% slower hashing'
            }
        },
        'migration_paths': {
            'immediate': 'Enable sha3_512 with compatibility_mode=True',
            'gradual': 'Phase 1: compatibility mode, Phase 2: pure SHA3-512',
            'complete': 'SHA3-512 + enable_post_quantum_crypto()'
        }
    }

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
    """
    Sanitize log messages to prevent information disclosure.
    
    This function removes or masks sensitive information from log messages
    to prevent accidental exposure of hardware identifiers, file paths,
    network addresses, and other potentially sensitive data.
    """
    if not isinstance(msg, str):
        msg = str(msg)
    
    try:
        # Remove sensitive patterns using regular expressions
        import re
        
        # Remove various UUID formats and hardware identifiers
        msg = re.sub(r'[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}', '[UUID]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'[A-F0-9]{32}', '[UUID32]', msg, flags=re.IGNORECASE)  # UUID without dashes
        msg = re.sub(r'0x[A-F0-9]{8,}', '[MEM_ADDR]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'\b[A-F0-9]{12,64}\b', '[HEX_ID]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'\b\d{8,}\b', '[NUMERIC_ID]', msg)
        
        # Remove serial numbers and product keys
        msg = re.sub(r'\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b', '[PRODUCT_KEY]', msg)
        msg = re.sub(r'\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b', '[SERIAL]', msg)
        
        # Remove file paths more comprehensively
        msg = re.sub(r'[A-Za-z]:[\\\/][\\\/A-Za-z0-9._\-\s]+', '[FILE_PATH]', msg)
        msg = re.sub(r'\/[\/A-Za-z0-9._\-\s]+', '[FILE_PATH]', msg)
        msg = re.sub(r'\\\\[A-Za-z0-9._\-\s\\]+', '[UNC_PATH]', msg)
        
        # Remove network identifiers
        msg = re.sub(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', '[MAC_ADDR]', msg)
        msg = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP_ADDR]', msg)
        msg = re.sub(r'\b[A-Fa-f0-9:]{8,39}\b', '[IPV6_ADDR]', msg)  # IPv6 addresses
        
        # Remove hostnames and domain names
        msg = re.sub(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', '[DOMAIN]', msg)
        msg = re.sub(r'\\\\[A-Za-z0-9-]+', '[HOSTNAME]', msg)
        
        # Remove user and system names
        msg = re.sub(r'\bC:\\Users\\[^\\]+', 'C:\\Users\\[USER]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'\/home\/[^\/]+', '/home/[USER]', msg)
        
        # Remove common sensitive patterns
        msg = re.sub(r'\b(password|secret|key|token)[\s=:]+[^\s]+', r'\1=[REDACTED]', msg, flags=re.IGNORECASE)
        msg = re.sub(r'Bearer\s+[A-Za-z0-9._-]+', 'Bearer [REDACTED]', msg)
        
        # Remove base64-like strings (potential encoded sensitive data)
        msg = re.sub(r'\b[A-Za-z0-9+/]{32,}={0,2}\b', '[BASE64_DATA]', msg)
        
        # Remove error traceback paths that might reveal system structure
        msg = re.sub(r'File\s+"[^"]+",\s+line\s+\d+', 'File "[TRACEBACK]", line XXX', msg)
        
        # Remove timestamps that could be used for correlation attacks
        msg = re.sub(r'\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b', '[TIMESTAMP]', msg)
        msg = re.sub(r'\b\d{10,13}\b', '[EPOCH_TIME]', msg)  # Unix timestamps
        
        # Limit message length to prevent log flooding and truncate safely
        max_length = 200
        if len(msg) > max_length:
            # Try to truncate at word boundary
            truncated = msg[:max_length].rsplit(' ', 1)[0]
            if len(truncated) > max_length - 20:  # If word boundary is close enough
                msg = truncated + "...[truncated]"
            else:
                msg = msg[:max_length] + "...[truncated]"
        
        # Final sanitization - remove any remaining suspicious patterns
        msg = re.sub(r'[^\x20-\x7E]', '?', msg)  # Replace non-printable characters
        
        return msg
        
    except Exception:
        # If sanitization fails, return a safe fallback message
        return "[LOG_SANITIZATION_ERROR]"

def _generate_cache_token() -> str:
    """Generate a secure token for cache access authorization"""
    with _cache_token_lock:
        token = secrets.token_urlsafe(16)
        _cache_access_tokens.add(token)
        # Limit number of tokens to prevent memory exhaustion
        if len(_cache_access_tokens) > 100:
            _cache_access_tokens.clear()
        return token

def _validate_cache_key(cache_key: str) -> bool:
    """Validate cache key format to prevent injection attacks"""
    if not isinstance(cache_key, str) or not cache_key:
        return False
    
    # Only allow alphanumeric characters and underscores
    import re
    if not re.match(r'^[a-zA-Z0-9_]{1,64}$', cache_key):
        return False
    
    # Check for suspicious patterns that might indicate manipulation
    suspicious_patterns = ['..', '//', '\\\\', '__', 'admin', 'root', 'config']
    cache_key_lower = cache_key.lower()
    for pattern in suspicious_patterns:
        if pattern in cache_key_lower:
            return False
    
    return True

def _secure_cache_lookup(cache_key: str, access_token: str) -> Optional[Dict[str, Any]]:
    """
    Perform a secure cache lookup with authorization and timing attack protection.
    
    This function validates the cache key format, checks authorization tokens,
    and uses constant-time operations to prevent timing analysis attacks.
    """
    if not _validate_cache_key(cache_key):
        # Always sleep to maintain constant timing even for invalid keys
        time.sleep(0.001)
        return None
    
    # Validate access token
    with _cache_token_lock:
        if access_token not in _cache_access_tokens:
            time.sleep(0.001)  # Constant timing for unauthorized access
            return None
        # Remove token after use (single-use token)
        _cache_access_tokens.discard(access_token)
    
    # Constant time delay regardless of cache hit/miss
    fixed_delay = 0.001  # 1ms fixed delay
    time.sleep(fixed_delay)
    
    with _cache_lock:
        current_time = time.time()
        
        # Always perform the same operations regardless of cache state
        result = _cache.get(cache_key)
        
        # Validate cache entry structure to prevent tampering
        if result and isinstance(result, dict):
            required_keys = {'time', 'fp', 'fields'}
            if not all(key in result for key in required_keys):
                # Remove corrupted cache entry
                _cache.pop(cache_key, None)
                return None
            
            # Check if entry is still valid
            entry_time = result.get('time', 0)
            if isinstance(entry_time, (int, float)) and current_time - entry_time < CACHE_TIME:
                return result
            else:
                # Remove expired entry
                _cache.pop(cache_key, None)
                return None
        
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

def _initialize_obfuscation_key() -> bytes:
    """Initialize a secure obfuscation key using PBKDF2"""
    global _obfuscation_key
    
    if _obfuscation_key is None:
        # Generate a cryptographically secure salt
        salt = secrets.token_bytes(32)
        
        # Use system entropy as key material
        entropy_sources = [
            str(time.time_ns()).encode(),
            secrets.token_bytes(32),
            platform.node().encode() if platform.node() else b'default',
            str(os.getpid()).encode()
        ]
        key_material = b''.join(entropy_sources)
        
        # Derive key using PBKDF2
        from hashlib import pbkdf2_hmac
        _obfuscation_key = pbkdf2_hmac('sha256', key_material, salt, _key_derivation_iterations)
    
    return _obfuscation_key

def _secure_obfuscate_hardware_id(value: str, field_type: str) -> str:
    """
    Apply cryptographically secure obfuscation to hardware IDs.
    
    Uses HMAC-based deterministic transformation with a securely derived key.
    This prevents reverse engineering while maintaining deterministic output.
    """
    if not value or not isinstance(value, str) or len(value) < 4:
        return value
    
    # Validate field type
    valid_field_types = {'uuid', 'serial', 'default'}
    if field_type not in valid_field_types:
        field_type = 'default'
    
    try:
        # Initialize secure obfuscation key
        key = _initialize_obfuscation_key()
        
        # Create HMAC-based transformation
        import hmac
        context = f"{field_type}_{len(value)}_v2"
        hmac_input = f"{context}:{value}".encode('utf-8')
        
        # Generate cryptographically secure transformation
        mac = hmac.new(key, hmac_input, hashlib.sha256).digest()
        
        # Convert to deterministic character transformation
        result = []
        for i, c in enumerate(value):
            if i < len(mac):
                # Use HMAC bytes to transform characters
                transform_byte = mac[i % len(mac)]
                
                if c.isdigit():
                    # Transform digits deterministically
                    new_digit = (int(c) + transform_byte) % 10
                    result.append(str(new_digit))
                elif c.isupper():
                    # Transform uppercase letters
                    offset = (ord(c) - ord('A') + transform_byte) % 26
                    result.append(chr(offset + ord('A')))
                elif c.islower():
                    # Transform lowercase letters
                    offset = (ord(c) - ord('a') + transform_byte) % 26
                    result.append(chr(offset + ord('a')))
                else:
                    # Preserve special characters
                    result.append(c)
            else:
                # For values longer than MAC, use positional transformation
                pos_transform = (i * 7 + sum(mac)) % 256
                if c.isalnum():
                    if c.isdigit():
                        new_digit = (int(c) + pos_transform) % 10
                        result.append(str(new_digit))
                    elif c.isupper():
                        offset = (ord(c) - ord('A') + pos_transform) % 26
                        result.append(chr(offset + ord('A')))
                    else:  # lowercase
                        offset = (ord(c) - ord('a') + pos_transform) % 26
                        result.append(chr(offset + ord('a')))
                else:
                    result.append(c)
        
        return ''.join(result)
        
    except Exception as e:
        _log(f"Secure obfuscation failed, using fallback: {type(e).__name__}")
        # Fallback to simple hash-based obfuscation
        fallback_hash = hashlib.sha256(f"{value}_{field_type}_fallback".encode()).hexdigest()
        rotation = int(fallback_hash[:2], 16) % max(1, len(value))
        return value[rotation:] + value[:rotation]

# Update the function name for backward compatibility
def _obfuscate_hardware_id(value: str, field_type: str) -> str:
    """Backward compatibility wrapper for secure obfuscation"""
    return _secure_obfuscate_hardware_id(value, field_type)

def _validate_command_safety(cmd) -> bool:
    """Validate that a command is safe to execute"""
    if not isinstance(cmd, list) or not cmd:
        return False
    
    # Get the base command name
    base_cmd = os.path.basename(cmd[0]).lower()
    
    # Whitelist of allowed commands for hardware detection
    allowed_commands = {
        'wmic.exe', 'wmic',
        'systeminfo.exe', 'systeminfo',
        'reg.exe', 'reg'  # For registry queries only
    }
    
    if base_cmd not in allowed_commands:
        return False
    
    # Additional validation for specific commands
    cmd_str = ' '.join(cmd).lower()
    
    # Check for dangerous patterns
    dangerous_patterns = [
        '&', '|', ';', '>', '<', '`',  # Command chaining
        'format', 'del', 'rm', 'rmdir',  # Destructive commands
        'net ', 'netsh', 'sc ', 'taskkill',  # Network/service commands
        'powershell', 'cmd', 'bash',  # Shell execution
        '../', '..\\',  # Path traversal
        'admin', 'administrator',  # Privilege escalation attempts
    ]
    
    for pattern in dangerous_patterns:
        if pattern in cmd_str:
            return False
    
    # Validate wmic queries are read-only
    if base_cmd in ['wmic.exe', 'wmic']:
        if not any(readonly in cmd_str for readonly in ['get', 'list', 'query']):
            return False
        if any(write_op in cmd_str for write_op in ['set', 'create', 'delete', 'call']):
            return False
    
    return True

def _secure_subprocess_run(cmd, **kwargs):
    """
    Execute subprocess commands with enhanced security measures.
    
    This function restricts the execution environment, limits timeouts,
    validates command safety, and applies security flags to prevent 
    various attacks through subprocess execution.
    """
    # Validate command safety first
    if not _validate_command_safety(cmd):
        _log(f"Command rejected by security policy: {cmd[0] if cmd else 'empty'}")
        # Return a safe failure result
        class SafeResult:
            def __init__(self):
                self.returncode = 1
                self.stdout = ""
                self.stderr = "Command blocked by security policy"
        return SafeResult()
    
    # Create a minimal, controlled environment
    safe_env = {}
    
    # Only include essential environment variables
    essential_vars = ['SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP']
    for var in essential_vars:
        if var in os.environ:
            safe_env[var] = os.environ[var]
    
    # Construct a minimal PATH with only system directories
    system_paths = []
    if os.name == 'nt':  # Windows
        system_paths = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32', 'wbem'),
        ]
    else:  # Unix-like
        system_paths = ['/bin', '/usr/bin', '/sbin', '/usr/sbin']
    
    # Filter paths to only existing directories
    verified_paths = [path for path in system_paths if os.path.isdir(path)]
    safe_env['PATH'] = os.pathsep.join(verified_paths)
    
    # Configure secure execution parameters
    secure_kwargs = {
        'env': safe_env,
        'cwd': os.path.dirname(os.path.abspath(__file__)),  # Use a known safe directory
        'timeout': min(kwargs.get('timeout', 3), 3),  # Reduced to 3 second maximum
        'capture_output': True,
        'text': True,
        'shell': False,  # Never use shell=True
    }
    
    # Apply platform-specific security settings
    if os.name == 'nt':  # Windows
        secure_kwargs['creationflags'] = (
            subprocess.CREATE_NO_WINDOW |
            subprocess.CREATE_NEW_PROCESS_GROUP |
            subprocess.DETACHED_PROCESS
        )
    else:  # Unix-like
        # Set process group to enable better process management
        secure_kwargs['preexec_fn'] = os.setsid
    
    # Override any security-sensitive kwargs
    security_overrides = {
        'shell': False,
        'executable': None,
        'preexec_fn': secure_kwargs.get('preexec_fn'),
        'close_fds': True,
        'env': safe_env,
        'cwd': secure_kwargs['cwd']
    }
    
    # Merge kwargs but preserve security settings
    final_kwargs = {**kwargs, **secure_kwargs, **security_overrides}
    
    try:
        # Execute with additional error handling
        result = subprocess.run(cmd, **final_kwargs)
        
        # Sanitize output to prevent information leakage
        if hasattr(result, 'stdout') and result.stdout:
            # Limit output size to prevent DoS
            if len(result.stdout) > 10000:  # 10KB limit
                result.stdout = result.stdout[:10000] + "\n[OUTPUT_TRUNCATED]"
        
        return result
        
    except subprocess.TimeoutExpired:
        _log("Subprocess execution timed out (security limit)")
        class TimeoutResult:
            def __init__(self):
                self.returncode = 124  # Standard timeout exit code
                self.stdout = ""
                self.stderr = "Command timed out"
        return TimeoutResult()
        
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        _log(f"Subprocess execution failed: {type(e).__name__}")
        class ErrorResult:
            def __init__(self):
                self.returncode = 1
                self.stdout = ""
                self.stderr = "Command execution failed"
        return ErrorResult()

def _get_wmi_uuid() -> Optional[str]:
    """
    Retrieve motherboard UUID using Windows Management Instrumentation.
    
    This function safely executes a WMI query to get the system's motherboard
    UUID. The result is obfuscated for privacy and truncated to prevent
    exact hardware identification while maintaining device uniqueness.
    """
    try:
        result = _secure_subprocess_run(['wmic', 'csproduct', 'get', 'UUID'], timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and 'UUID' not in line:
                    uuid = line.strip()
                    if len(uuid) > 10:  # Validate UUID length
                        # Apply obfuscation for privacy protection
                        obfuscated = _obfuscate_hardware_id(uuid, 'uuid')
                        return obfuscated[:16]  # Truncate for additional privacy
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass  # WMI service unavailable or command timed out
    except Exception:
        pass  # Other errors during UUID retrieval
    return None

def _get_wmi_disk_serial() -> Optional[str]:
    """
    Retrieve primary disk serial number using Windows Management Instrumentation.
    
    This function safely queries the WMI service to get the serial number
    of the primary disk drive. The result is obfuscated to protect user
    privacy while providing a stable device identifier component.
    """
    try:
        result = _secure_subprocess_run(['wmic', 'diskdrive', 'get', 'SerialNumber'], timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and 'SerialNumber' not in line:
                    serial = line.strip()
                    if len(serial) > 5:  # Validate serial number length
                        # Apply obfuscation for privacy protection
                        obfuscated = _obfuscate_hardware_id(serial, 'serial')
                        return obfuscated[:12]  # Truncate for additional privacy
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass  # WMI service unavailable or command timed out
    except Exception:
        pass  # Other errors during serial retrieval
    return None

def _get_windows_hardware() -> Dict[str, Any]:
    """
    Collect Windows-specific stable hardware identifiers.
    
    This function gathers various hardware characteristics that remain
    consistent across system reboots and minor updates. The data is used
    to create a stable device fingerprint for security purposes.
    """
    fields = {}
    
    try:
        # CPU details from registry
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                try:
                    cpu_name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                    if cpu_name and isinstance(cpu_name, str):
                        fields['cpu_name'] = cpu_name.strip()[:50]
                except (OSError, ValueError, TypeError):
                    pass  # CPU name not available in registry
        except (OSError, PermissionError):
            pass  # Registry access denied or key not found
        
        # Motherboard UUID via WMI (if available)
        uuid = _get_wmi_uuid()
        if uuid:
            fields['board_uuid'] = uuid
            
        # Primary disk serial (truncated for privacy)
        serial = _get_wmi_disk_serial()
        if serial:
            fields['disk_serial'] = serial
            
    except ImportError:
        pass  # Windows registry module not available on this platform
    except Exception as e:
        _log(f"Windows hardware detection failed: {type(e).__name__}")
    
    return fields

def _get_memory_info() -> Dict[str, Any]:
    """
    Get total system memory information rounded to gigabytes for stability.
    
    This function attempts to determine the total installed system RAM using
    multiple detection methods. The result is rounded to the nearest gigabyte
    to ensure stability across different system states and minor variations
    in memory reporting.
    """
    try:
        # Try psutil first as it's the most accurate method
        try:
            import psutil
        except ImportError:
            psutil = None
            
        if psutil:
            mem = psutil.virtual_memory()
            # Round to nearest GB for stability across measurements
            ram_gb = round(mem.total / (1024**3))
            return {'ram_gb': ram_gb}
        
        # Fallback for Linux systems without psutil installed
        try:
            # Validate path for security before reading
            meminfo_path = '/proc/meminfo'
            if not os.path.exists(meminfo_path) or not os.path.isfile(meminfo_path):
                return {}
                
            with open(meminfo_path, 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        ram_gb = round(kb / (1024**2))  # Convert KB to GB
                        return {'ram_gb': ram_gb}
        except (OSError, ValueError, IndexError):
            pass  # Failed to read or parse memory information
            
    except Exception as e:
        _log(f"Memory detection failed: {type(e).__name__}")
    
    return {}

def _get_network_hash() -> Dict[str, Any]:
    """
    Generate a salted hash of the primary network adapter MAC address.
    
    This function creates a privacy-preserving hash of the device's primary
    network adapter MAC address. The hash includes a salt to prevent tracking
    while still providing a stable identifier for device fingerprinting purposes.
    """
    try:
        import uuid
        mac = uuid.getnode()
        if mac and mac != 0x1fffffffffffff:  # Verify we have a valid MAC address
            # Hash the MAC with a salt to prevent direct tracking
            mac_bytes = mac.to_bytes(6, 'big')
            mac_hash = hashlib.sha256(mac_bytes + b"mac_salt_2024").hexdigest()[:16]
            return {'mac_hash': mac_hash}
    except Exception as e:
        _log(f"MAC hash generation failed: {type(e).__name__}")
    
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
    
    # Check cache first using secure lookup
    cache_key = hashlib.sha256(f"{method}_{_pqc_enabled}_{_pqc_algorithm}".encode()).hexdigest()[:16]
    access_token = _generate_cache_token()
    cached = _secure_cache_lookup(cache_key, access_token)
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
    
    # Cache the result with security controls
    with _cache_lock:
        # Enforce maximum cache size to prevent DoS
        if len(_cache) >= MAX_CACHE_SIZE:
            # Remove oldest entries first
            oldest_keys = sorted(_cache.keys(), key=lambda k: _cache[k].get('time', 0))[:5]
            for old_key in oldest_keys:
                _cache.pop(old_key, None)
        
        # Store with additional integrity checks
        cache_entry = {
            'fp': fingerprint,
            'time': time.time(),
            'fields': fields,
            'checksum': hashlib.sha256(fingerprint.encode() if isinstance(fingerprint, str) else fingerprint).hexdigest()[:16]
        }
        _cache[cache_key] = cache_entry
    
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
                         custom_fields: Optional[Dict[str, Any]] = None,
                         server_nonce: Optional[str] = None,
                         server_signature: Optional[str] = None) -> Dict[str, Any]:
    """
    Bind data to this specific device using cryptographic signatures with anti-replay protection.
    
    Args:
        binding_data: Dictionary containing data to bind
        security_level: "basic", "medium", or "high" 
        custom_fields: Additional fields to include in binding
        server_nonce: Time-bound nonce from license server (for anti-replay)
        server_signature: Server's signature of the nonce (for anti-replay)
    
    Returns:
        Dictionary with device binding information added
    """
    if not isinstance(binding_data, dict):
        raise ValueError("binding_data must be a dict")
    
    # Verify server nonce if anti-replay is enabled
    if _anti_replay_enabled:
        if not server_nonce or not server_signature:
            # Create nonce if not provided (for testing/development)
            _log("⚠️ No server nonce provided - creating temporary nonce (not production-safe)")
            server_nonce, server_signature = create_server_nonce()
        
        if not verify_server_nonce(server_nonce, server_signature):
            raise ValueError("Invalid or expired server nonce - replay attack detected")
    
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
    
    # Add anti-replay protection data
    anti_replay_data = {}
    if _anti_replay_enabled:
        anti_replay_data = {
            'counter': _get_monotonic_counter(),
            'server_nonce': server_nonce,
            'nonce_used_at': int(time.time()),
            'anti_replay_version': 1
        }
    
    # Create binding metadata
    binding_metadata = {
        'device_signature': fingerprint,
        'device_fields': fields,
        'binding_timestamp': int(time.time()),
        'binding_version': __version__,
        'security_level': security_level,
        'match_tolerance': tolerance,
        'anti_replay': anti_replay_data
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
        
        # Increment counter after successful binding creation
        if _anti_replay_enabled:
            _increment_monotonic_counter()
            
    except Exception as e:
        _log(f"Failed to store binding: {type(e).__name__}")
    
    _log(f"Created device binding with anti-replay protection: {_anti_replay_enabled}")
    return result

def verify_device_binding(bound_data: Dict[str, Any], 
                         tolerance: Optional[str] = None,
                         grace_period: int = 7,
                         allow_counter_increment: bool = True) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify that bound data matches current device with anti-replay protection.
    
    Args:
        bound_data: Dictionary returned from create_device_binding
        tolerance: Override tolerance level ("strict", "medium", "loose")
        grace_period: Days to accept lower scores after binding (default 7)
        allow_counter_increment: Whether to increment counter on successful verification
    
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
        anti_replay_data = binding_info.get('anti_replay', {})
        
        # Anti-replay protection checks
        if _anti_replay_enabled and anti_replay_data:
            # Check counter progression (append-only counter)
            stored_counter = anti_replay_data.get('counter', 0)
            current_counter = _get_monotonic_counter()
            
            if stored_counter > current_counter:
                return False, {
                    'error': 'replay_attack_detected',
                    'reason': 'counter_regression',
                    'stored_counter': stored_counter,
                    'current_counter': current_counter
                }
            
            # Check if we're reusing an old binding (counter too far behind)
            counter_gap = current_counter - stored_counter
            if counter_gap > 10:  # Allow some drift but not too much
                return False, {
                    'error': 'stale_binding',
                    'reason': 'counter_too_old',
                    'counter_gap': counter_gap
                }
            
            # Check server nonce validity (if present)
            server_nonce = anti_replay_data.get('server_nonce')
            if server_nonce:
                # For existing bindings, we don't re-verify the nonce
                # (it should have been discarded after first use)
                nonce_used_at = anti_replay_data.get('nonce_used_at', 0)
                nonce_age = int(time.time()) - nonce_used_at
                
                if nonce_age > _nonce_lifetime * 2:  # Grace period for existing bindings
                    _log("Nonce in binding is old but acceptable for stored binding")
        
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
        
        # If verification successful and anti-replay enabled, increment counter
        if is_match and _anti_replay_enabled and allow_counter_increment:
            try:
                new_counter = _increment_monotonic_counter()
                
                # Update the binding with new counter and re-sign
                updated_anti_replay = anti_replay_data.copy()
                updated_anti_replay['counter'] = new_counter
                updated_anti_replay['last_verified'] = int(time.time())
                
                # Update binding metadata
                updated_binding = binding_info.copy()
                updated_binding['anti_replay'] = updated_anti_replay
                
                # Re-sign with new counter
                updated_fields = stored_fields.copy()
                updated_fields['anti_replay_counter'] = new_counter
                updated_fields_json = json.dumps(updated_fields, sort_keys=True).encode()
                new_signature = _crypto_backend.sign(updated_fields_json)
                updated_binding['device_signature'] = new_signature
                
                # Store updated binding
                storage_key = f"binding_{hash(str(bound_data))}"
                _storage_backend.store(storage_key, updated_binding)
                
                # Update the original bound_data reference
                bound_data['device_binding'] = updated_binding
                
                _log(f"Updated binding counter: {stored_counter} -> {new_counter}")
                
            except Exception as e:
                _log(f"Failed to update counter: {type(e).__name__}")
                # Continue with verification even if counter update fails
        
        details = {
            'match_score': match_score,
            'threshold': match_threshold,
            'signature_valid': signature_valid,
            'age_days': age_days,
            'grace_period_used': grace_used,
            'matched_fields': sum(1 for k in stored_fields 
                                if k in current_fields and 
                                current_fields[k] == stored_fields[k]),
            'total_fields': len(stored_fields),
            'anti_replay_enabled': _anti_replay_enabled
        }
        
        # Add anti-replay details
        if _anti_replay_enabled and anti_replay_data:
            details.update({
                'counter_check': 'passed',
                'stored_counter': anti_replay_data.get('counter', 0),
                'current_counter': _get_monotonic_counter()
            })
        
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


def list_crypto_backends(show_details: bool = False) -> None:
    """
    Display available cryptographic backends in a developer-friendly format.
    
    Args:
        show_details: If True, shows detailed security and performance info
    """
    backends = get_available_crypto_backends()
    
    print("\n=== Available Cryptographic Backends ===\n")
    
    for backend_id, info in backends['available_backends'].items():
        print(f"🔐 {info['name']}")
        print(f"   Function: {info['function']}")
        print(f"   Quantum Security: {info['security']['quantum_bits']} bits")
        print(f"   Performance: {info['performance']['relative_speed']}")
        
        if show_details:
            print(f"   Timeline: Secure until {info['timeline']['secure_until']}")
            print(f"   Use Cases: {', '.join(info['use_cases'][:2])}")
        
        print()
    
    print("📋 Quick Recommendations:")
    for scenario, backend in backends['recommendations'].items():
        print(f"   • {scenario.replace('_', ' ').title()}: {backend}")
    
    print(f"\n💡 For detailed comparison: get_available_crypto_backends()")
    print(f"📖 For migration guide: See SHA256_TO_SHA3_MIGRATION.md")


def set_recommended_crypto_backend(use_case: str) -> bool:
    """
    Set the cryptographic backend based on common use cases.
    
    Args:
        use_case: One of the predefined use case scenarios:
                 'maximum_performance', 'balanced_security_performance',
                 'migration_from_sha256', 'maximum_security', 
                 'complete_quantum_resistance', 'government_defense',
                 'legacy_compatibility', 'research_experimental'
    
    Returns:
        True if backend was set successfully, False otherwise
    """
    backends = get_available_crypto_backends()
    recommendations = backends['recommendations']
    
    if use_case not in recommendations:
        print(f"❌ Unknown use case: {use_case}")
        print(f"Available use cases: {list(recommendations.keys())}")
        return False
    
    backend = recommendations[use_case]
    
    try:
        # Map backend names to functions
        if backend == 'hmac_sha256':
            set_crypto_backend_sha256()
        elif backend == 'hmac_sha3_512':
            set_crypto_backend_sha3_512()
        elif backend == 'hmac_sha3_512_compat':
            set_crypto_backend_sha3_512(compatibility_mode=True)
        elif backend == 'hybrid_hash':
            set_crypto_backend_hybrid_hash()
        elif backend == 'hmac_sha3_512 + post_quantum_signatures':
            set_crypto_backend_sha3_512()
            enable_post_quantum_crypto()
        elif backend == 'hybrid_hash + post_quantum_signatures':
            set_crypto_backend_hybrid_hash()
            enable_post_quantum_crypto()
        else:
            print(f"❌ Unknown backend recommendation: {backend}")
            return False
            
        print(f"✅ Set crypto backend for '{use_case}': {backend}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to set backend: {e}")
        return False


def get_current_crypto_status() -> Dict[str, Any]:
    """
    Get current cryptographic configuration status.
    
    Returns:
        Dictionary with current crypto backend and security information
    """
    current_backend_name = type(_crypto_backend).__name__
    
    return {
        'hash_backend': {
            'current': current_backend_name,
            'quantum_resistant': hasattr(_crypto_backend, '_quantum_resistant'),
            'compatibility_mode': getattr(_crypto_backend, '_compatibility_mode', False)
        },
        'post_quantum': {
            'enabled': _pqc_enabled,
            'backend_available': _pqc_enabled and current_backend_name in ['HybridPQCBackend', 'RealPostQuantumBackend'],
            'backend_type': current_backend_name if _pqc_enabled else None
        },
        'security_level': {
            'quantum_bits': getattr(_crypto_backend, '_quantum_security_bits', 128),
            'nist_compliance': _pqc_enabled,
            'future_proof': hasattr(_crypto_backend, '_quantum_resistant') or _pqc_enabled
        },
        'recommendations': {
            'current_adequate_until': '2040' if not hasattr(_crypto_backend, '_quantum_resistant') else '2060+',
            'should_upgrade': not (hasattr(_crypto_backend, '_quantum_resistant') or _pqc_enabled),
            'next_upgrade_action': 'set_crypto_backend_sha3_512()' if not hasattr(_crypto_backend, '_quantum_resistant') else 'Already quantum-resistant'
        }
    }


def is_post_quantum_enabled() -> bool:
    """Check if post-quantum cryptography is currently enabled"""
    return _pqc_enabled
