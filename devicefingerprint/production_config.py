"""
Production configuration for device fingerprinting.

This demonstrates how the fingerprinting would be used in a real system
with proper configuration management and monitoring.
"""

import logging
import os
import time
from typing import Dict, Any

# Production logging configuration
def setup_fingerprint_logging():
    """Configure logging for fingerprinting operations."""
    log_level = os.getenv('FINGERPRINT_LOG_LEVEL', 'INFO')
    
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('fingerprint.log') if os.getenv('LOG_TO_FILE') else logging.NullHandler()
        ]
    )

# Feature flags for different environments
FINGERPRINT_CONFIG = {
    'development': {
        'collect_sensitive': False,
        'timeout': 10,
        'cache_duration': 300,  # 5 minutes
        'min_confidence': 0.5
    },
    'staging': {
        'collect_sensitive': True,
        'timeout': 5,
        'cache_duration': 3600,  # 1 hour
        'min_confidence': 0.7
    },
    'production': {
        'collect_sensitive': True,
        'timeout': 3,
        'cache_duration': 86400,  # 24 hours
        'min_confidence': 0.8
    }
}

def get_config() -> Dict[str, Any]:
    """Get fingerprinting configuration for current environment."""
    env = os.getenv('ENVIRONMENT', 'development')
    return FINGERPRINT_CONFIG.get(env, FINGERPRINT_CONFIG['development'])

class FingerprintCache:
    """Simple in-memory cache for fingerprints."""
    
    def __init__(self):
        self._cache = {}
        
    def get(self, key: str) -> str:
        """Get cached fingerprint if not expired."""
        if key in self._cache:
            fp, timestamp = self._cache[key]
            config = get_config()
            if time.time() - timestamp < config['cache_duration']:
                return fp
        return None
        
    def set(self, key: str, fingerprint: str):
        """Cache fingerprint with timestamp."""
        self._cache[key] = (fingerprint, time.time())

# Global cache instance
_cache = FingerprintCache()

def get_device_fingerprint_cached() -> str:
    """Get device fingerprint with caching."""
    cache_key = "device_fp"
    
    # Try cache first
    cached = _cache.get(cache_key)
    if cached:
        return cached
        
    # Generate new fingerprint
    from .realistic_fingerprint import DeviceFingerprinter
    config = get_config()
    
    fp = DeviceFingerprinter(
        collect_sensitive=config['collect_sensitive'],
        timeout=config['timeout']
    )
    
    result = fp.get_fingerprint()
    
    # Check minimum confidence
    if result.confidence < config['min_confidence']:
        logging.warning(f"Low fingerprint confidence: {result.confidence}")
        
    # Cache and return
    _cache.set(cache_key, result.fingerprint)
    return result.fingerprint
