"""
Production Device Fingerprinting Module

Simple, honest device identification for session binding and fraud detection.
No security theater - just basic hardware characteristics with proper error handling.

Author: Production Engineering Team
Last Modified: 2025-09-06
"""

import hashlib
import json
import logging
import os
import platform
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

# Configure module logger
logger = logging.getLogger(__name__)


class FingerprintMethod(Enum):
    """Available fingerprinting methods ordered by reliability."""
    BASIC = "basic"              # Platform info only
    HARDWARE = "hardware"        # + MAC, system UUID  
    ENHANCED = "enhanced"        # + CPU, memory details


class FingerprintQuality(Enum):
    """Quality assessment of fingerprint data."""
    HIGH = "high"       # 4+ reliable sources
    MEDIUM = "medium"   # 2-3 sources
    LOW = "low"         # 1 source or fallback only
    FAILED = "failed"   # No usable data


@dataclass
class FingerprintResult:
    """Result of device fingerprinting operation."""
    fingerprint: str
    quality: FingerprintQuality
    method: FingerprintMethod
    sources: List[str]
    errors: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    entropy_bits: int = 0  # Estimated entropy
    
    def is_reliable(self) -> bool:
        """Check if fingerprint is reliable enough for production use."""
        return self.quality in [FingerprintQuality.HIGH, FingerprintQuality.MEDIUM]


class DeviceFingerprintError(Exception):
    """Raised when fingerprinting completely fails."""
    pass


class DeviceFingerprinter:
    """
    Production device fingerprinting with realistic expectations.
    
    Use cases:
    - Session binding (detect session hijacking)
    - Fraud detection (unusual device patterns)
    - Rate limiting (per-device quotas)
    
    NOT suitable for:
    - Primary authentication
    - Cryptographic security
    - Anti-forensics
    """
    
    def __init__(
        self,
        collect_hardware_ids: bool = False,
        subprocess_timeout: int = 3,
        cache_duration: int = 300
    ):
        """
        Initialize fingerprinter.
        
        Args:
            collect_hardware_ids: Whether to collect MAC/serial numbers (privacy impact)
            subprocess_timeout: Max time for subprocess calls (security)
            cache_duration: Cache lifetime in seconds (performance)
        """
        self.collect_hardware_ids = collect_hardware_ids
        self.subprocess_timeout = subprocess_timeout
        self.cache_duration = cache_duration
        self._cache: Dict[str, Tuple[FingerprintResult, float]] = {}
        
    def get_fingerprint(
        self, 
        method: FingerprintMethod = FingerprintMethod.HARDWARE
    ) -> FingerprintResult:
        """
        Generate device fingerprint.
        
        Args:
            method: Fingerprinting method to use
            
        Returns:
            FingerprintResult with quality assessment
            
        Raises:
            DeviceFingerprintError: If no fingerprint sources available
        """
        cache_key = f"{method.value}_{self.collect_hardware_ids}"
        
        # Check cache first
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self.cache_duration:
                logger.debug("Returning cached fingerprint")
                return result
        
        # Generate new fingerprint
        sources = []
        errors = []
        
        try:
            if method == FingerprintMethod.BASIC:
                sources, errors = self._collect_basic_info()
            elif method == FingerprintMethod.HARDWARE:
                sources, errors = self._collect_hardware_info()
            elif method == FingerprintMethod.ENHANCED:
                sources, errors = self._collect_enhanced_info()
            else:
                raise ValueError(f"Unknown method: {method}")
                
            if not sources:
                raise DeviceFingerprintError("No fingerprint sources available")
                
            # Generate fingerprint hash
            fingerprint = self._hash_sources(sources)
            
            # Assess quality
            quality = self._assess_quality(sources, errors)
            
            # Estimate entropy (rough approximation)
            entropy_bits = min(128, len(sources) * 16 + len(fingerprint) * 2)
            
            result = FingerprintResult(
                fingerprint=fingerprint,
                quality=quality,
                method=method,
                sources=self._sanitize_sources(sources),
                errors=errors,
                entropy_bits=entropy_bits
            )
            
            # Cache result
            self._cache[cache_key] = (result, time.time())
            
            logger.info(f"Generated {quality.value} quality fingerprint using {method.value} method")
            return result
            
        except Exception as e:
            logger.error(f"Fingerprinting failed: {e}")
            raise DeviceFingerprintError(f"Fingerprinting failed: {e}")
    
    def _collect_basic_info(self) -> Tuple[List[str], List[str]]:
        """Collect basic platform information (safe, no privacy concerns)."""
        sources = []
        errors = []
        
        try:
            sources.extend([
                f"os_{platform.system()}",
                f"arch_{platform.machine()}",
                f"release_{platform.release()}"
            ])
        except Exception as e:
            errors.append(f"Platform info failed: {e}")
            
        try:
            # Python version can indicate environment
            py_version = f"py_{platform.python_version()}"
            sources.append(py_version)
        except Exception as e:
            errors.append(f"Python version failed: {e}")
            
        return sources, errors
    
    def _collect_hardware_info(self) -> Tuple[List[str], List[str]]:
        """Collect hardware identifiers (requires privacy consent)."""
        sources, errors = self._collect_basic_info()
        
        if not self.collect_hardware_ids:
            logger.debug("Hardware ID collection disabled")
            return sources, errors
            
        # MAC address
        try:
            mac = uuid.getnode()
            # Verify it's not random (some systems return random values)
            if mac != uuid.getnode():
                errors.append("MAC address is random")
            else:
                sources.append(f"mac_{mac:012x}")
        except Exception as e:
            errors.append(f"MAC address failed: {e}")
            
        # System UUID (platform specific)
        sys_uuid = self._get_system_uuid()
        if sys_uuid:
            sources.append(sys_uuid)
        else:
            errors.append("System UUID unavailable")
            
        return sources, errors
    
    def _collect_enhanced_info(self) -> Tuple[List[str], List[str]]:
        """Collect additional system details for higher entropy."""
        sources, errors = self._collect_hardware_info()
        
        # CPU information
        try:
            cpu_info = platform.processor()
            if cpu_info and len(cpu_info.strip()) > 0:
                # Hash CPU info to normalize length
                cpu_hash = hashlib.sha256(cpu_info.encode()).hexdigest()[:16]
                sources.append(f"cpu_{cpu_hash}")
        except Exception as e:
            errors.append(f"CPU info failed: {e}")
            
        # Memory information (approximate)
        try:
            if hasattr(os, 'sysconf') and hasattr(os, 'sysconf_names'):
                if 'SC_PAGE_SIZE' in os.sysconf_names and 'SC_PHYS_PAGES' in os.sysconf_names:
                    page_size = os.sysconf('SC_PAGE_SIZE')
                    pages = os.sysconf('SC_PHYS_PAGES')
                    memory_gb = (page_size * pages) // (1024 ** 3)
                    sources.append(f"mem_{memory_gb}gb")
        except Exception as e:
            errors.append(f"Memory info failed: {e}")
            
        return sources, errors
    
    def _get_system_uuid(self) -> Optional[str]:
        """Get system UUID using platform-appropriate methods."""
        if platform.system() == "Windows":
            return self._get_windows_uuid()
        elif platform.system() == "Linux":
            return self._get_linux_machine_id()
        elif platform.system() == "Darwin":  # macOS
            return self._get_macos_uuid()
        else:
            logger.debug(f"No UUID method for platform: {platform.system()}")
            return None
    
    def _get_windows_uuid(self) -> Optional[str]:
        """Get Windows system UUID via WMI."""
        try:
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID", "/format:value"],
                capture_output=True,
                text=True,
                timeout=self.subprocess_timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode != 0:
                return None
                
            for line in result.stdout.split('\n'):
                if line.startswith('UUID='):
                    uuid_val = line.split('=', 1)[1].strip()
                    if uuid_val and uuid_val.lower() not in ['', 'unknown']:
                        return f"win_uuid_{uuid_val.lower()}"
                        
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            logger.debug(f"Windows UUID failed: {e}")
            
        return None
    
    def _get_linux_machine_id(self) -> Optional[str]:
        """Get Linux machine ID from standard locations."""
        machine_id_paths = [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id"
        ]
        
        for path in machine_id_paths:
            try:
                with open(path, 'r') as f:
                    machine_id = f.read().strip()
                    if machine_id and len(machine_id) >= 16:
                        return f"linux_mid_{machine_id}"
            except (OSError, IOError):
                continue
                
        return None
    
    def _get_macos_uuid(self) -> Optional[str]:
        """Get macOS hardware UUID."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=self.subprocess_timeout
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Hardware UUID' in line:
                        uuid_val = line.split(':', 1)[1].strip()
                        if uuid_val:
                            return f"mac_uuid_{uuid_val.lower()}"
                            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            logger.debug(f"macOS UUID failed: {e}")
            
        return None
    
    def _hash_sources(self, sources: List[str]) -> str:
        """Generate fingerprint hash from sources."""
        # Sort for consistent output
        sorted_sources = sorted(sources)
        combined = "|".join(sorted_sources)
        
        # Use SHA-256 (sufficient for fingerprinting, not crypto)
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        return hash_obj.hexdigest()[:32]  # 128 bits
    
    def _assess_quality(self, sources: List[str], errors: List[str]) -> FingerprintQuality:
        """Assess fingerprint quality based on available data."""
        if not sources:
            return FingerprintQuality.FAILED
            
        source_count = len(sources)
        error_count = len(errors)
        
        # Quality thresholds
        if source_count >= 4 and error_count <= 1:
            return FingerprintQuality.HIGH
        elif source_count >= 2 and error_count <= 3:
            return FingerprintQuality.MEDIUM
        else:
            return FingerprintQuality.LOW
    
    def _sanitize_sources(self, sources: List[str]) -> List[str]:
        """Sanitize source descriptions for logging."""
        sanitized = []
        for source in sources:
            if source.startswith('mac_'):
                sanitized.append('mac_[redacted]')
            elif 'uuid' in source.lower():
                sanitized.append(f"{source.split('_')[0]}_uuid_[redacted]")
            else:
                sanitized.append(source)
        return sanitized


# Production configuration
class FingerprintConfig:
    """Production configuration for device fingerprinting."""
    
    # Environment-specific settings
    DEVELOPMENT = {
        'collect_hardware_ids': False,
        'subprocess_timeout': 10,
        'cache_duration': 60,
        'min_quality': FingerprintQuality.LOW
    }
    
    STAGING = {
        'collect_hardware_ids': True,
        'subprocess_timeout': 5,
        'cache_duration': 300,
        'min_quality': FingerprintQuality.MEDIUM
    }
    
    PRODUCTION = {
        'collect_hardware_ids': True,
        'subprocess_timeout': 3,
        'cache_duration': 3600,
        'min_quality': FingerprintQuality.HIGH
    }
    
    @classmethod
    def get_config(cls, environment: str = None) -> Dict:
        """Get configuration for environment."""
        env = environment or os.getenv('FINGERPRINT_ENV', 'development')
        return getattr(cls, env.upper(), cls.DEVELOPMENT)


# Simple interface functions
def get_device_fingerprint(
    method: FingerprintMethod = FingerprintMethod.HARDWARE,
    collect_sensitive: bool = None
) -> str:
    """
    Simple function to get device fingerprint.
    
    Args:
        method: Fingerprinting method
        collect_sensitive: Override hardware ID collection setting
        
    Returns:
        Device fingerprint string
        
    Raises:
        DeviceFingerprintError: If fingerprinting fails
    """
    config = FingerprintConfig.get_config()
    
    if collect_sensitive is not None:
        config['collect_hardware_ids'] = collect_sensitive
    
    # Remove keys that DeviceFingerprinter doesn't accept
    init_config = {
        'collect_hardware_ids': config['collect_hardware_ids'],
        'subprocess_timeout': config['subprocess_timeout'],
        'cache_duration': config['cache_duration']
    }
    
    fingerprinter = DeviceFingerprinter(**init_config)
    result = fingerprinter.get_fingerprint(method)
    
    if not result.is_reliable():
        logger.warning(f"Low quality fingerprint: {result.quality.value}")
    
    return result.fingerprint


def quick_fingerprint() -> str:
    """Get basic device fingerprint quickly (no sensitive data)."""
    try:
        return get_device_fingerprint(
            method=FingerprintMethod.BASIC,
            collect_sensitive=False
        )
    except DeviceFingerprintError:
        # Ultimate fallback
        fallback_data = f"{platform.system()}_{platform.machine()}_{time.time_ns() % 10000}"
        return hashlib.sha256(fallback_data.encode()).hexdigest()[:16]


# Legacy compatibility
def generate_device_fingerprint() -> str:
    """Legacy function for backward compatibility."""
    return quick_fingerprint()


if __name__ == "__main__":
    # Basic functionality test
    logging.basicConfig(level=logging.INFO)
    
    try:
        fp = get_device_fingerprint()
        print(f"Device fingerprint: {fp}")
        
        # Test all methods
        for method in FingerprintMethod:
            try:
                result = DeviceFingerprinter().get_fingerprint(method)
                print(f"{method.value}: {result.fingerprint} ({result.quality.value})")
            except Exception as e:
                print(f"{method.value}: Failed - {e}")
                
    except Exception as e:
        print(f"Fingerprinting failed: {e}")
