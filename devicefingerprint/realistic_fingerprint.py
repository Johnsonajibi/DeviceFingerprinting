"""
Device fingerprinting for authentication systems.

Handles basic hardware identification with proper error handling,
logging, and privacy considerations.
"""

import hashlib
import json
import logging
import platform
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Set up module logger
logger = logging.getLogger(__name__)


@dataclass
class FingerprintResult:
    fingerprint: str
    confidence: float
    sources: List[str]
    errors: List[str]
    timestamp: float


class FingerprintError(Exception):
    """Raised when fingerprinting fails completely."""
    pass


class DeviceFingerprinter:
    """Basic device fingerprinting for session binding."""
    
    def __init__(self, collect_sensitive=False, timeout=5):
        """
        Args:
            collect_sensitive: Whether to collect MAC/serial numbers
            timeout: Subprocess timeout in seconds
        """
        self.collect_sensitive = collect_sensitive
        self.timeout = timeout
        
    def get_fingerprint(self) -> FingerprintResult:
        """Generate device fingerprint from available hardware info."""
        sources = []
        errors = []
        
        # Basic platform info (always safe)
        sources.extend([
            platform.system(),
            platform.machine(),
            platform.release()
        ])
        
        # CPU info if available
        cpu_info = self._get_cpu_info()
        if cpu_info:
            sources.append(cpu_info)
        else:
            errors.append("CPU info unavailable")
            
        # Network MAC (if permitted)
        if self.collect_sensitive:
            mac = self._get_mac_address()
            if mac:
                sources.append(mac)
            else:
                errors.append("MAC address unavailable")
                
        # System UUID (if permitted and available)
        if self.collect_sensitive:
            sys_uuid = self._get_system_uuid()
            if sys_uuid:
                sources.append(sys_uuid)
            else:
                errors.append("System UUID unavailable")
        
        if not sources:
            raise FingerprintError("No fingerprint sources available")
            
        # Simple hash of available data
        combined = "|".join(sorted(sources))
        fingerprint = hashlib.sha256(combined.encode()).hexdigest()[:32]
        
        # Confidence based on data quality
        confidence = min(0.9, 0.3 + (len(sources) * 0.15))
        
        return FingerprintResult(
            fingerprint=fingerprint,
            confidence=confidence,
            sources=[s[:20] + "..." if len(s) > 20 else s for s in sources],
            errors=errors,
            timestamp=time.time()
        )
    
    def _get_cpu_info(self) -> Optional[str]:
        """Get basic CPU identifier."""
        try:
            return platform.processor()[:50]  # Truncate for consistency
        except Exception as e:
            logger.debug(f"CPU info failed: {e}")
            return None
            
    def _get_mac_address(self) -> Optional[str]:
        """Get primary network MAC address."""
        try:
            mac = uuid.getnode()
            if mac != uuid.getnode():  # Check if it's random
                return None
            return f"mac_{mac:012x}"
        except Exception as e:
            logger.debug(f"MAC address failed: {e}")
            return None
            
    def _get_system_uuid(self) -> Optional[str]:
        """Get system UUID if available."""
        if platform.system() == "Windows":
            return self._get_windows_uuid()
        elif platform.system() == "Linux":
            return self._get_linux_machine_id()
        return None
        
    def _get_windows_uuid(self) -> Optional[str]:
        """Get Windows system UUID via WMI."""
        try:
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID", "/value"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            if result.returncode != 0:
                return None
                
            for line in result.stdout.split('\n'):
                if line.startswith('UUID='):
                    uuid_val = line.split('=', 1)[1].strip()
                    if uuid_val and uuid_val != "":
                        return f"win_uuid_{uuid_val}"
                        
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Windows UUID failed: {e}")
            
        return None
        
    def _get_linux_machine_id(self) -> Optional[str]:
        """Get Linux machine ID from standard locations."""
        paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        
        for path in paths:
            try:
                with open(path, 'r') as f:
                    machine_id = f.read().strip()
                    if machine_id:
                        return f"linux_mid_{machine_id}"
            except (OSError, IOError):
                continue
                
        return None


def quick_fingerprint() -> str:
    """Simple function for basic device identification."""
    fingerprinter = DeviceFingerprinter(collect_sensitive=False)
    try:
        result = fingerprinter.get_fingerprint()
        return result.fingerprint
    except FingerprintError:
        # Fallback to minimal platform info
        fallback = f"{platform.system()}_{platform.machine()}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:16]


# Legacy compatibility
def generate_device_fingerprint() -> str:
    """Legacy function name for backward compatibility."""
    return quick_fingerprint()
