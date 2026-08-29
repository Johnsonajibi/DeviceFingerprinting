"""
This module provides a high-level interface for generating production-ready device fingerprints.
"""

import os
import platform
import psutil
import uuid
import hashlib
import json
import logging
import threading
import secrets
import subprocess
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

# Libraries should not call logging.basicConfig() (mutates the host
# application's root logger as an import side effect) - use a module-scoped
# logger instead.
_logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class FingerprintMethod(Enum):
    BASIC = "basic"
    SYSTEM = "system"
    COMPOSITE = "composite"
    CRYPTOGRAPHIC = "cryptographic"
    TAMPER_RESISTANT = "tamper_resistant"


@dataclass
class FingerprintResult:
    fingerprint: str
    method: FingerprintMethod
    components: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    confidence: float = 0.0
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return bool(self.fingerprint) and self.confidence > 0.5 and not self.errors

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass to a dictionary, handling enum serialization."""
        return {
            "fingerprint": self.fingerprint,
            "method": self.method.value,
            "components": self.components,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "security_level": self.security_level.value,
            "execution_time": self.execution_time,
            "errors": self.errors,
            "metadata": self.metadata,
        }


class ProductionFingerprintGenerator:
    """
    Generates a detailed and robust device fingerprint suitable for production use.
    It combines hardware, software, and system configuration identifiers.
    """

    def __init__(self, security_level=SecurityLevel.HIGH, cache_ttl: int = 300):
        """
        Initializes the generator.

        Args:
            security_level: The security level for fingerprinting.
            cache_ttl: Time-to-live for cache in seconds.
        """
        self.security_level = security_level
        self._cache = {}
        self._cache_lock = threading.Lock()
        self.cache_ttl = cache_ttl
        self.salt = secrets.token_bytes(16)

    def _hash_sha3_512(self, data: bytes) -> str:
        """Hashes data using SHA3-512."""
        return hashlib.sha3_512(data).hexdigest()

    def _get_cpu_features(self) -> str:
        """Gets the CPU/processor identification string."""
        return platform.processor()

    def _get_system_info(self) -> Dict[str, Any]:
        """Gathers detailed system information."""
        info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "processor": self._get_cpu_features(),  # Use the method that might call Rust
        }
        if info["platform"] == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "csproduct", "get", "UUID"], capture_output=True, text=True, check=True
                )
                info["uuid"] = result.stdout.strip().split("\n")[-1]
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                _logger.warning(f"Could not get UUID on Windows: {e}")
        elif info["platform"] == "Linux":
            try:
                with open("/etc/machine-id", "r") as f:
                    info["machine_id"] = f.read().strip()
            except FileNotFoundError:
                try:
                    info["machine_id"] = (
                        subprocess.check_output(["cat", "/var/lib/dbus/machine-id"])
                        .strip()
                        .decode()
                    )
                except (FileNotFoundError, subprocess.CalledProcessError) as e:
                    _logger.warning(f"Could not get machine-id on Linux: {e}")

        # Add more hardware details
        try:
            info["cpu_cores"] = psutil.cpu_count(logical=False)
            info["ram_total_gb"] = round(psutil.virtual_memory().total / (1024**3), 2)
            info["boot_time"] = psutil.boot_time()
            info["mac_address"] = uuid.getnode()
        except (ImportError, AttributeError, FileNotFoundError):
            pass  # psutil might not be installed or some features not available

        return info

    def generate_fingerprint(self, method=FingerprintMethod.COMPOSITE, **kwargs) -> Dict[str, Any]:
        """
        Generates a dictionary of fingerprint components and a final hash.

        Returns:
            A dictionary containing detailed system information and a final hash.
        """
        components = self._get_system_info()

        # Add security-related info
        security_info = {
            "is_admin": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        }

        # Combine all info into a single dictionary
        full_fingerprint_data = {
            "system_info": components,
            "software_info": {
                "python_version": platform.python_version(),
            },
            "hardware_info": {
                "cpu_cores": components.get("cpu_cores"),
                "ram_total_gb": components.get("ram_total_gb"),
            },
            "security_info": security_info,
        }

        # Create a stable JSON string for hashing
        json_data = json.dumps(full_fingerprint_data, sort_keys=True, default=str)

        # Generate the final hash
        final_hash = self._hash_sha3_512(json_data.encode("utf-8"))
        full_fingerprint_data["fingerprint_hash"] = final_hash

        return full_fingerprint_data

    def get_security_metrics(self) -> Dict[str, Any]:
        with self._cache_lock:
            cache_size = len(self._cache)
        return {
            "fingerprint_count": cache_size,
            "cache_hit_ratio": 0.0,  # Placeholder for actual hit tracking
            "avg_execution_time": 0.01,  # Placeholder
        }


# NOTE: This module previously also defined generate_device_fingerprint(),
# create_device_binding(), verify_device_binding(), and
# AdvancedDeviceFingerprinter - an unreferenced, untested duplicate of the
# real device-binding implementation in device_fingerprinting.py, with its
# own forgeable-signature bug (it HMAC-signed binding data using the
# fingerprint itself as the key, and that fingerprint was stored in
# cleartext in the same payload) and an unused self.salt. They were removed
# as dead code rather than fixed in place, since device_fingerprinting.py's
# create_device_binding()/verify_device_binding() are the maintained,
# publicly exported implementation.
