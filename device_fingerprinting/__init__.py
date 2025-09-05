"""
Device Fingerprinting Library
============================

Advanced hardware-based device identification system for security applications.
Generates unique, stable fingerprints across reboots with tamper detection.

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

from .device_fingerprinting import (
    DeviceFingerprintGenerator,
    AdvancedDeviceFingerprinter,
    FingerprintResult,
    FingerprintMethod,
    bind_token_to_device,
    verify_device_binding
)

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"
__all__ = [
    "DeviceFingerprintGenerator",
    "AdvancedDeviceFingerprinter", 
    "FingerprintResult",
    "FingerprintMethod",
    "bind_token_to_device",
    "verify_device_binding"
]
