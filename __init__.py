"""
DeviceFingerprint Library
========================

Advanced hardware-based device identification system for security applications.
Generates unique, stable device fingerprints across reboots with tamper detection.

Author: DeviceFingerprint Development Team
License: MIT
Version: 1.0.0
"""

from .devicefingerprint import (
    DeviceFingerprintGenerator,
    AdvancedDeviceFingerprinter,
    FingerprintResult,
    FingerprintMethod,
    FingerprintGenerationError,
    generate_device_fingerprint,
    bind_token_to_device,
    verify_device_binding
)

__version__ = "1.0.0"
__author__ = "DeviceFingerprint Development Team"
__all__ = [
    "DeviceFingerprintGenerator",
    "AdvancedDeviceFingerprinter", 
    "FingerprintResult",
    "FingerprintMethod",
    "FingerprintGenerationError",
    "generate_device_fingerprint",
    "bind_token_to_device",
    "verify_device_binding"
]
