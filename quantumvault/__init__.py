"""
QuantumVault - Post-Quantum Cryptography Password Manager

A quantum-resistant password manager with advanced cryptographic features
designed for the post-quantum era.
"""

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"
__email__ = "support@quantumvault.com"
__license__ = "MIT"
__copyright__ = "Copyright 2025 QuantumVault Development Team"

# Import main classes for easy access
from .core.password_manager import QuantumVaultPasswordManager
from .crypto.quantum_resistant_crypto import QuantumResistantCrypto
from .recovery.dual_qr_recovery import DualQRRecoverySystem
from .steganography.steganographic_qr import SteganographicQR
from .security.forward_secure_encryption import ForwardSecureEncryption
from .optimization.dynamic_page_sizing import DynamicPageSizing

__all__ = [
    "QuantumVaultPasswordManager",
    "QuantumResistantCrypto", 
    "DualQRRecoverySystem",
    "SteganographicQR",
    "ForwardSecureEncryption",
    "DynamicPageSizing",
    "__version__",
]

# Version information
VERSION_INFO = {
    "major": 1,
    "minor": 0,
    "patch": 0,
    "pre_release": None,
    "build": None,
}

def get_version():
    """Get the current version string."""
    return __version__

def get_version_info():
    """Get detailed version information."""
    return VERSION_INFO.copy()
