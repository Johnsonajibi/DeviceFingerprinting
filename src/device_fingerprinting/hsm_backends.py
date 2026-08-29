"""
Hardware Security Module (HSM) integration for enterprise-grade key protection.

This module provides a robust and production-ready implementation for integrating
with Hardware Security Modules (HSMs) using the PKCS#11 standard, and simulates
secure enclave storage for protecting sensitive data.
"""

import os
import json
import base64
import logging
from typing import Dict, Any, Optional

try:
    import PyKCS11
    from PyKCS11 import PyKCS11Error, Mechanism

    PYKCS11_AVAILABLE = True
except ImportError:
    PYKCS11_AVAILABLE = False

from .backends import CryptoBackend, StorageBackend
from .crypto import AESGCMEncryptor, ScryptKDF

# Libraries should not call logging.basicConfig() (mutates the host
# application's root logger as an import side effect) - use a module-scoped
# logger instead.
_logger = logging.getLogger(__name__)


class HSMCryptoBackend(CryptoBackend):
    """
    HSM-backed cryptographic operations using PKCS#11 for maximum security.

    This backend interfaces with HSMs that support the PKCS#11 standard.
    """

    def __init__(self, pkcs11_lib_path: str, user_pin: str, key_label: str) -> None:
        """
        Initialize the HSM crypto backend.

        Args:
            pkcs11_lib_path: Path to the PKCS#11 library file (e.g., softhsm2.dll).
            user_pin: The PIN for the HSM token/slot.
            key_label: The label of the key to be used or created in the HSM.
        """
        if not PYKCS11_AVAILABLE:
            raise ImportError(
                "PyKCS11 is required for HSMCryptoBackend. Install it with: pip install PyKCS11"
            )

        self.pkcs11_lib_path = pkcs11_lib_path
        self.user_pin = user_pin
        self.key_label = key_label
        self.session: Optional[Any] = None
        self.key_handle: Optional[Any] = None
        self.hsm_available: bool = False
        self._init_hsm()

    def _init_hsm(self) -> None:
        """Initialize the HSM connection and session."""
        try:
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(self.pkcs11_lib_path)

            # Get the first available slot
            slot = pkcs11.getSlotList(tokenPresent=True)[0]

            # Open a session
            self.session = pkcs11.openSession(
                slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
            )
            self.session.login(self.user_pin)

            # Find or create the key
            self.key_handle = self._get_or_create_hsm_key()

            if self.key_handle:
                self.hsm_available = True
                _logger.info("HSM initialized successfully and key is available.")
            else:
                _logger.error("Failed to get or create HSM key.")
                self.session.logout()
        except (PyKCS11Error, IndexError, FileNotFoundError) as e:
            _logger.error(f"HSM initialization failed: {e}")
            self.hsm_available = False

    def _get_or_create_hsm_key(self) -> Optional[Any]:
        """Get or create a symmetric key in the HSM."""
        if not self.session:
            return None

        try:
            # Look for an existing key with the given label
            key = self.session.findObjects(
                [
                    (PyKCS11.CKA_LABEL, self.key_label),
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
                ]
            )
            if key:
                return key[0]

            # If not found, create a new key
            _logger.info(f"Key '{self.key_label}' not found. Creating a new one.")
            key_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
                (PyKCS11.CKA_VALUE_LEN, 32),  # 256-bit AES key
                (PyKCS11.CKA_LABEL, self.key_label),
                (PyKCS11.CKA_TOKEN, True),
                (PyKCS11.CKA_ENCRYPT, True),
                (PyKCS11.CKA_DECRYPT, True),
                (PyKCS11.CKA_SENSITIVE, True),
                (PyKCS11.CKA_EXTRACTABLE, False),
            ]
            return self.session.generateKey(key_template)
        except PyKCS11Error as e:
            _logger.error(f"Error accessing HSM key: {e}")
            return None

    def sign(self, data: bytes) -> str:
        """Sign data using the HSM (e.g., with HMAC), returning a base64-encoded signature."""
        if not self.hsm_available or not self.session or not self.key_handle:
            raise RuntimeError("HSM is not available for signing.")

        try:
            hmac_mechanism = Mechanism(PyKCS11.CKM_SHA256_HMAC, None)
            signature = bytes(self.session.sign(self.key_handle, data, hmac_mechanism))
            return base64.b64encode(signature).decode("utf-8")
        except PyKCS11Error as e:
            _logger.error(f"HSM signing failed: {e}")
            raise

    def verify(self, signature: str, data: bytes) -> bool:
        """Verify a base64-encoded signature using the HSM."""
        if not self.hsm_available or not self.session or not self.key_handle:
            raise RuntimeError("HSM is not available for verification.")

        try:
            signature_bytes = base64.b64decode(signature)
            hmac_mechanism = Mechanism(PyKCS11.CKM_SHA256_HMAC, None)
            # PyKCS11's Session.verify() returns None on success and raises
            # PyKCS11Error (CKR_SIGNATURE_INVALID) on a bad signature.
            self.session.verify(self.key_handle, data, signature_bytes, hmac_mechanism)
            return True
        except PyKCS11Error as e:
            _logger.warning(f"HSM verification failed: {e}")
            return False

    def __del__(self):
        """Clean up the HSM session on object destruction."""
        if getattr(self, "session", None):
            self.session.logout()
            self.session.closeSession()
            _logger.info("HSM session closed.")


class SecureEnclaveStorage(StorageBackend):
    """
    Simulated secure enclave storage using file-based encryption.

    This class provides a secure storage mechanism by encrypting data before
    writing it to disk, simulating the behavior of a hardware-backed secure enclave.
    """

    def __init__(self, storage_path: str, encryption_key: bytes) -> None:
        """
        Initialize the secure enclave storage.

        Args:
            storage_path: The directory path to store encrypted files.
            encryption_key: The master key for encrypting the stored data.
        """
        self.storage_path = storage_path
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path, exist_ok=True)

        # Use Scrypt for key derivation. The salt must be persisted (not
        # regenerated per-instantiation) or previously stored data becomes
        # permanently undecryptable across restarts.
        salt_path = os.path.join(self.storage_path, ".salt")
        if os.path.exists(salt_path):
            with open(salt_path, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(salt_path, "wb") as f:
                f.write(salt)
            os.chmod(salt_path, 0o600)

        self.kdf = ScryptKDF(key_size=32)
        password = base64.b64encode(encryption_key).decode("utf-8")
        self.derived_key = self.kdf.derive_key(password, salt)
        self.encryptor = AESGCMEncryptor(key_size=len(self.derived_key))
        self.enclave_available = True
        _logger.info("Secure enclave storage initialized.")

    def _get_file_path(self, key: str) -> str:
        """Generate a secure file path for a given key."""
        safe_key = "".join(c for c in key if c.isalnum() or c in ("-", "_")).rstrip()
        return os.path.join(self.storage_path, f"{safe_key}.enc")

    def store(self, key: str, data: Dict[str, Any]) -> bool:
        """Encrypt and store data in a file."""
        if not self.enclave_available:
            return False

        file_path = self._get_file_path(key)
        try:
            json_data = json.dumps(data, sort_keys=True).encode("utf-8")
            encrypted_data = self.encryptor.encrypt(json_data, self.derived_key)

            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            _logger.info(f"Successfully stored data for key: {key}")
            return True
        except IOError as e:
            _logger.error(f"Failed to write to secure storage for key {key}: {e}")
            return False

    def load(self, key: str) -> Optional[Dict[str, Any]]:
        """Load and decrypt data from a file."""
        if not self.enclave_available:
            return None

        file_path = self._get_file_path(key)
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self.encryptor.decrypt(encrypted_data, self.derived_key)
            _logger.info(f"Successfully loaded data for key: {key}")
            return json.loads(decrypted_data)
        except (IOError, ValueError) as e:
            _logger.error(f"Failed to load or decrypt data for key {key}: {e}")
            return None

    def delete(self, key: str) -> bool:
        """Delete data from the secure storage."""
        if not self.enclave_available:
            return False

        file_path = self._get_file_path(key)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                _logger.info(f"Successfully deleted data for key: {key}")
                return True
            except OSError as e:
                _logger.error(f"Failed to delete data for key {key}: {e}")
                return False
        return True  # Key doesn't exist, so it's "deleted"
