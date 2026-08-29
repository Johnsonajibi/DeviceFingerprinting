"""
Secure storage utilities for device binding tokens.

Handles platform-specific secure storage of sensitive data.
Falls back gracefully when secure storage is not available.
"""

import os
import sys
import json
import hashlib
from typing import Dict, Any, Optional, List

from .crypto import AESGCMEncryptor, ScryptKDF, InvalidTag

# Try to import keyring, but don't make it a hard dependency
try:
    import keyring
except ImportError:
    keyring = None


class SecureStorage:
    """
    Manages encrypted storage of key-value data in a file, with optional
    integration with the system's secret management service (keyring).
    """

    def __init__(
        self,
        file_path: str,
        password: Optional[str] = None,
        key_iterations: int = 100_000,
        allow_legacy_format: bool = False,
    ):
        """
        Initializes the secure storage.

        Args:
            file_path: The path to the file where data will be stored.
            password: The password to use for encryption. If not provided,
                      the system's keyring will be used as a fallback.
            key_iterations: The number of iterations for the key derivation function.
            allow_legacy_format: If True, load() will fall back to the old
                fixed-zero-salt file format if the current-format decrypt
                fails. Off by default: that format uses the same hardcoded
                salt for every store on every machine (defeating per-file
                salting) and doubles KDF cost on any read of a corrupted or
                tampered file. Only enable this while migrating pre-existing
                files, then turn it back off.
        """
        self.file_path = file_path
        self.key_iterations = key_iterations
        self.allow_legacy_format = allow_legacy_format
        self._password_was_explicit = password is not None
        self._password = password
        self._encryptor = None
        self._salt = None
        self._salt_loaded = False
        self.data: Dict[str, Any] = {}

        if not self._password and keyring:
            self._password = self._get_password_from_keyring()

        if not self._password:
            raise ValueError(
                "A password must be provided if the system keyring is not available or contains no password."
            )

        self._setup_encryptor()

        if os.path.exists(self.file_path):
            self.load()
        else:
            # New storage, set password in keyring if possible - but only
            # when the caller didn't supply their own password explicitly.
            # Otherwise a one-off/ephemeral password a caller derived for
            # this specific use would get silently persisted system-wide.
            if keyring and self._password and not self._password_was_explicit:
                self._set_password_in_keyring(self._password)

    def _keyring_username(self) -> str:
        """
        Derives the keyring username from the absolute file path (not just
        its basename), so two different SecureStorage files that happen to
        share a filename in different directories don't collide on the same
        keyring entry and hijack/overwrite each other's password.
        """
        abs_path = os.path.normcase(os.path.abspath(self.file_path))
        return hashlib.sha256(abs_path.encode("utf-8")).hexdigest()

    def _get_password_from_keyring(self) -> Optional[str]:
        """Retrieves the password from the system's keyring."""
        if not keyring:
            return None
        service_name = "device_fingerprinting_library"
        try:
            password = keyring.get_password(service_name, self._keyring_username())
            if password:
                return password
        except Exception:
            pass
        # Back-compat: earlier versions keyed the keyring entry by the
        # file's basename, which could collide across directories. Fall
        # back to it (and migrate forward) so upgrading doesn't strand
        # passwords already stored under the old key.
        try:
            legacy_username = os.path.basename(self.file_path)
            password = keyring.get_password(service_name, legacy_username)
            if password:
                self._set_password_in_keyring(password)
            return password
        except Exception:
            return None

    def _set_password_in_keyring(self, password: str):
        """Stores the password in the system's keyring for future use."""
        if not keyring:
            return
        try:
            service_name = "device_fingerprinting_library"
            keyring.set_password(service_name, self._keyring_username(), password)
        except Exception:
            pass

    def _setup_encryptor(self):
        """Sets up the encryptor with proper random salt."""
        if os.path.exists(self.file_path):
            # Try to load salt from existing file (new format)
            try:
                with open(self.file_path, "rb") as f:
                    self._salt = f.read(16)
                    if len(self._salt) == 16:
                        self._salt_loaded = True
                    else:
                        # File too short - generate new salt
                        self._salt = os.urandom(16)
                        self._salt_loaded = False
            except (IOError, OSError):
                self._salt = os.urandom(16)
                self._salt_loaded = False
        else:
            # Generate random salt for new files
            self._salt = os.urandom(16)
            self._salt_loaded = False

        kdf = ScryptKDF()
        self._key = kdf.derive_key(self._password, self._salt)
        self._encryptor = AESGCMEncryptor()

    def save(self):
        """
        Saves the data to the file with salt prepended.

        Writes to a temp file and atomically replaces the target so a crash
        or interruption mid-write can't leave a truncated/corrupted file
        with no recovery path.
        """
        if not self._encryptor:
            self._setup_encryptor()

        json_data = json.dumps(self.data).encode("utf-8")
        encrypted_blob = self._encryptor.encrypt(json_data, self._key)

        tmp_path = f"{self.file_path}.tmp-{os.getpid()}"
        with open(tmp_path, "wb") as f:
            f.write(self._salt)
            f.write(encrypted_blob)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass  # chmod semantics are platform-dependent (e.g. Windows)
        os.replace(tmp_path, self.file_path)

    def load(self):
        """
        Loads and decrypts the data from the file, reading salt from file.
        Supports both new format (with salt) and old format (without salt).
        """
        if not self._encryptor:
            self._setup_encryptor()

        with open(self.file_path, "rb") as f:
            if self._salt_loaded:
                # New format: skip salt prefix
                f.seek(16)
            # Old format or file too short: read from beginning
            encrypted_blob = f.read()

        try:
            decrypted_data = self._encryptor.decrypt(encrypted_blob, self._key)
            self.data = json.loads(decrypted_data)
        except (ValueError, InvalidTag) as e:
            if not self.allow_legacy_format:
                raise IOError(
                    f"Failed to decrypt or load data. Incorrect password or corrupted file. Reason: {e}"
                )

            # Try old format (no salt prefix) for backward compatibility.
            # Only reached when allow_legacy_format=True was explicitly
            # opted into: this format uses the same hardcoded zero salt for
            # every file on every machine, so leaving this fallback on
            # unconditionally would let an attacker precompute against that
            # fixed salt, and would double the KDF cost on every read of a
            # merely-corrupted (not actually legacy) file - a cheap DoS lever.
            with open(self.file_path, "rb") as f:
                encrypted_blob_old = f.read()

            # Use hardcoded salt for old format
            old_salt = b"\x00" * 16
            kdf = ScryptKDF()
            old_key = kdf.derive_key(self._password, old_salt)

            try:
                decrypted_data = self._encryptor.decrypt(encrypted_blob_old, old_key)
                self.data = json.loads(decrypted_data)
                # Successfully loaded old format - generate new salt for migration on next save
                self._salt = os.urandom(16)
                self._key = kdf.derive_key(self._password, self._salt)
            except (ValueError, InvalidTag):
                raise IOError(
                    f"Failed to decrypt or load data. Incorrect password or corrupted file. Reason: {e}"
                )
        except json.JSONDecodeError:
            raise IOError("File is corrupted and does not contain valid JSON.")

    def __setitem__(self, key: str, value: Any):
        """Sets an item in the store."""
        self.data[key] = value

    def __getitem__(self, key: str) -> Any:
        """Gets an item from the store."""
        return self.data[key]

    def __delitem__(self, key: str):
        """Deletes an item from the store."""
        del self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        """Gets an item, returning a default value if the key does not exist."""
        return self.data.get(key, default)

    def keys(self) -> List[str]:
        """Returns a list of all keys in the store."""
        return list(self.data.keys())

    # --- Compatibility methods for tests ---
    def set_item(self, key: str, value: Any):
        self[key] = value

    def get_item(self, key: str, default: Any = None) -> Any:
        return self.get(key, default)

    def delete_item(self, key: str) -> bool:
        if key in self.data:
            del self[key]
            return True
        return False

    def list_keys(self) -> List[str]:
        return self.keys()

    def __enter__(self):
        """Allows the class to be used as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Saves the data to the file upon exiting the context."""
        self.save()
