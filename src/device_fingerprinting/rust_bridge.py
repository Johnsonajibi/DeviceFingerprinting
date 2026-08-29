"""
Python Bridge to the pqc_rust Module

Provides a clean Python interface to pqc_rust's real capabilities:
accelerated AES-256-GCM / ChaCha20-Poly1305 encryption and Argon2id/Scrypt
key derivation. pqc_rust does not implement post-quantum signatures or KEMs
(Dilithium/Kyber) - that functionality lives in the pqcrypto/pqcdualusb
backends used by crypto.py and hybrid_pqc.py, not in this crate.
"""

import os
import sys
import subprocess
from typing import Dict, Any
import logging

_logger = logging.getLogger(__name__)

# --- Import ---
try:
    from pqc_rust import RustCrypto, SecureKey, get_crypto_info, test_crypto

    PQC_RUST_AVAILABLE = True
    _logger.info("Successfully imported pqc_rust module")

except ImportError:
    _logger.warning("pqc_rust module not found: No module named 'pqc_rust'")
    _logger.info("Run: pip install maturin && maturin develop (from pqc_rust_src/)")

    PQC_RUST_AVAILABLE = False


# --- Python Bridge Class ---
class RustCryptoBridge:
    """Bridge to the pqc_rust module's accelerated symmetric crypto/KDF operations."""

    def __init__(self):
        self._crypto = RustCrypto() if PQC_RUST_AVAILABLE else None

    def aes_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt using AES-256-GCM."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.aes_encrypt(plaintext, key)

    def aes_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using AES-256-GCM."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.aes_decrypt(ciphertext, key)

    def chacha_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt using ChaCha20-Poly1305."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.chacha_encrypt(plaintext, key)

    def chacha_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.chacha_decrypt(ciphertext, key)

    def derive_key_argon2(self, password: bytes, salt: bytes, length: int = 32) -> bytes:
        """Derive a key using Argon2id."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.derive_key_argon2(password, salt, length)

    def derive_key_scrypt(self, password: bytes, salt: bytes, length: int = 32) -> bytes:
        """Derive a key using Scrypt."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return self._crypto.derive_key_scrypt(password, salt, length)

    def generate_random(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        if not PQC_RUST_AVAILABLE:
            raise NotImplementedError("pqc_rust module not available.")
        return bytes(self._crypto.generate_random(length))

    @staticmethod
    def is_available() -> bool:
        """Check if the pqc_rust module is available."""
        return PQC_RUST_AVAILABLE

    @staticmethod
    def get_info() -> Dict[str, Any]:
        """Get crypto backend information."""
        if not PQC_RUST_AVAILABLE:
            return {"error": "pqc_rust module not available"}
        try:
            return dict(get_crypto_info())
        except Exception as e:
            return {"error": f"Failed to get info: {e}"}

    @staticmethod
    def self_test() -> bool:
        """Run pqc_rust's internal self-test (random generation + key derivation)."""
        if not PQC_RUST_AVAILABLE:
            return False
        try:
            return bool(test_crypto())
        except Exception as e:
            _logger.warning(f"pqc_rust self-test failed: {e}")
            return False


# Global instance
rust_pqc = RustCryptoBridge()


def install_rust_pqc() -> bool:
    """Build and install the pqc_rust module in-place (development helper)."""
    _logger.info("Installing pqc_rust module...")

    try:
        result = subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=True)
        _logger.info(f"Rust found: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        _logger.error("Rust not found. Please install Rust from https://rustup.rs/")
        return False

    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "maturin"], check=True)
        _logger.info("Maturin installed")
    except subprocess.CalledProcessError as e:
        _logger.error(f"Failed to install maturin: {e}")
        return False

    try:
        # The crate directory is pqc_rust_src/ at the repo root (this file
        # lives at src/device_fingerprinting/, two levels below that).
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        pqc_rust_dir = os.path.join(repo_root, "pqc_rust_src")
        if os.path.exists(pqc_rust_dir):
            _logger.info(f"Building pqc_rust module in: {pqc_rust_dir}")
            subprocess.run(["maturin", "develop"], cwd=pqc_rust_dir, check=True)
            _logger.info("pqc_rust module built and installed!")

            global rust_pqc
            rust_pqc = RustCryptoBridge()
            return True
        else:
            _logger.error(f"pqc_rust_src directory not found: {pqc_rust_dir}")
            return False

    except subprocess.CalledProcessError as e:
        _logger.error(f"Failed to build pqc_rust module: {e}")
        return False


if __name__ == "__main__":
    if rust_pqc.is_available():
        print("pqc_rust is available!")
        for k, v in rust_pqc.get_info().items():
            print(f"   {k}: {v}")
        print("Self-test:", "passed" if rust_pqc.self_test() else "failed")
    else:
        print("pqc_rust not available")
        print("Run install_rust_pqc() to set it up")
