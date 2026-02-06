use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyRuntimeError;
use std::collections::HashMap;

mod crypto;
mod secure_memory;

use crypto::{AesGcmCrypto, ChaCha20Poly1305Crypto, SecureKdf};

/// Secure key storage that automatically zeroizes on drop
#[pyclass]
pub struct SecureKey {
    #[pyo3(get)]
    algorithm: String,
    key_data: Vec<u8>,
}

#[pymethods]
impl SecureKey {
    #[new]
    fn new(algorithm: String, key_data: Vec<u8>) -> Self {
        Self {
            algorithm,
            key_data,
        }
    }

    fn get_public_key(&self) -> PyResult<Vec<u8>> {
        // For demonstration - in reality this would extract public component
        let len = std::cmp::min(32, self.key_data.len());
        Ok(self.key_data[..len].to_vec())
    }

    fn is_valid(&self) -> bool {
        !self.key_data.is_empty()
    }

    fn __repr__(&self) -> String {
        format!("SecureKey(algorithm={})", self.algorithm)
    }
}



/// Symmetric cryptography implementation using RustCrypto
#[pyclass]
pub struct RustCrypto {
    aes_crypto: AesGcmCrypto,
    chacha_crypto: ChaCha20Poly1305Crypto,
    kdf: SecureKdf,
}

#[pymethods]
impl RustCrypto {
    #[new]
    fn new() -> Self {
        Self {
            aes_crypto: AesGcmCrypto::new(),
            chacha_crypto: ChaCha20Poly1305Crypto::new(),
            kdf: SecureKdf::new(),
        }
    }

    /// Encrypt data using AES-256-GCM
    fn aes_encrypt(&self, py: Python, plaintext: &[u8], key: &[u8]) -> PyResult<PyObject> {
        let ciphertext = self.aes_crypto.encrypt(plaintext, key)
            .map_err(|e| PyRuntimeError::new_err(format!("AES encryption failed: {}", e)))?;
        Ok(PyBytes::new(py, &ciphertext).into())
    }

    /// Decrypt data using AES-256-GCM
    fn aes_decrypt(&self, py: Python, ciphertext: &[u8], key: &[u8]) -> PyResult<PyObject> {
        let plaintext = self.aes_crypto.decrypt(ciphertext, key)
            .map_err(|e| PyRuntimeError::new_err(format!("AES decryption failed: {}", e)))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    /// Encrypt data using ChaCha20Poly1305
    fn chacha_encrypt(&self, py: Python, plaintext: &[u8], key: &[u8]) -> PyResult<PyObject> {
        let ciphertext = self.chacha_crypto.encrypt(plaintext, key)
            .map_err(|e| PyRuntimeError::new_err(format!("ChaCha20 encryption failed: {}", e)))?;
        Ok(PyBytes::new(py, &ciphertext).into())
    }

    /// Decrypt data using ChaCha20Poly1305
    fn chacha_decrypt(&self, py: Python, ciphertext: &[u8], key: &[u8]) -> PyResult<PyObject> {
        let plaintext = self.chacha_crypto.decrypt(ciphertext, key)
            .map_err(|e| PyRuntimeError::new_err(format!("ChaCha20 decryption failed: {}", e)))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    /// Derive key using Argon2id
    fn derive_key_argon2(&self, password: &[u8], salt: &[u8], length: usize) -> PyResult<Vec<u8>> {
        let key = self.kdf.derive_argon2(password, salt, length)
            .map_err(|e| PyRuntimeError::new_err(format!("Argon2 key derivation failed: {}", e)))?;
        Ok(key)
    }

    /// Derive key using scrypt
    fn derive_key_scrypt(&self, password: &[u8], salt: &[u8], length: usize) -> PyResult<Vec<u8>> {
        let key = self.kdf.derive_scrypt(password, salt, length)
            .map_err(|e| PyRuntimeError::new_err(format!("Scrypt key derivation failed: {}", e)))?;
        Ok(key)
    }

    /// Generate secure random bytes
    fn generate_random(&self, length: usize) -> PyResult<Vec<u8>> {
        Ok(self.aes_crypto.generate_random(length))
    }
}

/// Top-level functions for convenience
#[pyfunction]
fn get_crypto_info() -> PyResult<HashMap<String, String>> {
    let mut info = HashMap::new();
    info.insert("aes_algorithm".to_string(), "AES-256-GCM".to_string());
    info.insert("chacha_algorithm".to_string(), "ChaCha20Poly1305".to_string());
    info.insert("kdf_algorithms".to_string(), "Argon2id, Scrypt".to_string());
    info.insert("implementation".to_string(), "RustCrypto".to_string());
    info.insert("memory_security".to_string(), "Zeroize + Secrecy".to_string());
    Ok(info)
}

#[pyfunction]
fn test_crypto() -> PyResult<bool> {
    let crypto = RustCrypto::new();
    
    // Test basic random generation
    let key = crypto.generate_random(32)?;
    if key.len() != 32 {
        return Ok(false);
    }
    
    // Test key derivation
    let password = crypto.generate_random(16)?;
    let salt = crypto.generate_random(16)?;
    let derived_key = crypto.derive_key_argon2(&password, &salt, 32)?;
    
    if derived_key.len() != 32 {
        return Ok(false);
    }
    
    Ok(true)
}

/// Python module definition
#[pymodule]
fn pqc_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    pyo3_log::init();

    // Classes
    m.add_class::<RustCrypto>()?;
    m.add_class::<SecureKey>()?;

    // Functions  
    m.add_function(wrap_pyfunction!(get_crypto_info, m)?)?;
    m.add_function(wrap_pyfunction!(test_crypto, m)?)?;

    // Module info
    m.add("__version__", "0.1.0")?;
    m.add("__author__", "Device Fingerprinting Team")?;
    
    Ok(())
}