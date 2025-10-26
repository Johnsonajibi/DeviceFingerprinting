use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::{Aead, OsRng}};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
use rand::RngCore;
use std::fmt;

/// Custom error type for crypto operations
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    InvalidNonceSize,
    KeyDerivationFailed,
    RandomGenerationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Encryption operation failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption operation failed"),
            CryptoError::InvalidKeySize => write!(f, "Invalid key size provided"),
            CryptoError::InvalidNonceSize => write!(f, "Invalid nonce size provided"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::RandomGenerationFailed => write!(f, "Random number generation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// AES-256-GCM implementation using RustCrypto
pub struct AesGcmCrypto {
    // No state needed - stateless operations
}

impl AesGcmCrypto {
    pub fn new() -> Self {
        Self {}
    }

    /// Encrypt data with AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Combine nonce + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Split nonce and ciphertext
        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Generate cryptographically secure random bytes
    pub fn generate_random(&self, length: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; length];
        OsRng.fill_bytes(&mut buffer);
        buffer
    }
}

/// ChaCha20Poly1305 implementation using RustCrypto
pub struct ChaCha20Poly1305Crypto {
    // No state needed - stateless operations
}

impl ChaCha20Poly1305Crypto {
    pub fn new() -> Self {
        Self {}
    }

    /// Encrypt data with ChaCha20Poly1305
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Combine nonce + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with ChaCha20Poly1305
    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Split nonce and ciphertext
        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = ChaChaNonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

/// Secure key derivation functions
pub struct SecureKdf {
    // No state needed
}

impl SecureKdf {
    pub fn new() -> Self {
        Self {}
    }

    /// Derive key using Argon2id (recommended for passwords)
    pub fn derive_argon2(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
        let argon2 = Argon2::default();
        
        // Convert salt to SaltString format
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // Hash the password
        let password_hash = argon2.hash_password(password, &salt_string)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // Extract the hash bytes and truncate/pad to desired length
        let hash_bytes = password_hash.hash.ok_or(CryptoError::KeyDerivationFailed)?;
        let mut result = vec![0u8; length];
        let copy_len = std::cmp::min(hash_bytes.as_bytes().len(), length);
        result[..copy_len].copy_from_slice(&hash_bytes.as_bytes()[..copy_len]);

        Ok(result)
    }

    /// Derive key using scrypt (memory-hard function)
    pub fn derive_scrypt(&self, password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
        use scrypt::scrypt;
        
        let mut result = vec![0u8; length];
        let params = scrypt::Params::new(14, 8, 1, length)  // log_n=14, r=8, p=1 (moderate security), with desired output length
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
        scrypt(password, salt, &params, &mut result)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(result)
    }
}