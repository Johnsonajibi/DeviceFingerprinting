/// Simple secure buffer implementation
pub struct SecureBuffer {
    data: Vec<u8>,
    metadata: BufferMetadata,
}

#[derive(Clone, Debug)]
struct BufferMetadata {
    algorithm: String,
    created_at: std::time::SystemTime,
    access_count: usize,
}

impl SecureBuffer {
    /// Create a new secure buffer
    pub fn new(data: Vec<u8>, algorithm: String) -> Self {
        Self {
            data,
            metadata: BufferMetadata {
                algorithm,
                created_at: std::time::SystemTime::now(),
                access_count: 0,
            },
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get algorithm name
    pub fn algorithm(&self) -> &str {
        &self.metadata.algorithm
    }
}

impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("algorithm", &self.metadata.algorithm)
            .field("length", &self.len())
            .field("created_at", &self.metadata.created_at)
            .field("access_count", &self.metadata.access_count)
            .finish()
    }
}

/// Error types for SecureBuffer operations
#[derive(Debug, Clone)]
pub enum SecureBufferError {
    SizeMismatch,
    AccessDenied,
    InvalidOperation,
}

impl std::fmt::Display for SecureBufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureBufferError::SizeMismatch => write!(f, "Buffer size mismatch"),
            SecureBufferError::AccessDenied => write!(f, "Access denied to secure buffer"),
            SecureBufferError::InvalidOperation => write!(f, "Invalid operation on secure buffer"),
        }
    }
}

impl std::error::Error for SecureBufferError {}

/// Utility functions for secure memory operations
pub mod secure_utils {
    use super::SecureBuffer;
    use rand::RngCore;
    use aes_gcm::aead::OsRng;

    /// Generate a secure random buffer
    pub fn generate_random_buffer(length: usize, algorithm: String) -> SecureBuffer {
        let mut data = vec![0u8; length];
        OsRng.fill_bytes(&mut data);
        SecureBuffer::new(data, algorithm)
    }

    /// Create a buffer from a hex string
    pub fn from_hex(hex_str: &str, algorithm: String) -> Result<SecureBuffer, hex::FromHexError> {
        let data = hex::decode(hex_str)?;
        Ok(SecureBuffer::new(data, algorithm))
    }
}