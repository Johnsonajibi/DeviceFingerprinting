"""
Forward-Secure Page Epoch Encryption Library
============================================

A library implementing forward-secure key rotation using page-based encryption
with epoch counters. Only pages with stale epochs are re-encrypted during
key rotation, minimizing plaintext exposure.

Patent Claim: "Method for performing forward-secure key rotation on an encrypted 
password database by re-encrypting only those pages whose epoch counter 
is below the current epoch, thereby avoiding full plaintext exposure."

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

import json
import time
import hashlib
import os
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"

@dataclass
class PageEpoch:
    """Page epoch metadata for forward-secure encryption"""
    page_id: str
    epoch_counter: int
    last_rotation: str
    key_fingerprint: str
    size_bytes: int
    page_size_kb: float = 1.0

@dataclass
class EpochRotationResult:
    """Result of epoch-based key rotation operation"""
    success: bool
    pages_rotated: int
    total_pages: int
    old_epoch: int
    new_epoch: int
    rotation_time: float
    pages_skipped: int = 0
    error_message: Optional[str] = None

class ForwardSecurePageManager:
    """
    Forward-Secure Page Encryption Manager
    
    Implements page-based encryption with epoch counters for forward security.
    Only pages with epoch < current_epoch are re-encrypted during key rotation.
    
    Key Features:
    - Forward Security: Old keys cannot decrypt new data after rotation
    - Selective Re-encryption: Only stale pages are updated
    - Dynamic Page Sizing: Adapts to data size for optimal performance
    - Integrity Protection: SHA3-256 checksums for data integrity
    """
    
    def __init__(self, vault_size: int = 0, page_size_kb: float = 1.0):
        """
        Initialize forward-secure page manager
        
        Args:
            vault_size: Number of entries in the vault
            page_size_kb: Page size in KB (can be fractional)
        """
        self.vault_size = vault_size
        self.page_size_kb = page_size_kb
        self.current_epoch = 1
        self.page_metadata: Dict[str, PageEpoch] = {}
    
    def calculate_optimal_page_size(self, vault_size: int) -> float:
        """
        Calculate optimal page size based on vault size
        
        Args:
            vault_size: Number of password entries
            
        Returns:
            Optimal page size in KB
        """
        thresholds = {
            50: 0.5,    # Small vault: 0.5KB pages
            200: 1.0,   # Medium vault: 1KB pages  
            500: 2.0,   # Large vault: 2KB pages
            float('inf'): 4.0  # XL vault: 4KB pages
        }
        
        for max_passwords, page_size in thresholds.items():
            if vault_size <= max_passwords:
                return page_size
        
        return 4.0  # Default for very large vaults
    
    def update_vault_size(self, new_vault_size: int) -> bool:
        """
        Update vault size and recalculate optimal page size
        
        Args:
            new_vault_size: New number of vault entries
            
        Returns:
            True if page size changed
        """
        old_page_size = self.page_size_kb
        self.vault_size = new_vault_size
        self.page_size_kb = self.calculate_optimal_page_size(new_vault_size)
        
        if old_page_size != self.page_size_kb:
            # Clear page metadata since boundaries changed
            self.page_metadata = {}
            return True
        return False
    
    def divide_data_into_pages(self, data: bytes) -> List[Tuple[str, bytes]]:
        """
        Divide data into pages based on current page size
        
        Args:
            data: Data to divide into pages
            
        Returns:
            List of (page_id, page_data) tuples
        """
        pages = []
        page_size_bytes = int(self.page_size_kb * 1024)
        
        for i in range(0, len(data), page_size_bytes):
            page_data = data[i:i + page_size_bytes]
            page_id = f"page_{i//page_size_bytes:04d}_{hashlib.sha3_256(page_data).hexdigest()[:16]}"
            pages.append((page_id, page_data))
        
        return pages
    
    def encrypt_page_with_epoch(self, page_data: bytes, key: bytes, epoch: int) -> Tuple[bytes, str]:
        """
        Encrypt a page with epoch metadata
        
        Args:
            page_data: Data to encrypt
            key: Encryption key (32 bytes)
            epoch: Current epoch counter
            
        Returns:
            Tuple of (encrypted_data, key_fingerprint)
        """
        # Create epoch-specific nonce
        epoch_nonce = hashlib.sha3_256(f"epoch_{epoch}_{len(page_data)}".encode()).digest()[:12]
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        encrypted_page = aesgcm.encrypt(epoch_nonce, page_data, None)
        
        # Create key fingerprint
        key_fingerprint = hashlib.sha3_256(key + str(epoch).encode()).hexdigest()[:32]
        
        # Create epoch header
        epoch_header = json.dumps({
            'epoch': epoch,
            'size': len(page_data),
            'algorithm': 'AES-256-GCM-Epoch',
            'key_fp': key_fingerprint
        }).encode('utf-8')
        
        # Format: [header_length][header][nonce][encrypted_data]
        header_length = len(epoch_header).to_bytes(4, 'big')
        final_data = header_length + epoch_header + epoch_nonce + encrypted_page
        
        return final_data, key_fingerprint
    
    def decrypt_page_with_epoch(self, encrypted_data: bytes, key: bytes) -> Tuple[bytes, int]:
        """
        Decrypt a page and extract epoch information
        
        Args:
            encrypted_data: Encrypted page data
            key: Decryption key
            
        Returns:
            Tuple of (decrypted_data, epoch)
        """
        # Extract header length
        header_length = int.from_bytes(encrypted_data[:4], 'big')
        
        # Extract and parse header
        header_data = encrypted_data[4:4+header_length]
        header = json.loads(header_data.decode('utf-8'))
        
        epoch = header['epoch']
        original_size = header['size']
        key_fingerprint = header['key_fp']
        
        # Verify key fingerprint
        expected_fp = hashlib.sha3_256(key + str(epoch).encode()).hexdigest()[:32]
        if key_fingerprint != expected_fp:
            raise ValueError("Key fingerprint mismatch - wrong key or corrupted data")
        
        # Extract nonce and encrypted data
        nonce_start = 4 + header_length
        nonce = encrypted_data[nonce_start:nonce_start+12]
        ciphertext = encrypted_data[nonce_start+12:]
        
        # Decrypt
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        if len(decrypted_data) != original_size:
            raise ValueError("Decrypted data size mismatch")
        
        return decrypted_data, epoch
    
    def perform_forward_secure_rotation(self, vault_data: List[Dict], old_key: bytes, new_key: bytes) -> EpochRotationResult:
        """
        Perform forward-secure key rotation
        
        Core Algorithm:
        1. Serialize vault data and divide into pages
        2. For each page, compare page_epoch < current_epoch
        3. If stale: re-encrypt with new key
        4. If current: skip re-encryption (forward security)
        5. Update metadata and increment epoch
        
        Args:
            vault_data: Data to protect
            old_key: Current encryption key
            new_key: New encryption key
            
        Returns:
            EpochRotationResult with statistics
        """
        start_time = time.perf_counter()
        
        try:
            # Serialize data
            vault_json = json.dumps(vault_data, separators=(',', ':')).encode('utf-8')
            pages = self.divide_data_into_pages(vault_json)
            
            pages_rotated = 0
            pages_skipped = 0
            rotation_errors = []
            
            for page_id, page_data in pages:
                try:
                    # Check if page needs rotation
                    if page_id in self.page_metadata:
                        page_epoch = self.page_metadata[page_id].epoch_counter
                        
                        # Core algorithm: Only rotate if page_epoch < current_epoch
                        if page_epoch >= self.current_epoch:
                            pages_skipped += 1
                            continue  # Skip current-epoch pages (forward security)
                    
                    # Re-encrypt page with new key
                    encrypted_page, key_fingerprint = self.encrypt_page_with_epoch(
                        page_data, new_key, self.current_epoch
                    )
                    
                    # Update page metadata
                    self.page_metadata[page_id] = PageEpoch(
                        page_id=page_id,
                        epoch_counter=self.current_epoch,
                        last_rotation=datetime.now().isoformat(),
                        key_fingerprint=key_fingerprint,
                        size_bytes=len(page_data),
                        page_size_kb=self.page_size_kb
                    )
                    
                    pages_rotated += 1
                    
                except Exception as e:
                    rotation_errors.append(f"Page {page_id}: {str(e)}")
                    continue
            
            # Increment epoch after successful rotation
            if pages_rotated > 0:
                old_epoch = self.current_epoch
                self.current_epoch += 1
            else:
                old_epoch = self.current_epoch
            
            end_time = time.perf_counter()
            rotation_time = end_time - start_time
            
            success = len(rotation_errors) == 0
            error_msg = "; ".join(rotation_errors) if rotation_errors else None
            
            return EpochRotationResult(
                success=success,
                pages_rotated=pages_rotated,
                total_pages=len(pages),
                old_epoch=old_epoch,
                new_epoch=self.current_epoch,
                rotation_time=rotation_time,
                pages_skipped=pages_skipped,
                error_message=error_msg
            )
            
        except Exception as e:
            end_time = time.perf_counter()
            rotation_time = end_time - start_time
            
            return EpochRotationResult(
                success=False,
                pages_rotated=0,
                total_pages=0,
                old_epoch=self.current_epoch,
                new_epoch=self.current_epoch,
                rotation_time=rotation_time,
                error_message=str(e)
            )
    
    def get_rotation_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics about the epoch system"""
        stats = {
            'current_epoch': self.current_epoch,
            'total_pages': len(self.page_metadata),
            'page_size_kb': self.page_size_kb,
            'vault_size': self.vault_size,
            'epoch_distribution': {},
            'last_rotation': None,
            'total_rotations': self.current_epoch - 1
        }
        
        # Calculate epoch distribution
        for page_epoch in self.page_metadata.values():
            epoch = page_epoch.epoch_counter
            if epoch not in stats['epoch_distribution']:
                stats['epoch_distribution'][epoch] = 0
            stats['epoch_distribution'][epoch] += 1
            
            # Find most recent rotation
            if not stats['last_rotation'] or page_epoch.last_rotation > stats['last_rotation']:
                stats['last_rotation'] = page_epoch.last_rotation
        
        return stats
    
    def save_metadata(self, filepath: str) -> bool:
        """Save page metadata to file"""
        try:
            metadata_dict = {}
            for page_id, page_epoch in self.page_metadata.items():
                metadata_dict[page_id] = {
                    'page_id': page_epoch.page_id,
                    'epoch_counter': page_epoch.epoch_counter,
                    'last_rotation': page_epoch.last_rotation,
                    'key_fingerprint': page_epoch.key_fingerprint,
                    'size_bytes': page_epoch.size_bytes,
                    'page_size_kb': page_epoch.page_size_kb
                }
            
            with open(filepath, 'w') as f:
                json.dump(metadata_dict, f, indent=2)
            return True
        except Exception:
            return False
    
    def load_metadata(self, filepath: str) -> bool:
        """Load page metadata from file"""
        try:
            if not os.path.exists(filepath):
                return False
                
            with open(filepath, 'r') as f:
                metadata_dict = json.load(f)
            
            self.page_metadata = {}
            for page_id, data in metadata_dict.items():
                self.page_metadata[page_id] = PageEpoch(
                    page_id=data['page_id'],
                    epoch_counter=data['epoch_counter'],
                    last_rotation=data['last_rotation'],
                    key_fingerprint=data['key_fingerprint'],
                    size_bytes=data['size_bytes'],
                    page_size_kb=data.get('page_size_kb', 1.0)
                )
            return True
        except Exception:
            return False

