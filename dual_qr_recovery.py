"""
Dual QR Recovery System

Splits recovery data across two QR codes to reduce single point of failure.
Simple implementation for password manager backup/recovery scenarios.

Author: Security Team
Version: 1.2.1
"""

import json
import hashlib
import base64
import zlib
import secrets
import platform
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__version__ = "1.2.1"

# Production settings based on security review Q4 2024
DEFAULT_PBKDF2_ITERATIONS = 50000  # Reduced from 100k for mobile compatibility
DEFAULT_EXPIRY_HOURS = 72  # 3 days - compromise between security and usability
QR_SIZE_LIMIT = 2000  # Conservative QR code data limit

logger = logging.getLogger(__name__)

@dataclass
class QRRecoveryData:
    """Recovery data for a single QR code."""
    qr_id: str
    qr_part: str  # 'A' or 'B'
    encrypted_payload: str
    device_id: str
    created_at: str
    expires_at: str
    checksum: str
    compressed: bool = False  # Track compression state

@dataclass
class SplitQRResult:
    """Result of splitting data across two QR codes."""
    qr_a: QRRecoveryData
    qr_b: QRRecoveryData
    instructions: str
    errors: List[str] = None

class DeviceIdentifier:
    """Simple device identification for binding QR codes to devices."""
    
    @staticmethod
    def get_device_id() -> str:
        """
        Get basic device identifier.
        
        Note: This is not cryptographically strong device fingerprinting.
        Used for basic binding to prevent casual QR code sharing.
        """
        try:
            components = [
                platform.system(),
                platform.machine(), 
                platform.node()[:20],  # Hostname truncated
                platform.python_version()
            ]
            combined = "|".join(components)
            digest = hashlib.sha256(combined.encode()).hexdigest()
            return f"dev_{digest[:16]}"
        except Exception as e:
            logger.warning(f"Device ID generation failed: {e}")
            # Fallback to random ID (will break recovery but prevents crashes)
            return f"dev_{secrets.token_hex(8)}"

class DualQRRecovery:
    """
    Split recovery data across two QR codes.
    
    Use case: Backup critical data when single QR code is too large 
    or when you want redundancy across two physical locations.
    
    Limitations:
    - Both QR codes needed for recovery (no threshold scheme)
    - Device binding is basic platform info (not hardware-level)
    - No forward secrecy - compromised device = compromised QRs
    """
    
    def __init__(self, expiry_hours: int = DEFAULT_EXPIRY_HOURS):
        """
        Initialize QR recovery system.
        
        Args:
            expiry_hours: Hours until QR codes expire (default 72)
        """
        self.device_id = DeviceIdentifier.get_device_id()
        self.expiry_hours = expiry_hours
        
        # QR size limits based on testing with common scanners
        self.max_qr_size = QR_SIZE_LIMIT
        
    def split_data(self, data: Dict[str, Any]) -> SplitQRResult:
        """
        Split data across two QR codes.
        
        Args:
            data: Dictionary to split and encode
            
        Returns:
            SplitQRResult with two QR codes
        """
        errors = []
        
        try:
            # Serialize data
            json_data = json.dumps(data, separators=(',', ':'))
            
            # Check if compression helps
            compressed = zlib.compress(json_data.encode('utf-8'))
            if len(compressed) < len(json_data):
                payload = base64.b64encode(compressed).decode('ascii')
                compressed_flag = True
            else:
                payload = base64.b64encode(json_data.encode('utf-8')).decode('ascii')
                compressed_flag = False
                
            # Split payload in half
            mid_point = len(payload) // 2
            part_a = payload[:mid_point]
            part_b = payload[mid_point:]
            
            # Check size limits
            if len(part_a) > self.max_qr_size:
                errors.append(f"Part A ({len(part_a)} bytes) exceeds QR limit")
            if len(part_b) > self.max_qr_size:
                errors.append(f"Part B ({len(part_b)} bytes) exceeds QR limit")
            
            # Create timestamps
            now = datetime.now()
            created_at = now.isoformat()
            expires_at = (now + timedelta(hours=self.expiry_hours)).isoformat()
            
            # Generate IDs
            session_id = secrets.token_hex(8)
            
            # Create QR data structures
            qr_a = self._create_qr_data(
                qr_id=f"{session_id}_A",
                qr_part="A",
                payload=part_a,
                created_at=created_at,
                expires_at=expires_at,
                compressed=compressed_flag
            )
            
            qr_b = self._create_qr_data(
                qr_id=f"{session_id}_B", 
                qr_part="B",
                payload=part_b,
                created_at=created_at,
                expires_at=expires_at,
                compressed=compressed_flag
            )
            
            instructions = self._generate_instructions(qr_a, qr_b)
            
            return SplitQRResult(
                qr_a=qr_a,
                qr_b=qr_b, 
                instructions=instructions,
                errors=errors if errors else None
            )
            
        except Exception as e:
            logger.error(f"QR split failed: {e}")
            errors.append(f"Split failed: {str(e)}")
            return SplitQRResult(
                qr_a=None,
                qr_b=None,
                instructions="",
                errors=errors
            )
    
    def recover_data(self, qr_a: QRRecoveryData, qr_b: QRRecoveryData) -> Optional[Dict[str, Any]]:
        """
        Recover data from two QR codes.
        
        Args:
            qr_a: First QR code data
            qr_b: Second QR code data
            
        Returns:
            Recovered data dictionary or None if failed
        """
        try:
            # Basic validation
            if not self._validate_qr_pair(qr_a, qr_b):
                return None
            
            # Decrypt payloads
            payload_a = self._decrypt_payload(qr_a)
            payload_b = self._decrypt_payload(qr_b)
            
            if not payload_a or not payload_b:
                logger.error("Failed to decrypt QR payloads")
                return None
            
            # Reconstruct original payload
            full_payload = payload_a + payload_b
            
            # Determine if compressed
            compressed = qr_a.compressed
            
            # Decode and optionally decompress
            try:
                decoded = base64.b64decode(full_payload)
                if compressed:
                    json_data = zlib.decompress(decoded).decode('utf-8')
                else:
                    json_data = decoded.decode('utf-8')
                    
                return json.loads(json_data)
                
            except Exception as e:
                logger.error(f"Data reconstruction failed: {e}")
                return None
                
        except Exception as e:
            logger.error(f"QR recovery failed: {e}")
            return None
    
    def _create_qr_data(self, qr_id: str, qr_part: str, payload: str,
                       created_at: str, expires_at: str, compressed: bool) -> QRRecoveryData:
        """Create QR data structure with encryption."""
        
        # Metadata (not encrypted - needed for validation)
        metadata = {
            'compressed': compressed,
            'part': qr_part,
            'created': created_at,
            'expires': expires_at
        }
        
        # Encrypt the actual payload
        encrypted_payload = self._encrypt_payload(payload, qr_id)
        encrypted_metadata = self._encrypt_metadata(metadata, qr_id)
        
        # Create checksum
        checksum_data = f"{qr_id}:{qr_part}:{encrypted_payload}:{self.device_id}"
        checksum = hashlib.sha256(checksum_data.encode()).hexdigest()[:16]
        
        return QRRecoveryData(
            qr_id=qr_id,
            qr_part=qr_part,
            encrypted_payload=encrypted_payload,
            device_id=self.device_id,
            created_at=created_at,
            expires_at=expires_at,
            checksum=checksum,
            compressed=compressed
        )
    
    def _encrypt_payload(self, payload: str, qr_id: str) -> str:
        """Encrypt payload with device binding."""
        # Derive key from device ID and QR ID
        key_material = f"{self.device_id}:{qr_id}"
        
        # Simple PBKDF2 key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=qr_id.encode('utf-8').ljust(16, b'\x00')[:16],
            iterations=DEFAULT_PBKDF2_ITERATIONS,
        )
        key = kdf.derive(key_material.encode('utf-8'))
        
        # AES-GCM encryption
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, payload.encode('utf-8'), None)
        
        # Combine and encode
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode('ascii')
    
    def _decrypt_payload(self, qr_data: QRRecoveryData) -> Optional[str]:
        """Decrypt payload with device binding."""
        try:
            # Check device binding
            if qr_data.device_id != self.device_id:
                logger.warning("Device ID mismatch - QR from different device")
                return None
            
            # Derive same key
            key_material = f"{self.device_id}:{qr_data.qr_id}"
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=qr_data.qr_id.encode('utf-8').ljust(16, b'\x00')[:16],
                iterations=DEFAULT_PBKDF2_ITERATIONS,
            )
            key = kdf.derive(key_material.encode('utf-8'))
            
            # Decrypt
            encrypted = base64.b64decode(qr_data.encrypted_payload)
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Payload decryption failed: {e}")
            return None
    
    def _encrypt_metadata(self, metadata: Dict[str, Any], qr_id: str) -> str:
        """Encrypt metadata (same method as payload)."""
        json_metadata = json.dumps(metadata)
        return self._encrypt_payload(json_metadata, f"meta_{qr_id}")
    
    def _decrypt_metadata(self, qr_data: QRRecoveryData) -> Optional[Dict[str, Any]]:
        """Decrypt metadata."""
        try:
            # For this implementation, metadata is stored in clear text in QR structure
            # In production, you might encrypt this too
            return {
                'compressed': False,  # Check based on actual compression during split
                'part': qr_data.qr_part,
                'created': qr_data.created_at,
                'expires': qr_data.expires_at
            }
        except Exception:
            return None
    
    def _validate_qr_pair(self, qr_a: QRRecoveryData, qr_b: QRRecoveryData) -> bool:
        """Validate that two QR codes form a valid pair."""
        try:
            # Check parts
            if not ((qr_a.qr_part == 'A' and qr_b.qr_part == 'B') or
                   (qr_a.qr_part == 'B' and qr_b.qr_part == 'A')):
                logger.error("QR parts don't form valid A/B pair")
                return False
            
            # Check session IDs match (everything before the _A/_B suffix)
            session_a = qr_a.qr_id.rsplit('_', 1)[0]
            session_b = qr_b.qr_id.rsplit('_', 1)[0]
            if session_a != session_b:
                logger.error("QR session IDs don't match")
                return False
            
            # Check device IDs
            if qr_a.device_id != self.device_id or qr_b.device_id != self.device_id:
                logger.error("Device ID mismatch")
                return False
            
            # Check expiry
            try:
                expires_a = datetime.fromisoformat(qr_a.expires_at)
                expires_b = datetime.fromisoformat(qr_b.expires_at)
                now = datetime.now()
                
                if now > expires_a or now > expires_b:
                    logger.error("QR codes have expired")
                    return False
                    
            except ValueError:
                logger.error("Invalid expiry date format")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"QR validation failed: {e}")
            return False
    
    def _generate_instructions(self, qr_a: QRRecoveryData, qr_b: QRRecoveryData) -> str:
        """Generate simple recovery instructions."""
        return f"""
QR Recovery Instructions
========================

Session ID: {qr_a.qr_id.rsplit('_', 1)[0]}
Created: {qr_a.created_at[:19]}
Expires: {qr_a.expires_at[:19]}

To recover your data:
1. Scan both QR codes (A and B)
2. Use the same device where QR codes were created
3. Run recovery process within expiry time

Note: Both QR codes are required for recovery.
Device binding: {qr_a.device_id[:16]}...
        """.strip()

