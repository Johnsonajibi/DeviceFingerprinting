"""
Secure Configuration Management for QuantumVault

This module provides secure configuration management with environment-based
settings and proper validation for commercial deployment.
"""

import os
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Union
from pathlib import Path


@dataclass
class CryptoConfig:
    """Cryptographic configuration parameters"""
    min_password_length: int = 30
    max_login_attempts: int = 3
    pbkdf2_iterations: int = 600000
    salt_length: int = 64
    lockout_duration: int = 300  # 5 minutes
    page_size_kb: float = 1.0
    kyber_key_size: int = 1568


@dataclass
class SecurityConfig:
    """Security policy configuration"""
    require_security_questions_with_token: bool = True
    min_security_questions_always: int = 2
    coercion_resistance_mode: bool = True
    duress_code_enabled: bool = True
    forward_secure_enabled: bool = True
    dynamic_page_sizing: bool = True
    epoch_increment_on_rotation: bool = True


@dataclass 
class BackupConfig:
    """Backup system configuration"""
    backup_count: int = 5
    emergency_delay_hours: int = 24
    backup_token_limit: int = 5
    recovery_code_count: int = 10
    qr_recovery_expiry_days: int = 365


@dataclass
class USBConfig:
    """USB token configuration"""
    usb_pin_length: int = 10
    usb_pin_max_attempts: int = 3


class SecureConfigManager:
    """
    Secure configuration manager with environment variable support
    and validation for commercial deployment
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else Path.cwd()
        self.crypto = self._load_crypto_config()
        self.security = self._load_security_config()
        self.backup = self._load_backup_config()
        self.usb = self._load_usb_config()
        
    def _load_crypto_config(self) -> CryptoConfig:
        """Load cryptographic configuration with environment overrides"""
        return CryptoConfig(
            min_password_length=int(os.getenv('QVAULT_MIN_PASSWORD_LENGTH', 30)),
            max_login_attempts=int(os.getenv('QVAULT_MAX_LOGIN_ATTEMPTS', 3)),
            pbkdf2_iterations=int(os.getenv('QVAULT_PBKDF2_ITERATIONS', 600000)),
            salt_length=int(os.getenv('QVAULT_SALT_LENGTH', 64)),
            lockout_duration=int(os.getenv('QVAULT_LOCKOUT_DURATION', 300)),
            page_size_kb=float(os.getenv('QVAULT_PAGE_SIZE_KB', 1.0)),
            kyber_key_size=int(os.getenv('QVAULT_KYBER_KEY_SIZE', 1568))
        )
    
    def _load_security_config(self) -> SecurityConfig:
        """Load security configuration with environment overrides"""
        return SecurityConfig(
            require_security_questions_with_token=os.getenv('QVAULT_REQUIRE_SECURITY_QUESTIONS', 'true').lower() == 'true',
            min_security_questions_always=int(os.getenv('QVAULT_MIN_SECURITY_QUESTIONS', 2)),
            coercion_resistance_mode=os.getenv('QVAULT_COERCION_RESISTANCE', 'true').lower() == 'true',
            duress_code_enabled=os.getenv('QVAULT_DURESS_CODE', 'true').lower() == 'true',
            forward_secure_enabled=os.getenv('QVAULT_FORWARD_SECURE', 'true').lower() == 'true',
            dynamic_page_sizing=os.getenv('QVAULT_DYNAMIC_PAGE_SIZING', 'true').lower() == 'true',
            epoch_increment_on_rotation=os.getenv('QVAULT_EPOCH_INCREMENT', 'true').lower() == 'true'
        )
    
    def _load_backup_config(self) -> BackupConfig:
        """Load backup configuration with environment overrides"""
        return BackupConfig(
            backup_count=int(os.getenv('QVAULT_BACKUP_COUNT', 5)),
            emergency_delay_hours=int(os.getenv('QVAULT_EMERGENCY_DELAY_HOURS', 24)),
            backup_token_limit=int(os.getenv('QVAULT_BACKUP_TOKEN_LIMIT', 5)),
            recovery_code_count=int(os.getenv('QVAULT_RECOVERY_CODE_COUNT', 10)),
            qr_recovery_expiry_days=int(os.getenv('QVAULT_QR_RECOVERY_EXPIRY_DAYS', 365))
        )
    
    def _load_usb_config(self) -> USBConfig:
        """Load USB configuration with environment overrides"""
        return USBConfig(
            usb_pin_length=int(os.getenv('QVAULT_USB_PIN_LENGTH', 10)),
            usb_pin_max_attempts=int(os.getenv('QVAULT_USB_PIN_MAX_ATTEMPTS', 3))
        )
    
    def get_file_paths(self) -> Dict[str, str]:
        """Get secure file paths based on environment and OS"""
        base_dir = Path(os.getenv('QVAULT_DATA_DIR', self.config_dir))
        
        # Ensure base directory exists and is secure
        base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        return {
            'vault_file': str(base_dir / 'vault.enc'),
            'info_file': str(base_dir / 'vault_info.json'),
            'archive_file': str(base_dir / 'vault_archive.json'),
            'token_file': str(base_dir / '.quantum_token'),
            'token_hash_file': str(base_dir / 'vault_token.hash'),
            'hash_file': str(base_dir / 'vault_master.hash'),
            'config_file': str(base_dir / 'vault_config.json'),
            'export_file': str(base_dir / 'vault_export.enc'),
            'security_questions_file': str(base_dir / 'vault_security_questions.enc'),
            'salt_file': str(base_dir / 'vault_salt.json'),
            'epoch_file': str(base_dir / 'vault_epoch.json'),
            'epoch_meta_file': str(base_dir / 'page_epochs.json'),
            'lockout_file': str(base_dir / '.vault_lockout'),
            'emergency_access_file': str(base_dir / '.vault_emergency_access'),
            'recovery_codes_file': str(base_dir / 'vault_recovery_codes.enc'),
            'qr_recovery_file': str(base_dir / 'secure_recovery.qr'),
            'qr_pin_file': str(base_dir / 'secure_pin_recovery.qr'),
            'qr_recovery_config': str(base_dir / 'qr_recovery_config.json'),
            'usb_pin_config': str(base_dir / 'usb_pin_config.enc'),
            'usb_signature_file': str(base_dir / '.quantum_vault_signature')
        }
    
    def get_backup_locations(self) -> Dict[str, List[str]]:
        """Get secure backup locations with proper permissions"""
        base_dir = Path(os.getenv('QVAULT_DATA_DIR', self.config_dir))
        backup_base = base_dir / '.backups'
        
        # Create backup directory with secure permissions
        backup_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        return {
            "primary": [str(backup_base / 'primary')],
            "secondary": [str(backup_base / 'secondary')],
            "tertiary": [str(backup_base / 'tertiary')]
        }
    
    def validate_configuration(self) -> List[str]:
        """Validate all configuration parameters"""
        errors = []
        
        # Validate crypto config
        if self.crypto.min_password_length < 12:
            errors.append("Minimum password length must be at least 12 characters")
        if self.crypto.pbkdf2_iterations < 100000:
            errors.append("PBKDF2 iterations must be at least 100,000 for security")
        if self.crypto.salt_length < 32:
            errors.append("Salt length must be at least 32 bytes")
        
        # Validate security config
        if self.security.min_security_questions_always < 1:
            errors.append("Must require at least 1 security question")
        
        # Validate backup config
        if self.backup.backup_count < 1:
            errors.append("Must keep at least 1 backup")
        if self.backup.recovery_code_count < 5:
            errors.append("Must generate at least 5 recovery codes")
            
        # Validate USB config
        if self.usb.usb_pin_length < 6:
            errors.append("USB PIN must be at least 6 digits")
        if self.usb.usb_pin_max_attempts < 1:
            errors.append("Must allow at least 1 USB PIN attempt")
            
        return errors
    
    def save_config_file(self, config_path: Optional[str] = None) -> bool:
        """Save current configuration to file"""
        try:
            config_file = Path(config_path) if config_path else self.config_dir / 'qvault_config.json'
            
            config_data = {
                'crypto': {
                    'min_password_length': self.crypto.min_password_length,
                    'max_login_attempts': self.crypto.max_login_attempts,
                    'pbkdf2_iterations': self.crypto.pbkdf2_iterations,
                    'salt_length': self.crypto.salt_length,
                    'lockout_duration': self.crypto.lockout_duration,
                    'page_size_kb': self.crypto.page_size_kb,
                    'kyber_key_size': self.crypto.kyber_key_size
                },
                'security': {
                    'require_security_questions_with_token': self.security.require_security_questions_with_token,
                    'min_security_questions_always': self.security.min_security_questions_always,
                    'coercion_resistance_mode': self.security.coercion_resistance_mode,
                    'duress_code_enabled': self.security.duress_code_enabled,
                    'forward_secure_enabled': self.security.forward_secure_enabled,
                    'dynamic_page_sizing': self.security.dynamic_page_sizing,
                    'epoch_increment_on_rotation': self.security.epoch_increment_on_rotation
                },
                'backup': {
                    'backup_count': self.backup.backup_count,
                    'emergency_delay_hours': self.backup.emergency_delay_hours,
                    'backup_token_limit': self.backup.backup_token_limit,
                    'recovery_code_count': self.backup.recovery_code_count,
                    'qr_recovery_expiry_days': self.backup.qr_recovery_expiry_days
                },
                'usb': {
                    'usb_pin_length': self.usb.usb_pin_length,
                    'usb_pin_max_attempts': self.usb.usb_pin_max_attempts
                }
            }
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
            
            # Set secure permissions
            config_file.chmod(0o600)
            return True
            
        except Exception:
            return False


# Create global configuration instance
config_manager = SecureConfigManager()

# Validate configuration on import
validation_errors = config_manager.validate_configuration()
if validation_errors:
    import sys
    print("Configuration validation errors:", file=sys.stderr)
    for error in validation_errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

# Export commonly used configurations
CRYPTO_CONFIG = config_manager.crypto
SECURITY_CONFIG = config_manager.security  
BACKUP_CONFIG = config_manager.backup
USB_CONFIG = config_manager.usb
FILE_PATHS = config_manager.get_file_paths()
BACKUP_LOCATIONS = config_manager.get_backup_locations()
