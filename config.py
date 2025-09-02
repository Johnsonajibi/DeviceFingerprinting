"""
Configuration constants for QuantumVault Password Manager

This module contains all configuration constants, file paths, and settings
used throughout the application. Centralizing configuration makes the code
more maintainable and follows commercial best practices.
"""

# Application metadata
APPLICATION_NAME = "QuantumVault"
APPLICATION_VERSION = "1.0.0"
CRYPTO_VERSION = "SHA3-512-Enhanced"

# File names for storing data
VAULT_FILE = "vault.enc"
INFO_FILE = "vault_info.json"
ARCHIVE_FILE = "vault_archive.json"
TOKEN_FILE = ".quantum_token"
TOKEN_HASH_FILE = "vault_token.hash"
HASH_FILE = "vault_master.hash"
CONFIG_FILE = "vault_config.json"
EXPORT_FILE = "vault_export.enc"
SECURITY_QUESTIONS_FILE = "vault_security_questions.enc"
SALT_FILE = "vault_salt.json"

# Security settings
MIN_PASSWORD_LENGTH = 30
MAX_LOGIN_ATTEMPTS = 3
PBKDF2_ITERATIONS = 600000  # High iteration count for security
SALT_LENGTH = 64
LOCKOUT_DURATION = 300  # 5 minutes

# Backup settings
BACKUP_DIR = ".system_cache"
BACKUP_COUNT = 5

# Page encryption settings
PAGE_SIZE_KB = 1
DYNAMIC_PAGE_SIZING = True
FORWARD_SECURE_ENABLED = True
KYBER_KEY_SIZE = 1568  # bytes
EPOCH_INCREMENT_ON_ROTATION = True

# Emergency access settings
EMERGENCY_DELAY_HOURS = 24
BACKUP_TOKEN_LIMIT = 5
RECOVERY_CODE_COUNT = 10

# Authentication settings
REQUIRE_SECURITY_QUESTIONS_WITH_TOKEN = True
MIN_SECURITY_QUESTIONS_ALWAYS = 2
COERCION_RESISTANCE_MODE = True  # Enable resistance to coercion attacks
DURESS_CODE_ENABLED = True  # Enable duress code functionality

# PIN settings
USB_PIN_LENGTH = 10
USB_PIN_MAX_ATTEMPTS = 3
USB_SIGNATURE_FILE = ".quantum_vault_signature"

# QR recovery system settings
QR_RECOVERY_FILE = "secure_recovery.qr"
QR_PIN_FILE = "secure_pin_recovery.qr"
QR_RECOVERY_CONFIG = "qr_recovery_config.json"
USB_PIN_CONFIG = "usb_pin_config.enc"
QR_RECOVERY_EXPIRY_DAYS = 365

# File system paths and locations
EPOCH_FILE = "vault_epoch.json"
EPOCH_META_FILE = "page_epochs.json"
LOCKOUT_FILE = ".vault_lockout"
EMERGENCY_ACCESS_FILE = ".vault_emergency_access"
RECOVERY_CODES_FILE = "vault_recovery_codes.enc"

# Page size thresholds for dynamic sizing
PAGE_SIZE_THRESHOLDS = {
    "small_vault": {"max_passwords": 50, "page_size_kb": 0.5},
    "medium_vault": {"max_passwords": 200, "page_size_kb": 1},
    "large_vault": {"max_passwords": 500, "page_size_kb": 2},
    "xlarge_vault": {"max_passwords": float('inf'), "page_size_kb": 4}
}

# Backup location configurations
BACKUP_LOCATIONS = {
    "primary": ".system_cache",
    "secondary": ".config/app_data",
    "windows_system": "microsoft_temp/cache",
    "unix_temp": ".tmp_session"
}

BACKUP_FILE_PATTERNS = {
    "prefix": "sys_",
    "suffix": ".cache",
    "timestamp_format": "%Y%m%d%H%M%S"
}

# Security questions for multi-factor authentication
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "In what city were you born?",
    "What was your childhood nickname?",
    "What is the name of your favorite childhood friend?",
    "What was the name of your first school?",
    "What is your mother's maiden name?",
    "What was the make of your first car?",
    "What is the name of the town where you were born?",
    "What was your favorite food as a child?",
    "What is the name of your favorite teacher?",
    "What street did you grow up on?",
    "What was the name of your first stuffed animal?",
    "What is your father's middle name?",
    "What was your favorite book as a child?",
    "What is the name of the hospital where you were born?"
]
