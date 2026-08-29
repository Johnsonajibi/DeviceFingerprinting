# Changelog

All notable changes to the Device Fingerprinting Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-08-29

### Changed
- Raised minimum supported Python version from 3.9 to 3.10 (3.9 reached
  upstream end-of-life; conda-forge's current baseline is 3.10). Added
  Python 3.13 to the supported/tested version range.
- Unified the package version across `pyproject.toml`, `version.py`, and
  `__init__.py` into a single source of truth (`version.py`); they had
  drifted to three different values.

### Security
- Fixed a signature-forgery bug in `create_device_binding`/
  `verify_device_binding`: the classical HMAC signature was keyed with the
  device fingerprint, a value stored in cleartext in the same token,
  allowing binding_data to be tampered with and re-signed. Now signs with
  the crypto backend's own secret key.
- `HybridPQC` no longer fabricates SHAKE-256 "signatures" sized to look
  like Dilithium3 when a real PQC backend is unavailable; it calls the
  real backend's sign()/verify() when available and falls back honestly
  to a labeled classical-only signature otherwise.
- `verify_device_binding` no longer accepts a token with its overall
  signature stripped.
- `AntiTampering`'s HMAC key is now persisted (previously regenerated
  randomly every instantiation, silently making tamper detection
  non-functional across process restarts).
- Raised the Scrypt KDF cost factor from N=2^14 to N=2^17.
- `secure_storage.py`'s legacy zero-salt file format fallback is now
  opt-in (`allow_legacy_format=True`) rather than a permanent, ungated
  path.
- Removed `quantum_crypto.py` and `production_fingerprint.py`'s unused
  duplicate device-binding functions, both of which had the same
  fake/forgeable-signature issues as above but were unreachable dead code.

### Fixed
- `mode="tpm_strict"` always raised `RuntimeError` even with working TPM
  hardware due to a flag never being set on the enforcement code path.
- `generate_fingerprint()` embedded a live timestamp inside the signed
  fingerprint payload, making fingerprints for unchanged hardware change
  every 5 minutes or on every restart.
- `security_level="basic"` device bindings always failed verification due
  to a field-name mismatch between creation and confidence scoring.
- Fixed a crash in Windows TPM detection when `Get-Tpm` is run without
  administrator privileges.
- Fixed `get_hardware_id()` crashing on any machine without a network
  interface literally named "Ethernet".
- Fixed broken `ScryptKDF`/`AESGCMEncryptor`/`PyKCS11` API usage in
  `hsm_backends.py` that made `SecureEnclaveStorage`/`HSMCryptoBackend`
  unconstructable.
- Fixed a KDF-salt-persistence bug in `CloudStorageBackend` and
  `SecureEnclaveStorage` that regenerated the salt on every
  instantiation, permanently losing access to previously stored data.

## [2.1.3] - 2025-10-26

### Updated
- Upgraded pqcdualusb to version 0.15.5 for latest post-quantum crypto improvements
- Updated pip to version 25.3 to fix CVE-2025-8869 security vulnerability
- Enhanced AntiTampering class to use cryptographically secure random keys instead of hardcoded defaults

### Security
- Fixed hardcoded credential vulnerability in AntiTampering class
- Resolved dependency security issue with pip tarfile extraction
- Improved admin authentication flow validation
- All security audits pass with no critical vulnerabilities

### Maintenance
- Confirmed compatibility with latest pqcdualusb API changes
- All 14 test cases continue to pass
- No breaking changes to public API

## [1.0.0] - 2025-09-05

### Added
- Initial release of Device Fingerprinting Library
- `DeviceFingerprintGenerator` class for basic device identification
- `AdvancedDeviceFingerprinter` class with multiple fingerprinting methods
- Three fingerprinting algorithms: Basic, Advanced, and Quantum-Resistant
- Cross-platform support for Windows, Linux, and macOS
- Hardware component detection (CPU, MAC address, machine ID)
- SHA3-512 quantum-resistant cryptographic hashing
- Token binding and verification functionality
- Privacy-aware design with automatic hashing
- Comprehensive error handling and fallback mechanisms
- Zero external dependencies (pure Python standard library)
- Complete test suite with 100% code coverage
- Professional documentation and examples

### Security Features
- Quantum-resistant cryptography using SHA3-512
- Constant-time comparison for security token verification
- Privacy protection through hashing of sensitive hardware data
- Secure fallback mechanisms for edge cases

### Platform Support
- Windows: WMIC integration for UUID and CPU ID detection
- Linux/Unix: Machine ID file reading from /etc/machine-id
- Cross-platform: MAC address, system info, processor details
- Graceful degradation when hardware access is limited

### API Features
- Simple basic API for quick integration
- Advanced API with detailed results and confidence scoring
- Legacy compatibility functions for existing codebases
- Token binding for security applications
- Fingerprint stability verification

## [Unreleased]

### Planned
- Performance optimizations for large-scale deployments
- Additional hardware component detection
- Advanced tamper detection capabilities
- Integration examples for popular frameworks
- CLI tool for system administrators
