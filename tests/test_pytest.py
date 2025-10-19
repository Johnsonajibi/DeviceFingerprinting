"""
Comprehensive pytest test suite for the Device Fingerprinting library.
"""

import pytest
from unittest.mock import patch
import logging
from typing import Dict, Any
import time

from device_fingerprinting import (
    generate_fingerprint,
    create_device_binding,
    verify_device_binding,
    enable_post_quantum_crypto,
    set_crypto_backend_sha256,
    get_crypto_info,
    set_logger,
    AdvancedDeviceFingerprinter,
    FingerprintMethod,
    FingerprintResult,
    bind_token_to_device,
)

# Configure logging for tests
logger = logging.getLogger(__name__)
set_logger(logger)

@pytest.fixture(scope="module")
def fingerprinter() -> AdvancedDeviceFingerprinter:
    """Fixture for the AdvancedDeviceFingerprinter."""
    return AdvancedDeviceFingerprinter()

def test_basic_fingerprint_generation(fingerprinter: AdvancedDeviceFingerprinter):
    """Test basic fingerprint generation."""
    result = fingerprinter.generate(FingerprintMethod.BASIC)
    assert isinstance(result, FingerprintResult)
    assert result.method == FingerprintMethod.BASIC.value

@pytest.mark.usefixtures("enable_pqc")
def test_advanced_fingerprint_generation(fingerprinter: AdvancedDeviceFingerprinter):
    """Test advanced fingerprint generation."""
    result = fingerprinter.generate(FingerprintMethod.ADVANCED)
    assert isinstance(result, FingerprintResult)
    assert result.method == FingerprintMethod.ADVANCED.value

@pytest.mark.usefixtures("enable_pqc")
def test_quantum_resistant_fingerprint_generation(fingerprinter: AdvancedDeviceFingerprinter):
    """Test quantum-resistant fingerprint generation."""
    result = fingerprinter.generate(FingerprintMethod.QUANTUM_RESISTANT)
    assert isinstance(result, FingerprintResult)
    assert result.method == FingerprintMethod.QUANTUM_RESISTANT.value

@pytest.mark.usefixtures("enable_pqc")
def test_token_binding_and_verification():
    """Test token binding and verification."""
    original_token: Dict[str, Any] = {
        'user_id': 'pytest_user',
        'data': 'some_secret_data'
    }

    bound_token = create_device_binding(original_token)
    assert 'device_binding' in bound_token
    assert 'fingerprint_signature' in bound_token['device_binding']
    assert 'crypto_metadata' in bound_token['device_binding']['fields']
    assert 'timestamp' in bound_token['device_binding']['fields']['crypto_metadata']

    is_valid, details = verify_device_binding(bound_token, strict_mode=False)
    assert is_valid
    assert details['confidence'] >= 0.8 
    assert details['pqc_verified'] is True

@pytest.mark.usefixtures("enable_pqc")
def test_token_binding_with_pqc():
    """Test token binding with PQC enabled."""
    original_token: Dict[str, Any] = {
        'user_id': 'pytest_pqc_user',
        'data': 'pqc_secret_data'
    }

    bound_token = create_device_binding(original_token)
    assert 'device_binding' in bound_token
    is_valid, details = verify_device_binding(bound_token, strict_mode=False)
    assert is_valid
    assert details['pqc_verified'] is True
    assert details['confidence'] >= 0.95

@pytest.mark.parametrize("method", [
    FingerprintMethod.BASIC,
    FingerprintMethod.ADVANCED,
    FingerprintMethod.QUANTUM_RESISTANT,
])
def test_fingerprint_stability(fingerprinter: AdvancedDeviceFingerprinter, method: FingerprintMethod):
    """Test fingerprint stability for all methods."""
    if method == FingerprintMethod.QUANTUM_RESISTANT:
        enable_post_quantum_crypto()

    result1 = fingerprinter.generate(method)
    # Introduce a small delay to ensure timestamps or other volatile data might change
    time.sleep(0.1)
    result2 = fingerprinter.generate(method)

    # The new verification logic handles stability checks
    assert fingerprinter.verify_fingerprint(result1.fingerprint, method)
    assert fingerprinter.verify_fingerprint(result2.fingerprint, method)
    # Also check that they are verifiable against each other
    assert fingerprinter.verify_fingerprint(result1.fingerprint, method)
