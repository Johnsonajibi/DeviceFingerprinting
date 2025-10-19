"""
Test suite for Device Fingerprinting Library
"""

import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any
import pytest
import base64

from device_fingerprinting import (
    generate_fingerprint,
    create_device_binding,
    verify_device_binding,
    DeviceFingerprintGenerator,
    AdvancedDeviceFingerprinter,
    FingerprintMethod,
    FingerprintResult,
    bind_token_to_device,
    reset_device_id,
    set_crypto_backend,
    set_storage_backend,
    set_security_check,
    enable_post_quantum_crypto,
    disable_post_quantum_crypto,
    get_crypto_info,
    get_available_crypto_backends,
    enable_anti_replay_protection,
    create_server_nonce,
    verify_server_nonce,
)


class TestDeviceFingerprintGenerator(unittest.TestCase):
    """Test basic device fingerprint generator"""

    def setUp(self) -> None:
        self.generator = DeviceFingerprintGenerator()

    def test_generate_fingerprint(self) -> None:
        """Test basic fingerprint generation"""
        result = self.generator.generate()
        self.assertIsInstance(result, FingerprintResult)
        self.assertIsInstance(result.fingerprint, str)
        self.assertGreater(len(result.fingerprint), 0)

    @patch("time.time", return_value=1234567890)
    def test_fingerprint_consistency(self, mock_time: MagicMock) -> None:
        """Test that fingerprint is consistent across calls"""
        fp1 = self.generator.generate().fingerprint
        fp2 = self.generator.generate().fingerprint
        self.assertEqual(fp1, fp2)

    def test_static_method(self) -> None:
        """Test static method access"""
        with self.assertRaises(TypeError):
            DeviceFingerprintGenerator.generate()


class TestAdvancedDeviceFingerprinter(unittest.TestCase):
    """Test advanced device fingerprinter"""

    def setUp(self) -> None:
        self.fingerprinter = AdvancedDeviceFingerprinter()

    def test_basic_method(self) -> None:
        """Test basic fingerprinting method"""
        result: FingerprintResult = self.fingerprinter.generate(FingerprintMethod.BASIC)
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.method, FingerprintMethod.BASIC.value)

    def test_advanced_method(self) -> None:
        """Test advanced fingerprinting method"""
        result: FingerprintResult = self.fingerprinter.generate(FingerprintMethod.ADVANCED)
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.method, FingerprintMethod.ADVANCED.value)

    def test_quantum_resistant_method(self) -> None:
        """Test quantum-resistant fingerprinting method"""
        result: FingerprintResult = self.fingerprinter.generate(FingerprintMethod.QUANTUM_RESISTANT)
        self.assertIsInstance(result, FingerprintResult)
        self.assertEqual(result.method, FingerprintMethod.QUANTUM_RESISTANT.value)

    def test_default_method(self) -> None:
        """Test default method is quantum resistant"""
        result: FingerprintResult = self.fingerprinter.generate()
        self.assertEqual(result.method, FingerprintMethod.QUANTUM_RESISTANT.value)

    def test_fingerprint_stability(self) -> None:
        """Test fingerprint stability verification"""
        result: FingerprintResult = self.fingerprinter.generate(FingerprintMethod.QUANTUM_RESISTANT)
        self.assertTrue(
            self.fingerprinter.verify_fingerprint(
                result.fingerprint, FingerprintMethod.QUANTUM_RESISTANT
            )
        )

    def test_fingerprint_components(self) -> None:
        """Test that fingerprint includes hardware components"""
        result: FingerprintResult = self.fingerprinter.generate(FingerprintMethod.ADVANCED)
        self.assertIn("cpu_model", result.components)
        self.assertIn("mac_hash", result.components)


class TestLegacyFunctions(unittest.TestCase):
    """Test suite for legacy functions to ensure backward compatibility."""

    def setUp(self) -> None:
        """Set up for legacy tests."""
        # PQC is enabled by the fixture for the relevant tests
        pass

    @pytest.mark.usefixtures("enable_pqc")
    def test_verify_device_binding_success(self) -> None:
        """Test successful device binding verification using the new API."""
        original_token: Dict[str, str] = {"user": "test", "data": "secret"}
        bound_token: Dict[str, Any] = create_device_binding(original_token)
        # Should verify successfully on the same device
        is_valid, _ = verify_device_binding(bound_token, strict_mode=False)
        self.assertTrue(is_valid)

    def test_verify_device_binding_no_binding(self) -> None:
        """Test verification of token without binding"""
        token_without_binding: Dict[str, str] = {"user": "test", "data": "secret"}

        # Should allow tokens without binding (backward compatibility)
        is_valid, _ = verify_device_binding(token_without_binding, strict_mode=False)
        self.assertTrue(is_valid)

    def test_verify_device_binding_wrong_fingerprint(self) -> None:
        """Test verification with wrong fingerprint"""
        # Create a valid token first
        original_token: Dict[str, str] = {"user": "test", "data": "secret"}
        bound_token: Dict[str, Any] = create_device_binding(original_token)

        # Now, tamper with the fingerprint. It must be a valid base64 string.
        tampered_fingerprint = base64.b64encode(
            b"tampered_fingerprint_value_that_is_long_enough"
        ).decode("utf-8")
        bound_token["device_binding"]["fingerprint"] = tampered_fingerprint

        # Should fail verification
        is_valid, details = verify_device_binding(bound_token, strict_mode=False)
        self.assertFalse(is_valid)
        self.assertIn("Internal fingerprint signature is invalid", details["reason"])

    @pytest.mark.usefixtures("enable_pqc")
    def test_bind_token_to_device(self) -> None:
        """Test token binding to device using the new API."""
        original_token: Dict[str, Any] = {
            "user_id": "test_user",
            "permissions": ["read", "write"],
            "data": "secret_data",
        }

        bound_token: Dict[str, Any] = create_device_binding(original_token)
        # Should have original data
        self.assertEqual(bound_token["user_id"], "test_user")
        self.assertEqual(bound_token["permissions"], ["read", "write"])
        self.assertEqual(bound_token["data"], "secret_data")

        # Should have binding data
        self.assertIn("device_binding", bound_token)
        self.assertIn("fingerprint_signature", bound_token["device_binding"])

        # Verification should pass
        is_valid, _ = verify_device_binding(bound_token, strict_mode=False)
        self.assertTrue(is_valid)

    @pytest.mark.usefixtures("enable_pqc")
    def test_bind_empty_token(self) -> None:
        """Test binding empty token using the new API."""
        empty_token: Dict[str, Any] = {}
        bound_token: Dict[str, Any] = create_device_binding(empty_token)
        # Should still add binding data
        self.assertIn("device_binding", bound_token)
        self.assertIn("fingerprint_signature", bound_token["device_binding"])

        # Verification should pass
        is_valid, _ = verify_device_binding(bound_token, strict_mode=False)
        self.assertTrue(is_valid)
