import unittest
import json
import hashlib
import platform
from unittest.mock import patch

from device_fingerprinting.production_fingerprint import ProductionFingerprintGenerator


class TestProductionFingerprintGenerator(unittest.TestCase):

    def setUp(self):
        """Set up the fingerprint generator for tests."""
        self.generator = ProductionFingerprintGenerator()

    def test_initialization(self):
        """Test that the generator initializes correctly."""
        self.assertIsNotNone(self.generator)

    def test_sha3_512_hashing(self):
        """Test the SHA3-512 hashing helper."""
        data = b"test data for hashing"
        expected_hash = hashlib.sha3_512(data).hexdigest()
        actual_hash = self.generator._hash_sha3_512(data)
        self.assertEqual(actual_hash, expected_hash)

    def test_get_cpu_features(self):
        """Test that CPU/processor identification is returned."""
        features = self.generator._get_cpu_features()
        self.assertEqual(features, platform.processor())

    def test_generate_fingerprint_structure(self):
        """Test the structure and types of the generated fingerprint."""
        fingerprint_dict = self.generator.generate_fingerprint()

        # Check top-level keys
        self.assertIn("system_info", fingerprint_dict)
        self.assertIn("hardware_info", fingerprint_dict)
        self.assertIn("software_info", fingerprint_dict)
        self.assertIn("security_info", fingerprint_dict)
        self.assertIn("fingerprint_hash", fingerprint_dict)

        # Check some nested keys and types
        self.assertIsInstance(fingerprint_dict["system_info"]["platform"], str)
        self.assertIsInstance(fingerprint_dict["hardware_info"]["cpu_cores"], int)
        self.assertIsInstance(fingerprint_dict["hardware_info"]["ram_total_gb"], float)
        self.assertIsInstance(fingerprint_dict["security_info"]["is_admin"], bool)

        # Check that the final hash is a valid SHA3-512 hash string
        self.assertIsInstance(fingerprint_dict["fingerprint_hash"], str)
        self.assertEqual(len(fingerprint_dict["fingerprint_hash"]), 128)

    def test_fingerprint_is_deterministic(self):
        """Test that generating a fingerprint twice yields the same result."""
        # We need to patch sources of non-determinism like boot time and MAC address
        with (
            patch("psutil.boot_time", return_value=1234567890.0),
            patch("uuid.getnode", return_value=123456789012345),
        ):

            generator = ProductionFingerprintGenerator()
            fingerprint1 = generator.generate_fingerprint()
            fingerprint2 = generator.generate_fingerprint()

            # The dictionaries should be identical
            self.assertDictEqual(fingerprint1, fingerprint2)

            # The final hashes must be the same
            self.assertEqual(fingerprint1["fingerprint_hash"], fingerprint2["fingerprint_hash"])

    def test_json_serialization(self):
        """Test that the fingerprint dictionary can be serialized to JSON."""
        fingerprint_dict = self.generator.generate_fingerprint()
        try:
            json_output = json.dumps(fingerprint_dict)
            self.assertIsInstance(json_output, str)
        except TypeError:
            self.fail("Generated fingerprint dictionary is not JSON serializable.")


if __name__ == "__main__":
    unittest.main()
