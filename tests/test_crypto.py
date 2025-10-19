import unittest
import os

from device_fingerprinting.crypto import AESGCMEncryptor, ScryptKDF


class TestCrypto(unittest.TestCase):

    def setUp(self):
        """Set up test variables."""
        self.password = "test_password"
        self.data = b"some secret data to be encrypted"
        self.encryptor = AESGCMEncryptor(key_size=32, nonce_size=12)
        self.kdf = ScryptKDF(salt_size=16, n=2**14, r=8, p=1, key_size=32)

    def test_scrypt_kdf_derivation(self):
        """Test that the Scrypt KDF derives a key of the correct length."""
        salt = os.urandom(16)
        key = self.kdf.derive_key(self.password, salt)
        self.assertEqual(len(key), 32)

        # Test that the same password and salt produce the same key
        key2 = self.kdf.derive_key(self.password, salt)
        self.assertEqual(key, key2)

        # Test that a different salt produces a different key
        salt2 = os.urandom(16)
        key3 = self.kdf.derive_key(self.password, salt2)
        self.assertNotEqual(key, key3)

    def test_aesgcm_encryption_decryption_cycle(self):
        """Test a full encryption and decryption cycle."""
        key = os.urandom(32)
        encrypted_blob = self.encryptor.encrypt(self.data, key)

        # The blob should contain nonce + ciphertext + tag
        self.assertGreater(len(encrypted_blob), len(self.data))

        decrypted_data = self.encryptor.decrypt(encrypted_blob, key)
        self.assertEqual(self.data, decrypted_data)

    def test_decryption_with_wrong_key(self):
        """Test that decryption fails with an incorrect key."""
        key1 = os.urandom(32)
        wrong_key = os.urandom(32)

        encrypted_blob = self.encryptor.encrypt(self.data, key1)

        with self.assertRaises(ValueError, msg="Decryption should fail with wrong key"):
            self.encryptor.decrypt(encrypted_blob, wrong_key)

    def test_decryption_with_tampered_data(self):
        """Test that decryption fails if the ciphertext is tampered with."""
        key = os.urandom(32)
        encrypted_blob = self.encryptor.encrypt(self.data, key)

        # Tamper with the ciphertext (flip a bit)
        tampered_blob = bytearray(encrypted_blob)
        tampered_blob[-5] ^= 1  # Tamper with the tag part

        with self.assertRaises(ValueError, msg="Decryption should fail with tampered data"):
            self.encryptor.decrypt(bytes(tampered_blob), key)

    def test_end_to_end_with_kdf(self):
        """Test the full cycle using a derived key."""
        salt = os.urandom(16)
        derived_key = self.kdf.derive_key(self.password, salt)

        # We need a new encryptor instance if we want to use a different key size
        # but here we use the same size, so it's fine.

        # The key for AES must be the correct size
        self.assertEqual(len(derived_key), self.encryptor.key_size)

        encrypted_blob = self.encryptor.encrypt(self.data, derived_key)
        decrypted_data = self.encryptor.decrypt(encrypted_blob, derived_key)

        self.assertEqual(self.data, decrypted_data)


if __name__ == "__main__":
    unittest.main()
