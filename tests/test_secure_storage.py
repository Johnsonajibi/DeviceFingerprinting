import unittest
import os
from unittest.mock import patch, MagicMock

from device_fingerprinting.secure_storage import SecureStorage


class TestSecureStorage(unittest.TestCase):

    def setUp(self):
        """Set up a test file and password for the secure storage."""
        self.test_file = "test_secure_store.bin"
        self.password = "a_strong_password_for_testing"
        # Ensure the file does not exist before each test
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def tearDown(self):
        """Clean up the test file after each test."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_initialization_creates_empty_store(self):
        """Test that initializing SecureStorage without a file creates an empty store."""
        with SecureStorage(self.test_file, self.password) as store:
            self.assertEqual(store.list_keys(), [])
        # The file should be created upon initialization.
        self.assertTrue(os.path.exists(self.test_file))
        # An empty store is not a zero-byte file, as it contains the encrypted structure.
        self.assertGreater(os.path.getsize(self.test_file), 0)

    def test_set_and_get_item(self):
        """Test setting and retrieving a single item."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("my_key", "my_value")
            retrieved_value = store.get_item("my_key")
            self.assertEqual(retrieved_value, "my_value")

    def test_store_is_encrypted(self):
        """Test that the stored file content is not plaintext."""
        test_data = {"secret": "this should not be readable"}
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("test_data", test_data)

        with open(self.test_file, "rb") as f:
            file_content = f.read()

        self.assertNotIn(b"this should not be readable", file_content)
        # Check for structure: salt + nonce + ciphertext
        self.assertGreater(len(file_content), 16 + 12)

    def test_loading_with_correct_password(self):
        """Test that data can be retrieved after saving and reloading."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("persistent_key", "persistent_value")

        # Create a new instance to force reloading from file
        with SecureStorage(self.test_file, self.password) as reloaded_store:
            value = reloaded_store.get_item("persistent_key")
            self.assertEqual(value, "persistent_value")

    def test_loading_with_incorrect_password_raises_error(self):
        """Test that loading with a wrong password raises an IOError."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("some_key", "some_value")

        with self.assertRaises(IOError, msg="Should fail with incorrect password"):
            with SecureStorage(self.test_file, "wrong_password") as store:
                # This code should not be reached
                pass

    def test_delete_item(self):
        """Test deleting an item from the store."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("to_delete", "this will be removed")
            self.assertIn("to_delete", store.list_keys())

            deleted = store.delete_item("to_delete")
            self.assertTrue(deleted)
            self.assertNotIn("to_delete", store.list_keys())

        # Verify deletion persists after reloading
        with SecureStorage(self.test_file, self.password) as reloaded_store:
            self.assertIsNone(reloaded_store.get_item("to_delete"))

    def test_get_item_with_default(self):
        """Test the default value functionality of get_item."""
        with SecureStorage(self.test_file, self.password) as store:
            value = store.get_item("non_existent_key", "default_val")
            self.assertEqual(value, "default_val")

            # Ensure it returns None by default if no default is provided
            self.assertIsNone(store.get_item("non_existent_key"))

    def test_context_manager_saves_on_exit(self):
        """Test that the context manager automatically saves changes."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("auto_saved", "data")

        # Re-open and check if data is there
        with SecureStorage(self.test_file, self.password) as reloaded_store:
            self.assertEqual(reloaded_store.get_item("auto_saved"), "data")

    def test_different_salts_for_new_files(self):
        """Test that different files get different random salts."""
        test_file1 = "test_salt_1.bin"
        test_file2 = "test_salt_2.bin"
        
        try:
            # Create two separate storage files with same password
            with SecureStorage(test_file1, self.password) as store1:
                store1.set_item("key", "value")
            
            with SecureStorage(test_file2, self.password) as store2:
                store2.set_item("key", "value")
            
            # Read the first 16 bytes (salt) from each file
            with open(test_file1, "rb") as f:
                salt1 = f.read(16)
            
            with open(test_file2, "rb") as f:
                salt2 = f.read(16)
            
            # Salts should be different
            self.assertNotEqual(salt1, salt2)
            self.assertEqual(len(salt1), 16)
            self.assertEqual(len(salt2), 16)
        finally:
            if os.path.exists(test_file1):
                os.remove(test_file1)
            if os.path.exists(test_file2):
                os.remove(test_file2)

    def test_same_password_different_salts_produces_different_keys(self):
        """Test that same password with different salts produces different encryption results."""
        test_file1 = "test_key_1.bin"
        test_file2 = "test_key_2.bin"
        
        try:
            # Create two storage files with same password and same data
            with SecureStorage(test_file1, self.password) as store1:
                store1.set_item("test", "same_data")
            
            with SecureStorage(test_file2, self.password) as store2:
                store2.set_item("test", "same_data")
            
            # Read the encrypted content (after the salt)
            with open(test_file1, "rb") as f:
                f.seek(16)  # Skip salt
                encrypted1 = f.read()
            
            with open(test_file2, "rb") as f:
                f.seek(16)  # Skip salt
                encrypted2 = f.read()
            
            # Encrypted content should be different due to different salts
            self.assertNotEqual(encrypted1, encrypted2)
        finally:
            if os.path.exists(test_file1):
                os.remove(test_file1)
            if os.path.exists(test_file2):
                os.remove(test_file2)

    def test_salt_persists_across_save_load_cycles(self):
        """Test that salt is stored and correctly loaded from file."""
        # Create and save data
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("persistent", "data")
        
        # Read the salt from file
        with open(self.test_file, "rb") as f:
            original_salt = f.read(16)
        
        # Load the file again and save without changes
        with SecureStorage(self.test_file, self.password) as store:
            # Access data to ensure it loaded correctly
            self.assertEqual(store.get_item("persistent"), "data")
            # Add new data
            store.set_item("more", "data")
        
        # Read the salt again - should be the same
        with open(self.test_file, "rb") as f:
            new_salt = f.read(16)
        
        self.assertEqual(original_salt, new_salt)
        
        # Verify data is still accessible
        with SecureStorage(self.test_file, self.password) as store:
            self.assertEqual(store.get_item("persistent"), "data")
            self.assertEqual(store.get_item("more"), "data")

    def test_salt_is_random_not_hardcoded(self):
        """Test that salt is not the hardcoded all-zero value."""
        with SecureStorage(self.test_file, self.password) as store:
            store.set_item("test", "value")
        
        with open(self.test_file, "rb") as f:
            salt = f.read(16)
        
        # Salt should NOT be all zeros
        hardcoded_salt = b"\\x00" * 16
        self.assertNotEqual(salt, hardcoded_salt)
        
        # Salt should have some randomness (very unlikely to have all same bytes)
        # This is a probabilistic test, but with 16 random bytes, 
        # having all same is virtually impossible
        unique_bytes = len(set(salt))
        self.assertGreater(unique_bytes, 1)


if __name__ == "__main__":
    unittest.main()
