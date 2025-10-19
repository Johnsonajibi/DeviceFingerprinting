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
        
        with open(self.test_file, 'rb') as f:
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

if __name__ == '__main__':
    unittest.main()
