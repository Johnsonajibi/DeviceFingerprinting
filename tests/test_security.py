import unittest
import os
import platform
import getpass
from unittest.mock import patch, MagicMock
import logging
import json

from device_fingerprinting.security import (
    SystemIntegrityChecker,
    EnvironmentValidator,
    AntiTampering,
    SecurityAuditor,
)

# Configure a logger for the auditor to use
auditor_logger = logging.getLogger("TestAuditor")
auditor_logger.setLevel(logging.WARNING)


class TestSecurityModules(unittest.TestCase):

    def setUp(self):
        """Set up common resources for tests."""
        self.test_file_path = "test_file.txt"
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file.")

        self.integrity_checker = SystemIntegrityChecker()
        self.env_validator = EnvironmentValidator()
        self.anti_tampering = AntiTampering(self.test_file_path)
        # Pass the logger to the auditor
        self.auditor = SecurityAuditor(logger=auditor_logger)

    def tearDown(self):
        """Clean up created files."""
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.test_file_path + ".mac"):
            os.remove(self.test_file_path + ".mac")

    # --- SystemIntegrityChecker Tests ---
    def test_integrity_checker_get_os_details(self):
        """Test that OS details are retrieved correctly."""
        os_details = self.integrity_checker.get_os_details()
        self.assertEqual(os_details["os_type"], platform.system())
        self.assertEqual(os_details["os_release"], platform.release())
        self.assertIn("os_version", os_details)

    @patch("psutil.net_if_addrs")
    def test_integrity_checker_get_hardware_id(self, mock_net_if_addrs):
        """Test that a hardware ID is generated, mocking network interfaces."""
        # Mock the network interface to provide a predictable MAC address
        mock_net_if_addrs.return_value = {"Ethernet": [MagicMock(address="00-1A-2B-3C-4D-5E")]}
        hw_id = self.integrity_checker.get_hardware_id()
        self.assertIsInstance(hw_id, str)
        self.assertGreater(len(hw_id), 0)
        # Check that it's a SHA256 hash
        self.assertEqual(len(hw_id), 64)

    # --- EnvironmentValidator Tests ---
    @patch("os.getuid", create=True, return_value=0)  # Mock for Unix-like systems
    @patch("ctypes.windll.shell32.IsUserAnAdmin", create=True, return_value=1)  # Mock for Windows
    def test_is_admin_true(self, mock_is_admin_win, mock_getuid):
        """Test admin check returns true when running as admin."""
        if platform.system() == "Windows":
            self.assertTrue(self.env_validator.is_admin())
        else:
            self.assertTrue(self.env_validator.is_admin())

    @patch("builtins.open", new_callable=unittest.mock.mock_open, read_data="GenuineIntel")
    def test_is_virtualized_false_for_real_cpu(self, mock_open):
        """Test virtualization check returns false on a real CPU."""
        self.assertFalse(self.env_validator.is_virtualized())

    @patch("psutil.boot_time", return_value=12345.0)
    def test_is_recently_booted_false(self, mock_boot_time):
        """Test that a long uptime returns false."""
        self.assertFalse(self.env_validator.is_recently_booted(threshold_seconds=10))

    # --- AntiTampering Tests ---
    def test_anti_tampering_generate_and_verify_mac(self):
        """Test MAC generation and successful verification."""
        self.anti_tampering.generate_mac()
        self.assertTrue(os.path.exists(self.test_file_path + ".mac"))
        self.assertTrue(self.anti_tampering.verify_mac())

    def test_anti_tampering_verify_mac_fails_on_tamper(self):
        """Test that MAC verification fails if the file is tampered with."""
        self.anti_tampering.generate_mac()

        # Tamper with the file
        with open(self.test_file_path, "a") as f:
            f.write(" some tampered data.")

        self.assertFalse(self.anti_tampering.verify_mac())

    # --- SecurityAuditor Tests ---
    @patch.object(auditor_logger, "warning")
    def test_auditor_log_security_event(self, mock_log_warning):
        """Test that security events are logged via the provided logger."""
        event_details = {"detail": "some data"}
        self.auditor.log_security_event("Test Event", "High", event_details)

        mock_log_warning.assert_called_once()

        # The argument to the logger should be a JSON string
        call_args = mock_log_warning.call_args[0][0]
        log_data = json.loads(call_args)

        self.assertEqual(log_data["event"], "Test Event")
        self.assertEqual(log_data["level"], "High")
        self.assertEqual(log_data["details"], event_details)

    def test_auditor_get_system_state(self):
        """Test that system state is captured."""
        state = self.auditor.get_system_state()
        self.assertEqual(state["user"], getpass.getuser())
        self.assertIn("os_details", state)
        self.assertIn("running_processes", state)


if __name__ == "__main__":
    unittest.main()
