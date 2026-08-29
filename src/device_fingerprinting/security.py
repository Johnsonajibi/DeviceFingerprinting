"""
This module provides classes for runtime security checks and tamper detection.
"""

import os
import platform
import getpass
import hashlib
import hmac
import psutil
import ctypes
import json


class SystemIntegrityChecker:
    """
    Provides methods to check the integrity and details of the underlying system.
    """

    def get_os_details(self) -> dict:
        """Returns a dictionary of OS details."""
        return {
            "os_type": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
        }

    def get_hardware_id(self) -> str:
        """
        Generates a stable hardware ID from various system components.
        """
        cpu_id = str(psutil.cpu_count()) + platform.processor()
        mac_addr = self._get_stable_mac_address()

        hw_string = f"{cpu_id}-{mac_addr}"
        return hashlib.sha256(hw_string.encode()).hexdigest()

    @staticmethod
    def _get_stable_mac_address() -> str:
        """
        Finds a stable MAC address by scanning all interfaces, rather than
        assuming an interface literally named "Ethernet" exists (it doesn't
        on Wi-Fi-only, Linux, or macOS systems).
        """
        try:
            interfaces = psutil.net_if_addrs()
        except Exception:
            return "unknown"

        # Sort by name for a deterministic choice across calls/reboots.
        for name in sorted(interfaces):
            if name.lower().startswith(("lo", "loopback")):
                continue
            for addr in interfaces[name]:
                if addr.family == psutil.AF_LINK and addr.address:
                    return addr.address

        return "unknown"


class EnvironmentValidator:
    """
    Validates the execution environment for signs of virtualization or debugging.
    """

    def is_admin(self) -> bool:
        """Checks if the current user has administrative privileges."""
        try:
            if platform.system() == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except (AttributeError, ImportError):
            return False  # Fallback for systems without these checks

    def is_virtualized(self) -> bool:
        """
        Checks for common signs of a virtualized environment.
        This is a heuristic and not foolproof.
        """
        # Check CPU vendor string (common in VMs)
        try:
            with open("/proc/cpuinfo") as f:
                if "hypervisor" in f.read().lower():
                    return True
        except FileNotFoundError:
            pass  # Not a Linux-like system

        # Check for VM-related MAC address prefixes
        vm_mac_prefixes = ("00:05:69", "00:0C:29", "00:50:56", "08:00:27")
        for iface in psutil.net_if_addrs().values():
            for addr in iface:
                if addr.family == psutil.AF_LINK and addr.address.startswith(vm_mac_prefixes):
                    return True
        return False

    def is_recently_booted(self, threshold_seconds: int = 300) -> bool:
        """Checks if the system was booted very recently."""
        boot_time = psutil.boot_time()
        uptime = psutil.time.time() - boot_time
        return uptime < threshold_seconds


class AntiTampering:
    """
    Provides methods to detect tampering of files using HMAC-SHA256.
    """

    def __init__(self, file_path: str, key: bytes = None):
        self.file_path = file_path
        self.mac_file_path = file_path + ".mac"
        self.key_file_path = file_path + ".hmackey"

        if key is not None:
            self._key = key
        else:
            # A randomly generated key that's never persisted would make
            # generate_mac() in one process/run unverifiable by verify_mac()
            # in any later one (a fresh random key every time never matches
            # the key a MAC was generated with) - tamper detection would
            # silently never work unless a caller manually threads the same
            # key through every call. Persist it next to the MAC file instead.
            self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        import secrets

        if os.path.exists(self.key_file_path):
            with open(self.key_file_path, "rb") as f:
                return f.read()

        new_key = secrets.token_bytes(32)  # 256-bit key
        with open(self.key_file_path, "wb") as f:
            f.write(new_key)
        try:
            os.chmod(self.key_file_path, 0o600)
        except OSError:
            pass  # chmod semantics are platform-dependent (e.g. Windows)
        return new_key

    def generate_mac(self):
        """Generates and saves an HMAC for the file."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, "rb") as f:
            file_content = f.read()

        mac = hmac.new(self._key, file_content, hashlib.sha256).hexdigest()

        with open(self.mac_file_path, "w") as f:
            f.write(mac)

    def verify_mac(self) -> bool:
        """Verifies the file's integrity against its saved HMAC."""
        if not os.path.exists(self.mac_file_path):
            return False  # No MAC to verify against

        with open(self.mac_file_path, "r") as f:
            saved_mac = f.read()

        with open(self.file_path, "rb") as f:
            file_content = f.read()

        current_mac = hmac.new(self._key, file_content, hashlib.sha256).hexdigest()

        return hmac.compare_digest(saved_mac, current_mac)


class SecurityAuditor:
    """
    Logs security-relevant events and system state.
    """

    def __init__(self, logger=None):
        if logger:
            self.logger = logger
        else:
            import logging

            self.logger = logging.getLogger(__name__)

    _LOG_METHODS = {
        "debug": "debug",
        "info": "info",
        "low": "info",
        "warning": "warning",
        "medium": "warning",
        "error": "error",
        "high": "error",
        "critical": "critical",
    }

    def log_security_event(self, event: str, level: str, details: dict):
        """Logs a structured security event at the log level matching `level`."""
        log_message = json.dumps(
            {"event": event, "level": level, "details": details, "timestamp": psutil.time.time()}
        )
        method_name = self._LOG_METHODS.get(level.lower(), "warning")
        getattr(self.logger, method_name)(log_message)

    def get_system_state(self) -> dict:
        """Captures a snapshot of the current system state for auditing."""
        return {
            "timestamp": psutil.time.time(),
            "user": getpass.getuser(),
            "os_details": platform.platform(),
            "running_processes": [p.name() for p in psutil.process_iter(["name"])],
        }
