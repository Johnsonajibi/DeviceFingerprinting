"""
Abstract base classes for pluggable backends.

Defines interfaces for crypto, storage, and security checks
that applications can implement with their own backends.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple


class CryptoBackend(ABC):
    """Interface for cryptographic operations"""

    @abstractmethod
    def sign(self, data: bytes) -> str:
        """Create signature for data"""
        pass

    @abstractmethod
    def verify(self, signature: str, data: bytes) -> bool:
        """Verify signature against data"""
        pass


class StorageBackend(ABC):
    """Interface for secure storage operations"""

    @abstractmethod
    def store(self, key: str, data: Dict[str, Any]) -> bool:
        """Store data under key"""
        pass

    @abstractmethod
    def load(self, key: str) -> Optional[Dict[str, Any]]:
        """Load data by key"""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete data by key"""
        pass


class SecurityCheck(ABC):
    """Interface for runtime security checks"""

    @abstractmethod
    def check(self) -> Tuple[bool, str]:
        """Run security check, return (is_suspicious, reason)"""
        pass


# --- Backend Factory ---

# Import default implementations
from .default_backends import HmacSha256Backend, InMemoryStorage, NoOpSecurityCheck

# A simple registry for backends
_backend_registry = {
    "crypto": HmacSha256Backend,
    "storage": InMemoryStorage,
    "security": NoOpSecurityCheck,
}


class ScreenResolutionBackend:
    """Detects the primary display's resolution using platform-native APIs.

    Returns None (rather than a fabricated value) when no display can be
    queried, e.g. on a headless server or CI runner.
    """

    def get(self) -> Optional[Tuple[int, int]]:
        import platform

        system = platform.system()
        if system == "Windows":
            resolution = self._get_windows()
        elif system == "Darwin":
            resolution = self._get_macos()
        else:
            resolution = self._get_linux()

        if resolution is None:
            resolution = self._get_tkinter_fallback()

        return resolution

    @staticmethod
    def _get_windows() -> Optional[Tuple[int, int]]:
        try:
            import ctypes

            user32 = ctypes.windll.user32
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            if width > 0 and height > 0:
                return (width, height)
            return None
        except Exception:
            return None

    @staticmethod
    def _get_macos() -> Optional[Tuple[int, int]]:
        try:
            import subprocess
            import re

            output = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
            match = re.search(r"(\d+)\s*x\s*(\d+)", output)
            if match:
                return (int(match.group(1)), int(match.group(2)))
            return None
        except Exception:
            return None

    @staticmethod
    def _get_linux() -> Optional[Tuple[int, int]]:
        try:
            import subprocess
            import re

            output = subprocess.run(
                ["xrandr", "--current"], capture_output=True, text=True, timeout=5
            ).stdout
            match = re.search(r"current\s+(\d+)\s*x\s*(\d+)", output)
            if match:
                return (int(match.group(1)), int(match.group(2)))
            return None
        except Exception:
            return None

    @staticmethod
    def _get_tkinter_fallback() -> Optional[Tuple[int, int]]:
        try:
            import tkinter

            root = tkinter.Tk()
            root.withdraw()
            width = root.winfo_screenwidth()
            height = root.winfo_screenheight()
            root.destroy()
            if width > 0 and height > 0:
                return (width, height)
            return None
        except Exception:
            return None


_backend_registry["screen_resolution"] = ScreenResolutionBackend


def get_backend(name: str) -> Any:
    """
    Factory function to get a backend instance by name.

    Args:
        name: The name of the backend to retrieve.

    Returns:
        An instance of the requested backend.

    Raises:
        ValueError: If the backend name is not found.
    """
    backend_class = _backend_registry.get(name)
    if backend_class:
        return backend_class()

    raise ValueError(f"Unknown backend: '{name}'")
