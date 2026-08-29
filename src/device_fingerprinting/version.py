"""Version information for device_fingerprinting package."""

__version__ = "2.3.0"
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())

# Version components
MAJOR = 2
MINOR = 3
PATCH = 0
BUILD = "stable"

# Full version string
VERSION = f"{MAJOR}.{MINOR}.{PATCH}"

# Release information
RELEASE_DATE = "2026-08-29"
RELEASE_NAME = "Security Hardening & Python 3.10+ Baseline"

# Compatibility information
MIN_PYTHON_VERSION = (3, 10)
SUPPORTED_PYTHON_VERSIONS = ["3.10", "3.11", "3.12", "3.13"]


def get_version() -> str:
    """Get the version string."""
    return __version__


def get_version_info() -> tuple:
    """Get the version as a tuple of integers."""
    return __version_info__


def check_python_version() -> bool:
    """Check if the current Python version is supported."""
    import sys

    return sys.version_info >= MIN_PYTHON_VERSION
