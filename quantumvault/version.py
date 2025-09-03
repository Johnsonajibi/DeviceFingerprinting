"""
Version management for QuantumVault

This module handles version information and provides utilities for
version checking and compatibility.
"""

import re
from typing import Tuple, Optional, Dict, Any

# Current version
__version__ = "1.0.0"

# Version pattern for parsing
VERSION_PATTERN = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<pre_release>alpha|beta|rc)\.?(?P<pre_number>\d+))?"
    r"(?:\+(?P<build>.+))?$"
)

class Version:
    """Version class for handling semantic versioning."""
    
    def __init__(self, version_string: str):
        """Initialize version from string."""
        self.version_string = version_string
        self._parse_version()
    
    def _parse_version(self):
        """Parse version string into components."""
        match = VERSION_PATTERN.match(self.version_string)
        if not match:
            raise ValueError(f"Invalid version format: {self.version_string}")
        
        self.major = int(match.group("major"))
        self.minor = int(match.group("minor"))
        self.patch = int(match.group("patch"))
        self.pre_release = match.group("pre_release")
        self.pre_number = int(match.group("pre_number")) if match.group("pre_number") else None
        self.build = match.group("build")
    
    def __str__(self) -> str:
        """String representation of version."""
        return self.version_string
    
    def __repr__(self) -> str:
        """Detailed representation of version."""
        return f"Version('{self.version_string}')"
    
    def __eq__(self, other) -> bool:
        """Check if versions are equal."""
        if not isinstance(other, Version):
            other = Version(str(other))
        return self.version_string == other.version_string
    
    def __lt__(self, other) -> bool:
        """Check if this version is less than other."""
        if not isinstance(other, Version):
            other = Version(str(other))
        
        # Compare major, minor, patch
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        
        # Handle pre-release versions
        if self.pre_release and not other.pre_release:
            return True
        if not self.pre_release and other.pre_release:
            return False
        if self.pre_release and other.pre_release:
            pre_order = {"alpha": 1, "beta": 2, "rc": 3}
            if self.pre_release != other.pre_release:
                return pre_order[self.pre_release] < pre_order[other.pre_release]
            return (self.pre_number or 0) < (other.pre_number or 0)
        
        return False
    
    def __le__(self, other) -> bool:
        """Check if this version is less than or equal to other."""
        return self < other or self == other
    
    def __gt__(self, other) -> bool:
        """Check if this version is greater than other."""
        return not self <= other
    
    def __ge__(self, other) -> bool:
        """Check if this version is greater than or equal to other."""
        return not self < other
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert version to dictionary."""
        return {
            "major": self.major,
            "minor": self.minor, 
            "patch": self.patch,
            "pre_release": self.pre_release,
            "pre_number": self.pre_number,
            "build": self.build,
            "full": self.version_string,
        }

# Current version instance
current_version = Version(__version__)

def get_version() -> str:
    """Get the current version string."""
    return __version__

def get_version_info() -> Dict[str, Any]:
    """Get detailed version information."""
    return current_version.to_dict()

def check_compatibility(required_version: str) -> bool:
    """Check if current version meets requirement."""
    required = Version(required_version)
    return current_version >= required

def bump_version(version_type: str = "patch") -> str:
    """
    Bump version number.
    
    Args:
        version_type: Type of version bump (major, minor, patch)
    
    Returns:
        New version string
    """
    if version_type == "major":
        new_version = f"{current_version.major + 1}.0.0"
    elif version_type == "minor":
        new_version = f"{current_version.major}.{current_version.minor + 1}.0"
    elif version_type == "patch":
        new_version = f"{current_version.major}.{current_version.minor}.{current_version.patch + 1}"
    else:
        raise ValueError(f"Invalid version type: {version_type}")
    
    return new_version

# Version history for changelog
VERSION_HISTORY = [
    {
        "version": "1.0.0",
        "date": "2025-09-03",
        "changes": [
            "Initial release with quantum-resistant cryptography",
            "Added dual QR recovery system",
            "Implemented steganographic QR codes",
            "Added forward secure encryption",
            "Implemented dynamic page sizing optimization",
            "Professional documentation and GitHub integration",
        ],
        "breaking_changes": [],
        "security_fixes": [],
    }
]
