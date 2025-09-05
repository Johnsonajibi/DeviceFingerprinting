"""
Setup configuration for Device Fingerprinting Library
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read version from __init__.py
def get_version():
    with open("device_fingerprinting/__init__.py", "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split('"')[1]
    return "1.0.0"

setup(
    name="device-fingerprinting",
    version=get_version(),
    author="QuantumVault Development Team",
    author_email="dev@quantumvault.com",
    description="Advanced hardware-based device identification for security applications",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Johnsonajibi/device-fingerprinting",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Hardware",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies - uses only standard library
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
        ],
        "docs": [
            "sphinx>=3.0",
            "sphinx-rtd-theme>=0.5",
        ],
    },
    keywords=[
        "device fingerprinting",
        "hardware identification", 
        "security",
        "authentication",
        "device binding",
        "quantum resistant",
        "hardware security",
        "device detection",
        "system identification",
        "anti-fraud"
    ],
    project_urls={
        "Bug Reports": "https://github.com/Johnsonajibi/device-fingerprinting/issues",
        "Source": "https://github.com/Johnsonajibi/device-fingerprinting",
        "Documentation": "https://device-fingerprinting.readthedocs.io/",
        "Funding": "https://github.com/sponsors/Johnsonajibi",
    },
)
