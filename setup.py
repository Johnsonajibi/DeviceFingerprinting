"""
QuantumVault Password Manager Setup Configuration

This module provides installation and distribution configuration
for the QuantumVault post-quantum cryptography password manager.
"""

from setuptools import setup, find_packages
import os
import sys

# Add the package to Python path for version import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantumvault'))
from version import __version__

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open(os.path.join(this_directory, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="quantumvault-password-manager",
    version=__version__,
    author="QuantumVault Development Team",
    author_email="support@quantumvault.dev",
    description="Post-quantum cryptography enhanced password manager with advanced security features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager",
    packages=find_packages(include=['quantumvault', 'quantumvault.*']),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
        "Topic :: Security",
        "Topic :: Office/Business",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "full": [
            "pandas>=2.0.0",
            "qrcode[pil]>=7.4.0",
            "Pillow>=10.0.0",
            "matplotlib>=3.7.0",
            "numpy>=1.24.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-xdist>=3.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
            "myst-parser>=2.0.0",
        ],
        "security": [
            "bandit>=1.7.0",
            "safety>=3.0.0",
            "semgrep>=1.45.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "quantumvault=quantumvault.cli:main",
            "qvault=quantumvault.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "quantumvault": [
            "data/*.json",
            "templates/*.txt",
            "config/*.yaml",
        ],
    },
    keywords=[
        "password", "manager", "security", "cryptography", 
        "quantum-resistant", "post-quantum", "encryption",
        "AES", "SHA3", "PBKDF2", "QR-codes", "steganography",
        "forward-secrecy", "authentication", "vault"
    ],
    project_urls={
        "Homepage": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager",
        "Bug Reports": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/issues",
        "Source": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager",
        "Documentation": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/wiki",
        "Changelog": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/blob/master/CHANGELOG.md",
        "Security": "https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager/security",
    },
    zip_safe=False,
    test_suite="tests",
)
