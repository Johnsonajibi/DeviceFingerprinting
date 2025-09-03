"""
QuantumVault Password Manager Setup Configuration

This module provides installation and distribution configuration
for the QuantumVault post-quantum cryptography password manager.
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open(os.path.join(this_directory, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="quantumvault-password-manager",
    version="1.0.0",
    author="QuantumVault Development Team",
    author_email="support@quantumvault.com",
    description="Post-quantum cryptography enhanced password manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/john123304/Post-quantum-cryptography-Offline-Password-Manager",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "full": [
            "pandas>=2.0.0",
            "qrcode[pil]>=7.4.0",
            "Pillow>=10.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "quantumvault=CorrectPQC:main",
        ],
    },
    keywords="password manager security cryptography quantum-resistant",
    project_urls={
        "Bug Reports": "https://github.com/john123304/Post-quantum-cryptography-Offline-Password-Manager/issues",
        "Source": "https://github.com/john123304/Post-quantum-cryptography-Offline-Password-Manager",
        "Documentation": "https://github.com/john123304/Post-quantum-cryptography-Offline-Password-Manager/wiki",
    },
)
