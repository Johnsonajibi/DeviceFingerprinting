#!/bin/bash

# QuantumVault Individual Repository Preparation Script
# This script prepares each library for individual GitHub publication

echo "🚀 Preparing QuantumVault Libraries for Individual GitHub Repositories"
echo "=================================================================="

# Create base directory for individual repositories
mkdir -p individual_repos
cd individual_repos

echo "📁 Creating individual repository folders..."

# 1. Dual QR Recovery System
echo "1️⃣ Setting up dual-qr-recovery-system..."
mkdir -p dual-qr-recovery-system
cp -r ../dual_qr_recovery/* dual-qr-recovery-system/
cd dual-qr-recovery-system

# Create proper structure
mkdir -p examples tests docs .github/workflows
mv dual_qr_recovery.py dual_qr_recovery_system.py

# Update __init__.py imports
cat > __init__.py << 'EOF'
"""
Dual QR Recovery System
======================

Revolutionary dual QR code recovery system with cryptographic isolation.

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

from .dual_qr_recovery_system import (
    DualQRRecoverySystem,
    QRRecoveryCredentials,
    DualQRResult,
    DeviceFingerprintGenerator
)

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"
__all__ = [
    "DualQRRecoverySystem",
    "QRRecoveryCredentials", 
    "DualQRResult",
    "DeviceFingerprintGenerator"
]
EOF

# Create setup.py
cat > setup.py << 'EOF'
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dual-qr-recovery-system",
    version="1.0.0",
    author="QuantumVault Development Team",
    description="Revolutionary dual QR code recovery system with cryptographic isolation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    keywords="cryptography qr-codes security recovery dual-factor quantum-vault",
)
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
cryptography>=41.0.0
EOF

# Create LICENSE
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 QuantumVault Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Create basic example
cat > examples/basic_usage.py << 'EOF'
"""
Basic Usage Example for Dual QR Recovery System
"""

from dual_qr_recovery_system import DualQRRecoverySystem
from datetime import datetime

def main():
    # Initialize the system
    qr_system = DualQRRecoverySystem()
    
    # Prepare recovery data
    master_data = {
        "master_password_hash": "your_secure_hash_here",
        "encryption_salt": "your_salt_here",
        "vault_key_encrypted": "your_encrypted_key_here"
    }
    
    security_data = {
        "question_1": "What was your first pet's name?",
        "answer_1_hash": "hash_of_answer_1",
        "question_2": "In what city were you born?",
        "answer_2_hash": "hash_of_answer_2"
    }
    
    # Create dual QR system
    dual_qr = qr_system.create_dual_qr_system(
        master_recovery_data=master_data,
        security_questions_data=security_data,
        expiry_hours=72
    )
    
    print(f"✓ Dual QR system created!")
    print(f"  Primary QR ID: {dual_qr.primary_qr.qr_id}")
    print(f"  Secondary QR ID: {dual_qr.secondary_qr.qr_id}")
    
    # Validate QR credentials
    primary_valid, reason = qr_system.validate_qr_credentials(dual_qr.primary_qr)
    print(f"  Primary QR valid: {primary_valid}")
    
if __name__ == "__main__":
    main()
EOF

cd ..

echo "✓ dual-qr-recovery-system prepared"

# 2. Quantum-Resistant Cryptography
echo "2️⃣ Setting up quantum-resistant-cryptography..."
mkdir -p quantum-resistant-cryptography
cp -r ../quantum_resistant_crypto/* quantum-resistant-cryptography/
cd quantum-resistant-cryptography

mkdir -p examples tests docs .github/workflows
mv quantum_resistant_crypto.py quantum_resistant_cryptography.py

# Update __init__.py
cat > __init__.py << 'EOF'
"""
Quantum-Resistant Cryptography Library
=====================================

Post-quantum cryptographic library with SHA3-512 and timing attack protection.

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

from .quantum_resistant_cryptography import (
    QuantumResistantCrypto,
    HashResult,
    DEFAULT_SALT_LENGTH,
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_MIN_PASSWORD_LENGTH
)

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"
__all__ = [
    "QuantumResistantCrypto",
    "HashResult",
    "DEFAULT_SALT_LENGTH",
    "DEFAULT_PBKDF2_ITERATIONS", 
    "DEFAULT_MIN_PASSWORD_LENGTH"
]
EOF

# Create setup.py
cat > setup.py << 'EOF'
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="quantum-resistant-cryptography",
    version="1.0.0",
    author="QuantumVault Development Team",
    description="Post-quantum cryptographic library with SHA3-512 and timing attack protection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    keywords="post-quantum cryptography sha3 pbkdf2 quantum-resistant security",
)
EOF

cat > requirements.txt << 'EOF'
cryptography>=41.0.0
EOF

cp ../dual-qr-recovery-system/LICENSE .

cd ..

echo "✓ quantum-resistant-cryptography prepared"

# Continue with other libraries...
echo "🎯 Basic repository structures created!"
echo ""
echo "📋 Next steps:"
echo "1. Review each repository folder in 'individual_repos/'"
echo "2. Customize README.md files for each repository"
echo "3. Test each library independently"
echo "4. Create GitHub repositories"
echo "5. Push to GitHub"
echo ""
echo "🚀 Your libraries are ready for individual GitHub publication!"
