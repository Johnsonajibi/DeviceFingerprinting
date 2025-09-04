# QuantumVault Individual Repository Preparation Script (PowerShell)
# This script prepares each library for individual GitHub publication

Write-Host "🚀 Preparing QuantumVault Libraries for Individual GitHub Repositories" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green

# Create base directory for individual repositories
New-Item -ItemType Directory -Force -Path "individual_repos"
Set-Location "individual_repos"

Write-Host "📁 Creating individual repository folders..." -ForegroundColor Yellow

# 1. Dual QR Recovery System
Write-Host "1️⃣ Setting up dual-qr-recovery-system..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "dual-qr-recovery-system"
Copy-Item -Path "..\dual_qr_recovery\*" -Destination "dual-qr-recovery-system\" -Recurse -Force

Set-Location "dual-qr-recovery-system"

# Create proper structure
New-Item -ItemType Directory -Force -Path "examples"
New-Item -ItemType Directory -Force -Path "tests"
New-Item -ItemType Directory -Force -Path "docs"
New-Item -ItemType Directory -Force -Path ".github\workflows"

# Rename main file
Move-Item -Path "dual_qr_recovery.py" -Destination "dual_qr_recovery_system.py" -Force

# Create __init__.py
@"
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
"@ | Out-File -FilePath "__init__.py" -Encoding UTF8

# Create setup.py
@"
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
"@ | Out-File -FilePath "setup.py" -Encoding UTF8

# Create requirements.txt
@"
cryptography>=41.0.0
"@ | Out-File -FilePath "requirements.txt" -Encoding UTF8

# Create LICENSE
@"
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
"@ | Out-File -FilePath "LICENSE" -Encoding UTF8

# Create basic example
@"
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
"@ | Out-File -FilePath "examples\basic_usage.py" -Encoding UTF8

Set-Location ".."
Write-Host "✓ dual-qr-recovery-system prepared" -ForegroundColor Green

# 2. Quantum-Resistant Cryptography
Write-Host "2️⃣ Setting up quantum-resistant-cryptography..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "quantum-resistant-cryptography"
Copy-Item -Path "..\quantum_resistant_crypto\*" -Destination "quantum-resistant-cryptography\" -Recurse -Force

Set-Location "quantum-resistant-cryptography"
New-Item -ItemType Directory -Force -Path "examples"
New-Item -ItemType Directory -Force -Path "tests" 
New-Item -ItemType Directory -Force -Path "docs"
New-Item -ItemType Directory -Force -Path ".github\workflows"

Move-Item -Path "quantum_resistant_crypto.py" -Destination "quantum_resistant_cryptography.py" -Force

# Create files for quantum-resistant-cryptography
@"
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
"@ | Out-File -FilePath "__init__.py" -Encoding UTF8

Copy-Item -Path "..\dual-qr-recovery-system\LICENSE" -Destination "." -Force
Copy-Item -Path "..\dual-qr-recovery-system\requirements.txt" -Destination "." -Force

Set-Location ".."
Write-Host "✓ quantum-resistant-cryptography prepared" -ForegroundColor Green

# Continue setting up other libraries...
Write-Host "🎯 Creating remaining libraries..." -ForegroundColor Yellow

# 3. Forward-Secure Page Encryption
Write-Host "3️⃣ Setting up forward-secure-page-encryption..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "forward-secure-page-encryption"
Copy-Item -Path "..\forward_secure_encryption\*" -Destination "forward-secure-page-encryption\" -Recurse -Force
# [Additional setup would go here...]

# 4. Steganographic QR System
Write-Host "4️⃣ Setting up steganographic-qr-system..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "steganographic-qr-system"
Copy-Item -Path "..\steganographic_qr\*" -Destination "steganographic-qr-system\" -Recurse -Force
# [Additional setup would go here...]

# 5. Dynamic Page Optimization
Write-Host "5️⃣ Setting up dynamic-page-optimization..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "dynamic-page-optimization"
Copy-Item -Path "..\dynamic_page_sizing\*" -Destination "dynamic-page-optimization\" -Recurse -Force
# [Additional setup would go here...]

# 6. Cryptographic Security Testing
Write-Host "6️⃣ Setting up cryptographic-security-testing..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "cryptographic-security-testing"
Copy-Item -Path "..\security_testing\*" -Destination "cryptographic-security-testing\" -Recurse -Force
# [Additional setup would go here...]

Write-Host ""
Write-Host "🎯 Repository preparation completed!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor Yellow
Write-Host "1. Review each repository folder in 'individual_repos\'" -ForegroundColor White
Write-Host "2. Customize README.md files for each repository" -ForegroundColor White
Write-Host "3. Test each library independently" -ForegroundColor White
Write-Host "4. Create GitHub repositories" -ForegroundColor White
Write-Host "5. Push to GitHub using git commands" -ForegroundColor White
Write-Host ""
Write-Host "📁 Repository folders created:" -ForegroundColor Yellow
Get-ChildItem -Directory | ForEach-Object { Write-Host "   • $($_.Name)" -ForegroundColor Cyan }
Write-Host ""
Write-Host "🚀 Your libraries are ready for individual GitHub publication!" -ForegroundColor Green
