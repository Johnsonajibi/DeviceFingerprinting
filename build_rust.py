#!/usr/bin/env python3
"""
Build script for the Rust PQC module
"""

import subprocess
import sys
import os
import platform
from pathlib import Path

def check_rust_installation():
    """Check if Rust is properly installed"""
    try:
        result = subprocess.run(['rustc', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Rust found: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ Rust not found!")
    print("📥 Please install Rust from: https://rustup.rs/")
    return False

def install_maturin():
    """Install maturin for Python-Rust integration"""
    print("🔧 Installing maturin...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'maturin'], check=True)
        print("✅ Maturin installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install maturin: {e}")
        return False

def build_rust_module():
    """Build the Rust PQC module"""
    pqc_rust_dir = Path(__file__).parent / "pqc_rust"
    
    if not pqc_rust_dir.exists():
        print(f"❌ pqc_rust directory not found: {pqc_rust_dir}")
        return False
    
    print(f"🏗️  Building Rust module in: {pqc_rust_dir}")
    
    try:
        # Change to the Rust directory
        original_dir = os.getcwd()
        os.chdir(pqc_rust_dir)
        
        # Build in development mode
        subprocess.run([sys.executable, '-m', 'maturin', 'develop', '--release'], check=True)
        
        print("✅ Rust PQC module built successfully!")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to build Rust module: {e}")
        return False
    except FileNotFoundError:
        print("❌ Maturin not found. Please install with: pip install maturin")
        return False
    finally:
        os.chdir(original_dir)

def test_rust_module():
    """Test the built Rust module"""
    print("🧪 Testing Rust PQC module...")
    
    try:
        import pqc_rust
        
        # Test basic import
        print("✅ Module import successful")
        
        # Test RustCrypto functionality
        crypto = pqc_rust.RustCrypto()
        result = pqc_rust.test_crypto()
        
        if result:
            print("✅ Self-test passed")
        else:
            print("❌ Self-test failed")
            return False
            
        # Test crypto functionality
        crypto = pqc_rust.RustCrypto()
        random_data = crypto.generate_random(32)
        
        if len(random_data) == 32:
            print("✅ Crypto functions working")
        else:
            print("❌ Crypto test failed")
            return False
        
        return True
    
    except ImportError as e:
        print(f"❌ Failed to import pqc_rust: {e}")
        return False
    except Exception as e:
        print(f"❌ Rust module test failed: {e}")
        return False

def main():
    """Main build process"""
    print("🦀 Building Rust Post-Quantum Crypto Module")
    print("=" * 50)
    
    # Check requirements
    if not check_rust_installation():
        return False
    
    if not install_maturin():
        return False
    
    # Build module
    if not build_rust_module():
        return False
    
    # Test module
    if not test_rust_module():
        print("⚠️  Build succeeded but tests failed")
        return False
    
    print("\n🎉 Rust PQC module built and tested successfully!")
    print("\n🔧 Integration Details:")
    print("   - Post-quantum signatures: Dilithium3")
    print("   - Post-quantum KEM: Kyber768")
    print("   - Symmetric crypto: AES-256-GCM, ChaCha20Poly1305")
    print("   - Key derivation: Argon2id, Scrypt")
    print("   - Memory security: Zeroize + Secrecy")
    print("   - Random generation: OsRng")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)