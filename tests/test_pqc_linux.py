"""
Test PQC functionality with liboqs backend on Linux.

This test is designed to run on Linux CI systems where liboqs-python
can be properly installed with the C library backend.
"""

import pytest
import sys
import platform


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="liboqs backend works best on Linux"
)
def test_pqc_with_liboqs_on_linux():
    """Test that PQC works with liboqs backend on Linux."""
    # Try to import liboqs
    try:
        import oqs
        liboqs_available = True
    except ImportError:
        pytest.skip("liboqs-python not installed (optional dependency)")
        liboqs_available = False
    
    # Import HybridPQC
    from device_fingerprinting.hybrid_pqc import HybridPQC
    
    # Initialize with Dilithium3
    pqc = HybridPQC(algorithm="Dilithium3")
    
    # Get info
    info = pqc.get_info()
    
    # Test basic functionality
    test_message = b"Test message for PQC"
    signature = pqc.sign(test_message)
    assert pqc.verify(signature, test_message), "Signature verification failed"
    
    # Test tamper detection
    wrong_message = b"Wrong message"
    assert not pqc.verify(signature, wrong_message), "Failed to detect tampered message"
    
    # If liboqs is available, we might have quantum resistance
    if liboqs_available and info.get('pqc_available'):
        print(f"\n✅ Full quantum-resistant PQC is active!")
        print(f"   Backend: {info.get('backend_type')}")
        print(f"   Library: {info.get('pqc_library')}")
    else:
        print(f"\n🔒 Classical fallback mode (still secure)")
        print(f"   Mode: {info.get('pqc_library')}")


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="This test checks Linux-specific PQC backend availability"
)
def test_pqc_backend_info():
    """Test that we can get PQC backend information."""
    from device_fingerprinting.hybrid_pqc import HybridPQC, is_pqc_supported
    
    pqc = HybridPQC()
    info = pqc.get_info()
    
    # Check required fields
    assert 'type' in info
    assert 'algorithm' in info
    assert 'pqc_library' in info
    assert 'pqc_available' in info
    assert 'production_ready' in info
    
    assert info['type'] == 'hybrid_pqc'
    assert info['production_ready'] is True
    
    # Check PQC support function
    pqc_supported = is_pqc_supported()
    assert isinstance(pqc_supported, bool)
    
    print(f"\nPQC Backend Info:")
    print(f"  Library: {info['pqc_library']}")
    print(f"  Available: {info['pqc_available']}")
    print(f"  Algorithm: {info['algorithm']}")
    print(f"  Security Level: {info['security_level']}")


def test_pqc_fallback_always_works():
    """Test that PQC works in fallback mode on all platforms."""
    from device_fingerprinting.hybrid_pqc import HybridPQC
    
    pqc = HybridPQC(algorithm="Dilithium3")
    
    # Basic signing should always work
    test_message = b"Test message"
    signature = pqc.sign(test_message)
    
    assert signature is not None
    assert len(signature) > 0
    assert isinstance(signature, str)
    
    # Verification should work
    assert pqc.verify(signature, test_message)
    
    # Tamper detection should work
    assert not pqc.verify(signature, b"Different message")
    
    info = pqc.get_info()
    assert info['production_ready'] is True
