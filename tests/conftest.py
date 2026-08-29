import pytest
import sys
import os

# Add the src directory to the Python path so that the tests can find the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


@pytest.fixture
def enable_pqc():
    """Fixture to enable post-quantum crypto for a test."""
    from device_fingerprinting.device_fingerprinting import (
        enable_post_quantum_crypto,
        disable_post_quantum_crypto,
    )

    enable_post_quantum_crypto()
    yield
    disable_post_quantum_crypto()
