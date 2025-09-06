"""
Performance enhancement additions for DeviceFingerprint Library
"""

import time
import threading
import asyncio
from functools import lru_cache
from typing import Optional
import json
import sys
import os

# Add the parent directory to the path to import devicefingerprint
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from devicefingerprint import FingerprintMethod, AdvancedDeviceFingerprinter
except ImportError:
    # Define basic enum for standalone use
    from enum import Enum
    class FingerprintMethod(Enum):
        BASIC = "basic"
        ADVANCED = "advanced"
        QUANTUM_RESISTANT = "quantum_resistant"

class FingerprintCache:
    """Thread-safe caching system for fingerprints to avoid repeated hardware queries"""
    
    def __init__(self, max_age_seconds: int = 300):  # 5 minutes default
        self.cache = {}
        self.timestamps = {}
        self.max_age = max_age_seconds
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[str]:
        """Get cached fingerprint if still valid"""
        with self.lock:
            if key in self.cache:
                if time.time() - self.timestamps[key] < self.max_age:
                    return self.cache[key]
                else:
                    # Cache expired
                    del self.cache[key]
                    del self.timestamps[key]
        return None
    
    def set(self, key: str, value: str):
        """Cache a fingerprint"""
        with self.lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()
    
    def clear(self):
        """Clear all cached fingerprints"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()

class AsyncDeviceFingerprinter:
    """Async wrapper for non-blocking fingerprint generation"""
    
    import asyncio
    
    def __init__(self, fingerprinter):
        self.fingerprinter = fingerprinter
        self.executor = None
    
    async def generate_fingerprint_async(self, method=FingerprintMethod.QUANTUM_RESISTANT):
        """Generate fingerprint asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor, 
            self.fingerprinter.generate_fingerprint, 
            method
        )

class BenchmarkProfiler:
    """Performance profiling for fingerprint operations"""
    
    def __init__(self):
        self.metrics = {}
    
    def profile_method(self, method: FingerprintMethod):
        """Decorator to profile fingerprint generation methods"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                start_memory = self._get_memory_usage()
                
                result = func(*args, **kwargs)
                
                end_time = time.perf_counter()
                end_memory = self._get_memory_usage()
                
                self.metrics[method.value] = {
                    'execution_time': end_time - start_time,
                    'memory_delta': end_memory - start_memory,
                    'components_analyzed': len(result.components) if hasattr(result, 'components') else 0
                }
                
                return result
            return wrapper
        return decorator
    
    def _get_memory_usage(self):
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # MB
        except ImportError:
            return 0  # psutil not available
    
    def get_performance_report(self) -> dict:
        """Get detailed performance metrics"""
        return self.metrics.copy()
