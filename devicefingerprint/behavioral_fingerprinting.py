"""
Behavioral Device Fingerprinting
==============================

Implements behavioral fingerprinting through micro-benchmarks and system interaction patterns.
This novel approach measures how the system behaves under specific workloads to create
unique timing profiles that are extremely difficult to spoof.
"""

import time
import threading
import hashlib
import statistics
import math
import json
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
import platform

class BehaviorComponent(Enum):
    """Different behavioral components measured"""
    CPU_PERFORMANCE = "cpu_performance"
    MEMORY_PATTERNS = "memory_patterns"
    THREAD_SCHEDULING = "thread_scheduling"
    IO_CHARACTERISTICS = "io_characteristics"
    CRYPTO_TIMING = "crypto_timing"
    SYSTEM_RESPONSE = "system_response"

@dataclass
class BehaviorObservation:
    """A single behavioral observation"""
    component: BehaviorComponent
    measurements: List[float]
    statistical_profile: Dict[str, float]
    confidence: float
    stability_prediction: float

@dataclass
class BehavioralFingerprint:
    """Complete behavioral fingerprint"""
    observations: List[BehaviorObservation]
    composite_signature: str
    generation_time: float
    system_load_factor: float
    reliability_score: float

class BehavioralFingerprinter:
    """
    Behavioral Device Fingerprinting System
    
    Creates unique device signatures by measuring system behavior under
    standardized micro-benchmarks. This approach is novel because it doesn't
    rely on static hardware identifiers but on the unique performance
    characteristics of the hardware combination.
    """
    
    def __init__(self, benchmark_iterations: int = 10):
        self.benchmark_iterations = benchmark_iterations
        self.calibration_data = {}
        
    def generate_behavioral_fingerprint(self) -> BehavioralFingerprint:
        """Generate a complete behavioral fingerprint"""
        observations = []
        
        # Measure CPU performance characteristics
        cpu_obs = self._measure_cpu_performance()
        observations.append(cpu_obs)
        
        # Measure memory access patterns
        memory_obs = self._measure_memory_patterns()
        observations.append(memory_obs)
        
        # Measure thread scheduling behavior
        thread_obs = self._measure_thread_scheduling()
        observations.append(thread_obs)
        
        # Measure I/O characteristics
        io_obs = self._measure_io_characteristics()
        observations.append(io_obs)
        
        # Measure cryptographic operation timing
        crypto_obs = self._measure_crypto_timing()
        observations.append(crypto_obs)
        
        # Measure system response patterns
        response_obs = self._measure_system_response()
        observations.append(response_obs)
        
        # Calculate composite metrics
        composite_signature = self._generate_composite_signature(observations)
        system_load_factor = self._estimate_system_load()
        reliability_score = self._calculate_reliability(observations)
        
        return BehavioralFingerprint(
            observations=observations,
            composite_signature=composite_signature,
            generation_time=time.time(),
            system_load_factor=system_load_factor,
            reliability_score=reliability_score
        )
    
    def _measure_cpu_performance(self) -> BehaviorObservation:
        """Measure CPU performance characteristics through various computational tasks"""
        measurements = []
        
        for _ in range(self.benchmark_iterations):
            # Integer arithmetic benchmark
            start_time = time.perf_counter()
            result = 0
            for i in range(50000):
                result += i * i + i // 2
            int_time = time.perf_counter() - start_time
            
            # Floating point benchmark
            start_time = time.perf_counter()
            result = 0.0
            for i in range(10000):
                result += math.sin(i) * math.cos(i) + math.sqrt(i)
            float_time = time.perf_counter() - start_time
            
            # Complex number operations
            start_time = time.perf_counter()
            z = complex(1, 1)
            for i in range(1000):  # Reduced iterations to prevent overflow
                try:
                    z = z ** 1.01 + complex(0.01, 0.01)  # Reduced exponent to prevent overflow
                    # Keep z bounded to prevent overflow
                    if abs(z) > 1000:
                        z = complex(1, 1)
                except (OverflowError, ValueError):
                    z = complex(1, 1)
            complex_time = time.perf_counter() - start_time
            
            # Combine into single measurement
            combined_metric = int_time * 1000 + float_time * 2000 + complex_time * 3000
            measurements.append(combined_metric)
        
        statistical_profile = self._calculate_statistical_profile(measurements)
        
        return BehaviorObservation(
            component=BehaviorComponent.CPU_PERFORMANCE,
            measurements=measurements,
            statistical_profile=statistical_profile,
            confidence=0.9,
            stability_prediction=0.95
        )
    
    def _measure_memory_patterns(self) -> BehaviorObservation:
        """Measure memory access patterns and cache behavior"""
        measurements = []
        
        for _ in range(self.benchmark_iterations):
            # Sequential memory access
            data = bytearray(1024 * 1024)  # 1MB
            start_time = time.perf_counter()
            for i in range(0, len(data), 64):
                data[i] = (i % 256)
            sequential_time = time.perf_counter() - start_time
            
            # Random memory access
            indices = list(range(0, len(data), 64))
            import random
            random.shuffle(indices)
            start_time = time.perf_counter()
            for i in indices[:1000]:  # Sample 1000 random accesses
                data[i] = (i % 256)
            random_time = time.perf_counter() - start_time
            
            # Cache behavior test
            small_data = bytearray(64 * 1024)  # 64KB (fits in L1/L2 cache)
            start_time = time.perf_counter()
            for _ in range(1000):
                for i in range(0, len(small_data), 8):
                    small_data[i] = (i % 256)
            cache_time = time.perf_counter() - start_time
            
            # Combine measurements
            memory_signature = sequential_time * 1000 + random_time * 2000 + cache_time * 500
            measurements.append(memory_signature)
        
        statistical_profile = self._calculate_statistical_profile(measurements)
        
        return BehaviorObservation(
            component=BehaviorComponent.MEMORY_PATTERNS,
            measurements=measurements,
            statistical_profile=statistical_profile,
            confidence=0.8,
            stability_prediction=0.85
        )
    
    def _measure_thread_scheduling(self) -> BehaviorObservation:
        """Measure thread scheduling and context switching behavior"""
        measurements = []
        
        for _ in range(self.benchmark_iterations):
            results = []
            
            def cpu_bound_worker(duration_ms: int):
                """CPU-bound worker thread"""
                start = time.perf_counter()
                target = start + (duration_ms / 1000.0)
                result = 0
                while time.perf_counter() < target:
                    result += 1
                return result
            
            # Measure thread creation and scheduling overhead
            start_time = time.perf_counter()
            
            threads = []
            for i in range(4):  # Create 4 worker threads
                thread = threading.Thread(target=lambda: cpu_bound_worker(10))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            total_time = time.perf_counter() - start_time
            measurements.append(total_time * 1000)  # Convert to milliseconds
        
        statistical_profile = self._calculate_statistical_profile(measurements)
        
        return BehaviorObservation(
            component=BehaviorComponent.THREAD_SCHEDULING,
            measurements=measurements,
            statistical_profile=statistical_profile,
            confidence=0.7,
            stability_prediction=0.8
        )
    
    def _measure_io_characteristics(self) -> BehaviorObservation:
        """Measure I/O performance characteristics"""
        measurements = []
        
        for iteration in range(self.benchmark_iterations):
            try:
                test_file = f'behavioral_test_{iteration}.tmp'
                test_data = b'0123456789ABCDEF' * 64  # 1KB of data
                
                # Write test
                start_time = time.perf_counter()
                with open(test_file, 'wb') as f:
                    for _ in range(100):  # Write 100KB total
                        f.write(test_data)
                        f.flush()  # Force write to disk
                write_time = time.perf_counter() - start_time
                
                # Read test
                start_time = time.perf_counter()
                with open(test_file, 'rb') as f:
                    total_bytes = 0
                    while True:
                        chunk = f.read(1024)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                read_time = time.perf_counter() - start_time
                
                # Cleanup
                try:
                    import os
                    os.remove(test_file)
                except:
                    pass
                
                # Combine measurements
                io_signature = write_time * 1000 + read_time * 500
                measurements.append(io_signature)
                
            except Exception:
                # If I/O test fails, use a fallback measurement
                measurements.append(float('nan'))
        
        # Filter out failed measurements
        valid_measurements = [m for m in measurements if not math.isnan(m)]
        
        if valid_measurements:
            statistical_profile = self._calculate_statistical_profile(valid_measurements)
            confidence = len(valid_measurements) / len(measurements)
        else:
            statistical_profile = {'error': True}
            confidence = 0.1
        
        return BehaviorObservation(
            component=BehaviorComponent.IO_CHARACTERISTICS,
            measurements=valid_measurements,
            statistical_profile=statistical_profile,
            confidence=confidence,
            stability_prediction=0.6
        )
    
    def _measure_crypto_timing(self) -> BehaviorObservation:
        """Measure cryptographic operation timing"""
        measurements = []
        
        for _ in range(self.benchmark_iterations):
            test_data = b'The quick brown fox jumps over the lazy dog' * 100
            
            # SHA256 timing
            start_time = time.perf_counter()
            for _ in range(1000):
                hashlib.sha256(test_data).hexdigest()
            sha256_time = time.perf_counter() - start_time
            
            # SHA3-256 timing
            start_time = time.perf_counter()
            for _ in range(100):  # Fewer iterations as SHA3 is slower
                hashlib.sha3_256(test_data).hexdigest()
            sha3_time = time.perf_counter() - start_time
            
            # MD5 timing (for comparison)
            start_time = time.perf_counter()
            for _ in range(2000):
                hashlib.md5(test_data).hexdigest()
            md5_time = time.perf_counter() - start_time
            
            # Combine measurements
            crypto_signature = sha256_time * 1000 + sha3_time * 2000 + md5_time * 500
            measurements.append(crypto_signature)
        
        statistical_profile = self._calculate_statistical_profile(measurements)
        
        return BehaviorObservation(
            component=BehaviorComponent.CRYPTO_TIMING,
            measurements=measurements,
            statistical_profile=statistical_profile,
            confidence=0.85,
            stability_prediction=0.9
        )
    
    def _measure_system_response(self) -> BehaviorObservation:
        """Measure system response time patterns"""
        measurements = []
        
        for _ in range(self.benchmark_iterations):
            response_times = []
            
            # Measure time.time() call overhead
            start = time.perf_counter()
            for _ in range(10000):
                current_time = time.time()
            time_overhead = time.perf_counter() - start
            
            # Measure sleep accuracy
            target_sleep = 0.001  # 1ms
            start = time.perf_counter()
            time.sleep(target_sleep)
            actual_sleep = time.perf_counter() - start
            sleep_accuracy = abs(actual_sleep - target_sleep)
            
            # Measure threading overhead
            start = time.perf_counter()
            
            def dummy_function():
                return sum(range(100))
            
            thread = threading.Thread(target=dummy_function)
            thread.start()
            thread.join()
            threading_overhead = time.perf_counter() - start
            
            # Combine measurements
            system_signature = (time_overhead * 10000 + 
                              sleep_accuracy * 100000 + 
                              threading_overhead * 1000)
            measurements.append(system_signature)
        
        statistical_profile = self._calculate_statistical_profile(measurements)
        
        return BehaviorObservation(
            component=BehaviorComponent.SYSTEM_RESPONSE,
            measurements=measurements,
            statistical_profile=statistical_profile,
            confidence=0.75,
            stability_prediction=0.7
        )
    
    def _calculate_statistical_profile(self, measurements: List[float]) -> Dict[str, float]:
        """Calculate statistical profile for a set of measurements"""
        if not measurements:
            return {'error': True}
        
        try:
            return {
                'mean': statistics.mean(measurements),
                'median': statistics.median(measurements),
                'stdev': statistics.stdev(measurements) if len(measurements) > 1 else 0.0,
                'min': min(measurements),
                'max': max(measurements),
                'range': max(measurements) - min(measurements),
                'cv': (statistics.stdev(measurements) / statistics.mean(measurements)) if len(measurements) > 1 and statistics.mean(measurements) != 0 else 0.0
            }
        except Exception:
            return {'calculation_error': True}
    
    def _generate_composite_signature(self, observations: List[BehaviorObservation]) -> str:
        """Generate a composite signature from all behavioral observations"""
        signature_components = []
        
        for obs in observations:
            # Create a signature for this observation
            if 'mean' in obs.statistical_profile:
                component_sig = f"{obs.component.value}:{obs.statistical_profile['mean']:.6f}"
                signature_components.append(component_sig)
        
        # Combine all components
        combined_signature = '|'.join(signature_components)
        
        # Create hash
        return hashlib.sha3_256(combined_signature.encode()).hexdigest()[:32]
    
    def _estimate_system_load(self) -> float:
        """Estimate current system load factor"""
        try:
            # Simple load estimation based on timing consistency
            test_times = []
            for _ in range(5):
                start = time.perf_counter()
                # Simple computation
                result = sum(i * i for i in range(10000))
                test_times.append(time.perf_counter() - start)
            
            if len(test_times) > 1:
                cv = statistics.stdev(test_times) / statistics.mean(test_times)
                # Higher coefficient of variation indicates higher system load
                return min(cv * 10, 1.0)  # Normalize to 0-1 range
            else:
                return 0.5  # Default moderate load
                
        except Exception:
            return 0.5  # Default on error
    
    def _calculate_reliability(self, observations: List[BehaviorObservation]) -> float:
        """Calculate overall reliability score for the behavioral fingerprint"""
        if not observations:
            return 0.0
        
        # Weight by confidence and stability prediction
        total_score = 0.0
        total_weight = 0.0
        
        for obs in observations:
            weight = obs.confidence
            score = obs.stability_prediction * obs.confidence
            total_score += score
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def compare_behavioral_fingerprints(self, fp1: BehavioralFingerprint, fp2: BehavioralFingerprint, tolerance: float = 0.15) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Compare two behavioral fingerprints
        
        Args:
            fp1: First fingerprint
            fp2: Second fingerprint  
            tolerance: Allowed variation tolerance (default 15%)
            
        Returns:
            Tuple of (is_match, similarity_score, detailed_comparison)
        """
        detailed_comparison = {
            'component_similarities': {},
            'overall_similarity': 0.0,
            'matching_components': 0,
            'total_components': 0
        }
        
        # Create lookup for fp2 observations
        fp2_lookup = {obs.component: obs for obs in fp2.observations}
        
        similarities = []
        matching_components = 0
        
        for obs1 in fp1.observations:
            if obs1.component in fp2_lookup:
                obs2 = fp2_lookup[obs1.component]
                similarity = self._compare_behavioral_observations(obs1, obs2, tolerance)
                similarities.append(similarity)
                detailed_comparison['component_similarities'][obs1.component.value] = similarity
                
                if similarity >= (1.0 - tolerance):
                    matching_components += 1
                
                detailed_comparison['total_components'] += 1
        
        # Calculate overall similarity
        overall_similarity = statistics.mean(similarities) if similarities else 0.0
        detailed_comparison['overall_similarity'] = overall_similarity
        detailed_comparison['matching_components'] = matching_components
        
        # Consider fingerprints matching if overall similarity is above threshold
        is_match = overall_similarity >= (1.0 - tolerance)
        
        return is_match, overall_similarity, detailed_comparison
    
    def _compare_behavioral_observations(self, obs1: BehaviorObservation, obs2: BehaviorObservation, tolerance: float) -> float:
        """Compare two behavioral observations"""
        if obs1.component != obs2.component:
            return 0.0
        
        if 'mean' not in obs1.statistical_profile or 'mean' not in obs2.statistical_profile:
            return 0.0
        
        try:
            mean1 = obs1.statistical_profile['mean']
            mean2 = obs2.statistical_profile['mean']
            
            if mean1 == 0 and mean2 == 0:
                return 1.0
            elif mean1 == 0 or mean2 == 0:
                return 0.0
            else:
                # Calculate percentage difference
                diff = abs(mean1 - mean2) / max(mean1, mean2)
                similarity = max(0.0, 1.0 - (diff / tolerance))
                return similarity
                
        except Exception:
            return 0.0
    
    def generate_stability_report(self, fingerprint: BehavioralFingerprint) -> Dict[str, Any]:
        """Generate a stability report for a behavioral fingerprint"""
        report = {
            'generation_time': fingerprint.generation_time,
            'system_load_factor': fingerprint.system_load_factor,
            'reliability_score': fingerprint.reliability_score,
            'component_analysis': {},
            'recommendations': []
        }
        
        for obs in fingerprint.observations:
            component_name = obs.component.value
            report['component_analysis'][component_name] = {
                'confidence': obs.confidence,
                'stability_prediction': obs.stability_prediction,
                'measurement_count': len(obs.measurements),
                'statistical_health': self._assess_statistical_health(obs.statistical_profile)
            }
        
        # Generate recommendations
        if fingerprint.system_load_factor > 0.7:
            report['recommendations'].append("High system load detected - consider re-measuring under lighter load")
        
        if fingerprint.reliability_score < 0.8:
            report['recommendations'].append("Low reliability score - some measurements may be inconsistent")
        
        low_confidence_components = [obs.component.value for obs in fingerprint.observations if obs.confidence < 0.5]
        if low_confidence_components:
            report['recommendations'].append(f"Low confidence components detected: {', '.join(low_confidence_components)}")
        
        return report
    
    def _assess_statistical_health(self, profile: Dict[str, float]) -> str:
        """Assess the statistical health of measurements"""
        if 'error' in profile or 'calculation_error' in profile:
            return "ERROR"
        
        if 'cv' in profile:
            cv = profile['cv']
            if cv < 0.1:
                return "EXCELLENT"  # Low variability
            elif cv < 0.2:
                return "GOOD"
            elif cv < 0.5:
                return "FAIR"
            else:
                return "POOR"  # High variability
        
        return "UNKNOWN"
