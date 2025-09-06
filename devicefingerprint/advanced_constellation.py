"""
Advanced Hardware Constellation Fingerprinting
============================================

This module implements the "Hardware Constellation" approach - a novel method that creates
a composite score of many hard-to-change system properties instead of a single identifier.
Verification becomes a similarity check rather than exact match, making it robust to
legitimate hardware changes while maintaining strong security.
"""

import hashlib
import time
import statistics
import subprocess
import json
import platform
import threading
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
import math

class ConstellationComponent(Enum):
    """Different components of the hardware constellation"""
    GPU_PROFILE = "gpu_profile"
    MEMORY_TIMING = "memory_timing"
    CPU_FEATURES = "cpu_features"
    STORAGE_CHARACTERISTICS = "storage_characteristics"
    NETWORK_STACK = "network_stack"
    SYSTEM_BEHAVIOR = "system_behavior"

@dataclass
class ConstellationObservation:
    """A single observation in the hardware constellation"""
    component: ConstellationComponent
    value: Any
    confidence: float
    timestamp: float
    stability_score: float

@dataclass
class HardwareConstellation:
    """Complete hardware constellation fingerprint"""
    observations: List[ConstellationObservation]
    constellation_id: str
    generation_timestamp: float
    total_confidence: float
    stability_prediction: float

class AdvancedHardwareProfiler:
    """
    Advanced Hardware Constellation Generator
    
    Implements novel deep hardware profiling techniques for robust device identification.
    Uses probabilistic matching and behavioral analysis rather than exact string matching.
    """
    
    def __init__(self):
        self.cache = {}
        self.benchmark_cache = {}
        
    def generate_constellation(self) -> HardwareConstellation:
        """Generate a complete hardware constellation fingerprint"""
        observations = []
        
        # GPU Fingerprinting
        gpu_obs = self._profile_gpu()
        if gpu_obs:
            observations.append(gpu_obs)
            
        # Memory Timing Analysis
        memory_obs = self._analyze_memory_timing()
        observations.append(memory_obs)
        
        # Advanced CPU Fingerprinting
        cpu_obs = self._profile_cpu_advanced()
        observations.append(cpu_obs)
        
        # Storage Characteristics
        storage_obs = self._analyze_storage_characteristics()
        observations.append(storage_obs)
        
        # Network Stack Timing
        network_obs = self._profile_network_stack()
        observations.append(network_obs)
        
        # System Behavior Analysis
        behavior_obs = self._analyze_system_behavior()
        observations.append(behavior_obs)
        
        # Calculate overall metrics
        total_confidence = sum(obs.confidence for obs in observations) / len(observations)
        stability_prediction = self._predict_stability(observations)
        
        # Generate constellation ID with proper serialization
        def serialize_observation(obs):
            obs_dict = asdict(obs)
            # Convert enum to its value
            obs_dict['component'] = obs_dict['component'].value if hasattr(obs_dict['component'], 'value') else str(obs_dict['component'])
            return obs_dict
        
        constellation_data = json.dumps([serialize_observation(obs) for obs in observations], sort_keys=True)
        constellation_id = hashlib.sha3_256(constellation_data.encode()).hexdigest()[:32]
        
        return HardwareConstellation(
            observations=observations,
            constellation_id=constellation_id,
            generation_timestamp=time.time(),
            total_confidence=total_confidence,
            stability_prediction=stability_prediction
        )
    
    def _profile_gpu(self) -> Optional[ConstellationObservation]:
        """Advanced GPU fingerprinting using multiple detection methods"""
        try:
            gpu_profile = {}
            confidence = 0.0
            
            # Method 1: Try OpenGL/DirectX detection
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'path', 'win32_VideoController', 'get', 'name,AdapterRAM,DriverVersion'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\\n')
                        for line in lines[1:]:  # Skip header
                            if line.strip():
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    gpu_profile['name'] = ' '.join(parts[:-2]) if len(parts) > 2 else parts[0]
                                    gpu_profile['memory'] = parts[-2] if parts[-2].isdigit() else "unknown"
                                    confidence = 0.9
                                    break
                except Exception:
                    pass
            
            # Method 2: Linux GPU detection
            elif platform.system() == "Linux":
                try:
                    result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.split('\\n'):
                            if 'VGA' in line or 'Display' in line:
                                gpu_profile['name'] = line.split(': ')[-1] if ': ' in line else line
                                confidence = 0.8
                                break
                except Exception:
                    pass
            
            # Method 3: Cross-platform fallback
            if not gpu_profile:
                gpu_profile = {
                    'name': 'integrated_or_unknown',
                    'detection_method': 'fallback'
                }
                confidence = 0.3
            
            return ConstellationObservation(
                component=ConstellationComponent.GPU_PROFILE,
                value=gpu_profile,
                confidence=confidence,
                timestamp=time.time(),
                stability_score=0.95  # GPU specs rarely change
            )
            
        except Exception:
            return None
    
    def _analyze_memory_timing(self) -> ConstellationObservation:
        """Memory timing analysis for unique RAM/motherboard signatures"""
        try:
            timing_profile = {}
            
            # Simple memory bandwidth test
            test_size = 1024 * 1024  # 1MB
            test_data = bytearray(test_size)
            
            # Measure write timing
            start_time = time.perf_counter()
            for i in range(0, test_size, 8):
                test_data[i:i+8] = b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07'
            write_time = time.perf_counter() - start_time
            
            # Measure read timing
            start_time = time.perf_counter()
            checksum = 0
            for i in range(0, test_size, 8):
                checksum += sum(test_data[i:i+8])
            read_time = time.perf_counter() - start_time
            
            timing_profile = {
                'write_time_ms': round(write_time * 1000, 3),
                'read_time_ms': round(read_time * 1000, 3),
                'bandwidth_ratio': round(write_time / read_time, 3) if read_time > 0 else 0
            }
            
            return ConstellationObservation(
                component=ConstellationComponent.MEMORY_TIMING,
                value=timing_profile,
                confidence=0.7,
                timestamp=time.time(),
                stability_score=0.8  # Memory timing is fairly stable
            )
            
        except Exception as e:
            return ConstellationObservation(
                component=ConstellationComponent.MEMORY_TIMING,
                value={'error': str(e)},
                confidence=0.1,
                timestamp=time.time(),
                stability_score=0.5
            )
    
    def _profile_cpu_advanced(self) -> ConstellationObservation:
        """Advanced CPU fingerprinting beyond basic processor strings"""
        try:
            cpu_profile = {}
            
            # Basic CPU info
            cpu_profile['system'] = platform.system()
            cpu_profile['machine'] = platform.machine()
            cpu_profile['processor'] = platform.processor()
            
            # CPU performance characteristics
            cpu_profile.update(self._cpu_performance_signature())
            
            # Platform-specific advanced detection
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'cpu', 'get', 'NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\\n')
                        for line in lines[1:]:
                            if line.strip():
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    cpu_profile['max_clock_mhz'] = parts[0]
                                    cpu_profile['cores'] = parts[1]
                                    cpu_profile['logical_processors'] = parts[2]
                                    break
                except Exception:
                    pass
            
            return ConstellationObservation(
                component=ConstellationComponent.CPU_FEATURES,
                value=cpu_profile,
                confidence=0.9,
                timestamp=time.time(),
                stability_score=0.98  # CPU features almost never change
            )
            
        except Exception as e:
            return ConstellationObservation(
                component=ConstellationComponent.CPU_FEATURES,
                value={'error': str(e), 'fallback': platform.processor()},
                confidence=0.4,
                timestamp=time.time(),
                stability_score=0.7
            )
    
    def _cpu_performance_signature(self) -> Dict[str, Any]:
        """Generate unique CPU performance signature through micro-benchmarks"""
        try:
            # Simple computational benchmark
            iterations = 10000
            
            # Integer operations timing
            start_time = time.perf_counter()
            result = 0
            for i in range(iterations):
                result += i * i
            int_time = time.perf_counter() - start_time
            
            # Floating point operations timing
            start_time = time.perf_counter()
            result = 0.0
            for i in range(iterations):
                result += math.sin(i) * math.cos(i)
            float_time = time.perf_counter() - start_time
            
            # Memory access pattern timing
            data = list(range(1000))
            start_time = time.perf_counter()
            for _ in range(100):
                data.sort()
                data.reverse()
            memory_time = time.perf_counter() - start_time
            
            return {
                'int_ops_ms': round(int_time * 1000, 3),
                'float_ops_ms': round(float_time * 1000, 3),
                'memory_ops_ms': round(memory_time * 1000, 3),
                'performance_ratio': round(int_time / float_time, 3) if float_time > 0 else 0
            }
            
        except Exception:
            return {'benchmark_error': True}
    
    def _analyze_storage_characteristics(self) -> ConstellationObservation:
        """Analyze storage device characteristics for fingerprinting"""
        try:
            storage_profile = {}
            
            # Simple I/O timing test
            test_file = 'temp_fingerprint_test.tmp'
            test_data = b'0' * 1024  # 1KB test
            
            try:
                # Write test
                start_time = time.perf_counter()
                with open(test_file, 'wb') as f:
                    for _ in range(100):  # 100KB total
                        f.write(test_data)
                        f.flush()
                write_time = time.perf_counter() - start_time
                
                # Read test
                start_time = time.perf_counter()
                with open(test_file, 'rb') as f:
                    while f.read(1024):
                        pass
                read_time = time.perf_counter() - start_time
                
                storage_profile = {
                    'write_time_ms': round(write_time * 1000, 3),
                    'read_time_ms': round(read_time * 1000, 3),
                    'io_ratio': round(write_time / read_time, 3) if read_time > 0 else 0
                }
                
                # Cleanup
                try:
                    import os
                    os.remove(test_file)
                except:
                    pass
                    
            except Exception as e:
                storage_profile = {'io_test_error': str(e)}
            
            return ConstellationObservation(
                component=ConstellationComponent.STORAGE_CHARACTERISTICS,
                value=storage_profile,
                confidence=0.6,
                timestamp=time.time(),
                stability_score=0.7  # Storage can change, but not frequently
            )
            
        except Exception as e:
            return ConstellationObservation(
                component=ConstellationComponent.STORAGE_CHARACTERISTICS,
                value={'error': str(e)},
                confidence=0.2,
                timestamp=time.time(),
                stability_score=0.5
            )
    
    def _profile_network_stack(self) -> ConstellationObservation:
        """Profile network stack characteristics"""
        try:
            network_profile = {}
            
            # Basic network interface detection
            try:
                import socket
                hostname = socket.gethostname()
                network_profile['hostname'] = hostname
                
                # Try to get network interfaces (cross-platform approach)
                try:
                    local_ip = socket.gethostbyname(hostname)
                    network_profile['local_ip_pattern'] = '.'.join(local_ip.split('.')[:-1]) + '.x'
                except:
                    network_profile['local_ip_pattern'] = 'unknown'
                    
            except Exception:
                network_profile['network_error'] = True
            
            return ConstellationObservation(
                component=ConstellationComponent.NETWORK_STACK,
                value=network_profile,
                confidence=0.5,
                timestamp=time.time(),
                stability_score=0.6  # Network config can change
            )
            
        except Exception as e:
            return ConstellationObservation(
                component=ConstellationComponent.NETWORK_STACK,
                value={'error': str(e)},
                confidence=0.1,
                timestamp=time.time(),
                stability_score=0.3
            )
    
    def _analyze_system_behavior(self) -> ConstellationObservation:
        """Analyze system behavior patterns through micro-benchmarks"""
        try:
            behavior_profile = {}
            
            # Thread scheduling behavior
            results = []
            for _ in range(5):
                start_time = time.perf_counter()
                
                def worker():
                    for i in range(1000):
                        math.sqrt(i)
                
                threads = [threading.Thread(target=worker) for _ in range(4)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                
                results.append(time.perf_counter() - start_time)
            
            if results:
                behavior_profile = {
                    'avg_thread_time_ms': round(statistics.mean(results) * 1000, 3),
                    'thread_time_stddev': round(statistics.stdev(results) * 1000, 3) if len(results) > 1 else 0,
                    'scheduler_signature': round(min(results) / max(results), 3) if max(results) > 0 else 0
                }
            
            return ConstellationObservation(
                component=ConstellationComponent.SYSTEM_BEHAVIOR,
                value=behavior_profile,
                confidence=0.7,
                timestamp=time.time(),
                stability_score=0.8  # System behavior is generally stable
            )
            
        except Exception as e:
            return ConstellationObservation(
                component=ConstellationComponent.SYSTEM_BEHAVIOR,
                value={'error': str(e)},
                confidence=0.2,
                timestamp=time.time(),
                stability_score=0.4
            )
    
    def _predict_stability(self, observations: List[ConstellationObservation]) -> float:
        """Predict how stable this constellation will be over time"""
        if not observations:
            return 0.0
        
        # Weight by confidence and inherent stability scores
        weighted_stability = sum(obs.stability_score * obs.confidence for obs in observations)
        total_weight = sum(obs.confidence for obs in observations)
        
        return weighted_stability / total_weight if total_weight > 0 else 0.0
    
    def compare_constellations(self, constellation1: HardwareConstellation, constellation2: HardwareConstellation) -> Tuple[float, Dict[str, float]]:
        """
        Compare two hardware constellations for similarity
        
        Returns:
            Tuple of (overall_similarity_score, component_similarities)
        """
        component_similarities = {}
        
        # Create lookup for constellation2 observations
        obs2_lookup = {obs.component: obs for obs in constellation2.observations}
        
        valid_comparisons = 0
        total_similarity = 0.0
        
        for obs1 in constellation1.observations:
            if obs1.component in obs2_lookup:
                obs2 = obs2_lookup[obs1.component]
                similarity = self._compare_observations(obs1, obs2)
                component_similarities[obs1.component.value] = similarity
                
                # Weight by confidence
                weight = min(obs1.confidence, obs2.confidence)
                total_similarity += similarity * weight
                valid_comparisons += weight
        
        overall_similarity = total_similarity / valid_comparisons if valid_comparisons > 0 else 0.0
        
        return overall_similarity, component_similarities
    
    def _compare_observations(self, obs1: ConstellationObservation, obs2: ConstellationObservation) -> float:
        """Compare two constellation observations for similarity"""
        if obs1.component != obs2.component:
            return 0.0
        
        try:
            if obs1.component == ConstellationComponent.GPU_PROFILE:
                return self._compare_gpu_profiles(obs1.value, obs2.value)
            elif obs1.component == ConstellationComponent.MEMORY_TIMING:
                return self._compare_timing_profiles(obs1.value, obs2.value)
            elif obs1.component == ConstellationComponent.CPU_FEATURES:
                return self._compare_cpu_profiles(obs1.value, obs2.value)
            elif obs1.component == ConstellationComponent.STORAGE_CHARACTERISTICS:
                return self._compare_timing_profiles(obs1.value, obs2.value)
            elif obs1.component == ConstellationComponent.NETWORK_STACK:
                return self._compare_network_profiles(obs1.value, obs2.value)
            elif obs1.component == ConstellationComponent.SYSTEM_BEHAVIOR:
                return self._compare_timing_profiles(obs1.value, obs2.value)
            else:
                # Generic comparison
                return 1.0 if obs1.value == obs2.value else 0.0
                
        except Exception:
            return 0.0
    
    def _compare_gpu_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """Compare GPU profiles"""
        if 'name' in profile1 and 'name' in profile2:
            return 1.0 if profile1['name'] == profile2['name'] else 0.0
        return 0.5  # Partial match if incomplete data
    
    def _compare_timing_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """Compare timing-based profiles with tolerance for minor variations"""
        similarities = []
        
        for key in profile1:
            if key in profile2 and isinstance(profile1[key], (int, float)) and isinstance(profile2[key], (int, float)):
                val1, val2 = profile1[key], profile2[key]
                if val1 == 0 and val2 == 0:
                    similarities.append(1.0)
                elif val1 == 0 or val2 == 0:
                    similarities.append(0.0)
                else:
                    # Allow for 20% variation in timing measurements
                    ratio = min(val1, val2) / max(val1, val2)
                    similarity = max(0.0, (ratio - 0.8) / 0.2)  # Linear scale from 80% to 100%
                    similarities.append(similarity)
        
        return statistics.mean(similarities) if similarities else 0.0
    
    def _compare_cpu_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """Compare CPU profiles"""
        exact_match_keys = ['system', 'machine', 'processor', 'cores', 'logical_processors']
        timing_keys = ['int_ops_ms', 'float_ops_ms', 'memory_ops_ms']
        
        exact_matches = sum(1 for key in exact_match_keys if profile1.get(key) == profile2.get(key))
        exact_score = exact_matches / len(exact_match_keys)
        
        timing_profile1 = {k: v for k, v in profile1.items() if k in timing_keys}
        timing_profile2 = {k: v for k, v in profile2.items() if k in timing_keys}
        timing_score = self._compare_timing_profiles(timing_profile1, timing_profile2)
        
        # Weight: 70% exact matches, 30% timing similarity
        return 0.7 * exact_score + 0.3 * timing_score
    
    def _compare_network_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """Compare network profiles"""
        if 'hostname' in profile1 and 'hostname' in profile2:
            return 1.0 if profile1['hostname'] == profile2['hostname'] else 0.0
        return 0.5  # Partial match if incomplete
