"""
Machine Learning enhancements for DeviceFingerprint Library
Provides intelligent device classification and anomaly detection
"""

import json
import math
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import statistics

class DeviceClass(Enum):
    """Device classification categories"""
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SERVER = "server"
    WORKSTATION = "workstation"
    VIRTUAL_MACHINE = "virtual_machine"
    MOBILE_DEVICE = "mobile_device"
    EMBEDDED_SYSTEM = "embedded_system"
    UNKNOWN = "unknown"

class AnomalyType(Enum):
    """Types of anomalies that can be detected"""
    HARDWARE_INCONSISTENCY = "hardware_inconsistency"
    UNUSUAL_PERFORMANCE = "unusual_performance"
    PATTERN_DEVIATION = "pattern_deviation"
    TEMPORAL_ANOMALY = "temporal_anomaly"
    CONFIGURATION_DRIFT = "configuration_drift"

@dataclass
class DeviceProfile:
    """Machine learning profile for a device"""
    device_id: str
    device_class: DeviceClass
    confidence_score: float
    feature_vector: List[float]
    learned_patterns: Dict[str, Any]
    last_updated: datetime
    anomaly_count: int = 0
    stability_score: float = 1.0

@dataclass
class AnomalyDetection:
    """Detected anomaly information"""
    anomaly_type: AnomalyType
    severity: float  # 0.0 to 1.0
    description: str
    affected_components: List[str]
    confidence: float
    timestamp: datetime
    suggested_action: str

class FeatureExtractor:
    """Extract machine learning features from device fingerprints"""
    
    @staticmethod
    def extract_features(fingerprint_data: Dict[str, str]) -> List[float]:
        """Extract numerical features from fingerprint data"""
        features = []
        
        # CPU features
        cpu_info = fingerprint_data.get('cpu', '')
        features.extend(FeatureExtractor._extract_cpu_features(cpu_info))
        
        # Memory features
        memory_info = fingerprint_data.get('memory', '')
        features.extend(FeatureExtractor._extract_memory_features(memory_info))
        
        # Platform features
        platform_info = fingerprint_data.get('platform', '')
        features.extend(FeatureExtractor._extract_platform_features(platform_info))
        
        # Network features
        network_info = fingerprint_data.get('network', '')
        features.extend(FeatureExtractor._extract_network_features(network_info))
        
        # General features
        features.extend(FeatureExtractor._extract_general_features(fingerprint_data))
        
        return features
    
    @staticmethod
    def _extract_cpu_features(cpu_info: str) -> List[float]:
        """Extract CPU-related features"""
        features = []
        
        # CPU vendor (Intel=1, AMD=2, ARM=3, Other=0)
        if 'intel' in cpu_info.lower():
            features.append(1.0)
        elif 'amd' in cpu_info.lower():
            features.append(2.0)
        elif 'arm' in cpu_info.lower():
            features.append(3.0)
        else:
            features.append(0.0)
        
        # CPU architecture (64-bit=1, 32-bit=0)
        features.append(1.0 if 'x64' in cpu_info or 'x86_64' in cpu_info else 0.0)
        
        # Extract core count (estimate from string)
        import re
        core_match = re.search(r'(\d+)[- ]core', cpu_info.lower())
        if core_match:
            features.append(float(core_match.group(1)))
        else:
            # Estimate based on processor name patterns
            if 'quad' in cpu_info.lower():
                features.append(4.0)
            elif 'dual' in cpu_info.lower():
                features.append(2.0)
            elif 'single' in cpu_info.lower():
                features.append(1.0)
            else:
                features.append(2.0)  # Default estimate
        
        # CPU generation/age indicator (newer=higher value)
        features.append(FeatureExtractor._estimate_cpu_generation(cpu_info))
        
        return features
    
    @staticmethod
    def _extract_memory_features(memory_info: str) -> List[float]:
        """Extract memory-related features"""
        features = []
        
        # Extract memory size in GB
        import re
        memory_match = re.search(r'(\d+(?:\.\d+)?)\s*([GMT]B)', memory_info, re.IGNORECASE)
        if memory_match:
            size = float(memory_match.group(1))
            unit = memory_match.group(2).upper()
            
            if unit == 'GB':
                features.append(size)
            elif unit == 'MB':
                features.append(size / 1024)
            elif unit == 'TB':
                features.append(size * 1024)
            else:
                features.append(4.0)  # Default 4GB
        else:
            features.append(4.0)  # Default
        
        # Memory type indicator (DDR4=4, DDR3=3, etc.)
        if 'ddr5' in memory_info.lower():
            features.append(5.0)
        elif 'ddr4' in memory_info.lower():
            features.append(4.0)
        elif 'ddr3' in memory_info.lower():
            features.append(3.0)
        elif 'ddr2' in memory_info.lower():
            features.append(2.0)
        else:
            features.append(3.0)  # Default DDR3
        
        return features
    
    @staticmethod
    def _extract_platform_features(platform_info: str) -> List[float]:
        """Extract platform-related features"""
        features = []
        
        # Operating system family
        platform_lower = platform_info.lower()
        if 'windows' in platform_lower:
            features.append(1.0)
        elif 'linux' in platform_lower:
            features.append(2.0)
        elif 'darwin' in platform_lower or 'macos' in platform_lower:
            features.append(3.0)
        elif 'freebsd' in platform_lower:
            features.append(4.0)
        else:
            features.append(0.0)
        
        # Architecture
        if 'x86_64' in platform_lower or 'amd64' in platform_lower:
            features.append(64.0)
        elif 'x86' in platform_lower or 'i386' in platform_lower:
            features.append(32.0)
        elif 'arm64' in platform_lower:
            features.append(64.0)
        elif 'arm' in platform_lower:
            features.append(32.0)
        else:
            features.append(64.0)  # Default 64-bit
        
        return features
    
    @staticmethod
    def _extract_network_features(network_info: str) -> List[float]:
        """Extract network-related features"""
        features = []
        
        # MAC address pattern analysis
        if network_info:
            # Count of network interfaces (estimate from MAC addresses)
            mac_count = len([x for x in network_info.split() if ':' in x and len(x) == 17])
            features.append(float(mac_count))
            
            # Network vendor analysis (based on OUI)
            features.append(FeatureExtractor._analyze_network_vendor(network_info))
        else:
            features.extend([1.0, 0.0])  # Default single interface, unknown vendor
        
        return features
    
    @staticmethod
    def _extract_general_features(fingerprint_data: Dict[str, str]) -> List[float]:
        """Extract general features"""
        features = []
        
        # Total data complexity (entropy-like measure)
        all_data = ' '.join(fingerprint_data.values())
        features.append(len(set(all_data.lower())) / max(1, len(all_data)))
        
        # Number of different component types
        features.append(float(len(fingerprint_data)))
        
        # Average component data length
        if fingerprint_data:
            avg_length = sum(len(v) for v in fingerprint_data.values()) / len(fingerprint_data)
            features.append(avg_length)
        else:
            features.append(0.0)
        
        return features
    
    @staticmethod
    def _estimate_cpu_generation(cpu_info: str) -> float:
        """Estimate CPU generation/age for feature extraction"""
        cpu_lower = cpu_info.lower()
        
        # Intel generations
        intel_generations = {
            '13th': 13.0, '12th': 12.0, '11th': 11.0, '10th': 10.0,
            '9th': 9.0, '8th': 8.0, '7th': 7.0, '6th': 6.0,
            'skylake': 6.0, 'haswell': 4.0, 'ivy': 3.0, 'sandy': 2.0
        }
        
        for gen, value in intel_generations.items():
            if gen in cpu_lower:
                return value
        
        # AMD generations (rough estimates)
        if 'ryzen' in cpu_lower:
            if '7000' in cpu_lower:
                return 12.0
            elif '6000' in cpu_lower:
                return 11.0
            elif '5000' in cpu_lower:
                return 10.0
            elif '4000' in cpu_lower:
                return 9.0
            elif '3000' in cpu_lower:
                return 8.0
            elif '2000' in cpu_lower:
                return 7.0
            elif '1000' in cpu_lower:
                return 6.0
        
        return 5.0  # Default moderate generation
    
    @staticmethod
    def _analyze_network_vendor(network_info: str) -> float:
        """Analyze network vendor from MAC address OUI"""
        # Common vendor OUIs mapped to values
        vendor_patterns = {
            '00:1b:63': 1.0,  # Apple
            '00:50:56': 2.0,  # VMware
            '08:00:27': 3.0,  # VirtualBox
            '00:0c:29': 4.0,  # VMware (another range)
            '52:54:00': 5.0,  # QEMU/KVM
        }
        
        for pattern, value in vendor_patterns.items():
            if pattern in network_info:
                return value
        
        return 0.0  # Unknown vendor

class DeviceClassifier:
    """Machine learning device classifier"""
    
    def __init__(self):
        self.device_profiles = {}
        self.classification_rules = self._init_classification_rules()
    
    def _init_classification_rules(self) -> Dict[DeviceClass, Dict[str, Any]]:
        """Initialize classification rules based on feature patterns"""
        return {
            DeviceClass.DESKTOP: {
                'cpu_cores_min': 2,
                'memory_gb_min': 4,
                'platform_types': [1.0],  # Windows primarily
                'confidence_threshold': 0.7
            },
            DeviceClass.LAPTOP: {
                'cpu_cores_max': 8,
                'memory_gb_range': (2, 32),
                'platform_types': [1.0, 3.0],  # Windows, macOS
                'confidence_threshold': 0.6
            },
            DeviceClass.SERVER: {
                'cpu_cores_min': 4,
                'memory_gb_min': 8,
                'platform_types': [2.0],  # Linux primarily
                'confidence_threshold': 0.8
            },
            DeviceClass.VIRTUAL_MACHINE: {
                'network_vendor_indicators': [2.0, 3.0, 4.0, 5.0],  # VM vendors
                'confidence_threshold': 0.9
            },
            DeviceClass.WORKSTATION: {
                'cpu_cores_min': 6,
                'memory_gb_min': 16,
                'cpu_generation_min': 6.0,
                'confidence_threshold': 0.75
            }
        }
    
    def classify_device(self, fingerprint_data: Dict[str, str]) -> Tuple[DeviceClass, float]:
        """Classify device based on fingerprint data"""
        features = FeatureExtractor.extract_features(fingerprint_data)
        
        # Extract key features for classification
        cpu_vendor = features[0] if len(features) > 0 else 0
        cpu_arch = features[1] if len(features) > 1 else 0
        cpu_cores = features[2] if len(features) > 2 else 2
        cpu_generation = features[3] if len(features) > 3 else 5
        memory_gb = features[4] if len(features) > 4 else 4
        memory_type = features[5] if len(features) > 5 else 3
        platform_type = features[6] if len(features) > 6 else 1
        network_vendor = features[9] if len(features) > 9 else 0
        
        # Calculate confidence for each device class
        class_scores = {}
        
        for device_class, rules in self.classification_rules.items():
            score = 0.0
            max_score = 0.0
            
            # Check CPU cores
            if 'cpu_cores_min' in rules:
                max_score += 1.0
                if cpu_cores >= rules['cpu_cores_min']:
                    score += 1.0
            
            if 'cpu_cores_max' in rules:
                max_score += 1.0
                if cpu_cores <= rules['cpu_cores_max']:
                    score += 1.0
            
            # Check memory
            if 'memory_gb_min' in rules:
                max_score += 1.0
                if memory_gb >= rules['memory_gb_min']:
                    score += 1.0
            
            if 'memory_gb_range' in rules:
                min_mem, max_mem = rules['memory_gb_range']
                max_score += 1.0
                if min_mem <= memory_gb <= max_mem:
                    score += 1.0
            
            # Check platform
            if 'platform_types' in rules:
                max_score += 1.0
                if platform_type in rules['platform_types']:
                    score += 1.0
            
            # Check VM indicators
            if 'network_vendor_indicators' in rules:
                max_score += 2.0  # Higher weight for VM detection
                if network_vendor in rules['network_vendor_indicators']:
                    score += 2.0
            
            # Check CPU generation
            if 'cpu_generation_min' in rules:
                max_score += 0.5
                if cpu_generation >= rules['cpu_generation_min']:
                    score += 0.5
            
            # Calculate normalized score
            if max_score > 0:
                class_scores[device_class] = score / max_score
            else:
                class_scores[device_class] = 0.0
        
        # Find best classification
        if class_scores:
            best_class = max(class_scores.keys(), key=lambda k: class_scores[k])
            confidence = class_scores[best_class]
            
            # Apply confidence threshold
            threshold = self.classification_rules[best_class].get('confidence_threshold', 0.5)
            if confidence >= threshold:
                return best_class, confidence
        
        return DeviceClass.UNKNOWN, 0.5
    
    def learn_device_pattern(self, device_id: str, fingerprint_data: Dict[str, str]):
        """Learn and update device patterns"""
        device_class, confidence = self.classify_device(fingerprint_data)
        features = FeatureExtractor.extract_features(fingerprint_data)
        
        if device_id not in self.device_profiles:
            # Create new profile
            self.device_profiles[device_id] = DeviceProfile(
                device_id=device_id,
                device_class=device_class,
                confidence_score=confidence,
                feature_vector=features,
                learned_patterns={},
                last_updated=datetime.utcnow()
            )
        else:
            # Update existing profile
            profile = self.device_profiles[device_id]
            
            # Weighted average of features
            alpha = 0.1  # Learning rate
            for i, new_feature in enumerate(features):
                if i < len(profile.feature_vector):
                    profile.feature_vector[i] = (
                        (1 - alpha) * profile.feature_vector[i] + 
                        alpha * new_feature
                    )
            
            # Update classification if confidence improved
            if confidence > profile.confidence_score:
                profile.device_class = device_class
                profile.confidence_score = confidence
            
            profile.last_updated = datetime.utcnow()

class AnomalyDetector:
    """Detect anomalies in device fingerprints using statistical methods"""
    
    def __init__(self, sensitivity: float = 0.8):
        self.sensitivity = sensitivity
        self.baseline_patterns = {}
        self.anomaly_history = {}
    
    def establish_baseline(self, device_id: str, fingerprint_history: List[Dict[str, str]]):
        """Establish baseline patterns for a device"""
        if len(fingerprint_history) < 3:
            return  # Need minimum samples
        
        feature_history = [FeatureExtractor.extract_features(fp) for fp in fingerprint_history]
        
        # Calculate statistical baselines
        baseline = {
            'mean_features': [],
            'std_features': [],
            'feature_ranges': [],
            'pattern_stability': 0.0
        }
        
        # Calculate feature statistics
        num_features = len(feature_history[0]) if feature_history else 0
        for i in range(num_features):
            feature_values = [features[i] for features in feature_history if i < len(features)]
            
            if feature_values:
                baseline['mean_features'].append(statistics.mean(feature_values))
                baseline['std_features'].append(statistics.stdev(feature_values) if len(feature_values) > 1 else 0.0)
                baseline['feature_ranges'].append((min(feature_values), max(feature_values)))
        
        # Calculate pattern stability
        similarities = []
        for i in range(1, len(feature_history)):
            similarity = self._calculate_feature_similarity(feature_history[i-1], feature_history[i])
            similarities.append(similarity)
        
        baseline['pattern_stability'] = statistics.mean(similarities) if similarities else 1.0
        
        self.baseline_patterns[device_id] = baseline
    
    def detect_anomalies(self, device_id: str, current_fingerprint: Dict[str, str]) -> List[AnomalyDetection]:
        """Detect anomalies in current fingerprint"""
        if device_id not in self.baseline_patterns:
            return []  # No baseline established
        
        baseline = self.baseline_patterns[device_id]
        current_features = FeatureExtractor.extract_features(current_fingerprint)
        anomalies = []
        
        # Feature deviation detection
        anomalies.extend(self._detect_feature_anomalies(device_id, current_features, baseline))
        
        # Pattern consistency detection
        pattern_anomaly = self._detect_pattern_anomaly(device_id, current_features, baseline)
        if pattern_anomaly:
            anomalies.append(pattern_anomaly)
        
        # Temporal anomaly detection
        temporal_anomaly = self._detect_temporal_anomaly(device_id, current_fingerprint)
        if temporal_anomaly:
            anomalies.append(temporal_anomaly)
        
        # Store anomaly history
        if device_id not in self.anomaly_history:
            self.anomaly_history[device_id] = []
        
        self.anomaly_history[device_id].extend(anomalies)
        
        # Keep only recent anomalies (last 100)
        self.anomaly_history[device_id] = self.anomaly_history[device_id][-100:]
        
        return anomalies
    
    def _detect_feature_anomalies(self, device_id: str, features: List[float], 
                                baseline: Dict) -> List[AnomalyDetection]:
        """Detect anomalies in individual features"""
        anomalies = []
        
        for i, feature_value in enumerate(features):
            if i >= len(baseline['mean_features']):
                continue
            
            mean_val = baseline['mean_features'][i]
            std_val = baseline['std_features'][i]
            
            # Z-score based anomaly detection
            if std_val > 0:
                z_score = abs(feature_value - mean_val) / std_val
                
                # Anomaly threshold based on sensitivity
                threshold = 2.0 * (1.0 - self.sensitivity)  # Higher sensitivity = lower threshold
                
                if z_score > threshold:
                    anomaly = AnomalyDetection(
                        anomaly_type=AnomalyType.HARDWARE_INCONSISTENCY,
                        severity=min(1.0, z_score / 3.0),  # Cap at 1.0
                        description=f"Feature {i} deviates significantly from baseline (z-score: {z_score:.2f})",
                        affected_components=[f"feature_{i}"],
                        confidence=min(1.0, z_score / 2.0),
                        timestamp=datetime.utcnow(),
                        suggested_action="Investigate hardware changes or configuration drift"
                    )
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_pattern_anomaly(self, device_id: str, current_features: List[float], 
                              baseline: Dict) -> Optional[AnomalyDetection]:
        """Detect pattern-level anomalies"""
        if not baseline['mean_features']:
            return None
        
        # Calculate similarity to baseline pattern
        similarity = self._calculate_feature_similarity(current_features, baseline['mean_features'])
        baseline_stability = baseline['pattern_stability']
        
        # Pattern deviation threshold
        deviation_threshold = (1.0 - self.sensitivity) * 0.5  # 0.0 to 0.5 range
        
        if similarity < (baseline_stability - deviation_threshold):
            severity = 1.0 - similarity
            return AnomalyDetection(
                anomaly_type=AnomalyType.PATTERN_DEVIATION,
                severity=severity,
                description=f"Overall pattern similarity dropped to {similarity:.2f} (baseline: {baseline_stability:.2f})",
                affected_components=["global_pattern"],
                confidence=severity,
                timestamp=datetime.utcnow(),
                suggested_action="Review overall system configuration and hardware integrity"
            )
        
        return None
    
    def _detect_temporal_anomaly(self, device_id: str, 
                               current_fingerprint: Dict[str, str]) -> Optional[AnomalyDetection]:
        """Detect temporal anomalies (unusual timing patterns)"""
        if device_id not in self.anomaly_history:
            return None
        
        recent_anomalies = [a for a in self.anomaly_history[device_id] 
                          if (datetime.utcnow() - a.timestamp).seconds < 3600]  # Last hour
        
        # Check for anomaly clustering (too many anomalies in short time)
        if len(recent_anomalies) > 5:
            return AnomalyDetection(
                anomaly_type=AnomalyType.TEMPORAL_ANOMALY,
                severity=min(1.0, len(recent_anomalies) / 10.0),
                description=f"Unusual frequency of anomalies: {len(recent_anomalies)} in the last hour",
                affected_components=["temporal_pattern"],
                confidence=0.8,
                timestamp=datetime.utcnow(),
                suggested_action="Investigate potential system instability or security incidents"
            )
        
        return None
    
    def _calculate_feature_similarity(self, features1: List[float], features2: List[float]) -> float:
        """Calculate similarity between two feature vectors"""
        if not features1 or not features2:
            return 0.0
        
        min_len = min(len(features1), len(features2))
        if min_len == 0:
            return 0.0
        
        # Cosine similarity
        dot_product = sum(features1[i] * features2[i] for i in range(min_len))
        norm1 = math.sqrt(sum(f * f for f in features1[:min_len]))
        norm2 = math.sqrt(sum(f * f for f in features2[:min_len]))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

class IntelligentFingerprintManager:
    """Intelligent fingerprint management with ML capabilities"""
    
    def __init__(self):
        self.classifier = DeviceClassifier()
        self.anomaly_detector = AnomalyDetector()
        self.device_intelligence = {}
    
    def analyze_device(self, device_id: str, fingerprint_data: Dict[str, str], 
                      fingerprint_history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Comprehensive device analysis using ML"""
        
        # Device classification
        device_class, classification_confidence = self.classifier.classify_device(fingerprint_data)
        
        # Learn device patterns
        self.classifier.learn_device_pattern(device_id, fingerprint_data)
        
        # Establish baseline if history available
        if fingerprint_history and len(fingerprint_history) >= 3:
            self.anomaly_detector.establish_baseline(device_id, fingerprint_history)
        
        # Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies(device_id, fingerprint_data)
        
        # Calculate intelligence score
        intelligence_score = self._calculate_intelligence_score(device_id, classification_confidence, anomalies)
        
        # Store device intelligence
        self.device_intelligence[device_id] = {
            'device_class': device_class.value,
            'classification_confidence': classification_confidence,
            'anomalies_detected': len(anomalies),
            'intelligence_score': intelligence_score,
            'last_analysis': datetime.utcnow().isoformat()
        }
        
        return {
            'device_id': device_id,
            'device_class': device_class.value,
            'classification_confidence': classification_confidence,
            'anomalies': [asdict(anomaly) for anomaly in anomalies],
            'intelligence_score': intelligence_score,
            'recommendations': self._generate_recommendations(device_class, anomalies),
            'risk_assessment': self._assess_risk(anomalies, classification_confidence)
        }
    
    def _calculate_intelligence_score(self, device_id: str, classification_confidence: float, 
                                    anomalies: List[AnomalyDetection]) -> float:
        """Calculate overall intelligence score for device analysis"""
        base_score = classification_confidence
        
        # Penalty for anomalies
        anomaly_penalty = sum(anomaly.severity for anomaly in anomalies) * 0.1
        
        # Bonus for learning history
        learning_bonus = 0.1 if device_id in self.classifier.device_profiles else 0.0
        
        score = max(0.0, min(1.0, base_score - anomaly_penalty + learning_bonus))
        return score
    
    def _generate_recommendations(self, device_class: DeviceClass, 
                                anomalies: List[AnomalyDetection]) -> List[str]:
        """Generate intelligent recommendations"""
        recommendations = []
        
        # Class-specific recommendations
        if device_class == DeviceClass.VIRTUAL_MACHINE:
            recommendations.append("Consider VM-specific security policies")
        elif device_class == DeviceClass.SERVER:
            recommendations.append("Apply server-grade monitoring and access controls")
        elif device_class == DeviceClass.MOBILE_DEVICE:
            recommendations.append("Implement mobile device management (MDM) policies")
        
        # Anomaly-specific recommendations
        for anomaly in anomalies:
            if anomaly.anomaly_type == AnomalyType.HARDWARE_INCONSISTENCY:
                recommendations.append("Verify hardware configuration integrity")
            elif anomaly.anomaly_type == AnomalyType.PATTERN_DEVIATION:
                recommendations.append("Investigate system configuration changes")
            elif anomaly.anomaly_type == AnomalyType.TEMPORAL_ANOMALY:
                recommendations.append("Monitor for potential security incidents")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _assess_risk(self, anomalies: List[AnomalyDetection], classification_confidence: float) -> Dict[str, Any]:
        """Assess overall risk based on ML analysis"""
        if not anomalies:
            risk_level = "low"
            risk_score = 0.1
        else:
            max_severity = max(anomaly.severity for anomaly in anomalies)
            anomaly_count = len(anomalies)
            
            risk_score = min(1.0, max_severity + (anomaly_count * 0.1))
            
            if risk_score > 0.7:
                risk_level = "high"
            elif risk_score > 0.4:
                risk_level = "medium"
            else:
                risk_level = "low"
        
        # Adjust risk based on classification confidence
        if classification_confidence < 0.5:
            risk_score += 0.2
            if risk_level == "low":
                risk_level = "medium"
        
        return {
            'risk_level': risk_level,
            'risk_score': min(1.0, risk_score),
            'factors': [anomaly.description for anomaly in anomalies],
            'confidence_factor': classification_confidence
        }
