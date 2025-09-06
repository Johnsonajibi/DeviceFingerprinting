"""
Security monitoring enhancements for DeviceFingerprint Library
"""

import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class SecurityAlert(Enum):
    """Different types of security alerts"""
    DEVICE_CHANGE = "device_change"
    HARDWARE_MODIFICATION = "hardware_modification"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    FINGERPRINT_COLLISION = "fingerprint_collision"
    TAMPER_ATTEMPT = "tamper_attempt"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    alert_type: SecurityAlert
    timestamp: datetime
    device_id: str
    previous_fingerprint: Optional[str]
    current_fingerprint: str
    confidence_score: float
    affected_components: List[str]
    risk_level: str  # "low", "medium", "high", "critical"
    additional_data: Dict[str, Any]

class SecurityMonitor:
    """Advanced security monitoring for device fingerprints"""
    
    def __init__(self, alert_callback=None):
        self.logger = logging.getLogger(__name__)
        self.alert_callback = alert_callback
        self.device_history = {}  # device_id -> list of fingerprints
        self.suspicious_patterns = []
        
    def register_fingerprint(self, device_id: str, fingerprint: str, 
                           components: List[str], confidence: float):
        """Register a new fingerprint for monitoring"""
        current_time = datetime.utcnow()
        
        if device_id not in self.device_history:
            self.device_history[device_id] = []
        
        # Check for suspicious changes
        if self.device_history[device_id]:
            last_fingerprint = self.device_history[device_id][-1]['fingerprint']
            if last_fingerprint != fingerprint:
                self._detect_device_change(device_id, last_fingerprint, 
                                         fingerprint, components, confidence)
        
        # Store new fingerprint
        self.device_history[device_id].append({
            'fingerprint': fingerprint,
            'timestamp': current_time,
            'components': components,
            'confidence': confidence
        })
        
        # Cleanup old entries (keep last 30 days)
        cutoff_date = current_time - timedelta(days=30)
        self.device_history[device_id] = [
            entry for entry in self.device_history[device_id]
            if entry['timestamp'] > cutoff_date
        ]
    
    def _detect_device_change(self, device_id: str, old_fp: str, 
                            new_fp: str, components: List[str], confidence: float):
        """Detect and analyze device changes"""
        
        # Calculate fingerprint similarity
        similarity = self._calculate_similarity(old_fp, new_fp)
        
        # Determine risk level based on change pattern
        if similarity > 0.8:
            risk_level = "low"  # Minor hardware change
        elif similarity > 0.5:
            risk_level = "medium"  # Moderate change
        elif confidence > 0.8:
            risk_level = "medium"  # Different device, but high confidence
        else:
            risk_level = "high"  # Major change with low confidence
        
        # Create security event
        event = SecurityEvent(
            alert_type=SecurityAlert.DEVICE_CHANGE,
            timestamp=datetime.utcnow(),
            device_id=device_id,
            previous_fingerprint=old_fp,
            current_fingerprint=new_fp,
            confidence_score=confidence,
            affected_components=components,
            risk_level=risk_level,
            additional_data={'similarity_score': similarity}
        )
        
        self._trigger_alert(event)
    
    def _calculate_similarity(self, fp1: str, fp2: str) -> float:
        """Calculate similarity between two fingerprints"""
        if fp1 == fp2:
            return 1.0
        
        # Use Hamming distance for binary comparison
        if len(fp1) != len(fp2):
            return 0.0
        
        matches = sum(c1 == c2 for c1, c2 in zip(fp1, fp2))
        return matches / len(fp1)
    
    def _trigger_alert(self, event: SecurityEvent):
        """Trigger security alert"""
        self.logger.warning(
            f"Security Alert: {event.alert_type.value} - "
            f"Device: {event.device_id}, Risk: {event.risk_level}"
        )
        
        if self.alert_callback:
            self.alert_callback(event)
    
    def get_device_risk_profile(self, device_id: str) -> Dict[str, Any]:
        """Get comprehensive risk profile for a device"""
        if device_id not in self.device_history:
            return {"status": "unknown", "risk_score": 0.5}
        
        history = self.device_history[device_id]
        
        # Calculate risk factors
        change_frequency = len(history) / max(1, 
            (datetime.utcnow() - history[0]['timestamp']).days)
        avg_confidence = sum(h['confidence'] for h in history) / len(history)
        
        # Risk scoring
        if change_frequency > 0.1:  # More than 1 change per 10 days
            risk_score = min(0.8, change_frequency * 2)
        else:
            risk_score = max(0.1, 1.0 - avg_confidence)
        
        return {
            "status": "monitored",
            "risk_score": risk_score,
            "change_frequency": change_frequency,
            "average_confidence": avg_confidence,
            "total_changes": len(history) - 1,
            "first_seen": history[0]['timestamp'].isoformat(),
            "last_seen": history[-1]['timestamp'].isoformat()
        }

class TamperDetector:
    """Detect potential tampering attempts"""
    
    def __init__(self):
        self.known_patterns = [
            "rapid_generation",  # Too many fingerprints in short time
            "low_confidence_spike",  # Sudden drop in confidence
            "component_manipulation"  # Unusual component changes
        ]
    
    def analyze_generation_pattern(self, timestamps: List[datetime]) -> bool:
        """Detect rapid fingerprint generation (potential attack)"""
        if len(timestamps) < 3:
            return False
        
        # Check for more than 10 generations in 1 minute
        recent_timestamps = [t for t in timestamps 
                           if (datetime.utcnow() - t).seconds < 60]
        
        return len(recent_timestamps) > 10

class FingerprintValidator:
    """Validate fingerprint integrity and detect anomalies"""
    
    @staticmethod
    def validate_fingerprint_format(fingerprint: str) -> bool:
        """Validate fingerprint follows expected format"""
        if not fingerprint or len(fingerprint) != 32:
            return False
        
        # Check if it's a valid hex string
        try:
            int(fingerprint, 16)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def detect_collision(fingerprint: str, known_fingerprints: List[str]) -> bool:
        """Detect potential fingerprint collisions"""
        return fingerprint in known_fingerprints
    
    @staticmethod
    def validate_component_consistency(components: List[str]) -> bool:
        """Validate that hardware components are consistent"""
        required_components = ['cpu', 'memory', 'platform']
        return all(any(comp in c.lower() for c in components) 
                  for comp in required_components)
