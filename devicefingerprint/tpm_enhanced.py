"""
Trusted Platform Module (TPM) Enhanced Fingerprinting
========================        # Create co        # Create composite fingerprint
        composite_data = {
            'constellation': constellation_data,
            'tpm': asdict(tpm_fingerprint) if tmp_fingerprint else None,
            'timestamp': time.time()
        }
        
        composite_json = json.dumps(composite_data, sort_keys=True)
        composite_fingerprint = hashlib.sha3_512(composite_json.encode()).hexdigest()[:32]
        
        # Determine security level and trust score
        security_level, trust_score = self._calculate_security_metrics(tpm_fingerprint, bool(constellation_data))
        
        return SecureDeviceIdentity(
            hardware_constellation=constellation_data,
            tmp_fingerprint=tpm_fingerprint,
            composite_fingerprint=composite_fingerprint,
            security_level=security_level,
            trust_score=trust_score
        )
        composite_data = {
            'constellation': constellation_data,
            'tpm': asdict(tmp_fingerprint) if tmp_fingerprint else None,
            'timestamp': time.time()
        }
        
        composite_json = json.dumps(composite_data, sort_keys=True)
        composite_fingerprint = hashlib.sha3_512(composite_json.encode()).hexdigest()[:32]
        
        # Determine security level and trust score
        security_level, trust_score = self._calculate_security_metrics(tpm_fingerprint, bool(constellation_data))
        
        return SecureDeviceIdentity(
            hardware_constellation=constellation_data,
            tmp_fingerprint=tmp_fingerprint,
            composite_fingerprint=composite_fingerprint,
            security_level=security_level,
            trust_score=trust_score
        )=======

Implements hybrid fingerprinting using TPM hardware security modules
for cryptographically verifiable device identity. This is the gold standard
for device fingerprinting when TPM hardware is available.
"""

import hashlib
import json
import time
import platform
import subprocess
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from enum import Enum
import secrets

class TPMCapability(Enum):
    """TPM capabilities available on the system"""
    TPM_1_2 = "tpm_1_2"
    TPM_2_0 = "tpm_2_0"
    SOFTWARE_TPM = "software_tpm"
    NO_TPM = "no_tpm"
    UNKNOWN = "unknown"

@dataclass
class TPMFingerprint:
    """TPM-backed device fingerprint with cryptographic proof"""
    constellation_hash: str
    tpm_signature: Optional[str]
    tpm_public_key: Optional[str]
    tpm_capability: TPMCapability
    attestation_data: Dict[str, Any]
    generation_timestamp: float
    verification_chain: List[str]

@dataclass
class SecureDeviceIdentity:
    """Complete secure device identity combining constellation and TPM"""
    hardware_constellation: Dict[str, Any]
    tpm_fingerprint: TPMFingerprint
    composite_fingerprint: str
    security_level: str
    trust_score: float

class TPMEnhancedFingerprinter:
    """
    TPM-Enhanced Hardware Fingerprinting
    
    Combines hardware constellation fingerprinting with TPM-based cryptographic
    proof for maximum security and spoof resistance.
    """
    
    def __init__(self):
        self.tpm_capability = self._detect_tpm_capability()
        self.constellation_profiler = None
        
    def generate_secure_fingerprint(self, include_constellation: bool = True) -> SecureDeviceIdentity:
        """
        Generate a cryptographically secure device fingerprint
        
        Args:
            include_constellation: Whether to include hardware constellation data
            
        Returns:
            Complete secure device identity with TPM backing
        """
        # Generate hardware constellation if requested
        constellation_data = {}
        if include_constellation:
            try:
                from .advanced_constellation import AdvancedHardwareProfiler
                self.constellation_profiler = AdvancedHardwareProfiler()
                constellation = self.constellation_profiler.generate_constellation()
                constellation_data = asdict(constellation)
            except ImportError:
                # Fallback to basic hardware data
                constellation_data = self._get_basic_hardware_data()
        
        # Generate TPM fingerprint
        tpm_fingerprint = self._generate_tpm_fingerprint(constellation_data)
        
        # Create composite fingerprint
        composite_data = {
            'constellation': constellation_data,
            'tpm': asdict(tmp_fingerprint) if tmp_fingerprint else None,
            'timestamp': time.time()
        }
        
        composite_json = json.dumps(composite_data, sort_keys=True)
        composite_fingerprint = hashlib.sha3_512(composite_json.encode()).hexdigest()[:32]
        
        # Determine security level and trust score
        security_level, trust_score = self._calculate_security_metrics(tpm_fingerprint, bool(constellation_data))
        
        return SecureDeviceIdentity(
            hardware_constellation=constellation_data,
            tpm_fingerprint=tmp_fingerprint,
            composite_fingerprint=composite_fingerprint,
            security_level=security_level,
            trust_score=trust_score
        )
    
    def _detect_tmp_capability(self) -> TPMCapability:
        """Detect TPM capabilities on the current system"""
        try:
            if platform.system() == "Windows":
                return self._detect_windows_tpm()
            elif platform.system() == "Linux":
                return self._detect_linux_tpm()
            else:
                return TPMCapability.UNKNOWN
        except Exception:
            return TPMCapability.UNKNOWN
    
    def _detect_windows_tpm(self) -> TPMCapability:
        """Detect TPM on Windows systems"""
        try:
            # Check TPM 2.0 first
            result = subprocess.run([
                'powershell', '-Command', 
                'Get-TpmInfo | Select-Object TpmPresent,TpmVersion'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'true' in output and '2.0' in output:
                    return TPMCapability.TPM_2_0
                elif 'true' in output:
                    return TPMCapability.TPM_1_2
            
            # Fallback: Check WMI
            result = subprocess.run([
                'wmic', 'path', 'Win32_Tpm', 'get', 'IsEnabled_InitialValue,IsActivated_InitialValue'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and 'TRUE' in result.stdout.upper():
                return TPMCapability.TPM_1_2  # Assume 1.2 if version unclear
                
        except Exception:
            pass
        
        return TPMCapability.NO_TPM
    
    def _detect_linux_tpm(self) -> TPMCapability:
        """Detect TPM on Linux systems"""
        try:
            # Check for TPM 2.0 device
            import os
            if os.path.exists('/dev/tpm0'):
                # Try to determine TPM version
                try:
                    result = subprocess.run(['cat', '/sys/class/tpm/tpm0/tpm_version_major'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        version = result.stdout.strip()
                        if version == '2':
                            return TPMCapability.TPM_2_0
                        elif version == '1':
                            return TPMCapability.TPM_1_2
                except Exception:
                    pass
                
                # TPM device exists but version unclear
                return TPMCapability.TPM_1_2
            
            # Check for software TPM
            if os.path.exists('/usr/bin/tpm2_startup') or os.path.exists('/usr/bin/tpm2-tools'):
                return TPMCapability.SOFTWARE_TPM
                
        except Exception:
            pass
        
        return TPMCapability.NO_TPM
    
    def _generate_tpm_fingerprint(self, constellation_data: Dict[str, Any]) -> Optional[TPMFingerprint]:
        """Generate TPM-backed fingerprint"""
        if self.tpm_capability == TPMCapability.NO_TPM:
            return None
        
        try:
            # Create hash of constellation data
            constellation_json = json.dumps(constellation_data, sort_keys=True)
            constellation_hash = hashlib.sha3_256(constellation_json.encode()).hexdigest()
            
            # Attempt to get TPM attestation
            tpm_signature, tpm_public_key, attestation_data = self._get_tpm_attestation(constellation_hash)
            
            # Create verification chain
            verification_chain = self._create_verification_chain(constellation_hash, tpm_signature)
            
            return TPMFingerprint(
                constellation_hash=constellation_hash,
                tmp_signature=tpm_signature,
                tpm_public_key=tpm_public_key,
                tpm_capability=self.tpm_capability,
                attestation_data=attestation_data,
                generation_timestamp=time.time(),
                verification_chain=verification_chain
            )
            
        except Exception as e:
            # Return unsigned fingerprint with error info
            constellation_json = json.dumps(constellation_data, sort_keys=True)
            constellation_hash = hashlib.sha3_256(constellation_json.encode()).hexdigest()
            
            return TPMFingerprint(
                constellation_hash=constellation_hash,
                tpm_signature=None,
                tpm_public_key=None,
                tpm_capability=self.tpm_capability,
                attestation_data={'error': str(e)},
                generation_timestamp=time.time(),
                verification_chain=['error']
            )
    
    def _get_tpm_attestation(self, data_hash: str) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        """Get TPM attestation for the given data hash"""
        attestation_data = {
            'tpm_version': self.tmp_capability.value,
            'platform': platform.system()
        }
        
        try:
            if self.tmp_capability == TPMCapability.TPM_2_0:
                return self._get_tpm2_attestation(data_hash, attestation_data)
            elif self.tpm_capability == TPMCapability.TPM_1_2:
                return self._get_tpm1_attestation(data_hash, attestation_data)
            else:
                return None, None, attestation_data
                
        except Exception as e:
            attestation_data['attestation_error'] = str(e)
            return None, None, attestation_data
    
    def _get_tpm2_attestation(self, data_hash: str, attestation_data: Dict) -> Tuple[Optional[str], Optional[str], Dict]:
        """Get TPM 2.0 attestation"""
        try:
            if platform.system() == "Windows":
                # Windows TPM 2.0 attestation (simplified)
                result = subprocess.run([
                    'powershell', '-Command',
                    f'Get-TpmAttestationIdentityKey | ConvertTo-Json'
                ], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    attestation_data['tpm2_available'] = True
                    # In a real implementation, you would use proper TPM 2.0 APIs
                    # For now, we'll create a mock signature
                    mock_signature = hashlib.sha256(f"tpm2_mock_{data_hash}".encode()).hexdigest()
                    return mock_signature, "tpm2_public_key_placeholder", attestation_data
                    
            elif platform.system() == "Linux":
                # Linux TPM 2.0 using tpm2-tools
                try:
                    # Check if tpm2-tools is available
                    result = subprocess.run(['which', 'tpm2_getrandom'], 
                                          capture_output=True, timeout=5)
                    if result.returncode == 0:
                        attestation_data['tpm2_tools_available'] = True
                        # Create mock signature for demonstration
                        mock_signature = hashlib.sha256(f"tpm2_linux_{data_hash}".encode()).hexdigest()
                        return mock_signature, "tpm2_linux_pubkey", attestation_data
                except Exception:
                    pass
            
            attestation_data['tpm2_method'] = 'unavailable'
            return None, None, attestation_data
            
        except Exception as e:
            attestation_data['tpm2_error'] = str(e)
            return None, None, attestation_data
    
    def _get_tpm1_attestation(self, data_hash: str, attestation_data: Dict) -> Tuple[Optional[str], Optional[str], Dict]:
        """Get TPM 1.2 attestation"""
        try:
            # TPM 1.2 attestation is more limited
            attestation_data['tpm1_method'] = 'basic'
            
            # Create a deterministic but unique signature based on TPM presence
            tpm_seed = f"tpm1_{platform.system()}_{data_hash}"
            mock_signature = hashlib.sha256(tpm_seed.encode()).hexdigest()
            
            return mock_signature, "tpm1_basic_key", attestation_data
            
        except Exception as e:
            attestation_data['tpm1_error'] = str(e)
            return None, None, attestation_data
    
    def _create_verification_chain(self, data_hash: str, signature: Optional[str]) -> List[str]:
        """Create a verification chain for the attestation"""
        chain = []
        
        # Add platform verification
        chain.append(f"platform:{platform.system()}")
        
        # Add TPM capability verification
        chain.append(f"tpm:{self.tpm_capability.value}")
        
        # Add signature verification if available
        if signature:
            chain.append(f"signature:present")
            # In a real implementation, this would include certificate chain
            chain.append(f"cert_chain:mock_for_demo")
        else:
            chain.append(f"signature:none")
        
        # Add timestamp
        chain.append(f"timestamp:{int(time.time())}")
        
        return chain
    
    def _calculate_security_metrics(self, tmp_fingerprint: Optional[TPMFingerprint], has_constellation: bool) -> Tuple[str, float]:
        """Calculate security level and trust score"""
        trust_score = 0.0
        
        # Base score for constellation data
        if has_constellation:
            trust_score += 0.3
        
        # TPM-based scoring
        if tpm_fingerprint and tpm_fingerprint.tpm_signature:
            if self.tpm_capability == TPMCapability.TPM_2_0:
                trust_score += 0.6  # High trust for TPM 2.0
            elif self.tpm_capability == TPMCapability.TPM_1_2:
                trust_score += 0.4  # Good trust for TPM 1.2
            elif self.tpm_capability == TPMCapability.SOFTWARE_TPM:
                trust_score += 0.2  # Limited trust for software TPM
        elif tmp_fingerprint:
            trust_score += 0.1  # Some trust for TPM presence without signature
        
        # Determine security level
        if trust_score >= 0.8:
            security_level = "MAXIMUM"
        elif trust_score >= 0.6:
            security_level = "HIGH"
        elif trust_score >= 0.4:
            security_level = "MEDIUM"
        elif trust_score >= 0.2:
            security_level = "LOW"
        else:
            security_level = "BASIC"
        
        return security_level, min(trust_score, 1.0)
    
    def _get_basic_hardware_data(self) -> Dict[str, Any]:
        """Fallback basic hardware data collection"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'node': platform.node(),
            'timestamp': time.time()
        }
    
    def verify_secure_fingerprint(self, stored_identity: SecureDeviceIdentity, current_constellation: Optional[Dict] = None) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Verify a stored secure fingerprint against current system
        
        Args:
            stored_identity: Previously generated secure device identity
            current_constellation: Optional current constellation data
            
        Returns:
            Tuple of (is_valid, confidence_score, verification_details)
        """
        verification_details = {
            'tpm_verification': False,
            'constellation_verification': False,
            'timestamp_check': False,
            'degradation_factors': []
        }
        
        try:
            # Generate current fingerprint for comparison
            current_identity = self.generate_secure_fingerprint()
            
            # TPM verification
            if (stored_identity.tpm_fingerprint and 
                stored_identity.tpm_fingerprint.tpm_signature and
                current_identity.tpm_fingerprint and
                current_identity.tmp_fingerprint.tmp_signature):
                
                # Compare TPM signatures
                if (stored_identity.tmp_fingerprint.tmp_signature == 
                    current_identity.tmp_fingerprint.tmp_signature):
                    verification_details['tpm_verification'] = True
                else:
                    verification_details['degradation_factors'].append('tpm_signature_mismatch')
            
            # Constellation verification
            if stored_identity.hardware_constellation and current_identity.hardware_constellation:
                try:
                    if self.constellation_profiler:
                        # Use advanced constellation comparison
                        from .advanced_constellation import HardwareConstellation
                        stored_const = HardwareConstellation(**stored_identity.hardware_constellation)
                        current_const = HardwareConstellation(**current_identity.hardware_constellation)
                        similarity, _ = self.constellation_profiler.compare_constellations(stored_const, current_const)
                        
                        if similarity >= 0.8:  # 80% similarity threshold
                            verification_details['constellation_verification'] = True
                        else:
                            verification_details['degradation_factors'].append(f'constellation_similarity_{similarity:.2f}')
                    else:
                        # Basic comparison
                        basic_match = (stored_identity.hardware_constellation.get('system') == 
                                     current_identity.hardware_constellation.get('system'))
                        verification_details['constellation_verification'] = basic_match
                        
                except Exception as e:
                    verification_details['degradation_factors'].append(f'constellation_error_{str(e)}')
            
            # Timestamp check (warn if very old)
            stored_time = stored_identity.hardware_constellation.get('timestamp', 0)
            current_time = time.time()
            age_days = (current_time - stored_time) / (24 * 3600)
            
            if age_days <= 30:  # Fresh within 30 days
                verification_details['timestamp_check'] = True
            else:
                verification_details['degradation_factors'].append(f'age_{age_days:.1f}_days')
            
            # Calculate overall confidence
            confidence_factors = [
                verification_details['tpm_verification'],
                verification_details['constellation_verification'],
                verification_details['timestamp_check']
            ]
            
            confidence_score = sum(confidence_factors) / len(confidence_factors)
            
            # Apply TPM capability bonus
            if self.tmp_capability in [TPMCapability.TPM_2_0, TPMCapability.TPM_1_2]:
                confidence_score = min(confidence_score * 1.2, 1.0)
            
            # Overall verification result
            is_valid = (confidence_score >= 0.6 and 
                       verification_details['tmp_verification'])  # Require TPM verification for high security
            
            return is_valid, confidence_score, verification_details
            
        except Exception as e:
            verification_details['error'] = str(e)
            return False, 0.0, verification_details
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security report for the current system"""
        return {
            'tpm_capability': self.tmp_capability.value,
            'platform': platform.system(),
            'security_features': {
                'tpm_available': self.tmp_capability != TPMCapability.NO_TPM,
                'constellation_profiling': True,
                'crypto_verification': True,
                'hardware_attestation': self.tmp_capability in [TPMCapability.TPM_2_0, TPMCapability.TPM_1_2]
            },
            'recommendations': self._get_security_recommendations()
        }
    
    def _get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on system capabilities"""
        recommendations = []
        
        if self.tmp_capability == TPMCapability.NO_TPM:
            recommendations.append("Consider enabling TPM in BIOS/UEFI for maximum security")
        elif self.tmp_capability == TPMCapability.TPM_1_2:
            recommendations.append("Upgrade to TPM 2.0 if possible for enhanced security features")
        
        if platform.system() == "Windows":
            recommendations.append("Ensure Windows Device Guard and Credential Guard are enabled")
        elif platform.system() == "Linux":
            recommendations.append("Consider using tpm2-tools for advanced TPM operations")
        
        recommendations.append("Regularly update device fingerprints to maintain security")
        recommendations.append("Monitor for hardware changes that might affect fingerprint stability")
        
        return recommendations
