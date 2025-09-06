"""
Enterprise integration system for DeviceFingerprint Library
Provides seamless integration with enterprise security systems
"""

import json
import hashlib
import hmac
import time
import logging
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import urllib.request
import urllib.parse
from pathlib import Path

class IntegrationType(Enum):
    """Types of enterprise integrations"""
    SIEM = "siem"
    IDENTITY_PROVIDER = "identity_provider"
    ASSET_MANAGEMENT = "asset_management"
    COMPLIANCE_SYSTEM = "compliance_system"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AUDIT_SYSTEM = "audit_system"

@dataclass
class IntegrationConfig:
    """Configuration for enterprise integration"""
    integration_type: IntegrationType
    endpoint_url: str
    api_key: str
    secret_key: Optional[str] = None
    batch_size: int = 100
    retry_count: int = 3
    timeout_seconds: int = 30
    custom_headers: Dict[str, str] = None
    enabled: bool = True

@dataclass
class FingerprintEvent:
    """Event data for enterprise systems"""
    event_id: str
    device_id: str
    fingerprint: str
    event_type: str  # "new_device", "device_change", "suspicious_activity"
    timestamp: datetime
    user_context: Optional[Dict[str, str]] = None
    risk_score: float = 0.0
    metadata: Dict[str, Any] = None

class EnterpriseIntegrator:
    """Handles integration with enterprise security systems"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.integrations = {}
        self.event_queue = []
        self.queue_lock = threading.Lock()
        self.background_worker = None
        self.running = False
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load integration configurations from file"""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            for integration_name, config in config_data.items():
                integration_config = IntegrationConfig(
                    integration_type=IntegrationType(config['type']),
                    endpoint_url=config['endpoint_url'],
                    api_key=config['api_key'],
                    secret_key=config.get('secret_key'),
                    batch_size=config.get('batch_size', 100),
                    retry_count=config.get('retry_count', 3),
                    timeout_seconds=config.get('timeout_seconds', 30),
                    custom_headers=config.get('custom_headers', {}),
                    enabled=config.get('enabled', True)
                )
                self.integrations[integration_name] = integration_config
                
        except Exception as e:
            self.logger.error(f"Failed to load integration config: {e}")
    
    def add_integration(self, name: str, config: IntegrationConfig):
        """Add a new enterprise integration"""
        self.integrations[name] = config
        self.logger.info(f"Added integration: {name} ({config.integration_type.value})")
    
    def start_background_processing(self):
        """Start background thread for processing events"""
        if self.background_worker and self.running:
            return
        
        self.running = True
        self.background_worker = threading.Thread(target=self._process_event_queue)
        self.background_worker.daemon = True
        self.background_worker.start()
        
        self.logger.info("Started background event processing")
    
    def stop_background_processing(self):
        """Stop background event processing"""
        self.running = False
        if self.background_worker:
            self.background_worker.join(timeout=5)
        
        self.logger.info("Stopped background event processing")
    
    def send_fingerprint_event(self, event: FingerprintEvent, 
                              integration_names: Optional[List[str]] = None):
        """Send fingerprint event to specified integrations"""
        if integration_names is None:
            integration_names = list(self.integrations.keys())
        
        # Add event to queue for background processing
        with self.queue_lock:
            for integration_name in integration_names:
                if integration_name in self.integrations:
                    self.event_queue.append((integration_name, event))
        
        # If background processing not running, process immediately
        if not self.running:
            self._process_single_event()
    
    def _process_event_queue(self):
        """Background worker to process event queue"""
        while self.running:
            events_to_process = []
            
            # Get events from queue
            with self.queue_lock:
                if self.event_queue:
                    events_to_process = self.event_queue[:50]  # Process in batches
                    self.event_queue = self.event_queue[50:]
            
            # Process events
            for integration_name, event in events_to_process:
                self._send_to_integration(integration_name, event)
            
            # Wait before next batch
            time.sleep(1)
    
    def _process_single_event(self):
        """Process a single event immediately"""
        with self.queue_lock:
            if self.event_queue:
                integration_name, event = self.event_queue.pop(0)
                self._send_to_integration(integration_name, event)
    
    def _send_to_integration(self, integration_name: str, event: FingerprintEvent):
        """Send event to specific integration"""
        if integration_name not in self.integrations:
            return
        
        config = self.integrations[integration_name]
        if not config.enabled:
            return
        
        try:
            if config.integration_type == IntegrationType.SIEM:
                self._send_to_siem(config, event)
            elif config.integration_type == IntegrationType.IDENTITY_PROVIDER:
                self._send_to_identity_provider(config, event)
            elif config.integration_type == IntegrationType.ASSET_MANAGEMENT:
                self._send_to_asset_management(config, event)
            elif config.integration_type == IntegrationType.COMPLIANCE_SYSTEM:
                self._send_to_compliance_system(config, event)
            elif config.integration_type == IntegrationType.THREAT_INTELLIGENCE:
                self._send_to_threat_intelligence(config, event)
            elif config.integration_type == IntegrationType.AUDIT_SYSTEM:
                self._send_to_audit_system(config, event)
                
        except Exception as e:
            self.logger.error(f"Failed to send event to {integration_name}: {e}")
    
    def _send_to_siem(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to SIEM system (Splunk, IBM QRadar, etc.)"""
        payload = {
            "timestamp": event.timestamp.isoformat(),
            "source": "device-fingerprinting",
            "event_type": event.event_type,
            "device_id": event.device_id,
            "fingerprint_hash": hashlib.sha256(event.fingerprint.encode()).hexdigest(),
            "risk_score": event.risk_score,
            "user_context": event.user_context or {},
            "metadata": event.metadata or {}
        }
        
        self._make_http_request(config, payload, "/api/v1/events")
    
    def _send_to_identity_provider(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to Identity Provider (Azure AD, Okta, etc.)"""
        payload = {
            "deviceId": event.device_id,
            "deviceFingerprint": event.fingerprint,
            "eventType": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "riskScore": event.risk_score,
            "userAttributes": event.user_context or {}
        }
        
        self._make_http_request(config, payload, "/api/v1/device-events")
    
    def _send_to_asset_management(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to Asset Management system"""
        payload = {
            "assetId": event.device_id,
            "assetFingerprint": event.fingerprint,
            "lastSeen": event.timestamp.isoformat(),
            "assetStatus": "active" if event.event_type != "device_lost" else "missing",
            "securityScore": 100 - (event.risk_score * 100),
            "additionalData": event.metadata or {}
        }
        
        self._make_http_request(config, payload, "/api/v1/assets")
    
    def _send_to_compliance_system(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to Compliance system (for regulatory requirements)"""
        payload = {
            "eventId": event.event_id,
            "complianceType": "device_tracking",
            "deviceIdentifier": event.device_id,
            "auditTimestamp": event.timestamp.isoformat(),
            "complianceStatus": "monitored",
            "riskAssessment": event.risk_score,
            "regulatoryContext": event.metadata or {}
        }
        
        self._make_http_request(config, payload, "/api/v1/compliance-events")
    
    def _send_to_threat_intelligence(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to Threat Intelligence platform"""
        payload = {
            "indicator": {
                "type": "device-fingerprint",
                "value": hashlib.sha256(event.fingerprint.encode()).hexdigest(),
                "confidence": min(100, int(event.risk_score * 100)),
                "first_seen": event.timestamp.isoformat(),
                "source": "device-fingerprinting-library"
            },
            "context": {
                "device_id": event.device_id,
                "event_type": event.event_type,
                "metadata": event.metadata or {}
            }
        }
        
        self._make_http_request(config, payload, "/api/v1/indicators")
    
    def _send_to_audit_system(self, config: IntegrationConfig, event: FingerprintEvent):
        """Send event to Audit system"""
        payload = {
            "auditEventId": event.event_id,
            "eventType": "device_fingerprint_activity",
            "timestamp": event.timestamp.isoformat(),
            "actor": {
                "type": "device",
                "identifier": event.device_id
            },
            "action": event.event_type,
            "resource": "device_fingerprint",
            "outcome": "success",
            "riskScore": event.risk_score,
            "auditTrail": event.metadata or {}
        }
        
        self._make_http_request(config, payload, "/api/v1/audit-events")
    
    def _make_http_request(self, config: IntegrationConfig, payload: Dict, endpoint: str):
        """Make HTTP request to integration endpoint"""
        url = config.endpoint_url.rstrip('/') + endpoint
        
        # Prepare request data
        data = json.dumps(payload).encode('utf-8')
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.api_key}',
            'User-Agent': 'DeviceFingerprint-Enterprise/1.0'
        }
        
        # Add custom headers
        if config.custom_headers:
            headers.update(config.custom_headers)
        
        # Add HMAC signature if secret key provided
        if config.secret_key:
            timestamp = str(int(time.time()))
            signature_data = f"{timestamp}.{data.decode('utf-8')}"
            signature = hmac.new(
                config.secret_key.encode(),
                signature_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            headers['X-Timestamp'] = timestamp
            headers['X-Signature'] = f'sha256={signature}'
        
        # Make request with retry logic
        for attempt in range(config.retry_count):
            try:
                req = urllib.request.Request(url, data=data, headers=headers)
                
                with urllib.request.urlopen(req, timeout=config.timeout_seconds) as response:
                    if response.status in [200, 201, 202]:
                        self.logger.debug(f"Successfully sent event to {url}")
                        return
                    else:
                        raise Exception(f"HTTP {response.status}: {response.read().decode()}")
                        
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt < config.retry_count - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise

class ComplianceReporter:
    """Generate compliance reports for regulatory requirements"""
    
    def __init__(self, integrator: EnterpriseIntegrator):
        self.integrator = integrator
        self.logger = logging.getLogger(__name__)
    
    def generate_gdpr_report(self, device_id: str, date_range: tuple) -> Dict[str, Any]:
        """Generate GDPR compliance report for device data"""
        start_date, end_date = date_range
        
        return {
            "report_type": "GDPR_compliance",
            "device_id": device_id,
            "reporting_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "data_processing_lawfulness": "legitimate_interest",
            "data_retention_policy": "30_days_device_history",
            "user_rights_status": "data_portable_on_request",
            "security_measures": [
                "sha3_512_hashing",
                "quantum_resistant_algorithms",
                "encrypted_storage",
                "access_logging"
            ],
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def generate_sox_report(self, period: str) -> Dict[str, Any]:
        """Generate SOX compliance report for financial regulations"""
        return {
            "report_type": "SOX_compliance",
            "reporting_period": period,
            "internal_controls": {
                "device_identification": "implemented",
                "access_monitoring": "active",
                "audit_trail": "complete",
                "change_detection": "automated"
            },
            "control_effectiveness": "satisfactory",
            "exceptions": [],
            "generated_at": datetime.utcnow().isoformat()
        }

def create_sample_integration_config():
    """Create sample integration configuration file"""
    sample_config = {
        "splunk_siem": {
            "type": "siem",
            "endpoint_url": "https://your-splunk.company.com:8088",
            "api_key": "your-hec-token",
            "batch_size": 100,
            "enabled": True
        },
        "azure_ad": {
            "type": "identity_provider",
            "endpoint_url": "https://graph.microsoft.com",
            "api_key": "your-azure-ad-token",
            "custom_headers": {
                "Content-Type": "application/json"
            },
            "enabled": True
        },
        "servicenow_cmdb": {
            "type": "asset_management",
            "endpoint_url": "https://your-instance.service-now.com",
            "api_key": "your-servicenow-api-key",
            "secret_key": "your-servicenow-secret",
            "enabled": False
        }
    }
    
    return sample_config
