"""
Hardware change detection and analysis for DeviceFingerprint Library
"""

import json
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

class ChangeType(Enum):
    """Types of hardware changes detected"""
    CPU_UPGRADE = "cpu_upgrade"
    MEMORY_CHANGE = "memory_change"
    STORAGE_MODIFICATION = "storage_modification"
    NETWORK_ADAPTER_CHANGE = "network_adapter_change"
    GRAPHICS_CHANGE = "graphics_change"
    MOTHERBOARD_CHANGE = "motherboard_change"
    BIOS_UPDATE = "bios_update"
    OS_CHANGE = "os_change"
    MINOR_UPDATE = "minor_update"
    UNKNOWN_CHANGE = "unknown_change"

@dataclass
class HardwareComponent:
    """Represents a hardware component"""
    component_type: str
    identifier: str
    properties: Dict[str, str]
    confidence: float
    last_seen: datetime

@dataclass
class ChangeEvent:
    """Represents a detected hardware change"""
    change_type: ChangeType
    component_name: str
    old_value: Optional[str]
    new_value: str
    impact_level: str  # "low", "medium", "high"
    detection_confidence: float
    timestamp: datetime
    additional_context: Dict[str, str]

class HardwareChangeDetector:
    """Detect and analyze hardware changes"""
    
    def __init__(self):
        self.component_history = {}  # component_type -> historical values
        self.sensitivity_settings = {
            'cpu': 0.9,          # High sensitivity for CPU changes
            'memory': 0.8,       # Medium-high for memory
            'storage': 0.7,      # Medium for storage (common changes)
            'network': 0.6,      # Lower for network (adapters change often)
            'bios': 0.95,        # Very high for BIOS
            'motherboard': 0.98  # Highest for motherboard
        }
    
    def register_baseline(self, components: Dict[str, str]):
        """Register initial hardware baseline"""
        timestamp = datetime.utcnow()
        
        for comp_type, value in components.items():
            if comp_type not in self.component_history:
                self.component_history[comp_type] = []
            
            # Create component record
            component = HardwareComponent(
                component_type=comp_type,
                identifier=self._generate_component_id(comp_type, value),
                properties={"value": value},
                confidence=1.0,
                last_seen=timestamp
            )
            
            self.component_history[comp_type].append(component)
    
    def detect_changes(self, current_components: Dict[str, str]) -> List[ChangeEvent]:
        """Detect changes between current and historical components"""
        changes = []
        
        for comp_type, current_value in current_components.items():
            if comp_type in self.component_history:
                change = self._analyze_component_change(comp_type, current_value)
                if change:
                    changes.append(change)
            else:
                # New component type detected
                changes.append(ChangeEvent(
                    change_type=ChangeType.UNKNOWN_CHANGE,
                    component_name=comp_type,
                    old_value=None,
                    new_value=current_value,
                    impact_level="medium",
                    detection_confidence=0.8,
                    timestamp=datetime.utcnow(),
                    additional_context={"reason": "new_component_type"}
                ))
        
        return changes
    
    def _analyze_component_change(self, comp_type: str, current_value: str) -> Optional[ChangeEvent]:
        """Analyze if a component has changed significantly"""
        history = self.component_history[comp_type]
        
        if not history:
            return None
        
        last_component = history[-1]
        last_value = last_component.properties.get("value", "")
        
        # Check if value has changed
        if last_value == current_value:
            # Update last seen time
            last_component.last_seen = datetime.utcnow()
            return None
        
        # Determine change type and impact
        change_type = self._classify_change(comp_type, last_value, current_value)
        impact_level = self._assess_impact(comp_type, change_type)
        confidence = self._calculate_confidence(comp_type, last_value, current_value)
        
        # Create change event
        change = ChangeEvent(
            change_type=change_type,
            component_name=comp_type,
            old_value=last_value,
            new_value=current_value,
            impact_level=impact_level,
            detection_confidence=confidence,
            timestamp=datetime.utcnow(),
            additional_context=self._gather_context(comp_type, last_value, current_value)
        )
        
        # Add new component to history
        new_component = HardwareComponent(
            component_type=comp_type,
            identifier=self._generate_component_id(comp_type, current_value),
            properties={"value": current_value},
            confidence=confidence,
            last_seen=datetime.utcnow()
        )
        history.append(new_component)
        
        # Cleanup old history (keep last 10 entries)
        if len(history) > 10:
            self.component_history[comp_type] = history[-10:]
        
        return change
    
    def _classify_change(self, comp_type: str, old_value: str, new_value: str) -> ChangeType:
        """Classify the type of change based on component and values"""
        
        # CPU changes
        if comp_type.lower() in ['cpu', 'processor']:
            if self._is_upgrade(old_value, new_value):
                return ChangeType.CPU_UPGRADE
            return ChangeType.CPU_UPGRADE
        
        # Memory changes
        elif comp_type.lower() in ['memory', 'ram']:
            return ChangeType.MEMORY_CHANGE
        
        # Storage changes
        elif comp_type.lower() in ['storage', 'disk', 'hdd', 'ssd']:
            return ChangeType.STORAGE_MODIFICATION
        
        # Network changes
        elif comp_type.lower() in ['network', 'mac', 'adapter']:
            return ChangeType.NETWORK_ADAPTER_CHANGE
        
        # Graphics changes
        elif comp_type.lower() in ['graphics', 'gpu', 'video']:
            return ChangeType.GRAPHICS_CHANGE
        
        # BIOS changes
        elif comp_type.lower() in ['bios', 'firmware']:
            return ChangeType.BIOS_UPDATE
        
        # OS changes
        elif comp_type.lower() in ['os', 'platform', 'system']:
            return ChangeType.OS_CHANGE
        
        # Motherboard changes
        elif comp_type.lower() in ['motherboard', 'mainboard', 'baseboard']:
            return ChangeType.MOTHERBOARD_CHANGE
        
        # Default to minor update for small changes
        similarity = self._calculate_string_similarity(old_value, new_value)
        if similarity > 0.8:
            return ChangeType.MINOR_UPDATE
        
        return ChangeType.UNKNOWN_CHANGE
    
    def _assess_impact(self, comp_type: str, change_type: ChangeType) -> str:
        """Assess the security impact of a hardware change"""
        
        # Critical changes
        if change_type in [ChangeType.MOTHERBOARD_CHANGE, ChangeType.BIOS_UPDATE]:
            return "high"
        
        # Medium impact changes
        elif change_type in [ChangeType.CPU_UPGRADE, ChangeType.OS_CHANGE]:
            return "medium"
        
        # Lower impact changes
        elif change_type in [ChangeType.MEMORY_CHANGE, ChangeType.STORAGE_MODIFICATION]:
            return "medium"
        
        # Minimal impact
        elif change_type in [ChangeType.NETWORK_ADAPTER_CHANGE, ChangeType.MINOR_UPDATE]:
            return "low"
        
        return "medium"  # Default
    
    def _calculate_confidence(self, comp_type: str, old_value: str, new_value: str) -> float:
        """Calculate confidence in change detection"""
        base_confidence = self.sensitivity_settings.get(comp_type, 0.7)
        
        # Adjust confidence based on value similarity
        similarity = self._calculate_string_similarity(old_value, new_value)
        
        # Lower similarity = higher confidence in actual change
        confidence_adjustment = 1.0 - similarity
        
        return min(1.0, base_confidence + (confidence_adjustment * 0.2))
    
    def _gather_context(self, comp_type: str, old_value: str, new_value: str) -> Dict[str, str]:
        """Gather additional context about the change"""
        context = {
            "component_type": comp_type,
            "change_size": str(len(new_value) - len(old_value)),
            "similarity": str(self._calculate_string_similarity(old_value, new_value))
        }
        
        # Add specific context based on component type
        if comp_type.lower() in ['memory', 'ram']:
            context["memory_analysis"] = self._analyze_memory_change(old_value, new_value)
        elif comp_type.lower() in ['cpu', 'processor']:
            context["cpu_analysis"] = self._analyze_cpu_change(old_value, new_value)
        
        return context
    
    def _analyze_memory_change(self, old_value: str, new_value: str) -> str:
        """Analyze memory-specific changes"""
        # Extract numbers that might represent memory size
        import re
        old_numbers = re.findall(r'\d+', old_value)
        new_numbers = re.findall(r'\d+', new_value)
        
        if old_numbers and new_numbers:
            old_size = max(int(x) for x in old_numbers)
            new_size = max(int(x) for x in new_numbers)
            
            if new_size > old_size:
                return f"memory_upgrade_{old_size}_to_{new_size}"
            elif new_size < old_size:
                return f"memory_downgrade_{old_size}_to_{new_size}"
        
        return "memory_configuration_change"
    
    def _analyze_cpu_change(self, old_value: str, new_value: str) -> str:
        """Analyze CPU-specific changes"""
        # Look for model numbers, frequencies, etc.
        if "intel" in old_value.lower() and "amd" in new_value.lower():
            return "vendor_change_intel_to_amd"
        elif "amd" in old_value.lower() and "intel" in new_value.lower():
            return "vendor_change_amd_to_intel"
        
        # Check for generation changes
        import re
        old_gen = re.findall(r'(\d+)(?:th|st|nd|rd)\s*gen', old_value.lower())
        new_gen = re.findall(r'(\d+)(?:th|st|nd|rd)\s*gen', new_value.lower())
        
        if old_gen and new_gen:
            return f"generation_change_{old_gen[0]}_to_{new_gen[0]}"
        
        return "cpu_model_change"
    
    def _is_upgrade(self, old_value: str, new_value: str) -> bool:
        """Determine if the change represents an upgrade"""
        # Simple heuristic: longer description might indicate newer/better hardware
        return len(new_value) > len(old_value)
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings"""
        if str1 == str2:
            return 1.0
        
        if not str1 or not str2:
            return 0.0
        
        # Simple similarity based on common characters
        common_chars = set(str1.lower()) & set(str2.lower())
        total_chars = set(str1.lower()) | set(str2.lower())
        
        if not total_chars:
            return 0.0
        
        return len(common_chars) / len(total_chars)
    
    def _generate_component_id(self, comp_type: str, value: str) -> str:
        """Generate unique identifier for a component"""
        combined = f"{comp_type}:{value}"
        return hashlib.md5(combined.encode()).hexdigest()[:16]
    
    def get_change_summary(self, device_id: str) -> Dict[str, any]:
        """Get summary of all changes for a device"""
        total_components = len(self.component_history)
        changed_components = sum(1 for history in self.component_history.values() 
                               if len(history) > 1)
        
        return {
            "device_id": device_id,
            "total_components_tracked": total_components,
            "components_with_changes": changed_components,
            "stability_score": 1.0 - (changed_components / max(1, total_components)),
            "last_analysis": datetime.utcnow().isoformat(),
            "component_details": {
                comp_type: len(history) for comp_type, history 
                in self.component_history.items()
            }
        }
    
    def export_change_history(self) -> Dict[str, any]:
        """Export complete change history for analysis"""
        export_data = {}
        
        for comp_type, history in self.component_history.items():
            export_data[comp_type] = [
                {
                    "identifier": comp.identifier,
                    "properties": comp.properties,
                    "confidence": comp.confidence,
                    "last_seen": comp.last_seen.isoformat()
                }
                for comp in history
            ]
        
        return {
            "export_timestamp": datetime.utcnow().isoformat(),
            "component_history": export_data,
            "sensitivity_settings": self.sensitivity_settings
        }
