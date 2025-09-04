"""
Dynamic Page Sizing Optimization Library
========================================

A library for automatically optimizing encryption page sizes based on 
vault size to balance security granularity with performance efficiency.

Features:
- Automatic page size calculation based on data size
- Performance optimization for different vault sizes
- Security granularity balancing
- Memory efficiency optimization
- Configurable size thresholds

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

from typing import Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"

class VaultSizeCategory(Enum):
    """Vault size categories for optimization"""
    TINY = "tiny"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    XLARGE = "xlarge"
    MASSIVE = "massive"

@dataclass
class PageSizeConfig:
    """Configuration for page size optimization"""
    max_entries: int
    page_size_kb: float
    description: str
    security_level: str
    performance_level: str

@dataclass
class OptimizationResult:
    """Result of page size optimization"""
    vault_size: int
    category: VaultSizeCategory
    optimal_page_size_kb: float
    expected_pages: int
    memory_efficiency: float
    security_granularity: str
    reasoning: str

class DynamicPageSizer:
    """
    Dynamic Page Size Optimization System
    
    Automatically calculates optimal encryption page sizes based on vault
    characteristics to balance security, performance, and memory efficiency.
    
    Key Principles:
    - Small vaults: Smaller pages for maximum security granularity
    - Large vaults: Larger pages for better performance
    - Memory efficiency: Minimize overhead while maintaining security
    - Forward compatibility: Handles vault growth gracefully
    """
    
    def __init__(self, custom_thresholds: Dict[str, PageSizeConfig] = None):
        """
        Initialize dynamic page sizer
        
        Args:
            custom_thresholds: Custom page size thresholds (optional)
        """
        if custom_thresholds:
            self.thresholds = custom_thresholds
        else:
            self.thresholds = self._default_thresholds()
    
    def _default_thresholds(self) -> Dict[str, PageSizeConfig]:
        """
        Default page size thresholds optimized for different vault sizes
        
        Returns:
            Dictionary of vault categories to page configurations
        """
        return {
            "tiny": PageSizeConfig(
                max_entries=10,
                page_size_kb=0.25,
                description="Ultra-small pages for maximum security granularity",
                security_level="Maximum",
                performance_level="Low"
            ),
            "small": PageSizeConfig(
                max_entries=50,
                page_size_kb=0.5,
                description="Small pages balancing security and efficiency",
                security_level="High",
                performance_level="Medium"
            ),
            "medium": PageSizeConfig(
                max_entries=200,
                page_size_kb=1.0,
                description="Standard pages for typical vault sizes",
                security_level="High",
                performance_level="Good"
            ),
            "large": PageSizeConfig(
                max_entries=500,
                page_size_kb=2.0,
                description="Large pages for performance optimization",
                security_level="Medium",
                performance_level="High"
            ),
            "xlarge": PageSizeConfig(
                max_entries=1000,
                page_size_kb=4.0,
                description="Extra-large pages for massive vaults",
                security_level="Medium",
                performance_level="Very High"
            ),
            "massive": PageSizeConfig(
                max_entries=float('inf'),
                page_size_kb=8.0,
                description="Maximum pages for enterprise-scale vaults",
                security_level="Basic",
                performance_level="Maximum"
            )
        }
    
    def calculate_optimal_page_size(self, vault_size: int, data_size_bytes: int = 0) -> OptimizationResult:
        """
        Calculate optimal page size for given vault characteristics
        
        Args:
            vault_size: Number of entries in vault
            data_size_bytes: Total data size in bytes (optional)
            
        Returns:
            OptimizationResult with optimal configuration
        """
        # Determine vault category
        category = self._categorize_vault_size(vault_size)
        config = self.thresholds[category.value]
        
        # Apply size-based adjustments
        adjusted_page_size = self._apply_size_adjustments(
            config.page_size_kb, 
            vault_size, 
            data_size_bytes
        )
        
        # Calculate expected metrics
        expected_pages = self._estimate_page_count(vault_size, adjusted_page_size, data_size_bytes)
        memory_efficiency = self._calculate_memory_efficiency(adjusted_page_size, expected_pages)
        security_granularity = self._assess_security_granularity(adjusted_page_size, vault_size)
        reasoning = self._generate_reasoning(category, config, adjusted_page_size, vault_size)
        
        return OptimizationResult(
            vault_size=vault_size,
            category=category,
            optimal_page_size_kb=adjusted_page_size,
            expected_pages=expected_pages,
            memory_efficiency=memory_efficiency,
            security_granularity=security_granularity,
            reasoning=reasoning
        )
    
    def _categorize_vault_size(self, vault_size: int) -> VaultSizeCategory:
        """Categorize vault size for optimization"""
        for category_name, config in self.thresholds.items():
            if vault_size <= config.max_entries:
                return VaultSizeCategory(category_name)
        
        return VaultSizeCategory.MASSIVE
    
    def _apply_size_adjustments(self, base_page_size: float, vault_size: int, data_size_bytes: int) -> float:
        """
        Apply fine-tuning adjustments based on vault characteristics
        
        Args:
            base_page_size: Base page size from thresholds
            vault_size: Number of vault entries
            data_size_bytes: Total data size
            
        Returns:
            Adjusted page size in KB
        """
        adjusted_size = base_page_size
        
        # Adjust for data density
        if data_size_bytes > 0 and vault_size > 0:
            avg_entry_size = data_size_bytes / vault_size
            
            # If entries are very large, increase page size slightly
            if avg_entry_size > 1024:  # > 1KB per entry
                adjusted_size *= 1.5
            elif avg_entry_size > 512:  # > 512B per entry
                adjusted_size *= 1.2
            elif avg_entry_size < 100:  # < 100B per entry (very small)
                adjusted_size *= 0.8
        
        # Ensure reasonable bounds
        adjusted_size = max(0.1, min(16.0, adjusted_size))  # 0.1KB to 16KB
        
        return round(adjusted_size, 2)
    
    def _estimate_page_count(self, vault_size: int, page_size_kb: float, data_size_bytes: int) -> int:
        """Estimate number of pages needed"""
        if data_size_bytes > 0:
            # Use actual data size if available
            page_size_bytes = page_size_kb * 1024
            return max(1, int((data_size_bytes + page_size_bytes - 1) // page_size_bytes))
        else:
            # Estimate based on typical entry size (assume 200 bytes per entry)
            estimated_data_size = vault_size * 200
            page_size_bytes = page_size_kb * 1024
            return max(1, int((estimated_data_size + page_size_bytes - 1) // page_size_bytes))
    
    def _calculate_memory_efficiency(self, page_size_kb: float, expected_pages: int) -> float:
        """
        Calculate memory efficiency score (0-100)
        
        Higher scores indicate better memory utilization
        """
        # Balance page size and count for optimal memory usage
        total_memory_kb = page_size_kb * expected_pages
        
        # Penalize both very small pages (high overhead) and very large pages (waste)
        if page_size_kb < 0.5:
            size_penalty = (0.5 - page_size_kb) * 20  # Penalty for small pages
        elif page_size_kb > 4.0:
            size_penalty = (page_size_kb - 4.0) * 10  # Penalty for large pages
        else:
            size_penalty = 0
        
        # Page count efficiency (sweet spot around 10-100 pages)
        if expected_pages < 5:
            count_penalty = (5 - expected_pages) * 5
        elif expected_pages > 200:
            count_penalty = (expected_pages - 200) * 0.1
        else:
            count_penalty = 0
        
        # Base efficiency score
        base_score = 100
        efficiency = max(0, base_score - size_penalty - count_penalty)
        
        return round(efficiency, 1)
    
    def _assess_security_granularity(self, page_size_kb: float, vault_size: int) -> str:
        """Assess security granularity level"""
        # Smaller pages = finer granularity = better security
        if page_size_kb <= 0.5:
            return "Ultra-Fine (Maximum Security)"
        elif page_size_kb <= 1.0:
            return "Fine (High Security)"
        elif page_size_kb <= 2.0:
            return "Medium (Balanced Security)"
        elif page_size_kb <= 4.0:
            return "Coarse (Performance Focused)"
        else:
            return "Very Coarse (Maximum Performance)"
    
    def _generate_reasoning(self, category: VaultSizeCategory, config: PageSizeConfig, 
                          final_size: float, vault_size: int) -> str:
        """Generate human-readable reasoning for the optimization decision"""
        reasons = []
        
        reasons.append(f"Vault categorized as '{category.value}' ({vault_size} entries)")
        reasons.append(f"Base recommendation: {config.page_size_kb}KB ({config.description})")
        
        if final_size != config.page_size_kb:
            reasons.append(f"Adjusted to {final_size}KB based on vault characteristics")
        
        reasons.append(f"Security level: {config.security_level}")
        reasons.append(f"Performance level: {config.performance_level}")
        
        return "; ".join(reasons)
    
    def optimize_for_operation(self, vault_size: int, operation_type: str) -> OptimizationResult:
        """
        Optimize page size for specific operations
        
        Args:
            vault_size: Number of vault entries
            operation_type: Type of operation ('read', 'write', 'rotation', 'backup')
            
        Returns:
            OptimizationResult optimized for the operation
        """
        base_result = self.calculate_optimal_page_size(vault_size)
        
        # Operation-specific adjustments
        operation_adjustments = {
            'read': 1.0,      # Standard size for reading
            'write': 0.8,     # Smaller pages for write operations (better granularity)
            'rotation': 1.2,  # Larger pages for rotation (better performance)
            'backup': 1.5     # Larger pages for backup operations (efficiency)
        }
        
        adjustment_factor = operation_adjustments.get(operation_type, 1.0)
        optimized_size = base_result.optimal_page_size_kb * adjustment_factor
        optimized_size = max(0.1, min(16.0, optimized_size))  # Bounds check
        
        # Update result
        base_result.optimal_page_size_kb = round(optimized_size, 2)
        base_result.reasoning += f"; Optimized for {operation_type} operations (×{adjustment_factor})"
        
        return base_result
    
    def compare_configurations(self, vault_size: int) -> Dict[str, OptimizationResult]:
        """
        Compare different page size configurations for analysis
        
        Args:
            vault_size: Number of vault entries
            
        Returns:
            Dictionary of configuration comparisons
        """
        results = {}
        
        # Test each category configuration
        for category_name, config in self.thresholds.items():
            # Temporarily apply this configuration
            temp_result = OptimizationResult(
                vault_size=vault_size,
                category=VaultSizeCategory(category_name),
                optimal_page_size_kb=config.page_size_kb,
                expected_pages=self._estimate_page_count(vault_size, config.page_size_kb, 0),
                memory_efficiency=self._calculate_memory_efficiency(
                    config.page_size_kb, 
                    self._estimate_page_count(vault_size, config.page_size_kb, 0)
                ),
                security_granularity=self._assess_security_granularity(config.page_size_kb, vault_size),
                reasoning=f"Fixed {category_name} configuration: {config.description}"
            )
            results[category_name] = temp_result
        
        # Add optimal result
        results['optimal'] = self.calculate_optimal_page_size(vault_size)
        
        return results
    
    def get_performance_metrics(self, result: OptimizationResult) -> Dict[str, Any]:
        """
        Get detailed performance metrics for an optimization result
        
        Args:
            result: OptimizationResult to analyze
            
        Returns:
            Dictionary with performance metrics
        """
        page_size_bytes = result.optimal_page_size_kb * 1024
        
        return {
            'page_size_bytes': int(page_size_bytes),
            'expected_pages': result.expected_pages,
            'total_overhead_kb': result.expected_pages * 0.1,  # Assume 0.1KB overhead per page
            'memory_efficiency_score': result.memory_efficiency,
            'security_granularity': result.security_granularity,
            'category': result.category.value,
            'vault_size': result.vault_size,
            'pages_per_entry': result.expected_pages / max(1, result.vault_size),
            'bytes_per_entry': page_size_bytes / max(1, result.expected_pages)
        }

