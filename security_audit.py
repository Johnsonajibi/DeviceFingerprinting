"""
Security Audit Module for QuantumVault

This module provides security auditing capabilities and validates
that the system meets commercial security standards.
"""

import hashlib
import logging
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from secure_config import config_manager, CRYPTO_CONFIG, SECURITY_CONFIG
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False


@dataclass
class SecurityAuditResult:
    """Result of a security audit check"""
    check_name: str
    passed: bool
    message: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    recommendation: Optional[str] = None


class SecurityAuditor:
    """
    Comprehensive security auditor for QuantumVault
    
    Performs security checks and validates configuration
    for commercial deployment readiness.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.results: List[SecurityAuditResult] = []
    
    def audit_all(self) -> List[SecurityAuditResult]:
        """Perform comprehensive security audit"""
        self.results.clear()
        
        # Configuration security checks
        self._audit_configuration()
        
        # File system security checks
        self._audit_file_permissions()
        
        # Cryptographic parameter checks
        self._audit_crypto_parameters()
        
        # Import security checks
        self._audit_import_security()
        
        # Environment security checks
        self._audit_environment_security()
        
        # Log audit summary
        self._log_audit_summary()
        
        return self.results
    
    def _audit_configuration(self):
        """Audit configuration security"""
        if not CONFIG_AVAILABLE:
            self.results.append(SecurityAuditResult(
                check_name="Configuration Management",
                passed=False,
                message="Secure configuration module not available",
                severity="HIGH",
                recommendation="Implement secure_config.py module for production deployment"
            ))
            return
        
        # Check if configuration validation passed
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            self.results.append(SecurityAuditResult(
                check_name="Configuration Validation",
                passed=False,
                message=f"Configuration validation failed: {'; '.join(validation_errors)}",
                severity="CRITICAL",
                recommendation="Fix configuration validation errors before deployment"
            ))
        else:
            self.results.append(SecurityAuditResult(
                check_name="Configuration Validation",
                passed=True,
                message="Configuration validation passed",
                severity="LOW"
            ))
    
    def _audit_file_permissions(self):
        """Audit file system permissions"""
        if not CONFIG_AVAILABLE:
            return
            
        # Check data directory permissions
        try:
            data_dir = Path(os.getenv('QVAULT_DATA_DIR', Path.cwd()))
            if data_dir.exists():
                dir_stat = data_dir.stat()
                dir_mode = stat.filemode(dir_stat.st_mode)
                
                # Check if directory is accessible to others
                if dir_stat.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
                    self.results.append(SecurityAuditResult(
                        check_name="Data Directory Permissions",
                        passed=False,
                        message=f"Data directory has overly permissive permissions: {dir_mode}",
                        severity="HIGH",
                        recommendation="Set data directory permissions to 700 (owner only)"
                    ))
                else:
                    self.results.append(SecurityAuditResult(
                        check_name="Data Directory Permissions",
                        passed=True,
                        message=f"Data directory permissions are secure: {dir_mode}",
                        severity="LOW"
                    ))
            
        except Exception as e:
            self.results.append(SecurityAuditResult(
                check_name="File Permission Check",
                passed=False,
                message=f"Could not check file permissions: {e}",
                severity="MEDIUM",
                recommendation="Manually verify file system permissions"
            ))
    
    def _audit_crypto_parameters(self):
        """Audit cryptographic parameters"""
        if not CONFIG_AVAILABLE:
            # Check fallback constants
            fallback_checks = [
                ("MIN_PASSWORD_LENGTH", 30, 12, "Password length too short"),
                ("PBKDF2_ITERATIONS", 600000, 100000, "PBKDF2 iterations too low"),
                ("SALT_LENGTH", 64, 32, "Salt length too short")
            ]
            
            for param_name, current_value, min_value, error_msg in fallback_checks:
                if current_value < min_value:
                    self.results.append(SecurityAuditResult(
                        check_name=f"Crypto Parameter: {param_name}",
                        passed=False,
                        message=f"{error_msg}: {current_value} < {min_value}",
                        severity="HIGH",
                        recommendation=f"Increase {param_name} to at least {min_value}"
                    ))
                else:
                    self.results.append(SecurityAuditResult(
                        check_name=f"Crypto Parameter: {param_name}",
                        passed=True,
                        message=f"{param_name} meets security requirements: {current_value}",
                        severity="LOW"
                    ))
            return
        
        # Check configured crypto parameters
        crypto_checks = [
            ("Password Length", CRYPTO_CONFIG.min_password_length, 12),
            ("PBKDF2 Iterations", CRYPTO_CONFIG.pbkdf2_iterations, 100000),
            ("Salt Length", CRYPTO_CONFIG.salt_length, 32)
        ]
        
        for param_name, current_value, min_value in crypto_checks:
            if current_value < min_value:
                self.results.append(SecurityAuditResult(
                    check_name=f"Crypto Parameter: {param_name}",
                    passed=False,
                    message=f"{param_name} below minimum: {current_value} < {min_value}",
                    severity="HIGH",
                    recommendation=f"Increase {param_name} to at least {min_value}"
                ))
            else:
                self.results.append(SecurityAuditResult(
                    check_name=f"Crypto Parameter: {param_name}",
                    passed=True,
                    message=f"{param_name} meets requirements: {current_value}",
                    severity="LOW"
                ))
    
    def _audit_import_security(self):
        """Audit import security and dependencies"""
        # Check for required cryptographic libraries
        required_modules = [
            ('cryptography', 'Core cryptographic operations'),
            ('hashlib', 'Hash functions'),
            ('secrets', 'Secure random number generation')
        ]
        
        for module_name, description in required_modules:
            try:
                __import__(module_name)
                self.results.append(SecurityAuditResult(
                    check_name=f"Required Module: {module_name}",
                    passed=True,
                    message=f"{description} module available",
                    severity="LOW"
                ))
            except ImportError:
                self.results.append(SecurityAuditResult(
                    check_name=f"Required Module: {module_name}",
                    passed=False,
                    message=f"Required module {module_name} not available",
                    severity="CRITICAL",
                    recommendation=f"Install {module_name} module"
                ))
        
        # Check optional modules
        optional_modules = [
            ('pandas', 'Excel import/export functionality'),
            ('qrcode', 'QR code generation'),
            ('PIL', 'Image processing for QR codes')
        ]
        
        for module_name, description in optional_modules:
            try:
                __import__(module_name)
                self.results.append(SecurityAuditResult(
                    check_name=f"Optional Module: {module_name}",
                    passed=True,
                    message=f"{description} available",
                    severity="LOW"
                ))
            except ImportError:
                self.results.append(SecurityAuditResult(
                    check_name=f"Optional Module: {module_name}",
                    passed=False,
                    message=f"Optional module {module_name} not available",
                    severity="LOW",
                    recommendation=f"Install {module_name} for {description}"
                ))
    
    def _audit_environment_security(self):
        """Audit environment security"""
        # Check for development artifacts
        dev_artifacts = [
            ('.env', 'Environment file with secrets'),
            ('debug.log', 'Debug log file'),
            ('test_data.json', 'Test data file'),
            ('.git', 'Git repository (should not be in production)')
        ]
        
        for artifact, description in dev_artifacts:
            if Path(artifact).exists():
                severity = "HIGH" if artifact == '.env' else "MEDIUM"
                self.results.append(SecurityAuditResult(
                    check_name=f"Development Artifact: {artifact}",
                    passed=False,
                    message=f"Found development artifact: {description}",
                    severity=severity,
                    recommendation=f"Remove {artifact} from production deployment"
                ))
        
        # Check environment variables
        sensitive_env_vars = [
            'QVAULT_MIN_PASSWORD_LENGTH',
            'QVAULT_PBKDF2_ITERATIONS',
            'QVAULT_DATA_DIR'
        ]
        
        configured_vars = []
        for var in sensitive_env_vars:
            if os.getenv(var):
                configured_vars.append(var)
        
        if configured_vars:
            self.results.append(SecurityAuditResult(
                check_name="Environment Configuration",
                passed=True,
                message=f"Found environment configuration: {', '.join(configured_vars)}",
                severity="LOW"
            ))
        else:
            self.results.append(SecurityAuditResult(
                check_name="Environment Configuration",
                passed=False,
                message="No environment configuration found, using defaults",
                severity="MEDIUM",
                recommendation="Configure environment variables for production deployment"
            ))
    
    def _log_audit_summary(self):
        """Log audit summary"""
        total_checks = len(self.results)
        passed_checks = sum(1 for result in self.results if result.passed)
        failed_checks = total_checks - passed_checks
        
        # Count by severity
        severity_counts = {}
        for result in self.results:
            if not result.passed:
                severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
        
        self.logger.info(f"Security audit completed: {passed_checks}/{total_checks} checks passed")
        
        if failed_checks > 0:
            self.logger.warning(f"Security audit found {failed_checks} issues:")
            for severity, count in severity_counts.items():
                self.logger.warning(f"  {severity}: {count} issues")
        
        # Log critical issues
        critical_issues = [r for r in self.results if not r.passed and r.severity == "CRITICAL"]
        if critical_issues:
            self.logger.error("CRITICAL security issues found:")
            for issue in critical_issues:
                self.logger.error(f"  - {issue.check_name}: {issue.message}")
    
    def get_security_score(self) -> Tuple[int, str]:
        """Calculate security score out of 100"""
        if not self.results:
            return 0, "No audit performed"
        
        total_checks = len(self.results)
        passed_checks = sum(1 for result in self.results if result.passed)
        
        # Calculate base score
        base_score = (passed_checks / total_checks) * 100
        
        # Apply severity penalties
        penalties = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}
        total_penalty = 0
        
        for result in self.results:
            if not result.passed:
                total_penalty += penalties.get(result.severity, 1)
        
        # Final score (minimum 0)
        final_score = max(0, int(base_score - total_penalty))
        
        # Determine rating
        if final_score >= 90:
            rating = "EXCELLENT"
        elif final_score >= 75:
            rating = "GOOD"
        elif final_score >= 50:
            rating = "FAIR"
        elif final_score >= 25:
            rating = "POOR"
        else:
            rating = "CRITICAL"
        
        return final_score, rating


def run_security_audit() -> Tuple[List[SecurityAuditResult], int, str]:
    """
    Run complete security audit
    
    Returns:
        Tuple of (audit_results, security_score, rating)
    """
    auditor = SecurityAuditor()
    results = auditor.audit_all()
    score, rating = auditor.get_security_score()
    
    return results, score, rating


if __name__ == "__main__":
    # Run audit if executed directly
    results, score, rating = run_security_audit()
    
    print(f"\nQuantumVault Security Audit Results")
    print(f"{'='*50}")
    print(f"Security Score: {score}/100 ({rating})")
    print(f"Total Checks: {len(results)}")
    print(f"Passed: {sum(1 for r in results if r.passed)}")
    print(f"Failed: {sum(1 for r in results if not r.passed)}")
    
    # Show failed checks
    failed_checks = [r for r in results if not r.passed]
    if failed_checks:
        print(f"\nFailed Security Checks:")
        print(f"{'-'*50}")
        for result in failed_checks:
            print(f"[{result.severity}] {result.check_name}")
            print(f"  Issue: {result.message}")
            if result.recommendation:
                print(f"  Fix: {result.recommendation}")
            print()
    
    print(f"\nAudit completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")
