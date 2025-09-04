"""
Security Testing and Validation Library
=======================================

Comprehensive security testing framework for cryptographic operations
including timing attack resistance, input validation, and security
monitoring for quantum-resistant password management systems.

Features:
- Timing attack resistance testing
- Cryptographic consistency validation
- Input sanitization and validation
- Security event monitoring
- Performance benchmarking
- Vulnerability assessment

Author: QuantumVault Development Team
License: MIT
Version: 1.0.0
"""

import time
import secrets
import hashlib
import re
import os
import gc
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging

__version__ = "1.0.0"
__author__ = "QuantumVault Development Team"

class SecurityTestResult(Enum):
    """Security test result types"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"

@dataclass
class TestResult:
    """Individual test result"""
    test_name: str
    result: SecurityTestResult
    message: str
    execution_time: float
    details: Dict[str, Any]

@dataclass
class SecurityTestSuite:
    """Complete security test suite results"""
    total_tests: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    execution_time: float
    results: List[TestResult]

class TimingAttackTester:
    """
    Test for timing attack resistance in cryptographic operations
    
    Timing attacks exploit variations in execution time to infer
    information about secret data. This class validates that
    cryptographic operations take constant time regardless of input.
    """
    
    @staticmethod
    def test_constant_time_comparison(compare_func: Callable, 
                                    correct_input: Any,
                                    incorrect_input: Any,
                                    iterations: int = 100) -> TestResult:
        """
        Test if a comparison function has constant execution time
        
        Args:
            compare_func: Function to test (should return bool)
            correct_input: Input that should return True
            incorrect_input: Input that should return False
            iterations: Number of test iterations
            
        Returns:
            TestResult with timing analysis
        """
        start_time = time.perf_counter()
        
        correct_times = []
        incorrect_times = []
        
        try:
            # Test correct inputs
            for _ in range(iterations):
                test_start = time.perf_counter()
                result = compare_func(correct_input)
                test_end = time.perf_counter()
                correct_times.append(test_end - test_start)
                
                if not result:
                    return TestResult(
                        test_name="timing_attack_resistance",
                        result=SecurityTestResult.FAIL,
                        message="Correct input returned False",
                        execution_time=time.perf_counter() - start_time,
                        details={"error": "function_logic_error"}
                    )
            
            # Test incorrect inputs
            for _ in range(iterations):
                test_start = time.perf_counter()
                result = compare_func(incorrect_input)
                test_end = time.perf_counter()
                incorrect_times.append(test_end - test_start)
                
                if result:
                    return TestResult(
                        test_name="timing_attack_resistance",
                        result=SecurityTestResult.FAIL,
                        message="Incorrect input returned True",
                        execution_time=time.perf_counter() - start_time,
                        details={"error": "function_logic_error"}
                    )
            
            # Analyze timing differences
            avg_correct = sum(correct_times) / len(correct_times)
            avg_incorrect = sum(incorrect_times) / len(incorrect_times)
            time_difference = abs(avg_correct - avg_incorrect)
            max_allowed_difference = max(avg_correct, avg_incorrect) * 0.2  # 20% tolerance
            
            timing_resistant = time_difference < max_allowed_difference
            
            details = {
                "avg_correct_time": avg_correct,
                "avg_incorrect_time": avg_incorrect,
                "time_difference": time_difference,
                "max_allowed_difference": max_allowed_difference,
                "iterations": iterations,
                "timing_resistant": timing_resistant
            }
            
            if timing_resistant:
                result = SecurityTestResult.PASS
                message = f"Timing attack resistant (difference: {time_difference:.6f}s)"
            else:
                result = SecurityTestResult.FAIL
                message = f"Timing attack vulnerable (difference: {time_difference:.6f}s)"
            
            return TestResult(
                test_name="timing_attack_resistance",
                result=result,
                message=message,
                execution_time=time.perf_counter() - start_time,
                details=details
            )
            
        except Exception as e:
            return TestResult(
                test_name="timing_attack_resistance",
                result=SecurityTestResult.FAIL,
                message=f"Test execution failed: {str(e)}",
                execution_time=time.perf_counter() - start_time,
                details={"exception": str(e)}
            )

class InputValidator:
    """
    Comprehensive input validation and sanitization
    
    Validates inputs for security issues including injection attacks,
    path traversal, and malformed data that could compromise security.
    """
    
    @staticmethod
    def validate_password_strength(password: str, min_length: int = 30) -> TestResult:
        """
        Validate password strength for quantum resistance
        
        Args:
            password: Password to validate
            min_length: Minimum required length
            
        Returns:
            TestResult with validation details
        """
        start_time = time.perf_counter()
        
        issues = []
        score = 100
        
        try:
            # Length check
            if len(password) < min_length:
                issues.append(f"Too short (minimum {min_length} characters)")
                score -= 30
            
            # Character diversity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
            
            diversity_score = sum([has_upper, has_lower, has_digit, has_special])
            if diversity_score < 3:
                issues.append("Insufficient character diversity")
                score -= 25
            
            # Common patterns
            weak_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
            if any(pattern in password.lower() for pattern in weak_patterns):
                issues.append("Contains common weak patterns")
                score -= 40
            
            # Repetitive patterns
            if re.search(r'(.)\1{3,}', password):
                issues.append("Contains repetitive character sequences")
                score -= 20
            
            # Sequential patterns
            sequential_patterns = ['1234', 'abcd', 'qwer']
            if any(pattern in password.lower() for pattern in sequential_patterns):
                issues.append("Contains sequential patterns")
                score -= 15
            
            result = SecurityTestResult.PASS if score >= 80 else SecurityTestResult.FAIL
            message = f"Password strength: {score}/100"
            if issues:
                message += f" (Issues: {', '.join(issues)})"
            
            return TestResult(
                test_name="password_strength_validation",
                result=result,
                message=message,
                execution_time=time.perf_counter() - start_time,
                details={
                    "score": score,
                    "issues": issues,
                    "character_diversity": diversity_score,
                    "length": len(password)
                }
            )
            
        except Exception as e:
            return TestResult(
                test_name="password_strength_validation",
                result=SecurityTestResult.FAIL,
                message=f"Validation failed: {str(e)}",
                execution_time=time.perf_counter() - start_time,
                details={"exception": str(e)}
            )
    
    @staticmethod
    def validate_file_path(file_path: str) -> TestResult:
        """
        Validate file path for security issues
        
        Args:
            file_path: File path to validate
            
        Returns:
            TestResult with path validation
        """
        start_time = time.perf_counter()
        
        vulnerabilities = []
        
        try:
            # Path traversal check
            if '..' in file_path:
                vulnerabilities.append("Path traversal attempt (..) detected")
            
            # Absolute path check (could be dangerous)
            if os.path.isabs(file_path) and not file_path.startswith('/tmp/'):
                vulnerabilities.append("Absolute path outside safe directory")
            
            # Dangerous characters
            dangerous_chars = ['|', ';', '&', '$', '`', '>', '<']
            if any(char in file_path for char in dangerous_chars):
                vulnerabilities.append("Dangerous shell characters detected")
            
            # Null byte injection
            if '\x00' in file_path:
                vulnerabilities.append("Null byte injection detected")
            
            # Excessive length
            if len(file_path) > 4096:
                vulnerabilities.append("Path length exceeds safe limits")
            
            result = SecurityTestResult.PASS if not vulnerabilities else SecurityTestResult.FAIL
            message = "Path is safe" if not vulnerabilities else f"Vulnerabilities: {', '.join(vulnerabilities)}"
            
            return TestResult(
                test_name="file_path_validation",
                result=result,
                message=message,
                execution_time=time.perf_counter() - start_time,
                details={
                    "vulnerabilities": vulnerabilities,
                    "path_length": len(file_path),
                    "is_absolute": os.path.isabs(file_path)
                }
            )
            
        except Exception as e:
            return TestResult(
                test_name="file_path_validation",
                result=SecurityTestResult.FAIL,
                message=f"Validation failed: {str(e)}",
                execution_time=time.perf_counter() - start_time,
                details={"exception": str(e)}
            )

class CryptographicTester:
    """
    Test cryptographic operations for consistency and security
    
    Validates that cryptographic functions behave correctly and
    securely under various conditions and inputs.
    """
    
    @staticmethod
    def test_hash_consistency(hash_func: Callable, test_input: str, iterations: int = 10) -> TestResult:
        """
        Test that hash function produces consistent results
        
        Args:
            hash_func: Hash function to test
            test_input: Input to hash
            iterations: Number of consistency tests
            
        Returns:
            TestResult with consistency validation
        """
        start_time = time.perf_counter()
        
        try:
            # Get reference hash
            reference_hash = hash_func(test_input)
            
            # Test consistency
            inconsistencies = 0
            for i in range(iterations):
                current_hash = hash_func(test_input)
                if current_hash != reference_hash:
                    inconsistencies += 1
            
            consistency_rate = ((iterations - inconsistencies) / iterations) * 100
            
            if inconsistencies == 0:
                result = SecurityTestResult.PASS
                message = f"Hash function is consistent ({iterations}/{iterations} tests passed)"
            else:
                result = SecurityTestResult.FAIL
                message = f"Hash function inconsistent ({inconsistencies}/{iterations} failures)"
            
            return TestResult(
                test_name="hash_consistency",
                result=result,
                message=message,
                execution_time=time.perf_counter() - start_time,
                details={
                    "iterations": iterations,
                    "inconsistencies": inconsistencies,
                    "consistency_rate": consistency_rate
                }
            )
            
        except Exception as e:
            return TestResult(
                test_name="hash_consistency",
                result=SecurityTestResult.FAIL,
                message=f"Test failed: {str(e)}",
                execution_time=time.perf_counter() - start_time,
                details={"exception": str(e)}
            )
    
    @staticmethod
    def test_salt_uniqueness(salt_generator: Callable, count: int = 100) -> TestResult:
        """
        Test that salt generator produces unique values
        
        Args:
            salt_generator: Function that generates salts
            count: Number of salts to generate and test
            
        Returns:
            TestResult with uniqueness validation
        """
        start_time = time.perf_counter()
        
        try:
            salts = set()
            duplicates = 0
            
            for _ in range(count):
                salt = salt_generator()
                if salt in salts:
                    duplicates += 1
                else:
                    salts.add(salt)
            
            uniqueness_rate = ((count - duplicates) / count) * 100
            
            if duplicates == 0:
                result = SecurityTestResult.PASS
                message = f"Salt generator produces unique values ({count}/{count} unique)"
            else:
                result = SecurityTestResult.FAIL
                message = f"Salt generator has duplicates ({duplicates}/{count} duplicates)"
            
            return TestResult(
                test_name="salt_uniqueness",
                result=result,
                message=message,
                execution_time=time.perf_counter() - start_time,
                details={
                    "total_generated": count,
                    "unique_salts": len(salts),
                    "duplicates": duplicates,
                    "uniqueness_rate": uniqueness_rate
                }
            )
            
        except Exception as e:
            return TestResult(
                test_name="salt_uniqueness",
                result=SecurityTestResult.FAIL,
                message=f"Test failed: {str(e)}",
                execution_time=time.perf_counter() - start_time,
                details={"exception": str(e)}
            )

class SecurityTestFramework:
    """
    Comprehensive security testing framework
    
    Coordinates and executes all security tests, providing detailed
    reports on the security posture of cryptographic operations.
    """
    
    def __init__(self):
        """Initialize security test framework"""
        self.timing_tester = TimingAttackTester()
        self.input_validator = InputValidator()
        self.crypto_tester = CryptographicTester()
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup security test logging"""
        logger = logging.getLogger('SecurityTestFramework')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def run_comprehensive_tests(self, 
                               crypto_functions: Dict[str, Callable],
                               test_data: Dict[str, Any]) -> SecurityTestSuite:
        """
        Run comprehensive security test suite
        
        Args:
            crypto_functions: Dictionary of cryptographic functions to test
            test_data: Test data for validation
            
        Returns:
            SecurityTestSuite with complete results
        """
        start_time = time.perf_counter()
        results = []
        
        self.logger.info("Starting comprehensive security test suite")
        
        # Test password strength validation
        if 'test_passwords' in test_data:
            for password_type, password in test_data['test_passwords'].items():
                result = self.input_validator.validate_password_strength(password)
                result.test_name = f"password_strength_{password_type}"
                results.append(result)
        
        # Test file path validation
        if 'test_paths' in test_data:
            for path_type, path in test_data['test_paths'].items():
                result = self.input_validator.validate_file_path(path)
                result.test_name = f"file_path_{path_type}"
                results.append(result)
        
        # Test hash consistency
        if 'hash_function' in crypto_functions:
            result = self.crypto_tester.test_hash_consistency(
                crypto_functions['hash_function'],
                test_data.get('test_string', 'test_data_for_hashing')
            )
            results.append(result)
        
        # Test salt uniqueness
        if 'salt_generator' in crypto_functions:
            result = self.crypto_tester.test_salt_uniqueness(crypto_functions['salt_generator'])
            results.append(result)
        
        # Test timing attack resistance
        if 'verify_function' in crypto_functions and 'test_credentials' in test_data:
            creds = test_data['test_credentials']
            
            # Create test function for timing analysis
            def test_verify(password):
                return crypto_functions['verify_function'](password, creds['hash_data'])
            
            result = self.timing_tester.test_constant_time_comparison(
                test_verify,
                creds['correct_password'],
                creds['incorrect_password']
            )
            results.append(result)
        
        # Calculate summary statistics
        total_tests = len(results)
        passed = sum(1 for r in results if r.result == SecurityTestResult.PASS)
        failed = sum(1 for r in results if r.result == SecurityTestResult.FAIL)
        warnings = sum(1 for r in results if r.result == SecurityTestResult.WARNING)
        skipped = sum(1 for r in results if r.result == SecurityTestResult.SKIP)
        
        execution_time = time.perf_counter() - start_time
        
        self.logger.info(f"Security test suite completed: {passed}/{total_tests} tests passed")
        
        return SecurityTestSuite(
            total_tests=total_tests,
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            execution_time=execution_time,
            results=results
        )
    
    def generate_security_report(self, test_suite: SecurityTestSuite) -> str:
        """
        Generate detailed security test report
        
        Args:
            test_suite: Completed test suite results
            
        Returns:
            Formatted security report string
        """
        report = []
        report.append("SECURITY TEST REPORT")
        report.append("=" * 50)
        report.append(f"Total Tests: {test_suite.total_tests}")
        report.append(f"Passed: {test_suite.passed}")
        report.append(f"Failed: {test_suite.failed}")
        report.append(f"Warnings: {test_suite.warnings}")
        report.append(f"Skipped: {test_suite.skipped}")
        report.append(f"Execution Time: {test_suite.execution_time:.3f}s")
        report.append(f"Success Rate: {(test_suite.passed/test_suite.total_tests)*100:.1f}%")
        report.append("")
        
        # Detailed results
        report.append("DETAILED RESULTS")
        report.append("-" * 30)
        
        for result in test_suite.results:
            status_icon = {
                SecurityTestResult.PASS: "✓",
                SecurityTestResult.FAIL: "✗",
                SecurityTestResult.WARNING: "⚠",
                SecurityTestResult.SKIP: "○"
            }[result.result]
            
            report.append(f"{status_icon} {result.test_name}: {result.result.value}")
            report.append(f"  Message: {result.message}")
            report.append(f"  Time: {result.execution_time:.6f}s")
            if result.details:
                report.append(f"  Details: {result.details}")
            report.append("")
        
        # Security recommendations
        if test_suite.failed > 0:
            report.append("SECURITY RECOMMENDATIONS")
            report.append("-" * 30)
            
            failed_tests = [r for r in test_suite.results if r.result == SecurityTestResult.FAIL]
            for result in failed_tests:
                report.append(f"• {result.test_name}: {result.message}")
            report.append("")
        
        report.append("END OF REPORT")
        
        return "\n".join(report)

# Example usage and testing
if __name__ == "__main__":
    # Example cryptographic functions for testing
    def example_hash_function(data: str) -> str:
        return hashlib.sha3_512(data.encode()).hexdigest()
    
    def example_salt_generator() -> bytes:
        return secrets.token_bytes(64)
    
    def example_verify_function(password: str, hash_data: dict) -> bool:
        # Simulate constant-time password verification
        time.sleep(0.001)  # Simulate processing time
        return secrets.compare_digest(password, hash_data.get('password', ''))
    
    # Test data
    test_data = {
        'test_passwords': {
            'weak': 'password123',
            'strong': 'MyVerySecurePassword123!@#ForQuantumResistance',
            'medium': 'GoodPassword456!'
        },
        'test_paths': {
            'safe': 'data/vault.enc',
            'traversal': '../../../etc/passwd',
            'dangerous': 'file.txt; rm -rf /',
            'absolute': '/home/user/vault.enc'
        },
        'test_string': 'test_data_for_cryptographic_consistency_validation',
        'test_credentials': {
            'correct_password': 'correct_test_password',
            'incorrect_password': 'wrong_test_password',
            'hash_data': {'password': 'correct_test_password'}
        }
    }
    
    # Cryptographic functions
    crypto_functions = {
        'hash_function': example_hash_function,
        'salt_generator': example_salt_generator,
        'verify_function': example_verify_function
    }
    
    # Run comprehensive security tests
    framework = SecurityTestFramework()
    test_suite = framework.run_comprehensive_tests(crypto_functions, test_data)
    
    # Generate and display report
    report = framework.generate_security_report(test_suite)
    print(report)
