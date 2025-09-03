"""
QuantumVault Innovation Libraries - Usage Examples
=================================================

Complete usage guide with practical examples for all innovative libraries.
This file demonstrates how to use each library individually and together.

Author: QuantumVault Development Team
License: MIT
"""

import json
import os
from datetime import datetime

# Example 1: Using the Dual QR Recovery System
def example_dual_qr_recovery():
    """
    Example: How to use the Dual QR Recovery System
    
    This system creates two QR codes that work together for secure recovery,
    preventing single point of failure in password recovery scenarios.
    """
    print("Example 1: Dual QR Recovery System")
    print("=" * 40)
    
    # Import the library
    from dual_qr_recovery import DualQRRecoverySystem
    
    # Initialize the system
    qr_system = DualQRRecoverySystem()
    
    # Step 1: Prepare your recovery data
    master_recovery_data = {
        "master_password_hash": "sha3_512_hash_of_your_master_password",
        "encryption_salt": "your_encryption_salt_here",
        "vault_key_encrypted": "your_encrypted_vault_key",
        "backup_timestamp": datetime.now().isoformat(),
        "recovery_version": "1.0"
    }
    
    security_questions_data = {
        "question_1": "What was your first pet's name?",
        "answer_1_hash": "sha3_512_hash_of_answer_1",
        "question_2": "In what city were you born?",
        "answer_2_hash": "sha3_512_hash_of_answer_2", 
        "question_3": "What was your childhood nickname?",
        "answer_3_hash": "sha3_512_hash_of_answer_3",
        "recovery_timestamp": datetime.now().isoformat()
    }
    
    # Step 2: Create the dual QR system
    print("Creating dual QR recovery system...")
    dual_qr_result = qr_system.create_dual_qr_system(
        master_recovery_data=master_recovery_data,
        security_questions_data=security_questions_data,
        expiry_hours=72  # QR codes expire in 72 hours
    )
    
    print(f"✓ Dual QR system created successfully!")
    print(f"  Primary QR ID: {dual_qr_result.primary_qr.qr_id}")
    print(f"  Secondary QR ID: {dual_qr_result.secondary_qr.qr_id}")
    
    # Step 3: Validate the QR credentials
    print("\nValidating QR credentials...")
    primary_valid, primary_reason = qr_system.validate_qr_credentials(dual_qr_result.primary_qr)
    secondary_valid, secondary_reason = qr_system.validate_qr_credentials(dual_qr_result.secondary_qr)
    
    print(f"Primary QR: {'✓ Valid' if primary_valid else '✗ Invalid'} - {primary_reason}")
    print(f"Secondary QR: {'✓ Valid' if secondary_valid else '✗ Invalid'} - {secondary_reason}")
    
    # Step 4: Simulate recovery process
    if primary_valid:
        print("\nTesting recovery from primary QR...")
        recovered_master_data = qr_system.recover_data_from_qr(dual_qr_result.primary_qr)
        if recovered_master_data:
            print("✓ Master password recovery data retrieved successfully")
            print(f"  Available keys: {list(recovered_master_data.keys())}")
        else:
            print("✗ Failed to recover master password data")
    
    if secondary_valid:
        print("\nTesting recovery from secondary QR...")
        recovered_security_data = qr_system.recover_data_from_qr(dual_qr_result.secondary_qr)
        if recovered_security_data:
            print("✓ Security questions recovery data retrieved successfully")
            print(f"  Available questions: {len([k for k in recovered_security_data.keys() if k.startswith('question')])}")
        else:
            print("✗ Failed to recover security questions data")
    
    # Step 5: Get system statistics
    print("\nSystem Statistics:")
    stats = qr_system.get_qr_statistics(dual_qr_result)
    print(f"  Primary QR size: {stats['primary_qr_size']} bytes")
    print(f"  Secondary QR size: {stats['secondary_qr_size']} bytes")
    print(f"  QR capacity utilization: {stats['qr_capacity_utilization']['primary']:.1f}% / {stats['qr_capacity_utilization']['secondary']:.1f}%")
    print(f"  Time until expiry: {stats['expiry_hours']:.1f} hours")
    
    # Step 6: Print recovery instructions for the user
    print(f"\n{dual_qr_result.recovery_instructions}")
    
    return dual_qr_result

# Example 2: Using Quantum-Resistant Cryptography
def example_quantum_crypto():
    """
    Example: How to use Quantum-Resistant Cryptography
    
    This demonstrates SHA3-512 hashing with quantum resistance features.
    """
    print("\n\nExample 2: Quantum-Resistant Cryptography")
    print("=" * 40)
    
    # Import the library
    from quantum_resistant_crypto import QuantumResistantCrypto
    
    # Initialize quantum-resistant crypto
    crypto = QuantumResistantCrypto(
        salt_length=64,           # 64-byte salts for security
        pbkdf2_iterations=600000, # 600,000 iterations for quantum resistance
        min_password_length=30    # Minimum 30 characters
    )
    
    # Step 1: Validate password strength
    print("Testing password strength validation...")
    
    weak_password = "password123"
    strong_password = "MyVerySecurePassword123!@#ForQuantumResistance2025"
    
    weak_valid, weak_msg = crypto.validate_password_strength(weak_password)
    strong_valid, strong_msg = crypto.validate_password_strength(strong_password)
    
    print(f"Weak password: {'✓' if weak_valid else '✗'} - {weak_msg}")
    print(f"Strong password: {'✓' if strong_valid else '✗'} - {strong_msg}")
    
    # Step 2: Hash a password with quantum resistance
    print("\nHashing password with quantum resistance...")
    if strong_valid:
        hash_result = crypto.hash_password(strong_password)
        print(f"✓ Password hashed successfully")
        print(f"  Algorithm: {hash_result.algorithm}")
        print(f"  Iterations: {hash_result.iterations:,}")
        print(f"  Salt length: {len(hash_result.salt)} characters")
        print(f"  Hash length: {len(hash_result.hash)} characters")
        print(f"  Created: {hash_result.created_at}")
    
    # Step 3: Verify password (with timing attack protection)
    print("\nTesting password verification...")
    correct_verify = crypto.verify_password(strong_password, hash_result)
    incorrect_verify = crypto.verify_password("wrong_password_123", hash_result)
    
    print(f"Correct password verification: {'✓ Pass' if correct_verify else '✗ Fail'}")
    print(f"Incorrect password verification: {'✓ Correctly rejected' if not incorrect_verify else '✗ Incorrectly accepted'}")
    
    # Step 4: Derive encryption keys
    print("\nDeriving encryption keys...")
    vault_key, salt = crypto.derive_key(strong_password, purpose="vault_encryption")
    backup_key, _ = crypto.derive_key(strong_password, salt, purpose="backup_encryption")
    
    print(f"✓ Keys derived successfully")
    print(f"  Vault key length: {len(vault_key)} bytes")
    print(f"  Backup key length: {len(backup_key)} bytes")
    print(f"  Keys are different: {vault_key != backup_key}")
    
    # Step 5: Generate secure random passwords
    print("\nGenerating secure random passwords...")
    random_password_24 = crypto.secure_random_password(24)
    random_password_32 = crypto.secure_random_password(32)
    
    print(f"24-character password: {random_password_24}")
    print(f"32-character password: {random_password_32}")
    
    # Step 6: Test timing attack resistance
    print("\nTesting timing attack resistance...")
    timing_stats = crypto.test_timing_resistance(strong_password, iterations=10)
    
    print(f"Timing resistant: {'✓ Yes' if timing_stats['timing_resistant'] else '✗ No'}")
    print(f"Average correct time: {timing_stats['avg_correct_time']:.6f}s")
    print(f"Average incorrect time: {timing_stats['avg_incorrect_time']:.6f}s")
    print(f"Time difference: {timing_stats['time_difference']:.6f}s")
    
    return hash_result, vault_key

# Example 3: Using Forward-Secure Page Encryption
def example_forward_secure_encryption():
    """
    Example: How to use Forward-Secure Page Encryption
    
    This demonstrates selective page re-encryption during key rotation.
    """
    print("\n\nExample 3: Forward-Secure Page Encryption")
    print("=" * 40)
    
    # Import the library
    from forward_secure_encryption import ForwardSecurePageManager
    
    # Step 1: Initialize with vault size for optimization
    vault_size = 150  # Number of password entries
    fs_manager = ForwardSecurePageManager(vault_size=vault_size)
    
    print(f"Initialized forward-secure manager for {vault_size} entries")
    
    # Step 2: Prepare sample vault data
    vault_data = []
    for i in range(vault_size):
        vault_data.append({
            "service": f"service_{i:03d}",
            "username": f"user_{i:03d}@email.com",
            "password": f"secure_password_{i:03d}!@#",
            "url": f"https://service{i:03d}.com",
            "notes": f"Notes for service {i:03d}",
            "created": datetime.now().isoformat()
        })
    
    print(f"✓ Created sample vault with {len(vault_data)} entries")
    
    # Step 3: Generate encryption keys (32 bytes for AES-256)
    old_key = os.urandom(32)  # Current encryption key
    new_key = os.urandom(32)  # New encryption key for rotation
    
    print("✓ Generated encryption keys for rotation")
    
    # Step 4: Perform forward-secure key rotation
    print("\nPerforming forward-secure key rotation...")
    rotation_result = fs_manager.perform_forward_secure_rotation(
        vault_data=vault_data,
        old_key=old_key,
        new_key=new_key
    )
    
    print(f"Rotation completed:")
    print(f"  Success: {'✓ Yes' if rotation_result.success else '✗ No'}")
    print(f"  Pages rotated: {rotation_result.pages_rotated}")
    print(f"  Pages skipped: {rotation_result.pages_skipped} (forward security)")
    print(f"  Total pages: {rotation_result.total_pages}")
    print(f"  Old epoch: {rotation_result.old_epoch}")
    print(f"  New epoch: {rotation_result.new_epoch}")
    print(f"  Execution time: {rotation_result.rotation_time:.3f}s")
    
    if rotation_result.pages_skipped > 0:
        efficiency = (rotation_result.pages_skipped / rotation_result.total_pages) * 100
        print(f"  Efficiency: {efficiency:.1f}% of pages skipped (already current)")
    
    # Step 5: Get rotation statistics
    print("\nRotation Statistics:")
    stats = fs_manager.get_rotation_statistics()
    print(f"  Current epoch: {stats['current_epoch']}")
    print(f"  Total pages: {stats['total_pages']}")
    print(f"  Page size: {stats['page_size_kb']}KB")
    print(f"  Total rotations: {stats['total_rotations']}")
    print(f"  Dynamic sizing enabled: {stats['dynamic_sizing_enabled']}")
    
    # Step 6: Test vault size update and dynamic resizing
    print("\nTesting dynamic page resizing...")
    new_vault_size = 500
    size_changed = fs_manager.update_vault_size(new_vault_size)
    
    if size_changed:
        print(f"✓ Page size updated for {new_vault_size} entries")
        print(f"  New page size: {fs_manager.page_size_kb}KB")
    else:
        print("○ Page size unchanged")
    
    return rotation_result

# Example 4: Using Steganographic QR System
def example_steganographic_qr():
    """
    Example: How to use Steganographic QR System (Patent Pending)
    
    This demonstrates hiding encrypted data in QR error correction space.
    """
    print("\n\nExample 4: Steganographic QR System (Patent Pending)")
    print("=" * 40)
    
    # Import the library
    from steganographic_qr import SteganographicQRSystem
    
    # Initialize steganographic QR system
    steg_qr = SteganographicQRSystem()
    
    # Step 1: Prepare data for steganographic embedding
    visible_data = "This is the visible QR code data that everyone can see and scan normally"
    hidden_data = "SECRET: This is confidential data hidden in error correction space - vault recovery key abc123xyz789"
    master_key = "steganographic_master_key_for_encryption_2025"
    
    print("Data prepared for steganographic embedding:")
    print(f"  Visible data: {len(visible_data)} characters")
    print(f"  Hidden data: {len(hidden_data)} characters")
    
    # Step 2: Calculate steganographic capacity
    visible_size = len(steg_qr.optimize_data_for_qr(visible_data))
    capacity = steg_qr.calculate_steganographic_capacity(visible_size, 'M')
    
    print(f"\nSteganographic capacity analysis:")
    print(f"  Optimized visible data: {visible_size} bytes")
    print(f"  Available hidden space: {capacity} bytes")
    print(f"  Space utilization: {(len(hidden_data)/capacity)*100:.1f}%")
    
    # Step 3: Embed hidden data in QR error correction space
    print("\nEmbedding hidden data in QR error correction space...")
    steg_result = steg_qr.embed_steganographic_data(
        qr_data=visible_data,
        hidden_data=hidden_data,
        master_key=master_key,
        error_level='M'  # Medium error correction
    )
    
    if steg_result:
        print("✓ Steganographic embedding successful!")
        print(f"  Algorithm: {steg_result['algorithm']}")
        print(f"  Capacity used: {steg_result['capacity_used']} bytes")
        print(f"  Capacity available: {steg_result['capacity_available']} bytes")
        print(f"  Utilization: {steg_result['utilization_percent']:.1f}%")
        print(f"  Patent status: {'Patent Pending' if steg_result['patent_pending'] else 'Standard'}")
    else:
        print("✗ Steganographic embedding failed")
        return None
    
    # Step 4: Extract hidden data from steganographic QR
    print("\nExtracting hidden data from steganographic QR...")
    extracted_data = steg_qr.extract_steganographic_data(steg_result, master_key)
    
    if extracted_data and extracted_data == hidden_data:
        print("✓ Steganographic extraction successful!")
        print(f"  Extracted data matches original: {len(extracted_data)} characters")
    else:
        print("✗ Steganographic extraction failed")
    
    # Step 5: Create dual steganographic QR system
    print("\nCreating dual steganographic QR system...")
    primary_qr, secondary_qr = steg_qr.create_dual_qr_system(
        primary_data="Primary recovery data for master password",
        secondary_data="Secondary recovery data for security questions",
        master_key=master_key
    )
    
    if primary_qr and secondary_qr:
        print("✓ Dual steganographic QR system created!")
        print(f"  Primary QR type: {primary_qr['qr_type']}")
        print(f"  Secondary QR type: {secondary_qr['qr_type']}")
        
        # Show statistics
        stats = steg_qr.get_steganographic_statistics(primary_qr)
        print(f"\nStatistics:")
        print(f"  Space efficiency: {stats['space_efficiency']:.1f}%")
        print(f"  Innovation type: {stats['innovation_type']}")
        print(f"  Patent status: {stats['patent_status']}")
    else:
        print("✗ Dual steganographic QR system creation failed")
    
    return steg_result

# Example 5: Using Dynamic Page Sizing
def example_dynamic_page_sizing():
    """
    Example: How to use Dynamic Page Sizing Optimization
    
    This demonstrates automatic page size calculation for different vault sizes.
    """
    print("\n\nExample 5: Dynamic Page Sizing Optimization")
    print("=" * 40)
    
    # Import the library
    from dynamic_page_sizing import DynamicPageSizer, VaultSizeCategory
    
    # Initialize dynamic page sizer
    sizer = DynamicPageSizer()
    
    # Step 1: Test page sizing for different vault sizes
    print("Testing optimal page sizes for different vault sizes:")
    
    test_vault_sizes = [5, 25, 100, 300, 750, 2000, 10000]
    
    for vault_size in test_vault_sizes:
        result = sizer.calculate_optimal_page_size(vault_size)
        print(f"\n{vault_size:5d} entries:")
        print(f"  Category: {result.category.value}")
        print(f"  Optimal page size: {result.optimal_page_size_kb}KB")
        print(f"  Expected pages: {result.expected_pages}")
        print(f"  Memory efficiency: {result.memory_efficiency}%")
        print(f"  Security granularity: {result.security_granularity}")
    
    # Step 2: Operation-specific optimization
    print(f"\n\nOperation-specific optimization for 200-entry vault:")
    vault_size = 200
    operations = ['read', 'write', 'rotation', 'backup']
    
    for operation in operations:
        result = sizer.optimize_for_operation(vault_size, operation)
        print(f"{operation:8s}: {result.optimal_page_size_kb}KB (efficiency: {result.memory_efficiency}%)")
    
    # Step 3: Configuration comparison
    print(f"\n\nConfiguration comparison for {vault_size}-entry vault:")
    comparisons = sizer.compare_configurations(vault_size)
    
    for config_name, result in comparisons.items():
        print(f"{config_name:8s}: {result.optimal_page_size_kb}KB pages, {result.expected_pages} pages, {result.memory_efficiency}% efficiency")
    
    # Step 4: Detailed performance metrics
    optimal_result = sizer.calculate_optimal_page_size(vault_size)
    metrics = sizer.get_performance_metrics(optimal_result)
    
    print(f"\nDetailed performance metrics for optimal configuration:")
    print(f"  Page size: {metrics['page_size_bytes']} bytes")
    print(f"  Expected pages: {metrics['expected_pages']}")
    print(f"  Total overhead: {metrics['total_overhead_kb']:.1f}KB")
    print(f"  Pages per entry: {metrics['pages_per_entry']:.2f}")
    print(f"  Bytes per entry: {metrics['bytes_per_entry']:.0f}")
    
    return optimal_result

# Example 6: Using Security Testing Framework
def example_security_testing():
    """
    Example: How to use Security Testing Framework
    
    This demonstrates comprehensive security validation and testing.
    """
    print("\n\nExample 6: Security Testing Framework")
    print("=" * 40)
    
    # Import the libraries
    from security_testing import SecurityTestFramework
    from quantum_resistant_crypto import QuantumResistantCrypto
    
    # Initialize components
    framework = SecurityTestFramework()
    crypto = QuantumResistantCrypto()
    
    # Step 1: Prepare test functions and data
    print("Preparing security tests...")
    
    # Create cryptographic functions to test
    crypto_functions = {
        'hash_function': lambda x: crypto.hash_password(x + "A" * 10).hash,  # Add padding for min length
        'salt_generator': crypto.generate_salt,
        'verify_function': crypto.verify_password
    }
    
    # Create test data
    test_password = "SecureTestPassword123!@#ForSecurityValidation"
    hash_result = crypto.hash_password(test_password)
    
    test_data = {
        'test_passwords': {
            'weak': 'password123',
            'medium': 'GoodPassword456!',
            'strong': test_password
        },
        'test_paths': {
            'safe': 'data/vault.enc',
            'traversal': '../../../etc/passwd',
            'dangerous': 'file.txt; rm -rf /',
            'absolute': '/tmp/safe_file.txt'
        },
        'test_string': 'test_data_for_cryptographic_consistency_validation',
        'test_credentials': {
            'correct_password': test_password,
            'incorrect_password': 'wrong_test_password_that_should_fail',
            'hash_data': hash_result
        }
    }
    
    # Step 2: Run comprehensive security tests
    print("\nRunning comprehensive security test suite...")
    test_suite = framework.run_comprehensive_tests(crypto_functions, test_data)
    
    print(f"\nTest Results Summary:")
    print(f"  Total tests: {test_suite.total_tests}")
    print(f"  Passed: {test_suite.passed}")
    print(f"  Failed: {test_suite.failed}")
    print(f"  Warnings: {test_suite.warnings}")
    print(f"  Skipped: {test_suite.skipped}")
    print(f"  Success rate: {(test_suite.passed/test_suite.total_tests)*100:.1f}%")
    print(f"  Execution time: {test_suite.execution_time:.3f}s")
    
    # Step 3: Show detailed results
    print(f"\nDetailed Test Results:")
    for result in test_suite.results:
        status_icon = {"PASS": "✓", "FAIL": "✗", "WARNING": "⚠", "SKIP": "○"}[result.result.value]
        print(f"  {status_icon} {result.test_name}: {result.message}")
    
    # Step 4: Generate security report
    print(f"\nGenerating comprehensive security report...")
    report = framework.generate_security_report(test_suite)
    
    # Save report to file
    with open('security_test_report.txt', 'w') as f:
        f.write(report)
    
    print(f"✓ Security report saved to 'security_test_report.txt'")
    
    return test_suite

# Complete Integration Example
def example_complete_integration():
    """
    Example: Complete Integration of All Libraries
    
    This demonstrates how all libraries work together in a real-world scenario.
    """
    print("\n\nExample 7: Complete Integration")
    print("=" * 40)
    
    # Step 1: Initialize all systems
    print("Initializing all quantum vault systems...")
    
    from quantum_resistant_crypto import QuantumResistantCrypto
    from forward_secure_encryption import ForwardSecurePageManager
    from dual_qr_recovery import DualQRRecoverySystem
    from steganographic_qr import SteganographicQRSystem
    from dynamic_page_sizing import DynamicPageSizer
    from security_testing import SecurityTestFramework
    
    # Initialize components
    crypto = QuantumResistantCrypto()
    fs_manager = ForwardSecurePageManager(vault_size=100)
    qr_recovery = DualQRRecoverySystem()
    steg_qr = SteganographicQRSystem()
    sizer = DynamicPageSizer()
    security = SecurityTestFramework()
    
    print("✓ All systems initialized")
    
    # Step 2: Create and secure a vault
    master_password = "MyQuantumResistantMasterPassword123!@#$%^&*()"
    
    # Hash the master password
    print("\nSecuring master password with quantum-resistant hashing...")
    master_hash = crypto.hash_password(master_password)
    print(f"✓ Master password secured with {master_hash.algorithm}")
    
    # Derive vault encryption key
    vault_key, vault_salt = crypto.derive_key(master_password, purpose="vault_encryption")
    print(f"✓ Vault encryption key derived ({len(vault_key)} bytes)")
    
    # Step 3: Optimize page sizing for the vault
    vault_size = 150
    page_optimization = sizer.calculate_optimal_page_size(vault_size)
    fs_manager.update_vault_size(vault_size)
    
    print(f"\n✓ Page sizing optimized for {vault_size} entries:")
    print(f"  Optimal page size: {page_optimization.optimal_page_size_kb}KB")
    print(f"  Expected pages: {page_optimization.expected_pages}")
    print(f"  Security level: {page_optimization.security_granularity}")
    
    # Step 4: Create recovery system with steganographic QR codes
    print(f"\nCreating advanced recovery system...")
    
    # Prepare recovery data
    master_recovery = {
        "master_hash": master_hash.hash,
        "vault_salt": master_hash.salt,
        "vault_key_encrypted": "encrypted_vault_key_here",
        "algorithm": master_hash.algorithm
    }
    
    security_recovery = {
        "question_1": "What was your first pet's name?",
        "answer_1_hash": crypto.hash_password("Fluffy" + "A" * 25).hash,
        "question_2": "In what city were you born?",
        "answer_2_hash": crypto.hash_password("Springfield" + "A" * 20).hash
    }
    
    # Create dual QR with steganographic enhancement
    dual_qr_result = qr_recovery.create_dual_qr_system(
        master_recovery, security_recovery, expiry_hours=48
    )
    
    # Add steganographic layer
    steg_primary = steg_qr.embed_steganographic_data(
        qr_data=json.dumps(master_recovery),
        hidden_data=json.dumps(security_recovery),
        master_key=master_password[:32]  # Use part of master password as steg key
    )
    
    print(f"✓ Advanced recovery system created:")
    print(f"  Dual QR codes: {dual_qr_result.primary_qr.qr_id[:16]}... / {dual_qr_result.secondary_qr.qr_id[:16]}...")
    if steg_primary:
        print(f"  Steganographic enhancement: {steg_primary['utilization_percent']:.1f}% utilization")
    
    # Step 5: Simulate vault operations with forward-secure encryption
    print(f"\nSimulating vault operations...")
    
    # Create sample vault data
    vault_data = [
        {"service": "gmail", "password": "secure_gmail_password_123!"},
        {"service": "github", "password": "secure_github_password_456!"},
        {"service": "aws", "password": "secure_aws_password_789!"}
    ]
    
    # Perform forward-secure key rotation
    new_key, _ = crypto.derive_key(master_password + "_rotated", purpose="vault_encryption")
    rotation_result = fs_manager.perform_forward_secure_rotation(vault_data, vault_key, new_key)
    
    print(f"✓ Forward-secure key rotation completed:")
    print(f"  Pages rotated: {rotation_result.pages_rotated}")
    print(f"  Pages preserved: {rotation_result.pages_skipped}")
    print(f"  Rotation time: {rotation_result.rotation_time:.3f}s")
    
    # Step 6: Run comprehensive security validation
    print(f"\nRunning final security validation...")
    
    test_functions = {
        'hash_function': lambda x: crypto.hash_password(x + "A" * 10).hash,
        'verify_function': crypto.verify_password,
        'salt_generator': crypto.generate_salt
    }
    
    test_data = {
        'test_passwords': {'strong': master_password},
        'test_credentials': {
            'correct_password': master_password,
            'incorrect_password': 'wrong_password',
            'hash_data': master_hash
        }
    }
    
    final_tests = security.run_comprehensive_tests(test_functions, test_data)
    
    print(f"✓ Security validation completed:")
    print(f"  Tests passed: {final_tests.passed}/{final_tests.total_tests}")
    print(f"  Security score: {(final_tests.passed/final_tests.total_tests)*100:.1f}%")
    
    # Step 7: Generate comprehensive report
    print(f"\nGenerating comprehensive system report...")
    
    system_report = {
        "quantum_vault_version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "master_password_security": {
            "algorithm": master_hash.algorithm,
            "iterations": master_hash.iterations,
            "quantum_resistant": True
        },
        "vault_configuration": {
            "vault_size": vault_size,
            "page_size_kb": page_optimization.optimal_page_size_kb,
            "expected_pages": page_optimization.expected_pages,
            "forward_secure": True
        },
        "recovery_system": {
            "dual_qr_enabled": True,
            "steganographic_enhancement": steg_primary is not None,
            "device_bound": True,
            "time_limited": True
        },
        "security_validation": {
            "tests_passed": final_tests.passed,
            "total_tests": final_tests.total_tests,
            "success_rate": (final_tests.passed/final_tests.total_tests)*100
        },
        "innovations_active": [
            "Forward-Secure Page Epoch Encryption",
            "Quantum-Resistant Cryptography",
            "Steganographic QR Code System",
            "Dynamic Page Sizing Optimization", 
            "Dual QR Recovery System",
            "Security Testing Framework"
        ]
    }
    
    # Save comprehensive report
    with open('quantum_vault_system_report.json', 'w') as f:
        json.dump(system_report, f, indent=2)
    
    print(f"✓ System report saved to 'quantum_vault_system_report.json'")
    print(f"\n🎉 Complete QuantumVault system integration successful!")
    print(f"   All 6 innovative libraries working together seamlessly.")
    
    return system_report

# Main execution
if __name__ == "__main__":
    print("QuantumVault Innovation Libraries - Complete Usage Guide")
    print("=" * 60)
    print("This guide demonstrates how to use all innovative libraries.")
    print("Each example can be run independently or as part of integration.")
    print()
    
    try:
        # Run all examples
        example_dual_qr_recovery()
        example_quantum_crypto()
        example_forward_secure_encryption()
        example_steganographic_qr()
        example_dynamic_page_sizing()
        example_security_testing()
        example_complete_integration()
        
        print("\n" + "=" * 60)
        print("🎉 ALL EXAMPLES COMPLETED SUCCESSFULLY!")
        print("   Check the generated files for detailed reports:")
        print("   • security_test_report.txt")
        print("   • quantum_vault_system_report.json")
        
    except ImportError as e:
        print(f"\n❌ Library import error: {e}")
        print("   Make sure all library files are in the same directory.")
        
    except Exception as e:
        print(f"\n❌ Execution error: {e}")
        print("   Check the error details above for troubleshooting.")
