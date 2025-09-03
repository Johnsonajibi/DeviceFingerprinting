"""
Command Line Interface for QuantumVault Password Manager

This module provides the main entry point for the QuantumVault CLI application.
"""

import sys
import os
import argparse
from typing import Optional, List

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from quantumvault.version import get_version, get_version_info


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="quantumvault",
        description="QuantumVault - Post-Quantum Cryptography Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  quantumvault                    # Start interactive mode
  quantumvault --version          # Show version information
  quantumvault --check-security   # Run security validation
  quantumvault --export vault.csv # Export passwords to CSV
  
For more information, visit: https://github.com/Johnsonajibi/Post_Quantum_Offline_Manager
        """,
    )
    
    # Version
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"QuantumVault {get_version()}",
    )
    
    # Security options
    parser.add_argument(
        "--check-security",
        action="store_true",
        help="Run comprehensive security validation",
    )
    
    parser.add_argument(
        "--audit",
        action="store_true", 
        help="Perform security audit of the system",
    )
    
    # Data management
    parser.add_argument(
        "--import",
        dest="import_file",
        metavar="FILE",
        help="Import passwords from CSV file",
    )
    
    parser.add_argument(
        "--export",
        dest="export_file",
        metavar="FILE",
        help="Export passwords to CSV file",
    )
    
    # Configuration
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Use custom configuration file",
    )
    
    parser.add_argument(
        "--verbose", "-V",
        action="store_true",
        help="Enable verbose output",
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-essential output",
    )
    
    # Interactive mode (default)
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        default=True,
        help="Start in interactive mode (default)",
    )
    
    return parser


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for QuantumVault CLI.
    
    Args:
        args: Command line arguments (for testing)
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    try:
        # Import the main application
        from CorrectPQC import main as app_main
        
        # Handle special commands
        if parsed_args.check_security:
            print("🔍 Running security validation...")
            from quantumvault.security.audit import run_security_check
            return run_security_check()
            
        if parsed_args.audit:
            print("🛡️ Performing security audit...")
            from quantumvault.security.audit import run_full_audit
            return run_full_audit()
            
        if parsed_args.import_file:
            print(f"📥 Importing passwords from {parsed_args.import_file}...")
            from quantumvault.data.importer import import_passwords
            return import_passwords(parsed_args.import_file)
            
        if parsed_args.export_file:
            print(f"📤 Exporting passwords to {parsed_args.export_file}...")
            from quantumvault.data.exporter import export_passwords
            return export_passwords(parsed_args.export_file)
        
        # Default: Start interactive mode
        print(f"🚀 Starting QuantumVault v{get_version()}")
        if parsed_args.verbose:
            print("📊 Version Info:", get_version_info())
            
        return app_main()
        
    except KeyboardInterrupt:
        print("\n👋 QuantumVault stopped by user")
        return 0
    except Exception as e:
        if parsed_args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
