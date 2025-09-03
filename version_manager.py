#!/usr/bin/env python3
"""
Version Management Script for QuantumVault

This script helps manage version bumping, tagging, and releases.
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Optional
import re

# Version file path
VERSION_FILE = Path(__file__).parent / "quantumvault" / "version.py"
CHANGELOG_FILE = Path(__file__).parent / "CHANGELOG.md"


def run_command(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def get_current_version() -> str:
    """Get the current version from version.py."""
    with open(VERSION_FILE, 'r') as f:
        content = f.read()
    
    match = re.search(r'__version__ = ["\']([^"\']+)["\']', content)
    if not match:
        raise ValueError("Could not find version in version.py")
    
    return match.group(1)


def bump_version(version_type: str) -> str:
    """Bump version number."""
    current = get_current_version()
    major, minor, patch = map(int, current.split('.'))
    
    if version_type == 'major':
        major += 1
        minor = 0
        patch = 0
    elif version_type == 'minor':
        minor += 1
        patch = 0
    elif version_type == 'patch':
        patch += 1
    else:
        raise ValueError(f"Invalid version type: {version_type}")
    
    new_version = f"{major}.{minor}.{patch}"
    
    # Update version.py
    with open(VERSION_FILE, 'r') as f:
        content = f.read()
    
    new_content = re.sub(
        r'__version__ = ["\'][^"\']+["\']',
        f'__version__ = "{new_version}"',
        content
    )
    
    with open(VERSION_FILE, 'w') as f:
        f.write(new_content)
    
    print(f"Version bumped from {current} to {new_version}")
    return new_version


def create_git_tag(version: str, message: str = None):
    """Create a git tag for the version."""
    tag_name = f"v{version}"
    
    if message is None:
        message = f"Release version {version}"
    
    run_command(['git', 'add', str(VERSION_FILE)])
    run_command(['git', 'commit', '-m', f"Bump version to {version}"])
    run_command(['git', 'tag', '-a', tag_name, '-m', message])
    
    print(f"Created git tag: {tag_name}")


def push_changes():
    """Push changes and tags to remote."""
    run_command(['git', 'push'])
    run_command(['git', 'push', '--tags'])
    print("Pushed changes and tags to remote")


def create_release_package():
    """Create distribution packages."""
    # Clean previous builds
    run_command(['rm', '-rf', 'build/', 'dist/', '*.egg-info/'], check=False)
    
    # Build packages
    run_command([sys.executable, '-m', 'build'])
    print("Created distribution packages in dist/")


def update_changelog(version: str, changes: List[str]):
    """Update CHANGELOG.md with new version."""
    from datetime import datetime
    
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    new_entry = f"""
## [{version}] - {date_str}

### Added
{chr(10).join(f'- {change}' for change in changes)}

"""
    
    if CHANGELOG_FILE.exists():
        with open(CHANGELOG_FILE, 'r') as f:
            content = f.read()
        
        # Insert new entry after the header
        lines = content.split('\n')
        header_end = 0
        for i, line in enumerate(lines):
            if line.startswith('## ['):
                header_end = i
                break
        
        lines.insert(header_end, new_entry.strip())
        new_content = '\n'.join(lines)
    else:
        new_content = f"""# Changelog

All notable changes to this project will be documented in this file.

{new_entry.strip()}
"""
    
    with open(CHANGELOG_FILE, 'w') as f:
        f.write(new_content)
    
    print(f"Updated CHANGELOG.md with version {version}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="QuantumVault Version Management")
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Current version
    subparsers.add_parser('current', help='Show current version')
    
    # Bump version
    bump_parser = subparsers.add_parser('bump', help='Bump version')
    bump_parser.add_argument('type', choices=['major', 'minor', 'patch'],
                           help='Type of version bump')
    bump_parser.add_argument('--message', '-m', help='Commit message')
    bump_parser.add_argument('--tag', action='store_true', help='Create git tag')
    bump_parser.add_argument('--push', action='store_true', help='Push to remote')
    
    # Release
    release_parser = subparsers.add_parser('release', help='Create release')
    release_parser.add_argument('type', choices=['major', 'minor', 'patch'],
                              help='Type of version bump')
    release_parser.add_argument('--changes', nargs='+', 
                              help='List of changes for changelog')
    
    # Package
    subparsers.add_parser('package', help='Create distribution packages')
    
    args = parser.parse_args()
    
    if args.command == 'current':
        print(f"Current version: {get_current_version()}")
    
    elif args.command == 'bump':
        new_version = bump_version(args.type)
        
        if args.tag:
            create_git_tag(new_version, args.message)
        
        if args.push:
            push_changes()
    
    elif args.command == 'release':
        new_version = bump_version(args.type)
        
        if args.changes:
            update_changelog(new_version, args.changes)
        
        create_git_tag(new_version)
        create_release_package()
        
        print(f"Created release {new_version}")
        print("Don't forget to push with: git push && git push --tags")
    
    elif args.command == 'package':
        create_release_package()
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
