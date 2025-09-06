#!/usr/bin/env python3
"""
Setup script for configuring download tracking
"""

import json
import os

def setup_tracking():
    """Interactive setup for download tracking configuration"""
    config_file = "tracking_config.json"
    
    print("🔧 Download Tracking Setup")
    print("=" * 40)
    
    # Load existing config
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {
            "package_name": "device-fingerprinting-pro",
            "npm_package_name": "device-fingerprinting-pro-js",
            "docker_username": "yourusername",
            "github_username": "Johnsonajibi",
            "github_token": "",
            "tracking_interval_hours": 24,
            "output_file": "download_stats.csv"
        }
    
    print(f"Current package name: {config['package_name']}")
    print(f"Current GitHub username: {config['github_username']}")
    print(f"Current Docker username: {config['docker_username']}")
    
    # Check if GitHub token is set
    if not config.get('github_token'):
        print("\n⚠️  GitHub token not configured!")
        print("To track GitHub Packages downloads, you need a GitHub personal access token.")
        print("\nSteps to create a GitHub token:")
        print("1. Go to https://github.com/settings/tokens")
        print("2. Click 'Generate new token (classic)'")
        print("3. Select scope: 'read:packages'")
        print("4. Copy the generated token")
        
        token = input("\nEnter your GitHub token (or press Enter to skip): ").strip()
        if token:
            config['github_token'] = token
            print("✅ GitHub token configured!")
        else:
            print("⚠️  GitHub Packages tracking will be skipped")
    else:
        print("✅ GitHub token is configured")
    
    # Update Docker username if needed
    if config['docker_username'] == 'yourusername':
        docker_user = input(f"\nEnter your Docker Hub username (current: {config['docker_username']}): ").strip()
        if docker_user:
            config['docker_username'] = docker_user
            print(f"✅ Docker username updated to: {docker_user}")
    
    # Save configuration
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Configuration saved to {config_file}")
    print("\nYou can now run: python download_tracker.py")

if __name__ == "__main__":
    setup_tracking()
