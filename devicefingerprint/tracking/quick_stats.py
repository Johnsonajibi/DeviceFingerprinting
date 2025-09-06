#!/usr/bin/env python3
"""
Quick Download Stats - Simple command line tool to check current download statistics
"""

import requests
import json
from datetime import datetime

def get_quick_stats():
    """Get quick overview of download statistics"""
    package_name = "device-fingerprinting-pro"
    
    print("🔍 Fetching current download statistics...")
    print("=" * 50)
    
    # PyPI Stats
    try:
        url = f"https://api.pepy.tech/api/v2/projects/{package_name}"
        response = requests.get(url, timeout=10)
        data = response.json()
        total_downloads = data.get('total_downloads', 0)
        print(f"📦 PyPI Total Downloads: {total_downloads:,}")
        
        # Recent downloads
        recent_url = f"https://pypistats.org/api/packages/{package_name}/recent"
        recent_response = requests.get(recent_url, timeout=10)
        recent_data = recent_response.json()
        
        last_day = recent_data.get('data', {}).get('last_day', 0)
        last_week = recent_data.get('data', {}).get('last_week', 0)
        last_month = recent_data.get('data', {}).get('last_month', 0)
        
        print(f"📅 Last Day: {last_day:,}")
        print(f"📅 Last Week: {last_week:,}")
        print(f"📅 Last Month: {last_month:,}")
        
    except Exception as e:
        print(f"❌ PyPI Error: {e}")
    
    print("\n" + "=" * 50)
    print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("For detailed multi-platform tracking, run: python download_tracker.py")

if __name__ == "__main__":
    get_quick_stats()
