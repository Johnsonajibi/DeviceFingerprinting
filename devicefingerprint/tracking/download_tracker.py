#!/usr/bin/env python3
"""
Multi-Platform Download Tracker for DeviceFingerprint Library
Automatically collects download statistics from all distribution platforms
"""

import requests
import json
import os
from datetime import datetime, timedelta
import csv
from typing import Dict, List, Any

class MultiPlatformTracker:
    def __init__(self, config_file="tracking_config.json"):
        """Initialize tracker with configuration"""
        self.config = self.load_config(config_file)
        self.stats = []
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "package_name": "device-fingerprinting-pro",
            "npm_package_name": "device-fingerprinting-pro-js",
            "docker_username": "yourusername",
            "github_username": "Johnsonajibi",
            "github_token": "",  # Add your GitHub token
            "tracking_interval_hours": 24,
            "output_file": "download_stats.csv"
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            # Create default config file
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config
    
    def get_pypi_stats(self) -> Dict[str, Any]:
        """Get PyPI download statistics"""
        package_name = self.config["package_name"]
        try:
            # Pepy.tech API for total downloads (more reliable)
            pepy_url = f"https://api.pepy.tech/api/v2/projects/{package_name}"
            pepy_response = requests.get(pepy_url, timeout=10)
            
            if pepy_response.status_code == 404:
                # Package not found or no downloads yet
                return {
                    'platform': 'PyPI',
                    'daily_downloads': 0,
                    'weekly_downloads': 0,
                    'monthly_downloads': 0,
                    'total_downloads': 0,
                    'status': 'success',
                    'note': 'Package found but no download data available yet'
                }
            
            total_data = pepy_response.json()
            
            # Try PyPI Stats API for recent data
            recent_downloads = {'last_day': 0, 'last_week': 0, 'last_month': 0}
            try:
                url = f"https://pypistats.org/api/packages/{package_name}/recent"
                response = requests.get(url, timeout=10)
                recent_data = response.json()
                if 'data' in recent_data:
                    recent_downloads = recent_data['data']
            except:
                pass  # Use defaults if recent stats fail
            
            return {
                'platform': 'PyPI',
                'daily_downloads': recent_downloads.get('last_day', 0),
                'weekly_downloads': recent_downloads.get('last_week', 0),
                'monthly_downloads': recent_downloads.get('last_month', 0),
                'total_downloads': total_data.get('total_downloads', 0),
                'status': 'success'
            }
        except Exception as e:
            return {'platform': 'PyPI', 'status': 'error', 'error': str(e)}
    
    def get_conda_stats(self) -> Dict[str, Any]:
        """Get Conda-Forge download statistics"""
        package_name = self.config["package_name"]
        try:
            url = f"https://api.anaconda.org/package/conda-forge/{package_name}"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            return {
                'platform': 'Conda-Forge',
                'total_downloads': data.get('download_count', 0),
                'recent_downloads': data.get('recent_download_count', 0),
                'status': 'success'
            }
        except Exception as e:
            return {'platform': 'Conda-Forge', 'status': 'error', 'error': str(e)}
    
    def get_docker_stats(self) -> Dict[str, Any]:
        """Get Docker Hub pull statistics"""
        username = self.config["docker_username"]
        package_name = self.config["package_name"]
        try:
            url = f"https://hub.docker.com/v2/repositories/{username}/{package_name}/"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            return {
                'platform': 'Docker Hub',
                'total_downloads': data.get('pull_count', 0),
                'stars': data.get('star_count', 0),
                'status': 'success'
            }
        except Exception as e:
            return {'platform': 'Docker Hub', 'status': 'error', 'error': str(e)}
    
    def get_github_packages_stats(self) -> Dict[str, Any]:
        """Get GitHub Packages download statistics"""
        username = self.config["github_username"]
        package_name = self.config["package_name"]
        token = self.config.get("github_token")
        
        if not token:
            return {'platform': 'GitHub Packages', 'status': 'error', 'error': 'No GitHub token provided'}
        
        try:
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"https://api.github.com/users/{username}/packages/pypi/{package_name}/versions"
            response = requests.get(url, headers=headers, timeout=10)
            versions = response.json()
            
            total_downloads = 0
            for version in versions:
                total_downloads += version.get('download_count', 0)
            
            return {
                'platform': 'GitHub Packages',
                'total_downloads': total_downloads,
                'versions': len(versions),
                'status': 'success'
            }
        except Exception as e:
            return {'platform': 'GitHub Packages', 'status': 'error', 'error': str(e)}
    
    def get_npm_stats(self) -> Dict[str, Any]:
        """Get NPM download statistics"""
        package_name = self.config["npm_package_name"]
        try:
            # Monthly downloads
            monthly_url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
            monthly_response = requests.get(monthly_url, timeout=10)
            monthly_data = monthly_response.json()
            
            # Weekly downloads
            weekly_url = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
            weekly_response = requests.get(weekly_url, timeout=10)
            weekly_data = weekly_response.json()
            
            # Total downloads (approximate - get from range)
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
            total_url = f"https://api.npmjs.org/downloads/range/{start_date}:{end_date}/{package_name}"
            total_response = requests.get(total_url, timeout=10)
            total_data = total_response.json()
            
            total_downloads = sum(day['downloads'] for day in total_data.get('downloads', []))
            
            return {
                'platform': 'NPM',
                'weekly_downloads': weekly_data.get('downloads', 0),
                'monthly_downloads': monthly_data.get('downloads', 0),
                'total_downloads': total_downloads,
                'status': 'success'
            }
        except Exception as e:
            return {'platform': 'NPM', 'status': 'error', 'error': str(e)}
    
    def get_enterprise_stats(self) -> Dict[str, Any]:
        """Placeholder for enterprise platform statistics"""
        # Note: Enterprise platforms (Azure Artifacts, AWS CodeArtifact) 
        # require custom API integration with your specific accounts
        return {
            'platform': 'Enterprise (Azure/AWS)',
            'total_downloads': 0,
            'status': 'manual_tracking_required',
            'note': 'Enterprise platforms require manual API setup'
        }
    
    def collect_all_stats(self) -> List[Dict[str, Any]]:
        """Collect statistics from all platforms"""
        print("🔍 Collecting download statistics from all platforms...")
        
        collectors = [
            self.get_pypi_stats,
            self.get_conda_stats,
            self.get_docker_stats,
            self.get_github_packages_stats,
            self.get_npm_stats,
            self.get_enterprise_stats
        ]
        
        all_stats = []
        for collector in collectors:
            try:
                stats = collector()
                stats['timestamp'] = datetime.now().isoformat()
                all_stats.append(stats)
                
                platform = stats.get('platform', 'Unknown')
                status = stats.get('status', 'unknown')
                if status == 'success':
                    total = stats.get('total_downloads', 0)
                    note = stats.get('note', '')
                    if note:
                        print(f"✅ {platform}: {total:,} total downloads ({note})")
                    else:
                        print(f"✅ {platform}: {total:,} total downloads")
                elif status == 'manual_tracking_required':
                    note = stats.get('note', 'Manual setup required')
                    print(f"⚠️ {platform}: {note}")
                else:
                    print(f"❌ {platform}: {stats.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"❌ Error collecting stats: {e}")
        
        return all_stats
    
    def calculate_totals(self, stats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate total downloads across all platforms"""
        totals = {
            'total_downloads': 0,
            'monthly_downloads': 0,
            'weekly_downloads': 0,
            'daily_downloads': 0,
            'active_platforms': 0
        }
        
        for stat in stats:
            if stat.get('status') == 'success':
                totals['active_platforms'] += 1
                totals['total_downloads'] += stat.get('total_downloads', 0)
                totals['monthly_downloads'] += stat.get('monthly_downloads', 0)
                totals['weekly_downloads'] += stat.get('weekly_downloads', 0)
                totals['daily_downloads'] += stat.get('daily_downloads', 0)
        
        return totals
    
    def save_to_csv(self, stats: List[Dict[str, Any]]) -> None:
        """Save statistics to CSV file"""
        output_file = self.config["output_file"]
        
        # Prepare data for CSV
        csv_data = []
        for stat in stats:
            row = {
                'timestamp': stat.get('timestamp'),
                'platform': stat.get('platform'),
                'status': stat.get('status'),
                'total_downloads': stat.get('total_downloads', 0),
                'monthly_downloads': stat.get('monthly_downloads', 0),
                'weekly_downloads': stat.get('weekly_downloads', 0),
                'daily_downloads': stat.get('daily_downloads', 0),
                'error': stat.get('error', '')
            }
            csv_data.append(row)
        
        # Write to CSV
        fieldnames = ['timestamp', 'platform', 'status', 'total_downloads', 
                     'monthly_downloads', 'weekly_downloads', 'daily_downloads', 'error']
        
        file_exists = os.path.exists(output_file)
        with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            if not file_exists:
                writer.writeheader()
            
            writer.writerows(csv_data)
        
        print(f"📊 Statistics saved to {output_file}")
    
    def generate_report(self, stats: List[Dict[str, Any]]) -> str:
        """Generate a formatted report"""
        totals = self.calculate_totals(stats)
        
        report = f"""
📊 DEVICE-FINGERPRINTING-PRO DOWNLOAD REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

🎯 SUMMARY STATISTICS:
  Total Downloads (All Platforms): {totals['total_downloads']:,}
  Monthly Downloads: {totals['monthly_downloads']:,}
  Weekly Downloads: {totals['weekly_downloads']:,}
  Daily Downloads: {totals['daily_downloads']:,}
  Active Platforms: {totals['active_platforms']}/6

📈 PLATFORM BREAKDOWN:
"""
        
        for stat in stats:
            platform = stat.get('platform', 'Unknown')
            status = stat.get('status', 'unknown')
            
            if status == 'success':
                total = stat.get('total_downloads', 0)
                monthly = stat.get('monthly_downloads', 0)
                weekly = stat.get('weekly_downloads', 0)
                daily = stat.get('daily_downloads', 0)
                
                report += f"""
  {platform}:
    ✅ Status: Active
    📊 Total: {total:,}
    📅 Monthly: {monthly:,}
    📅 Weekly: {weekly:,}
    📅 Daily: {daily:,}
"""
            else:
                error = stat.get('error', 'Unknown error')
                report += f"""
  {platform}:
    ❌ Status: Error
    🔍 Issue: {error}
"""
        
        report += f"""
{'='*60}
🚀 Next Steps:
  1. Fix any platform errors shown above
  2. Set up automated tracking (cron job/GitHub Actions)
  3. Create dashboard for real-time monitoring
  4. Analyze trends to optimize distribution strategy
"""
        
        return report
    
    def run_tracking(self) -> None:
        """Run complete tracking cycle"""
        print("🚀 Starting Multi-Platform Download Tracking...")
        
        # Collect statistics
        stats = self.collect_all_stats()
        
        # Save to CSV
        self.save_to_csv(stats)
        
        # Generate and display report
        report = self.generate_report(stats)
        print(report)
        
        # Save report to file
        report_file = f"download_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"📄 Full report saved to {report_file}")

if __name__ == "__main__":
    tracker = MultiPlatformTracker()
    tracker.run_tracking()