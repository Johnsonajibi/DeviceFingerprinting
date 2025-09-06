# Installation Guide for Distribution Tools

This guide helps you install the necessary tools for multi-platform distribution.

## 🐳 Docker Installation

### Windows:
1. **Download Docker Desktop**: https://www.docker.com/products/docker-desktop/
2. **Install**: Run the installer and follow prompts
3. **Restart**: Restart your computer
4. **Verify**: Open PowerShell and run `docker --version`

### Alternative (Chocolatey):
```powershell
# Install Chocolatey first (if not installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Docker
choco install docker-desktop
```

## 📦 Node.js Installation

### Windows:
1. **Download Node.js**: https://nodejs.org/en/download/
2. **Install**: Run the installer (choose LTS version)
3. **Verify**: Open PowerShell and run `node --version`

### Alternative (Chocolatey):
```powershell
choco install nodejs
```

## 🚀 Quick Deployment Commands

Once tools are installed:

### Docker Hub:
```bash
# Build the image
docker build -t johnsonajibi/device-fingerprinting-pro:1.0.3 .

# Test locally
docker run --rm johnsonajibi/device-fingerprinting-pro:1.0.3

# Push to Docker Hub (requires login)
docker login
docker push johnsonajibi/device-fingerprinting-pro:1.0.3
```

### NPM Package:
```bash
# Navigate to npm folder
cd npm

# Login to NPM
npm login

# Publish package
npm publish
```

## 📊 Current Status

- ✅ **PyPI**: Published (device-fingerprinting-pro 1.0.3)
- 🟡 **Conda-Forge**: Under review
- ✅ **GitHub Packages**: Workflow configured
- 🔄 **Docker Hub**: Ready to build
- 🔄 **NPM**: Ready to publish

## 🎯 Next Steps

1. Install Docker and Node.js
2. Test local builds
3. Publish to remaining platforms
4. Monitor download analytics

## 📈 Analytics Tracking

Your download tracker is ready at: `tracking/download_tracker.py`

Run it with:
```bash
python tracking/download_tracker.py
```
