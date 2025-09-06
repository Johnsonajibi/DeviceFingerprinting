# Quick Installation Guide for Distribution Tools

## 🚨 IMPORTANT: Run PowerShell as Administrator

Right-click on PowerShell and select "Run as Administrator" for all installations below.

## Method 1: Automated Installation (Recommended)

### Install Chocolatey (Package Manager)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

### Install Docker Desktop
```powershell
choco install docker-desktop -y
```

### Install Node.js
```powershell
choco install nodejs -y
```

### Refresh Environment
```powershell
refreshenv
```

## Method 2: Manual Downloads

### Docker Desktop
1. Download: https://www.docker.com/products/docker-desktop/
2. Run installer as Administrator
3. Follow setup wizard
4. Restart computer when prompted

### Node.js
1. Download LTS version: https://nodejs.org/en/download/
2. Run installer as Administrator
3. Accept all default settings
4. Restart PowerShell

## ✅ Verification Commands

After installation, verify everything works:

```powershell
# Check Docker
docker --version
docker run hello-world

# Check Node.js and NPM
node --version
npm --version

# Check Python (should already work)
python --version
pip --version
```

## 🚀 Once Installed - Deployment Commands

### Docker Hub Deployment
```bash
cd C:\Users\ajibi\Music\CorrectOne\devicefingerprint

# Build image
docker build -t johnsonajibi/device-fingerprinting-pro:1.0.3 .

# Test locally
docker run --rm johnsonajibi/device-fingerprinting-pro:1.0.3

# Login to Docker Hub
docker login

# Push to Docker Hub
docker push johnsonajibi/device-fingerprinting-pro:1.0.3
```

### NPM Package Deployment
```bash
cd C:\Users\ajibi\Music\CorrectOne\devicefingerprint\npm

# Login to NPM
npm login

# Publish package
npm publish
```

## 📊 Current Status Dashboard

- ✅ **PyPI**: Published (device-fingerprinting-pro 1.0.3)
- 🟡 **Conda-Forge**: Under review (excellent condition!)
- ✅ **GitHub Packages**: Workflow ready
- 🔄 **Docker Hub**: Ready to deploy (needs Docker)
- 🔄 **NPM**: Ready to deploy (needs Node.js)

## 🎯 Next Steps After Installation

1. **Test Docker build**: `docker build -t test-device-fp .`
2. **Test NPM package**: `cd npm && npm test`
3. **Deploy to platforms**: Follow deployment commands above
4. **Monitor analytics**: `python tracking/download_tracker.py`

## 🔧 Troubleshooting

**If Docker fails to start:**
- Enable Windows features: Hyper-V, Containers
- Restart computer
- Check Docker Desktop settings

**If NPM publish fails:**
- Create NPM account: https://www.npmjs.com/signup
- Verify email address
- Use `npm login` before publishing

## 📞 Ready for Next Steps?

Once you've installed Docker and Node.js, come back and I'll help you:
1. Build and test your Docker container
2. Publish to Docker Hub
3. Deploy your NPM wrapper package
4. Set up automated monitoring

Your conda-forge submission is already progressing beautifully! 🎉
