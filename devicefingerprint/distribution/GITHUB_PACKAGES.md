# GitHub Packages Distribution Setup

## Overview
This guide helps you publish the DeviceFingerprint library to GitHub Packages, which provides a private package registry integrated with your GitHub repository.

## Prerequisites
- GitHub Personal Access Token with `write:packages` permission
- Repository with GitHub Packages enabled

## Configuration

### 1. Update .pypirc for GitHub Packages
Create or update `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    github

[pypi]
username = __token__
password = <your-pypi-token>

[github]
repository = https://upload.pypi.org/legacy/
username = Johnsonajibi
password = <your-github-token>
```

### 2. Build and Upload
```bash
# Build the package
python -m build

# Upload to GitHub Packages
python -m twine upload --repository github dist/*
```

### 3. Installation from GitHub Packages
```bash
# Configure pip to use GitHub Packages
pip install --index-url https://pypi.org/simple/ --extra-index-url https://upload.pypi.org/legacy/ device-fingerprinting-pro
```

## Benefits
- Private distribution control
- Integration with GitHub repository
- Access control via GitHub permissions
- Automatic versioning with git tags

## Use Cases
- Enterprise internal distribution
- Beta/development versions
- Private forks and customizations
