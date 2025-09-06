# AWS CodeArtifact Distribution Setup

## Overview
AWS CodeArtifact is a managed package repository service that supports PyPI packages.

## Prerequisites
- AWS CLI installed and configured
- AWS account with CodeArtifact permissions

## Setup Steps

### 1. Create Domain and Repository
```bash
# Create domain
aws codeartifact create-domain --domain device-fingerprint-domain

# Create repository
aws codeartifact create-repository \
    --domain device-fingerprint-domain \
    --repository device-fingerprint-repo \
    --description "DeviceFingerprint library repository"
```

### 2. Configure Authentication
```bash
# Get authentication token
aws codeartifact get-authorization-token \
    --domain device-fingerprint-domain \
    --query authorizationToken \
    --output text

# Configure pip
aws codeartifact login \
    --tool pip \
    --domain device-fingerprint-domain \
    --repository device-fingerprint-repo
```

### 3. Upload Package
```bash
# Build package
python -m build

# Upload to CodeArtifact
python -m twine upload \
    --repository-url $(aws codeartifact get-repository-endpoint \
        --domain device-fingerprint-domain \
        --repository device-fingerprint-repo \
        --format pypi \
        --query repositoryEndpoint \
        --output text) \
    dist/*
```

### 4. Installation
```bash
# Install from CodeArtifact
pip install device-fingerprinting-pro \
    --index-url $(aws codeartifact get-repository-endpoint \
        --domain device-fingerprint-domain \
        --repository device-fingerprint-repo \
        --format pypi \
        --query repositoryEndpoint \
        --output text)simple/
```

## Benefits
- Enterprise-grade security
- Integration with AWS services
- Fine-grained access control
- Cost-effective for large organizations
