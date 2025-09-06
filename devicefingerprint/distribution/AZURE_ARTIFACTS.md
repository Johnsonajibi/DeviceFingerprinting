# Azure Artifacts Package Distribution

## Overview
Azure Artifacts provides enterprise-grade package management integrated with Azure DevOps.

## Setup Instructions

### 1. Azure DevOps Pipeline (azure-pipelines.yml)
```yaml
trigger:
  tags:
    include:
      - v*

pool:
  vmImage: 'ubuntu-latest'

variables:
  python.version: '3.8'

stages:
- stage: Build
  jobs:
  - job: BuildPackage
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '$(python.version)'
      displayName: 'Use Python $(python.version)'

    - script: |
        python -m pip install --upgrade pip
        pip install build twine keyring artifacts-keyring
      displayName: 'Install dependencies'

    - script: |
        python -m build
      displayName: 'Build package'

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: 'dist'
        artifactName: 'python-package'

- stage: Deploy
  condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/tags/'))
  jobs:
  - deployment: DeployPackage
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '$(python.version)'

          - task: TwineAuthenticate@1
            inputs:
              artifactFeed: 'YourOrganization/YourProject/YourFeed'

          - script: |
              python -m twine upload -r YourFeed --config-file $(PYPIRC_PATH) $(Pipeline.Workspace)/python-package/*
            displayName: 'Upload to Azure Artifacts'
```

### 2. pip.conf Configuration
```ini
[global]
index-url = https://pkgs.dev.azure.com/YourOrganization/YourProject/_packaging/YourFeed/pypi/simple/
extra-index-url = https://pypi.org/simple/

[install]
trusted-host = pkgs.dev.azure.com
```

### 3. Installation Commands
```bash
# Configure authentication
pip install keyring artifacts-keyring

# Install package
pip install device-fingerprinting-pro
```

## Benefits
- Enterprise security and compliance
- Integration with Azure DevOps workflows
- Advanced access control and permissions
- Audit trails and package analytics
- Private package hosting
