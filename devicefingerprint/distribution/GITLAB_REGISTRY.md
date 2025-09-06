# GitLab Package Registry Setup

## Overview
GitLab Package Registry provides integrated package management with CI/CD pipelines.

## Configuration

### 1. .gitlab-ci.yml for Automated Publishing
```yaml
stages:
  - build
  - test
  - publish

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/
    - venv/

before_script:
  - python -m venv venv
  - source venv/bin/activate
  - pip install --upgrade pip
  - pip install build twine

build:
  stage: build
  script:
    - python -m build
  artifacts:
    paths:
      - dist/
    expire_in: 1 hour

test:
  stage: test
  script:
    - pip install dist/*.whl
    - python -c "from devicefingerprint import generate_device_fingerprint; print('Import test passed')"

publish_to_gitlab:
  stage: publish
  script:
    - TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
  only:
    - tags

publish_to_pypi:
  stage: publish
  script:
    - TWINE_PASSWORD=${PYPI_TOKEN} TWINE_USERNAME=__token__ python -m twine upload dist/*
  only:
    - tags
  when: manual
```

### 2. Installation from GitLab Registry
```bash
# Configure pip for GitLab
pip config set global.index-url https://gitlab.com/api/v4/projects/{project_id}/packages/pypi/simple
pip config set global.extra-index-url https://pypi.org/simple

# Install package
pip install device-fingerprinting-pro
```

## Benefits
- Integrated with GitLab CI/CD
- Private package distribution
- Automated publishing on tags
- Access control via GitLab permissions
