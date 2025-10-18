# PyPI Publishing Guide for Device Fingerprinting

## Package Information
- **Package Name:** `device-fingerprinting`
- **Version:** 2.0.0
- **PyPI URL:** https://pypi.org/project/device-fingerprinting/

## Prerequisites

✅ Package built successfully:
- `device_fingerprinting-2.0.0-py3-none-any.whl`
- `device_fingerprinting-2.0.0.tar.gz`

✅ Package validated with twine check - PASSED

## Publishing Steps

### Option 1: Using PyPI API Token (Recommended)

1. **Go to PyPI Account Settings:**
   - Visit: https://pypi.org/manage/account/token/
   - Login with your PyPI credentials

2. **Create a New API Token:**
   - Click "Add API token"
   - Token name: `device-fingerprinting-upload`
   - Scope: **"Entire account (all projects)"** (for first upload)
   - Click "Add token"
   - **IMPORTANT:** Copy the token immediately (shown only once)

3. **Upload to PyPI:**
   ```powershell
   python -m twine upload dist/*
   ```
   
   When prompted:
   - Username: `__token__`
   - Password: `pypi-...` (paste your API token)

### Option 2: Using Username/Password

```powershell
python -m twine upload dist/* -u YOUR_USERNAME -p YOUR_PASSWORD
```

### Option 3: Using .pypirc Configuration File

Create/edit `~/.pypirc` (Windows: `C:\Users\YourName\.pypirc`):

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_API_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TEST_API_TOKEN_HERE
```

Then upload with:
```powershell
python -m twine upload dist/*
```

## Test PyPI (Optional - Test Before Production)

### Upload to Test PyPI First

1. **Get Test PyPI Token:**
   - Visit: https://test.pypi.org/manage/account/token/
   - Create token with same steps

2. **Upload to Test PyPI:**
   ```powershell
   python -m twine upload --repository testpypi dist/*
   ```

3. **Test Installation:**
   ```powershell
   pip install --index-url https://test.pypi.org/simple/ device-fingerprinting
   ```

4. **If successful, upload to production PyPI:**
   ```powershell
   python -m twine upload dist/*
   ```

## After Publishing

### Verify Publication

1. **Check PyPI page:**
   - https://pypi.org/project/device-fingerprinting/

2. **Install from PyPI:**
   ```powershell
   pip install device-fingerprinting
   ```

3. **Test installation:**
   ```python
   from device_fingerprinting import ProductionFingerprintGenerator
   
   generator = ProductionFingerprintGenerator()
   fp = generator.generate_fingerprint()
   print(f"Fingerprint: {fp['fingerprint_hash']}")
   ```

### Update GitHub Release

1. **Create GitHub release:**
   ```powershell
   git tag -a v2.0.0 -m "Release v2.0.0 - Production-ready with comprehensive documentation"
   git push origin v2.0.0
   ```

2. **Create release on GitHub:**
   - Go to: https://github.com/Johnsonajibi/DeviceFingerprinting/releases
   - Click "Create a new release"
   - Tag: `v2.0.0`
   - Title: "Device Fingerprinting v2.0.0"
   - Description: Copy from CHANGELOG.md

### Update README Badge

Add PyPI badge to README.md:
```markdown
[![PyPI version](https://badge.fury.io/py/device-fingerprinting.svg)](https://badge.fury.io/py/device-fingerprinting)
[![Downloads](https://pepy.tech/badge/device-fingerprinting)](https://pepy.tech/project/device-fingerprinting)
```

## Troubleshooting

### Error: "Project name already exists"
- The package `device-fingerprinting` must not exist on PyPI
- Check: https://pypi.org/project/device-fingerprinting/
- If it exists and you don't own it, choose a different name in `pyproject.toml`

### Error: "Invalid API Token"
- Make sure token is copied correctly (starts with `pypi-`)
- Username must be exactly `__token__` (not your PyPI username)
- Token must be for "Entire account" or specifically for "device-fingerprinting"

### Error: "File already exists"
- You cannot re-upload the same version
- Increment version in `pyproject.toml` and `src/device_fingerprinting/version.py`
- Rebuild: `python -m build`
- Upload again: `python -m twine upload dist/*`

### Error: "Package has invalid metadata"
- Run: `python -m twine check dist/*`
- Fix any errors in `pyproject.toml`
- Rebuild package

## Updating the Package (Future Releases)

1. **Update version:**
   ```python
   # src/device_fingerprinting/version.py
   __version__ = "2.1.0"
   ```

2. **Update pyproject.toml:**
   ```toml
   [project]
   version = "2.1.0"
   ```

3. **Update CHANGELOG.md:**
   ```markdown
   ## [2.1.0] - 2025-11-XX
   ### Added
   - New feature X
   ```

4. **Commit changes:**
   ```powershell
   git add .
   git commit -m "chore: bump version to 2.1.0"
   git push
   ```

5. **Clean and rebuild:**
   ```powershell
   Remove-Item -Recurse -Force dist, build, *.egg-info
   python -m build
   ```

6. **Upload:**
   ```powershell
   python -m twine upload dist/*
   ```

7. **Tag release:**
   ```powershell
   git tag -a v2.1.0 -m "Release v2.1.0"
   git push origin v2.1.0
   ```

## Package Statistics

After publishing, monitor your package:

- **PyPI Stats:** https://pypistats.org/packages/device-fingerprinting
- **Libraries.io:** https://libraries.io/pypi/device-fingerprinting
- **GitHub Insights:** https://github.com/Johnsonajibi/DeviceFingerprinting/pulse

## Support

- **PyPI Help:** https://pypi.org/help/
- **Packaging Guide:** https://packaging.python.org/
- **Twine Documentation:** https://twine.readthedocs.io/
