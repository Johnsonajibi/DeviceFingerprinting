# GitHub Packages Setup

## 📦 **Enable GitHub Packages for Your Repository**

### **Quick Setup (5 minutes)**

1. **Update setup.py with GitHub URL**
   Your setup.py already has the correct URL: `https://github.com/Johnsonajibi/DeviceFingerprinting`

2. **Create .pypirc for GitHub Packages**
   ```bash
   # Create ~/.pypirc file with:
   [distutils]
   index-servers = 
       pypi
       github

   [pypi]
   username = __token__
   password = your_pypi_token

   [github]
   repository = https://upload.pypi.org/legacy/
   username = Johnsonajibi
   password = your_github_token
   ```

3. **Build and upload**
   ```bash
   cd devicefingerprint
   python -m build
   
   # Upload to GitHub Packages
   python -m twine upload --repository github dist/*
   ```

### **Alternative: Use GitHub Actions**

The repository includes a workflow that will automatically publish to GitHub Packages when you push a new tag.

### **Expected Result**
After upload, users can install via:
```bash
pip install --index-url https://pypi.org/simple/ --extra-index-url https://test.pypi.org/simple/ device-fingerprinting-pro
```

### **Integration Benefits**
- Automatic versioning with your GitHub releases
- Private package distribution for enterprises
- Integrated with your repository's access controls
- Free for public repositories
