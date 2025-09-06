# Command Line Submission to Your Fork

## 🔧 Git Commands for Conda-Forge Submission

If you prefer using git commands instead of the web interface:

### **1. Clone your fork**
```bash
git clone https://github.com/Johnsonajibi/recipes-device-fingerprinting-pro-meta.yaml.git
cd recipes-device-fingerprinting-pro-meta.yaml
```

### **2. Create a new branch**
```bash
git checkout -b add-device-fingerprinting-pro
```

### **3. Create recipe directory**
```bash
mkdir -p recipes/device-fingerprinting-pro
```

### **4. Copy your recipe**
```bash
# Copy from your local conda-recipe/meta.yaml
cp /path/to/your/conda-recipe/meta.yaml recipes/device-fingerprinting-pro/meta.yaml
```

### **5. Commit and push**
```bash
git add recipes/device-fingerprinting-pro/meta.yaml
git commit -m "Add device-fingerprinting-pro recipe"
git push origin add-device-fingerprinting-pro
```

### **6. Create Pull Request**
Go to GitHub and create a PR from your branch to conda-forge/staged-recipes main branch.

---

## 📋 Recipe Content for Your meta.yaml

Use this exact content in your `recipes/device-fingerprinting-pro/meta.yaml`:

```yaml
{% set name = "device-fingerprinting-pro" %}
{% set version = "1.0.3" %}

package:
  name: {{ name|lower }}
  version: {{ version }}

source:
  url: https://pypi.io/packages/source/{{ name[0] }}/{{ name }}/device_fingerprinting_pro-{{ version }}.tar.gz
  sha256: # Will be filled automatically by conda-forge bot

build:
  noarch: python
  script: {{ PYTHON }} -m pip install . -vv
  number: 0

requirements:
  host:
    - python >=3.8
    - pip
    - setuptools
  run:
    - python >=3.8

test:
  imports:
    - devicefingerprint
  commands:
    - python -c "from devicefingerprint import generate_device_fingerprint; print('Import successful')"
  requires:
    - pip

about:
  home: https://github.com/Johnsonajibi/DeviceFingerprinting
  license: MIT
  license_family: MIT
  license_file: LICENSE
  summary: Professional-grade hardware-based device identification for Python applications
  description: |
    DeviceFingerprint is a comprehensive security library that creates unique, stable 
    identifiers for computing devices by analyzing their hardware characteristics. 
    Built for enterprise security applications, fraud prevention systems, and 
    authentication workflows that demand reliable device recognition.
  doc_url: https://github.com/Johnsonajibi/DeviceFingerprinting#readme
  dev_url: https://github.com/Johnsonajibi/DeviceFingerprinting

extra:
  recipe-maintainers:
    - Johnsonajibi
```
