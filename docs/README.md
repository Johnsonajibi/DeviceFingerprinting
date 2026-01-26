# GitHub Pages Documentation for Device Fingerprinting Library

This directory contains comprehensive documentation for the Device Fingerprinting Library, ready for publication on GitHub Pages.

## Structure

```
docs/
├── _config.yml                 # Jekyll configuration
├── index.md                    # Homepage
├── assets/                     # Images, diagrams
├── guides/                     # How-to guides
│   ├── getting-started.md     # Quick start guide
│   ├── installation.md        # Installation instructions
│   ├── examples.md            # Code examples
│   ├── security-architecture.md
│   ├── troubleshooting.md
│   └── faq.md
└── api/                       # API documentation
    └── reference.md           # Complete API reference
```

## Quick Start

1. **Getting Started**: [guides/getting-started.md](guides/getting-started.md)
   - Introduction to device fingerprinting
   - Basic concepts and terminology
   - Your first fingerprint

2. **Installation**: [guides/installation.md](guides/installation.md)
   - Platform-specific instructions
   - Virtual environment setup
   - Troubleshooting installation issues

3. **Usage Examples**: [guides/examples.md](guides/examples.md)
   - 10+ practical examples
   - Real-world use cases
   - Integration patterns

4. **API Reference**: [api/reference.md](api/reference.md)
   - Complete API documentation
   - Method signatures
   - Class descriptions

5. **Security Guide**: [guides/security-architecture.md](guides/security-architecture.md)
   - Cryptographic implementation
   - Threat analysis
   - Best practices

6. **FAQ**: [guides/faq.md](guides/faq.md)
   - Common questions
   - Troubleshooting tips

7. **Troubleshooting**: [guides/troubleshooting.md](guides/troubleshooting.md)
   - Error messages and solutions
   - Platform-specific issues

## Publishing to GitHub Pages

### Method 1: GitHub Pages with docs/ folder

1. Ensure this `docs` folder is in your repository root
2. Go to GitHub repository settings
3. Under "GitHub Pages" section:
   - Source: `Deploy from a branch`
   - Branch: `main` (or your default branch)
   - Folder: `/docs`
4. Save settings
5. Your site will be published at: `https://yourusername.github.io/device-fingerprinting`

### Method 2: GitHub Pages with gh-pages branch

```bash
# Create and checkout gh-pages branch
git checkout --orphan gh-pages
git rm -rf .

# Copy docs to root
cp -r ../docs/* .

# Commit and push
git add .
git commit -m "Deploy documentation"
git push -u origin gh-pages

# Switch back to main
git checkout main
```

### Method 3: Automated Deployment

Create `.github/workflows/deploy-docs.yml`:

```yaml
name: Deploy Documentation

on:
  push:
    branches:
      - main
    paths:
      - 'docs/**'

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Build documentation
        run: |
          cd docs
          # Add any build steps here
      
      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./docs
```

## Customization

### Change Theme

Edit `_config.yml`:

```yaml
# Other theme options:
# remote_theme: pages-themes/slate@v0.2.0
# remote_theme: pages-themes/architect@v0.2.0
# remote_theme: pages-themes/tactile@v0.2.0
# remote_theme: pages-themes/minimal@v0.2.0
# remote_theme: pages-themes/leap-day@v0.2.0
# remote_theme: pages-themes/merlot@v0.2.0
# remote_theme: pages-themes/midnight@v0.2.0
# remote_theme: pages-themes/dinky@v0.2.0
```

### Add Navigation

Add a `_layouts/default.html` file to customize navigation:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ page.title }}</title>
</head>
<body>
    <nav>
        <a href="/">Home</a>
        <a href="/guides/getting-started">Getting Started</a>
        <a href="/guides/installation">Installation</a>
        <a href="/guides/examples">Examples</a>
        <a href="/api/reference">API Reference</a>
        <a href="/guides/faq">FAQ</a>
    </nav>
    
    <main>
        {{ content }}
    </main>
</body>
</html>
```

### Add Custom CSS

Create `assets/style.css` and link in `_config.yml`.

## Content Guidelines

### Writing Style

- **Clear and Professional**: Industry-standard language
- **No AI-Generated Tone**: Human-written, professional
- **Technical Accuracy**: Precise specifications
- **Practical Examples**: Real-world use cases
- **Visual Diagrams**: ASCII diagrams for architecture

### Structure

Each document should have:

1. **Front matter**: Title, description
2. **Table of contents**: For longer documents
3. **Introduction**: What and why
4. **Concepts**: Key ideas explained
5. **Examples**: Practical code
6. **Reference**: Detailed specifications
7. **Troubleshooting**: Common issues

### Code Examples

- Include imports
- Show complete working code
- Explain expected output
- Include error handling
- Comment non-obvious sections

### Diagrams

Use ASCII art or text-based diagrams:

```
┌─────────────────┐
│   Your App      │
├─────────────────┤
│  FP Library     │
├─────────────────┤
│  Hardware       │
└─────────────────┘
```

## Local Testing

### Test with Jekyll

```bash
# Install Jekyll (if not already installed)
gem install bundler jekyll

# Navigate to docs
cd docs

# Serve locally
jekyll serve

# Visit http://localhost:4000
```

### Test without Jekyll

Most browsers can open HTML files directly. For a better testing experience:

```bash
# Python 3
cd docs
python -m http.server 8000

# Then visit http://localhost:8000
```

## Maintenance

### Update Documentation

When making changes to the library:

1. Update relevant `.md` files in `docs/guides/`
2. Update API reference if methods changed
3. Add examples for new features
4. Update FAQ if new common questions arise

### Version Updates

When releasing a new version:

1. Update version number in all docs
2. Add release notes
3. Update API documentation
4. Test all examples

## Integration with README

The main `README.md` should link to the GitHub Pages:

```markdown
## Documentation

- **Full Documentation**: [https://yourusername.github.io/device-fingerprinting](https://yourusername.github.io/device-fingerprinting)
- [Getting Started](docs/guides/getting-started.md)
- [Installation](docs/guides/installation.md)
- [API Reference](docs/api/reference.md)
```

## Support

For questions about the documentation:

- Create an issue with `documentation` label
- Email: ajibijohnson@jtnetsolutions.com
- See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines

---

**Last Updated**: January 2026
**Documentation Version**: 2.2.3 (matches library version)
