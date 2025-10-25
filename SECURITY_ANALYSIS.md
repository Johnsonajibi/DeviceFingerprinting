# CodeQL Security Analysis

This repository uses **GitHub's default CodeQL setup** for automatic security scanning.

## Configuration

- **Default Setup**: Enabled in repository settings
- **Language**: Python (auto-detected)
- **Analysis**: Security and quality queries
- **Schedule**: Automatic on push and pull requests
- **Results**: Available in the Security tab

## Why Default Setup?

We use GitHub's default CodeQL setup instead of a custom workflow because:

1. **Automatic Management**: GitHub manages updates and configurations
2. **Conflict Prevention**: Avoids SARIF upload conflicts
3. **Optimal Performance**: GitHub optimizes the default setup for common use cases
4. **Maintenance**: Reduces workflow maintenance overhead

## Viewing Results

Security analysis results are available at:
- Repository → Security tab → Code scanning
- Pull request security checks
- Security advisories for detected issues

## Manual Analysis

If you need to run CodeQL manually:

```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries

# Create database
codeql database create python-db --language=python --source-root=src/

# Run analysis
codeql database analyze python-db --format=sarif-latest --output=results.sarif

# View results
codeql bqrs decode results.sarif
```

For more information, see [GitHub's CodeQL documentation](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning-with-codeql).