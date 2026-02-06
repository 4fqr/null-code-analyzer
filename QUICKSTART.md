# Quick Start Guide

## Installation

```bash
cd /path/to/Null-Code-Analyzer
pip install -e .
```

## First Run - Ethics Acceptance

On first run, you must accept the ethical usage terms:

```bash
nullcode scan ./your-project --i-accept-ethics
```

This creates `~/.nullcode/.ethics_accepted` to confirm you understand the legal implications.

## Basic Usage

### Quick Scan (Regex Heuristics)

Fastest scan using pattern matching:

```bash
nullcode scan ./my-project --mode quick
```

### Deep Scan (AI-Powered)

Most thorough scan using CodeBERT (requires model download on first use):

```bash
nullcode scan ./my-project --mode deep
```

### Hybrid Scan (Recommended)

Combines both methods for optimal results:

```bash
nullcode scan ./my-project --mode hybrid
```

## Output Formats

### Terminal Output (Default)

Beautiful black/white terminal display with animations:

```bash
nullcode scan ./app
```

### JSON Report

Machine-readable format for CI/CD integration:

```bash
nullcode scan ./app --output vulnerabilities.json
```

### SARIF Format

Standard format for security tools (GitHub, GitLab, etc.):

```bash
nullcode scan ./app --sarif
```

### HTML Dashboard

Professional HTML report for stakeholders:

```bash
nullcode scan ./app --html report.html
```

### Multiple Formats

Generate all formats at once:

```bash
nullcode scan ./app --output report.json --sarif --html dashboard.html
```

## Advanced Features

### Confidence Threshold

Filter results by confidence level (0-100%):

```bash
nullcode scan ./app --threshold 85
```

### Git Diff Mode

Scan only changed files vs last commit:

```bash
nullcode scan ./app --diff
```

### CI/CD Mode

No animations, non-zero exit code if vulnerabilities found:

```bash
nullcode scan ./src --ci --format json
```

## Testing with Sample Vulnerabilities

Test the scanner with included vulnerable code:

```bash
# Scan test fixtures
nullcode scan tests/fixtures/ --i-accept-ethics

# Should detect multiple vulnerabilities across languages
```

## Downloading AI Models

Pre-download models for offline use:

```bash
nullcode download-models
```

Models are cached in `~/.nullcode/models/` (approximately 480MB).

## GitHub Actions Integration

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install Null-Code-Analyzer
        run: pip install nullcode
      
      - name: Run Security Scan
        run: |
          nullcode scan . --ci --output scan-results.json --sarif --i-accept-ethics
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.sarif
```

## Common Commands

```bash
# Basic scan
nullcode scan .

# Professional workflow
nullcode scan . --mode deep --threshold 80 --output report.json --html dashboard.html

# Git integration
nullcode scan . --diff --ci

# Display version
nullcode version

# Get help
nullcode --help
nullcode scan --help
```

## Troubleshooting

### Model Download Issues

If model download fails:

```bash
# Manually download
nullcode download-models

# Check cache directory
ls -la ~/.nullcode/models/
```

### Permission Errors

Ensure you have write permissions to cache directory:

```bash
mkdir -p ~/.nullcode/models
chmod 755 ~/.nullcode
```

### False Positives

Adjust confidence threshold:

```bash
nullcode scan . --threshold 90  # Higher = fewer false positives
```

## Next Steps

- Read [ETHICS.md](ETHICS.md) for legal guidelines
- Check [SECURITY.md](SECURITY.md) for responsible disclosure
- Review test fixtures in `tests/fixtures/` to understand vulnerabilities
- Integrate into your CI/CD pipeline
- Share findings responsibly

## Support

- Issues: https://github.com/nullcode/analyzer/issues
- Security: security@nullcode.dev
- Documentation: https://nullcode.dev/docs
