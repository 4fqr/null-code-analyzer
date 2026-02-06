# Test Fixtures

This directory contains intentionally vulnerable code samples for testing and validating the Null-Code-Analyzer.

## ⚠️ WARNING

**DO NOT USE THIS CODE IN PRODUCTION**

All code in this directory contains deliberate security vulnerabilities for educational and testing purposes only.

## Files

### Python Vulnerabilities

- **vulnerable_sql.py** - SQL injection vulnerabilities
  - String concatenation in queries
  - Format string injection
  - F-string interpolation

- **vulnerable_command_injection.py** - Command injection flaws
  - os.system() misuse
  - subprocess with shell=True
  - eval() and exec() dangers

- **vulnerable_secrets.py** - Hardcoded credentials
  - API keys in source code
  - Database passwords
  - AWS credentials
  - Authentication tokens

- **vulnerable_path_traversal.py** - Path traversal attacks
  - Unsanitized file paths
  - Directory traversal (../)
  - Unsafe os.path.join usage

- **vulnerable_deserialization.py** - Insecure deserialization
  - pickle.loads() with user data
  - yaml.load() without safe loader
  - marshal.loads() dangers

### JavaScript Vulnerabilities

- **vulnerable_xss.js** - Cross-site scripting (XSS)
  - innerHTML manipulation
  - document.write() misuse
  - eval() with user input
  - dangerouslySetInnerHTML in React
  - Prototype pollution

### C Vulnerabilities

- **vulnerable_buffer_overflow.c** - Memory safety issues
  - strcpy() buffer overflow
  - gets() usage
  - sprintf() without bounds
  - Format string vulnerabilities
  - Integer overflow in malloc

## Usage

Scan these files to test the analyzer:

```bash
# Scan all test fixtures
nullcode scan tests/fixtures/ --i-accept-ethics

# Test specific vulnerability type
nullcode scan tests/fixtures/vulnerable_sql.py --mode deep

# Generate report
nullcode scan tests/fixtures/ --output test_report.json --html test_dashboard.html
```

## Expected Results

The scanner should detect:

- ✓ SQL injection patterns (CWE-89)
- ✓ Command injection (CWE-78)
- ✓ Hardcoded secrets (CWE-798)
- ✓ Path traversal (CWE-22)
- ✓ Insecure deserialization (CWE-502)
- ✓ XSS vulnerabilities (CWE-79)
- ✓ Buffer overflows (CWE-120)
- ✓ Format string bugs (CWE-134)

## Learning Resources

Each file includes:
- Vulnerable code examples
- Comments explaining the vulnerability
- Safe alternatives for comparison

Use these to understand common security flaws and how to prevent them.

## Contributing

To add new test cases:

1. Create clearly commented vulnerable code
2. Mark each vulnerability with `# VULNERABLE:` or `// VULNERABLE:`
3. Include safe alternatives with `# SAFE:` or `// SAFE:`
4. Add to this README with expected CWE mappings
