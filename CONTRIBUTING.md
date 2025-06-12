# Contributing to UBA Certificate Tools

Thank you for your interest in contributing to the UBA Certificate Tools project! This document provides guidelines for contributing to the project.

## Development Environment

### Prerequisites

- RHEL/CentOS 7/8 or Red Hat Enterprise Linux
- Splunk UBA 5.x or later
- OpenJDK 8 or Oracle JDK 8+
- OpenSSL 1.0.2+ with FIPS support
- Root access for testing UBA integration

### Setting Up Development Environment

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd uba-certificate-tools
   ```

2. Make scripts executable:
   ```bash
   chmod +x scripts/*.sh examples/*.sh
   ```

3. Verify UBA environment:
   ```bash
   # Check UBA installation
   ls -la /opt/caspida/
   
   # Verify Java environment
   ./scripts/test_cert_java.sh
   ```

## Code Style and Standards

### Shell Script Guidelines

1. **Shebang**: Use `#!/bin/bash` for all bash scripts
2. **Error Handling**: Use `set -euo pipefail` for strict error handling
3. **Functions**: Use lowercase with underscores for function names
4. **Variables**: Use UPPERCASE for constants, lowercase for local variables
5. **Logging**: Use consistent logging functions (log_info, log_error, log_debug)
6. **FIPS Compliance**: Always use FIPS-approved algorithms (SHA-256, not MD5)

### Example Function Structure

```bash
function install_certificate() {
    local cert_file="$1"
    local dest_dir="$2"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    log_info "Installing certificate: $(basename "$cert_file")"
    
    # Implementation here
    
    log_info "Certificate installation completed successfully"
}
```

### FIPS Compliance Requirements

- Use `openssl sha256` instead of `openssl md5`
- Use AES-256-CBC for symmetric encryption
- Validate all cryptographic operations in FIPS mode
- Test scripts on FIPS-enabled systems

## Testing

### Running Tests

```bash
# Generate test certificates
./scripts/generate_test_certs.sh

# Run certificate validation
./scripts/validate_uba_certs.sh

# Test installation (dry run)
./scripts/install_uba_certs.sh -s /tmp/uba_test_certs/ --dry-run -v
```

### Adding New Tests

1. Create test scripts in the `tests/` directory
2. Use descriptive names: `test_<feature>_<scenario>.sh`
3. Include both positive and negative test cases
4. Test FIPS compliance scenarios
5. Validate cleanup after tests

### Test Script Template

```bash
#!/bin/bash
set -euo pipefail

# Test: <description>
# Author: <name>
# Date: <date>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

source "$PROJECT_DIR/scripts/install_uba_certs.sh"

function test_certificate_validation() {
    local test_cert="/tmp/test.pem"
    
    # Setup
    generate_test_certificate "$test_cert"
    
    # Test
    if validate_certificate_format "$test_cert"; then
        echo "PASS: Certificate validation"
    else
        echo "FAIL: Certificate validation"
        return 1
    fi
    
    # Cleanup
    rm -f "$test_cert"
}

# Run tests
test_certificate_validation
echo "All tests passed"
```

## Pull Request Guidelines

### Before Submitting

1. **Test Thoroughly**: Run all tests and verify FIPS compliance
2. **Update Documentation**: Update README.md, CHANGELOG.md, and inline comments
3. **Check Code Style**: Follow shell script guidelines
4. **Verify Functionality**: Test on actual UBA environment if possible

### Pull Request Description

Include in your PR description:

- **Summary**: Brief description of changes
- **Testing**: How you tested the changes
- **FIPS Compliance**: Confirmation of FIPS testing
- **Breaking Changes**: Any backwards compatibility issues
- **Documentation**: Updates to docs or examples

### Example PR Template

```
## Summary
Brief description of what this PR does.

## Changes
- [ ] Added new feature X
- [ ] Fixed bug Y
- [ ] Updated documentation Z

## Testing
- [ ] Tested on RHEL 8 with UBA 5.4.2
- [ ] Verified FIPS compliance
- [ ] Ran full certificate installation workflow
- [ ] Tested error scenarios

## FIPS Compliance
- [ ] All cryptographic operations use approved algorithms
- [ ] Tested in FIPS-enabled environment
- [ ] No MD5 usage detected

## Documentation
- [ ] Updated README.md
- [ ] Updated CHANGELOG.md
- [ ] Added/updated inline comments
- [ ] Updated examples if needed
```

## Reporting Issues

### Bug Reports

When reporting bugs, include:

1. **Environment**: OS version, UBA version, Java version
2. **FIPS Status**: Whether FIPS mode is enabled
3. **Steps to Reproduce**: Exact commands and inputs
4. **Expected vs Actual**: What you expected vs what happened
5. **Logs**: Relevant log excerpts (sanitize sensitive data)
6. **Certificate Details**: Certificate format, source, any special characteristics

### Feature Requests

For feature requests, include:

1. **Use Case**: Why this feature is needed
2. **Proposed Solution**: How you envision it working
3. **Alternatives**: Other approaches considered
4. **UBA Integration**: How it fits with UBA components

## Development Guidelines

### Security Considerations

1. **Never commit sensitive data**: Private keys, passwords, real certificates
2. **Sanitize logs**: Remove sensitive information from debug output
3. **Validate inputs**: Always validate user inputs and file paths
4. **Use secure defaults**: Default to secure configurations
5. **Handle errors gracefully**: Don't expose sensitive information in error messages

### UBA Integration Guidelines

1. **Service Management**: Always stop services before certificate changes
2. **Backup Strategy**: Create backups before making changes
3. **Configuration Updates**: Maintain existing configuration structure
4. **Java Integration**: Use CaspidaCommonEnv.sh-compatible Java detection
5. **File Permissions**: Set proper ownership (caspida:caspida) and permissions

### Performance Considerations

1. **Minimize Service Downtime**: Prepare all certificates before stopping services
2. **Efficient Certificate Validation**: Cache validation results when appropriate
3. **Parallel Operations**: Use parallel processing where safe
4. **Resource Cleanup**: Always clean up temporary files and processes

## Release Process

1. **Version Bumping**: Follow semantic versioning
2. **Changelog**: Update CHANGELOG.md with all changes
3. **Testing**: Full testing on supported platforms
4. **Documentation**: Ensure all docs are current
5. **Tagging**: Create git tags for releases

## Getting Help

- **Documentation**: Check docs/ directory for detailed information
- **Examples**: Review examples/ directory for usage patterns
- **Issues**: Search existing issues before creating new ones
- **Testing**: Use verbose mode (-v) for detailed debugging information

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help others learn and contribute
- Maintain security and quality standards
- Document your work clearly