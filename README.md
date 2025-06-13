# UBA Certificate Tools

Comprehensive certificate management tools for Splunk UBA (User Behavior Analytics) that support certificate installation, validation, and generation for UBA instances and search heads.

## Features

- **Certificate Diagnostics** - Comprehensive read-only analysis of certificate health and PKIX issues
- **Automated Certificate Installation** - Install SSL/TLS certificates for UBA instances with full keystore management
- **Remote Certificate Pulling** - Pull certificates from remote Splunk instances via HTTPS
- **Certificate Validation** - Comprehensive validation and testing of installed certificates
- **Test Certificate Generation** - Create test certificates with proper Subject Alternative Names (SANs)
- **FIPS Compliance** - All operations use FIPS-compliant cryptographic algorithms
- **UBA Service Integration** - Proper UBA service management during certificate installation
- **Java Environment Detection** - CaspidaCommonEnv.sh-compatible Java detection for RHEL/Red Hat platforms
- **Backup and Recovery** - Automatic backup of existing certificates and configurations

## Quick Start

### Diagnose Certificate Issues

```bash
# Comprehensive certificate and service diagnostics (read-only)
./scripts/diagnose_uba_certificates.sh

# Shows:
# - Java environment and keystore access
# - UBA service management detection (systemd vs traditional)
# - Certificate validity and PKIX error analysis
# - Endpoint connectivity and health checks
# - Recent error analysis from JobManager logs
```

### Install Certificates

```bash
# Basic installation from certificate directory
./scripts/install_uba_certs.sh -s /path/to/certificates/

# Install with remote certificate pulling
./scripts/install_uba_certs.sh -s /path/to/certificates/ --pull-from 192.168.1.239:8000

# Dry run to preview changes
./scripts/install_uba_certs.sh -s /path/to/certificates/ --dry-run

# Verbose installation with detailed logging
./scripts/install_uba_certs.sh -s /path/to/certificates/ -v
```

### Validate Installation

```bash
# Validate installed certificates
./scripts/validate_uba_certs.sh

# Test specific certificate
./scripts/validate_uba_certs.sh -c /path/to/certificate.pem
```

### Generate Test Certificates

```bash
# Generate test certificates for current hostname
./scripts/generate_test_certs.sh

# Generate for specific hostname with custom validity
./scripts/generate_test_certs.sh -h myuba.example.com -d 365
```

## Scripts

### Core Scripts

| Script | Description |
|--------|-------------|
| `diagnose_uba_certificates.sh` | Comprehensive certificate and service diagnostics (read-only) |
| `install_uba_certs.sh` | Main certificate installation script with full UBA integration |
| `validate_uba_certs.sh` | Certificate validation and testing utility |
| `generate_test_certs.sh` | Test certificate generation with proper SANs |

### Utility Scripts

| Script | Description |
|--------|-------------|
| `test_cert_java.sh` | Java environment and certificate testing |
| `cleanup_certificate_scripts.sh` | Clean up test certificates and temporary files |

### Examples

| Script | Description |
|--------|-------------|
| `demo_certificate_workflow.sh` | Complete end-to-end workflow demonstration |
| `example_cert_install.sh` | Interactive installation guide with examples |
| `cert_tools_summary.sh` | Usage instructions and command examples |

## Installation Options

### install_uba_certs.sh Options

```
-s, --source-dir DIR     Source directory containing PEM certificates
-d, --destination DIR    Destination directory (default: /etc/caspida/local/conf)
--pull-from HOST:PORT    Pull certificates from remote Splunk instance
--dry-run               Preview changes without applying them
-v, --verbose           Enable verbose logging
--force                 Force installation even if certificates exist
--backup-dir DIR        Custom backup directory
-h, --help              Show help message
```

### Certificate Requirements

The installer expects certificates in PEM format:

- **Server Certificate**: `*.crt` or `*.pem` files
- **Private Key**: `*.key` files (must match certificate)
- **CA Certificate**: `*ca*.crt` or `*ca*.pem` files
- **Certificate Chain**: Optional `*chain*.pem` or `*bundle*.pem` files

## UBA Integration

The tools integrate with UBA components:

1. **Job Manager Keystore** (`keystore.jm`)
   - Creates PKCS12 keystore with server certificate and key
   - Uses password "password" as per UBA requirements
   - Installs `jmserver` alias for Job Manager

2. **UBA Site Configuration** (`uba-site.properties`)
   - Updates SSL certificate paths
   - Configures keystore location and password
   - Maintains existing configuration structure

3. **Java Truststore** (`$JAVA_HOME/lib/security/cacerts`)
   - Installs CA certificates for SSL validation
   - Uses Java keytool with proper alias management

4. **Service Management**
   - Stops UBA services before certificate installation
   - Restarts services after successful installation
   - Validates service status

## FIPS Compliance

All cryptographic operations use FIPS-compliant algorithms:

- **SHA-256** for certificate validation (not MD5)
- **AES-256-CBC** for symmetric encryption
- **RSA** with proper key lengths for asymmetric operations
- **ECDSA** support for elliptic curve certificates

## Java Environment Detection

The tools use CaspidaCommonEnv.sh-compatible logic to detect Java:

1. Check `$JAVA_HOME` environment variable
2. Look for Java in `/opt/caspida/jre/bin/java`
3. Fall back to system Java in `/usr/bin/java`
4. Validate Java version and capabilities

## Backup and Recovery

Automatic backup system:

- **Configuration Files**: `uba-site.properties`, service configs
- **Keystore Files**: `keystore.jm`, existing keystores
- **Certificates**: Existing PEM files and CA certificates
- **Backup Location**: `/opt/caspida/cert_backups/YYYYMMDD_HHMMSS/`

To restore from backup:
```bash
# List available backups
ls -la /opt/caspida/cert_backups/

# Restore from specific backup
cp -r /opt/caspida/cert_backups/20250612_123456/* /etc/caspida/local/conf/
```

## Troubleshooting

### Common Issues

1. **FIPS Environment Errors**
   ```
   Error: MD5 digest disabled in FIPS mode
   ```
   Solution: Use SHA-256 validation (scripts handle this automatically)

2. **Java Detection Issues**
   ```
   Error: Java not found
   ```
   Solution: Set `JAVA_HOME` or install Java in expected locations

3. **Service Restart Failures**
   ```
   Error: Failed to restart UBA services
   ```
   Solution: Check service status manually and restart as needed

4. **Certificate Format Issues**
   ```
   Error: Invalid PEM format
   ```
   Solution: Validate certificate format with OpenSSL

### Debugging

Enable verbose logging:
```bash
./scripts/install_uba_certs.sh -s /path/to/certs/ -v
```

Check installation logs:
```bash
tail -f /var/log/caspida/uba_cert_install_*.log
```

Validate certificate chain:
```bash
./scripts/validate_uba_certs.sh -v
```

## Requirements

- **Operating System**: RHEL/CentOS 7/8, Red Hat Enterprise Linux
- **UBA Version**: Splunk UBA 5.x or later
- **Java**: OpenJDK 8 or Oracle JDK 8+
- **OpenSSL**: 1.0.2+ with FIPS support
- **Permissions**: Root access for service management and keystore operations

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

See [LICENSE](LICENSE) for license information.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the detailed documentation in `docs/`
3. Examine example scripts in `examples/`
4. Enable verbose logging for detailed diagnostics

## Related Documentation

- [Certificate Scripts Summary](docs/CERTIFICATE_SCRIPTS_SUMMARY.md) - Development notes and implementation details
- [FIPS Compliance Fixes](docs/FIPS_COMPLIANCE_FIXES.md) - FIPS-specific implementation notes
- [UBA Certificate Scripts Final](docs/UBA_CERTIFICATE_SCRIPTS_FINAL.md) - Production deployment guide