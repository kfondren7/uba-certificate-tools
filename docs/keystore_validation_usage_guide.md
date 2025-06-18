# UBA Keystore Validation Script - Usage Guide

## Overview

The `keystore_validation.sh` script is a comprehensive tool for validating UBA (User Behavior Analytics) keystores and certificates. It performs thorough validation of all certificate-related components in a UBA deployment, including keystores, truststores, certificate files, and trust relationships.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Command Line Options](#command-line-options)
3. [Usage Examples](#usage-examples)
4. [Output Examples](#output-examples)
5. [Keytool Command Reference](#keytool-command-reference)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

- **Root Access**: The script must be run as root to access UBA configuration files and use `sudo -u caspida`
- **Java Environment**: Java must be installed with keytool available
- **UBA Installation**: UBA must be installed in the expected location (`/opt/caspida`)

## Command Line Options

```
Usage: ./keystore_validation.sh [OPTIONS]

Options:
  -j, --java-home PATH    Set JAVA_HOME path (default: auto-detect)
  -s, --summary          Generate machine-readable summary report
  --skip-jvm-full        Skip full JVM truststore validation (faster)
  -h, --help             Show this help message
  --keytool-help         Show detailed keytool command examples
```

### Option Details

- **`-j, --java-home PATH`**: Specify a custom JAVA_HOME path. The script will auto-detect if not provided.
- **`-s, --summary`**: Generate a machine-readable JSON summary report at the end of validation.
- **`--skip-jvm-full`**: Skip comprehensive JVM truststore validation for faster execution.
- **`-h, --help`**: Display usage information and exit.
- **`--keytool-help`**: Display detailed keytool command examples and exit.

## Usage Examples

### Basic Validation
```bash
sudo ./keystore_validation.sh
```
Performs complete validation with auto-detected Java environment.

### Custom Java Home
```bash
sudo ./keystore_validation.sh --java-home /usr/lib/jvm/java-11-openjdk
sudo ./keystore_validation.sh -j /opt/java
```
Specify a custom Java installation path.

### Generate Summary Report
```bash
sudo ./keystore_validation.sh --summary > keystore_report.json
```
Generate a machine-readable summary report and save to file.

### Fast Validation
```bash
sudo ./keystore_validation.sh --skip-jvm-full
```
Skip full JVM truststore validation for faster execution.

### Help and Documentation
```bash
./keystore_validation.sh --help
./keystore_validation.sh --keytool-help
```
Display usage help or detailed keytool command reference.

## Output Examples

### Basic Validation Output

When running basic validation, the script provides comprehensive output:

```
[2025-06-18 15:08:31] UBA Keystore and Certificate Validation
[2025-06-18 15:08:31] ========================================
JAVA_HOME: /usr/lib/jvm/java-1.8.0-openjdk
CASPIDA_HOME: /opt/caspida

[2025-06-18 15:08:31] Validating Critical UBA UI Authentication Certificates
=====================================================
  Checking UBA UI authentication certificate configuration...

  ✓ Found: ui.auth.rootca=/var/vcap/store/caspida/certs/my_certs/my-root-ca.crt.pem
[SUCCESS]     ✓ Certificate file exists: /var/vcap/store/caspida/certs/my_certs/my-root-ca.crt.pem
[SUCCESS]     ✓ Valid certificate: expires Jun 12 00:23:28 2026 GMT
    🔍 Cross-validating against UBA keystores...
      ○ Certificate not in keystore: uba-keystore
      ○ Certificate not in keystore: keystore.jm
      ○ Certificate not in keystore: server.keystore.jks
[WARNING]       ⚠ VALIDATION: UI certificate NOT found in any UBA keystore
        This may be normal if UI uses separate certificate files
        Recommendation: Verify UBA web service is using the configured certificate

[2025-06-18 15:08:39] Validating UBA Unified Keystore
  Path: /opt/caspida/conf/keystore/uba-keystore
  User: caspida
[SUCCESS] UBA Unified Keystore validated successfully (4 certificates)
    Certificate: jmserver
    Certificate: uba-server
    Certificate: kafka-server
    Certificate: root-ca
```

### Key Features Validated

1. **UBA UI Authentication Certificates**
   - Root CA certificate validation
   - Server certificate validation
   - Private key validation
   - Cross-validation against UBA keystores

2. **UBA Unified Keystore**
   - Accessibility and password validation
   - Certificate count and details
   - Expiration date checking

3. **JobManager Keystore**
   - Keystore integrity
   - Certificate validation

4. **Kafka SSL Certificates**
   - Server keystore validation
   - Truststore validation
   - Certificate chain verification

5. **Java System Truststore**
   - JVM cacerts validation
   - Trust relationship verification

### Success Indicators

- ✓ Green [SUCCESS] messages indicate passed validations
- Certificate counts show keystore contents
- Expiration dates are checked automatically

### Warning Indicators

- ⚠ Yellow [WARNING] messages indicate potential issues
- Recommendations provided for each warning
- Issues may be normal depending on configuration

### Error Indicators

- ✗ Red [ERROR] messages indicate validation failures
- Detailed error descriptions provided
- Exit code reflects number of errors found

## Script Features

### Certificate Validation Capabilities

1. **Keystore Access Validation**
   - Tests multiple common passwords
   - Validates file permissions
   - Checks user access (caspida user)

2. **Certificate Content Validation**
   - Expiration date checking
   - Certificate chain verification
   - Fingerprint validation

3. **Trust Relationship Validation**
   - Cross-keystore certificate verification
   - Java truststore integration
   - SSL connection trust chains

4. **Configuration Validation**
   - UBA configuration file parsing
   - Certificate path resolution
   - Missing configuration detection

### Performance Considerations

- **Full Validation**: Complete verification including JVM truststore (~2-5 minutes)
- **Fast Validation**: Skip JVM validation for faster execution (~30 seconds)
- **Summary Mode**: Generate machine-readable output for automation

## Exit Codes

- **0**: All validations passed successfully
- **>0**: Number of validation errors encountered

## Files and Paths Validated

### UBA Keystores
- `/opt/caspida/conf/keystore/uba-keystore` - Unified UBA keystore
- `/opt/caspida/conf/jobconf/keystore.jm` - JobManager keystore
- `/opt/caspida/conf/kafka/auth/server.keystore.jks` - Kafka server keystore
- `/opt/caspida/conf/kafka/auth/server.truststore.jks` - Kafka truststore

### Configuration Files
- `/opt/caspida/conf/deploy/conf-cache.properties` - Main configuration
- `/opt/caspida/conf/ui/application.properties` - UI configuration
- Various other UBA configuration files

### Certificate Files
- UBA UI authentication certificates (configurable paths)
- System CA certificates
- Custom certificate installations

## Security Considerations

1. **Privileged Access**: Script requires root access for complete validation
2. **Password Security**: Uses secure methods to test keystore passwords
3. **File Permissions**: Validates appropriate file access permissions
4. **Temporary Files**: Cleans up temporary files securely

## Integration

The script can be integrated into:
- **Deployment Pipelines**: Automated validation after UBA installation
- **Monitoring Systems**: Regular certificate health checks
- **Troubleshooting**: Diagnostic tool for certificate issues
- **Compliance Audits**: Certificate inventory and validation

## Related Documentation

- [UBA Certificate Management Guide](./UBA_CERTIFICATE_SCRIPTS_FINAL.md)
- [UBA Keystore Management](./SplunkUBAKeystoreManagement.md)
- [Troubleshooting Guide](./Splunk_UBA_Troubleshooting_Guide.md)

---

*Generated on: June 18, 2025*  
*Script Version: keystore_validation.sh*  
*Author: UBA Certificate Tools Suite*
