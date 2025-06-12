# Changelog

All notable changes to the UBA Certificate Tools project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-12

### Added
- Initial release of UBA Certificate Tools
- Core certificate installation script (`install_uba_certs.sh`) with comprehensive UBA integration
- Certificate validation utility (`validate_uba_certs.sh`) with FIPS compliance
- Test certificate generation script (`generate_test_certs.sh`) with proper SANs
- Remote certificate pulling functionality from Splunk instances
- Java environment detection using CaspidaCommonEnv.sh-compatible logic
- Automatic backup system for certificates and configurations
- UBA service management (stop/start) during certificate installation
- PKCS12 keystore generation with "password" password for Job Manager
- CA certificate installation in Java truststore
- uba-site.properties configuration updates

### Features
- **FIPS Compliance**: All cryptographic operations use FIPS-approved algorithms
- **Dry Run Mode**: Preview changes without applying them
- **Verbose Logging**: Detailed logging for debugging and monitoring
- **Certificate Auto-Discovery**: Automatic detection of PEM certificates, keys, and CA certs
- **Service Integration**: Proper UBA service lifecycle management
- **Backup and Recovery**: Timestamped backups with easy restoration
- **Remote Certificate Pulling**: Retrieve certificates from remote Splunk instances via HTTPS

### Security
- Uses SHA-256 instead of MD5 for certificate validation (FIPS compliance)
- Proper file ownership (caspida:caspida) and permissions (644 for certs, 600 for keys)
- Secure keystore generation with industry-standard practices
- Certificate chain validation and verification

### Bug Fixes
- Fixed OpenSSL command syntax issues (removed `\\` line continuations)
- Corrected Java truststore path (`$JAVA_HOME/lib/security/cacerts` instead of `/jre/`)
- Fixed keystore alias handling for non-existent `jmserver` alias
- Resolved duplicate certificate configurations in uba-site.properties
- Fixed FIPS environment compatibility issues

### Documentation
- Comprehensive README with usage examples and troubleshooting
- Detailed FIPS compliance documentation
- Certificate scripts development summary
- Production deployment guide
- Interactive examples and workflow demonstrations

### Testing
- End-to-end testing with remote certificate pulling
- FIPS environment validation
- Service integration testing
- Certificate chain validation testing

### Examples
- Complete workflow demonstration script
- Interactive installation guide
- Usage summary with command examples
- Certificate generation examples with proper SANs

## [0.9.0] - 2025-06-11

### Added
- Initial development versions of certificate scripts
- Basic certificate installation functionality
- Java detection logic implementation

### Fixed
- Multiple iterations of FIPS compliance fixes
- Command syntax corrections
- Service management improvements

## [0.1.0] - 2025-06-10

### Added
- Project inception and initial requirements gathering
- Basic script framework development