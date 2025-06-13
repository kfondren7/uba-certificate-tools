# Splunk UBA 5.4.2 Deployment Validation Checklist

This comprehensive checklist ensures all critical aspects of Splunk UBA 5.4.2 deployment on RHEL 8.10 are properly validated. Use this document alongside the main deployment guide to verify successful installation and configuration.

## Pre-Installation Validation

### Hardware Requirements
- [ ] **CPU**: Minimum 16 cores per node verified
- [ ] **Memory**: Minimum 64 GB RAM per node verified
- [ ] **Storage Requirements Met**:
  - [ ] Disk 1: 100 GB for UBA installation (available on all nodes)
  - [ ] Disk 2: 1 TB for metadata storage (available on all nodes)
  - [ ] Disk 3: 1 TB for Spark services (available on required nodes per topology)
- [ ] **IOPS**: Disk subsystem supports minimum 1200 IOPS
- [ ] **Network**: At least one 1 Gb ethernet interface per node
- [ ] **AWS Instance Types** (if applicable): Using supported instance types (m4.4xlarge, m5.4xlarge, m5a.4xlarge, m5.8xlarge, m6a.4xlarge, m6i.4xlarge)

### Operating System Requirements
- [ ] **RHEL 8.10 Installed**: Target operating system confirmed
- [ ] **Kernel Version**: 4.18.0-553.36.1.el8_10.x86_64 (or compatible)
- [ ] **OS Updates**: Automatic OS updating disabled on all nodes
- [ ] **Hardened OS**: Confirmed not using hardened OS (not supported)
- [ ] **RHEL Subscriptions**:
  - [ ] Red Hat Enterprise Linux Server subscription active
  - [ ] Red Hat Enterprise Linux Server - Extended Update Support (EUS) subscription active

### User Access and Permissions
- [ ] **Root Access**: Confirmed ability to log in as root or use sudo for root privileges
- [ ] **Caspida User**: Can create caspida user with appropriate privileges
- [ ] **UMASK Value**: Root user UMASK set to 0002 or 0022
- [ ] **File Permissions**: Verified read permissions for newly created files and directories for caspida user

### Networking Validation
- [ ] **Static IP Addresses**: All UBA servers have static IP addresses assigned
- [ ] **DNS Resolution**: All nodes can resolve each other by hostname
- [ ] **Firewall Ports**: Required ports configured and accessible
  - [ ] External access: SSH (22), HTTPS (443)
  - [ ] Internal cluster communication ports configured per requirements
  - [ ] Splunk platform communication ports configured
  - [ ] Outbound ports for UBA telemetry configured
- [ ] **Network Interface**: UBA interface associated with "public" firewall zone
- [ ] **Default Route**: Default route set for UBA interface
- [ ] **Network Connectivity**: Verified connectivity between all nodes

### Storage Preparation
- [ ] **Disk Identification**: 1TB disks identified and available
- [ ] **Disk Partitioning**: Disks properly partitioned with GPT partition table
- [ ] **File System**: ext4 file system created on partitions
- [ ] **Mount Points**: /var/vcap and /var/vcap2 directories created
- [ ] **fstab Configuration**: Disk mounts added to /etc/fstab with UUIDs
- [ ] **Mount Verification**: File systems mounted successfully
- [ ] **Permissions**: Proper permissions set on mount points (755, root:root)
## Installation Process Validation

### Pre-Installation Setup
- [ ] **Caspida User Created**: User and group created with correct UID/GID (2018)
- [ ] **Sudo Configuration**: Caspida user configured with appropriate sudo permissions
- [ ] **Software Directory**: /opt/caspida directory created with proper ownership
- [ ] **Environment Variables**: PostgreSQL locale variables configured
- [ ] **Hostname Resolution**: Hostname resolution working properly
- [ ] **SELinux**: Set to permissive mode
- [ ] **System Time**: Date, time, and timezone configured correctly
- [ ] **Bridge Networking**: Kernel configured for bridge networking if required

### Installation Package
- [ ] **Software Downloaded**: UBA 5.4.2 software package obtained
- [ ] **Package Integrity**: MD5 checksums verified (if available)
- [ ] **Package Extracted**: Installation package extracted to /home/caspida
- [ ] **Platform Files**: UBA platform files extracted to /opt/caspida

### Installation Execution
- [ ] **Installation Method Selected**:
  - [ ] Single server installation (-s flag), OR
  - [ ] Distributed installation (-c flag for management node, -n flag for additional nodes)
- [ ] **Installation Script**: INSTALL.sh executed successfully
- [ ] **Interactive Prompts**: All installation prompts answered correctly
  - [ ] Network interface specified
  - [ ] IP address for web UI provided
  - [ ] Admin password set
- [ ] **Installation Completion**: Installation completed without errors

## Post-Installation Validation

### Basic System Verification
- [ ] **Web Interface Access**: Can access UBA web interface via HTTPS
- [ ] **Admin Login**: Can log in with admin credentials
- [ ] **Health Check**: Health check script runs without critical errors
  ```bash
  /opt/caspida/bin/utils/uba_health_check.sh
  ```
- [ ] **Service Status**: All required services running
  ```bash
  /opt/caspida/bin/Caspida status
  ```

### License and FIPS (if applicable)
- [ ] **License Upload**: Valid UBA license uploaded
- [ ] **License Verification**: License status shows as valid
- [ ] **FIPS Enabled** (if required):
  - [ ] FIPS mode enabled on all RHEL 8.10 nodes
  - [ ] FIPS status verified (/proc/sys/crypto/fips_enabled = 1)

### User Management and Authentication
- [ ] **Admin Password**: Default admin password changed
- [ ] **User Roles**: User roles and permissions validated
- [ ] **SSO Configuration** (if applicable):
  - [ ] Identity provider metadata uploaded
  - [ ] Role mappings configured
  - [ ] SSO login tested successfully
- [ ] **Splunk Authentication** (if applicable):
  - [ ] Splunk service account created
  - [ ] Authentication credentials configured and tested

### SSL Certificate Management
- [ ] **Default Certificate**: Default self-signed certificate working
- [ ] **Third-Party Certificate** (if applicable):
  - [ ] CSR generated with proper subject and SANs
  - [ ] Signed certificate obtained from CA
  - [ ] Certificate installed and configured
  - [ ] Certificate validation successful in browser
- [ ] **Certificate Expiration**: Certificate expiration monitoring configured

## Data Source Configuration Validation

### Required Data Sources
- [ ] **HR Data Source**:
  - [ ] Data source configured and connected
  - [ ] Required fields mapped correctly
  - [ ] Data ingestion confirmed (EPS > 0)
  - [ ] Refresh schedule configured
- [ ] **Assets Data Source**:
  - [ ] Data source configured and connected
  - [ ] Device-to-user mapping working
  - [ ] Asset inventory data flowing
- [ ] **Authentication Data**:
  - [ ] Authentication logs configured
  - [ ] Success/failure events ingesting
  - [ ] User login patterns visible
- [ ] **Network/Proxy Data** (if applicable):
  - [ ] Proxy or network data configured
  - [ ] Web activity data flowing

### Splunk Data Source Configuration
- [ ] **Splunk Connection**:
  - [ ] Splunk Enterprise/Cloud connection configured
  - [ ] Connectivity test successful
  - [ ] SSL certificate validation configured (if HTTPS)
- [ ] **Data Ingestion**:
  - [ ] Micro-batching enabled and configured
  - [ ] Data ingestion parameters optimized
  - [ ] Backfill window configured appropriately
- [ ] **Identity Resolution**:
  - [ ] User-device associations established
  - [ ] IDR exclusions configured if needed
  - [ ] Identity resolution working properly

### Data Flow Validation
- [ ] **EPS Monitoring**: Events per second showing non-zero values
- [ ] **Processing Logs**: No critical errors in data source logs
- [ ] **Event Parsing**: Events parsing correctly without significant errors
- [ ] **Data Quality**: Sample data inspection shows expected content

## Security and Hardening Validation

### Account Security
- [ ] **Default Admin**: Default admin account secured with strong password
- [ ] **Sudo Access**: Sudo permissions reviewed and restricted if needed
- [ ] **Service Accounts**: All service account passwords are strong and documented

### System Security
- [ ] **Third-Party Agents**: Security agents installed after UBA (if applicable)
- [ ] **Directory Exclusions**: UBA directories excluded from security scanning
- [ ] **Security Updates**: OS security patching process established
- [ ] **Certificate Security**: Certificate storage permissions secured

### Network Security
- [ ] **Firewall Configuration**: Only required ports open
- [ ] **SSL/TLS**: All communications using secure protocols
- [ ] **Certificate Validation**: SSL certificate validation enabled for external connections

## Performance and Monitoring Validation

### Health Monitoring
- [ ] **Health Monitor**: Health Monitor dashboard accessible and functional
- [ ] **Resource Monitor**: Resource monitoring service running
- [ ] **Key Metrics**: All health monitor indicators showing healthy status
- [ ] **Log Monitoring**: Key log files accessible and being written

### Performance Optimization
- [ ] **Data Ingestion**: Ingestion parameters optimized for workload
- [ ] **Container Resources**: Docker container resources properly allocated
- [ ] **Anomaly Retention**: Anomaly retention policies configured
- [ ] **Threat Processing**: Threat rule processing timeout configured

### Diagnostic Capabilities
- [ ] **Diagnostic Bundle**: Can generate diagnostic bundle successfully
- [ ] **Log Access**: All key log locations accessible
- [ ] **Support Information**: Version and build information documented

## Backup and Recovery Validation

### Backup Configuration
- [ ] **Backup Directory**: Backup directory created and properly sized
- [ ] **Automated Backups**: Incremental backup configuration tested
- [ ] **Full Backup**: Manual full backup procedure tested
- [ ] **Backup Verification**: Backup files created and verified

### Recovery Procedures
- [ ] **Restore Testing**: Restore procedure documented and tested (in test environment)
- [ ] **Warm Standby** (if applicable):
  - [ ] Standby system configured
  - [ ] Replication working
  - [ ] Failover procedure documented and tested

## Final Production Readiness

### Documentation
- [ ] **Deployment Documentation**: All configurations documented
- [ ] **Admin Procedures**: Administrative procedures documented
- [ ] **Emergency Contacts**: Support contacts and escalation procedures documented
- [ ] **Password Management**: All passwords documented in secure location

### User Training and Handoff
- [ ] **Admin Training**: System administrators trained on UBA management
- [ ] **Analyst Training**: Security analysts trained on UBA interface and workflows
- [ ] **Documentation Handoff**: All documentation provided to operational teams

### Monitoring and Alerting
- [ ] **Health Monitoring**: Ongoing health monitoring configured
- [ ] **Performance Monitoring**: Performance metrics being collected
- [ ] **Alert Configuration**: Critical alerts configured for operational issues
- [ ] **Capacity Monitoring**: Disk space and resource utilization monitoring configured

### Operational Readiness
- [ ] **Change Management**: Change management procedures established
- [ ] **Maintenance Windows**: Planned maintenance procedures documented
- [ ] **Incident Response**: Incident response procedures documented
- [ ] **Support Channels**: Splunk support channels configured and tested

## Sign-off

### Technical Validation
- [ ] **System Administrator**: _________________________ Date: _________
- [ ] **Security Team Lead**: __________________________ Date: _________
- [ ] **Network Administrator**: _______________________ Date: _________

### Operational Readiness
- [ ] **Operations Manager**: __________________________ Date: _________
- [ ] **Security Operations Lead**: _____________________ Date: _________
- [ ] **Project Manager**: _____________________________ Date: _________

### Final Approval
- [ ] **Technical Lead**: ______________________________ Date: _________
- [ ] **Business Sponsor**: ____________________________ Date: _________

---

**Deployment Status:** 
- [ ] **PASSED** - All validation items completed successfully
- [ ] **CONDITIONAL** - Minor issues identified but acceptable for production
- [ ] **FAILED** - Critical issues require resolution before production use

**Notes:**
_Use this space to document any issues, exceptions, or additional configurations required_

_______________________________________________________________________________

_______________________________________________________________________________

_______________________________________________________________________________

**Document Version:** 1.0  
**Created:** June 2025  
**Last Updated:** ___________  
**Next Review:** ___________

**Installation Date:** _______________

**Installed Version:** 5.4.2

**Deployment Type:** [ ] Single Node [ ] 3 Node [ ] 5 Node [ ] 7 Node [ ] 10 Node [ ] 20 Node

**Operating System:** RHEL 8.10

**Special Configurations:**
- [ ] FIPS Compliance Enabled
- [ ] Warm Standby Configured  
- [ ] SSO Authentication
- [ ] Custom SSL Certificates

**Key Contact Information:**
- **UBA Administrator:** _______________
- **Network Administrator:** _______________
- **Security Administrator:** _______________
- **Splunk Administrator:** _______________

**Critical Passwords and Certificates:**
- **Admin Password Location:** _______________
- **Certificate Expiration Dates:** _______________
- **Service Account Credentials:** _______________

**Known Issues or Deviations:**
_______________________________________________________________________________
_______________________________________________________________________________
_______________________________________________________________________________

**Security Lead:** _________________________ **Date:** _________

**Operations Lead:** _______________________ **Date:** _________
