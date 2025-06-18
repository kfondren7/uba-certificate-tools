# Adding Data Sources to Splunk UBA - Complete Guide

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Required Data Sources (Critical)](#required-data-sources-critical)
4. [Data Source Priority and Configuration Order](#data-source-priority-and-configuration-order)
5. [Splunk Platform Data Sources](#splunk-platform-data-sources)
6. [Identity Resolution Data Sources](#identity-resolution-data-sources)
7. [Use Case-Specific Data Sources](#use-case-specific-data-sources)
8. [Data Source Configuration Steps](#data-source-configuration-steps)
9. [Validation and Troubleshooting](#validation-and-troubleshooting)
10. [Best Practices](#best-practices)
11. [Common Issues and Solutions](#common-issues-and-solutions)

## Overview

This guide provides comprehensive instructions for adding and configuring data sources in Splunk User Behavior Analytics (UBA). Proper data source configuration is essential for UBA to perform accurate behavioral analysis, identity resolution, and threat detection.

### Why Data Sources Matter

- **Behavioral Modeling**: UBA requires diverse data types to establish baseline user and entity behavior
- **Identity Resolution**: Multiple data sources help UBA map users to devices and activities
- **Threat Detection**: Different data sources enable various use cases and detection capabilities
- **Context Enhancement**: Rich data provides better investigative context for security analysts

## Prerequisites

### System Requirements
- ✅ Splunk UBA 5.4.2 properly installed and licensed
- ✅ Valid UBA license (without license, data sources show as "Suspended")
- ✅ Network connectivity to data source systems
- ✅ Appropriate permissions to access source data

### Access Requirements
- **UBA Admin Access**: Administrative privileges in UBA web interface
- **Source System Access**: Credentials for each data source system
- **Network Access**: Firewall rules allowing UBA to connect to data sources
- **Service Accounts**: Dedicated service accounts with appropriate permissions

### Important Notes
⚠️ **Critical**: HR data must be the first data source configured  
⚠️ **Important**: Assets data must be the second data source configured  
⚠️ **License**: Ensure valid UBA license before adding data sources

## Required Data Sources (Critical)

### 1. HR Data Source (MUST BE FIRST)

**Purpose**: Provides user contextual information and enables proper identity resolution.

**Required Fields**:
- **User ID** (required) - Unique identifier for each user
- **Full Name** - User's complete name
- **Email Address** - Primary email address
- **Manager ID** - For establishing reporting hierarchy
- **Title/Role** - Job title or role
- **Department** - Department or business unit
- **Location** - Physical location or office
- **Start Date** - Employment start date
- **Termination Date** - Employment end date (if applicable)

**Configuration Steps**:
1. Navigate to **Data Sources** > **Add Data Source** > **HR Data Source**
2. Configure connection to HR system:
   - **Connection Type**: File upload, Database, or API
   - **Data Format**: CSV, JSON, or Database query
   - **Refresh Schedule**: Daily at 2:00 AM (default)
3. Map required fields to your HR data schema
4. Test connection and validate data ingestion
5. Verify user records appear in UBA

**Validation**:
```bash
# Check HR data ingestion
grep "HR data" /var/vcap/sys/log/caspida-datasource/*.log

# Verify users in UBA interface
# Navigate to Manage > Users
```

### 2. Assets Data Source (MUST BE SECOND)

**Purpose**: Device-to-user mapping and network asset inventory.

**Required Fields**:
- **Asset ID** (required) - Hostname or MAC address
- **IP Address** - Current or assigned IP address
- **Owner** - User ID (links to HR data)
- **Asset Type** - Workstation, server, mobile device, etc.
- **Location** - Physical location (optional)

**Configuration Steps**:
1. Navigate to **Data Sources** > **Add Data Source** > **Assets Data Source**
2. Configure data source:
   - **Source**: CMDB, Splunk ES, Active Directory, or CSV file
   - **Field Mapping**: Map asset fields to UBA schema
   - **Multi-value Delimiter**: Set if needed (comma, semicolon)
3. Configure refresh schedule
4. Test and validate data ingestion

**Special Configuration for Multi-value Fields**:
```bash
# Edit /etc/caspida/local/conf/uba-site.properties
attribution.keyvalue.delimiter=,

# Restart UBA services
/opt/caspida/bin/Caspida stop-all
/opt/caspida/bin/Caspida start-all
```

## Data Source Priority and Configuration Order

### Recommended Configuration Sequence

1. **HR Data** (Critical - First)
2. **Assets Data** (Critical - Second)
3. **Authentication Data** (High Priority)
4. **DNS Data** (High Priority - for identity resolution)
5. **DHCP Data** (High Priority - for identity resolution)
6. **Network/Firewall Data** (Medium Priority)
7. **Endpoint Data** (Medium Priority)
8. **Email Data** (Medium Priority)
9. **VPN Data** (Medium Priority)
10. **Additional Data Sources** (As needed for specific use cases)

### Why Order Matters

- **Identity Foundation**: HR and Assets establish the baseline for user and device identification
- **Identity Resolution**: Authentication, DNS, and DHCP data builds user-to-device mappings
- **Behavioral Context**: Additional data sources enhance detection capabilities
- **Dependencies**: Some anomaly models require specific data combinations

## Splunk Platform Data Sources

### Connection Types

UBA provides two connectors for Splunk platform data:

#### Splunk Direct Connector
**Use When**:
- Data is CIM-compliant
- Want Splunk to perform field extractions before sending to UBA
- Data format is supported by UBA

**Supported Data Sources**:
- Authentication, Badge Access, Cloud Data, Database
- DHCP, DLP, DNS, Email, Endpoint, External Alarm
- Firewall, Host AV, Network IDS/IPS, Printer, VPN, HTTP
- Windows Event Logs (XML format)

#### Splunk Raw Events Connector
**Use When**:
- Data is partially or non-CIM compliant
- UBA has native parsers for the data format
- Need UBA to parse raw events directly

**Supported Data Sources**:
- Windows Event Logs (multiline format)
- Windows PowerShell Logs
- USB Logs, NetFlow Logs, Cisco Logs

### Splunk Data Source Configuration

1. **Navigate to Data Sources**:
   ```
   UBA Web Interface > Data Sources > Add Data Source > Splunk Data
   ```

2. **Configure Connection**:
   - **Splunk Host**: Hostname or IP address
   - **Management Port**: Usually 8089
   - **Username**: Service account with appropriate permissions
   - **Password**: Service account password
   - **Protocol**: HTTP or HTTPS

3. **Configure SSL (for HTTPS)**:
   ```bash
   # Copy Splunk certificate
   scp user@splunk-host:/opt/splunk/etc/auth/ca.pem.default /home/caspida/
   
   # Import certificate to Java keystore
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit \
     -import -trustcacerts -alias SplunkESRootCA -file ~/ca.pem.default
   
   # Enable SSL validation in uba-site.properties
   validate.splunk.ssl.certificate=true
   ```

4. **Configure Data Ingestion Method**:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   # Enable micro-batching (recommended)
   splunk.live.micro.batching=true
   splunk.live.micro.batching.delay.seconds=180
   splunk.live.micro.batching.interval.seconds=60
   connector.splunk.max.backtrace.time.in.hour=4
   ```

5. **Restart Services**:
   ```bash
   /opt/caspida/bin/Caspida stop-all
   /opt/caspida/bin/Caspida start-all
   ```

## Identity Resolution Data Sources

These data sources are crucial for UBA to perform accurate identity resolution:

### Authentication Data
**Purpose**: Maps users to IP addresses and devices through login events

**Configuration**:
1. Navigate to **Data Sources** > **Add Data Source** > **Authentication Data**
2. Select source type: Active Directory, VPN, Application logs
3. Map required fields:
   - User ID, Success/Failure status, Timestamp
   - Source IP, Event Type (login/logout)

**Supported Event Types**:
- Windows Active Directory Events: 4768, 4769, 4776, 4672, 4673
- VPN login/logout events
- Application authentication events

### DNS Data
**Purpose**: Maps IP addresses to hostnames for device identification

**Configuration**:
1. Configure DNS logging on DNS servers
2. Send DNS query/response data to Splunk
3. Add DNS data source in UBA using Splunk Direct connector

**Required Fields**:
- Query/Response type, Source/Destination IP
- Queried domain, Response data, Timestamp

### DHCP Data
**Purpose**: Maps IP addresses to MAC addresses and hostnames

**Configuration**:
1. Enable DHCP logging on DHCP servers
2. Configure Splunk to collect DHCP logs
3. Add DHCP data source in UBA

**Key DHCP Events**:
- New lease assignments
- Lease renewals
- Lease releases

### VPN Data
**Purpose**: Maps external IP addresses to internal users

**Configuration**:
1. Configure VPN logging
2. Ensure login/logout events are captured
3. Add VPN data source with proper field mapping

## Use Case-Specific Data Sources

### Account Misuse Detection
**Required Data Sources**:
- HR Data, Assets Data, Authentication
- Badge Access, Cloud Data, Email
- Endpoint, External Alarm, VPN
- Windows Security Events

### Compromised User Account Detection
**Required Data Sources**:
- HR Data, Assets Data, Authentication
- Badge Access, Cloud Data, Endpoint
- External Alarm, VPN
- Windows Security Events

### Data Exfiltration Detection
**Required Data Sources**:
- Cloud Data, DLP, Email
- Firewall, HTTP, Network IDS/IPS
- Printer, VPN

### Compromised/Infected Machine Detection
**Required Data Sources**:
- DLP, DNS, External Alarm
- Firewall, HTTP, Network IDS/IPS
- Windows Security Events

### Lateral Movement Detection
**Required Data Sources**:
- External Alarm, Network IDS/IPS
- Windows Security Events

## Data Source Configuration Steps

### Step-by-Step Configuration Process

#### 1. Access UBA Web Interface
```
https://<uba-server>/
Login with admin credentials
```

#### 2. Navigate to Data Sources
```
Main Menu > Data Sources > Add Data Source
```

#### 3. Select Data Source Type
- Choose appropriate connector (Splunk Direct/Raw Events)
- Select specific data source type
- Configure connection parameters

#### 4. Configure Field Mapping
- Map source fields to UBA schema
- Set required field mappings
- Configure optional field mappings

#### 5. Set Ingestion Parameters
- Configure refresh/polling schedule
- Set data backfill window
- Configure filtering criteria

#### 6. Test Connection
- Verify connectivity to source system
- Test authentication credentials
- Validate data retrieval

#### 7. Validate Data Ingestion
- Monitor data source status
- Check Events Per Second (EPS)
- Verify data quality and parsing

### Example: Adding Windows Active Directory Data

1. **Prepare Splunk Data**:
   ```splunk
   # Ensure Windows events are properly indexed in Splunk
   index=wineventlog source="WinEventLog:Security"
   | head 100
   ```

2. **Add Data Source in UBA**:
   - Navigate to **Data Sources** > **Add Data Source**
   - Select **Splunk Direct** connector
   - Choose **Windows Security Events** data source type

3. **Configure Connection**:
   - Splunk Host: `splunk.company.com`
   - Port: `8089`
   - Username: `uba_service`
   - Password: `<service_account_password>`

4. **Configure Search Query**:
   ```splunk
   index=wineventlog source="WinEventLog:Security" 
   (EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769 OR EventCode=4776)
   | eval dataFormat="AD"
   ```

5. **Field Mapping**:
   - Map EventCode to event type
   - Map Account_Name to user ID
   - Map Source_Network_Address to source IP

6. **Test and Save**:
   - Click **Test Connection**
   - Verify sample data appears
   - Save configuration

## Validation and Troubleshooting

### Data Source Health Monitoring

#### 1. Check Data Source Status
```
UBA Web Interface > Data Sources
Verify all sources show "Running" status
Check EPS (Events Per Second) > 0
```

#### 2. Monitor Data Ingestion Logs
```bash
# Check data source logs
tail -f /var/vcap/sys/log/caspida-datasource/caspida-datasource.stderr.log

# Check for errors
grep ERROR /var/vcap/sys/log/caspida-datasource/*.log

# Check processing statistics
grep "events processed" /var/vcap/sys/log/caspida-datasource/*.log
```

#### 3. Validate Identity Resolution
```
UBA Web Interface > Manage > IDR Exclusions
Verify user-device associations are being established
```

#### 4. Check Data Quality
```
UBA Web Interface > Data Sources > [Source Name]
Review data samples and field parsing
Check for parsing errors or missing fields
```

### Common Data Source Issues

#### No Data Flowing
**Symptoms**: EPS shows 0, no events in logs

**Troubleshooting**:
1. **Verify Connection**:
   ```bash
   # Test Splunk connectivity
   curl -k https://splunk-hostname:8089
   telnet splunk-hostname 8089
   ```

2. **Check Authentication**:
   ```bash
   # Test Splunk credentials
   curl -k -u username:password https://splunk-hostname:8089/services/auth/login
   ```

3. **Verify Search Query**:
   - Log into Splunk and run the same search query
   - Ensure data exists in the specified time range
   - Check index permissions for service account

#### Authentication Failures
**Symptoms**: Connection errors, authentication timeouts

**Solutions**:
1. **Verify Service Account**:
   - Check username/password
   - Verify account is not locked or expired
   - Ensure appropriate Splunk roles assigned

2. **Check SSL Configuration**:
   ```bash
   # Verify SSL certificates
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -list -keystore $JAVA_HOME/lib/security/cacerts \
     -storepass changeit | grep -i splunk
   ```

#### Identity Resolution Issues
**Symptoms**: Users not associated with devices

**Solutions**:
1. **Check IDR Configuration**:
   ```
   UBA Interface > Manage > IDR Exclusions
   Review exclusion rules and thresholds
   ```

2. **Verify HR Data**:
   ```
   UBA Interface > Manage > HR Data
   Ensure HR data is properly loaded and current
   ```

3. **Adjust IDR Thresholds**:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   identity.resolution.blacklist.threshold.device.hostnamecount=2
   identity.resolution.blacklist.threshold.device.hostnamehours=6
   
   # Synchronize changes
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   ```

## Best Practices

### Data Source Planning

#### 1. Prioritize Critical Data Sources
- **Always start with HR and Assets data**
- **Focus on identity resolution sources next**
- **Add use case-specific sources based on security priorities**

#### 2. Ensure Data Quality
- **Validate data completeness before adding to UBA**
- **Establish data quality monitoring**
- **Implement data retention policies**

#### 3. Plan for Scale
- **Consider data volume and EPS requirements**
- **Plan network bandwidth for data transfer**
- **Monitor UBA performance impact**

### Security Considerations

#### 1. Service Account Security
- **Use dedicated service accounts for each data source**
- **Implement least-privilege access**
- **Regularly rotate service account passwords**
- **Monitor service account usage**

#### 2. Network Security
- **Use SSL/TLS for all data source connections**
- **Implement network segmentation**
- **Configure firewall rules properly**
- **Monitor network traffic**

#### 3. Data Privacy
- **Understand data sensitivity and classification**
- **Implement data masking where appropriate**
- **Comply with data retention requirements**
- **Document data flows for compliance**

### Performance Optimization

#### 1. Optimize Data Ingestion
```bash
# Configure micro-batching for better performance
splunk.live.micro.batching=true
splunk.live.micro.batching.delay.seconds=180
splunk.live.micro.batching.interval.seconds=60

# Limit backfill window
connector.splunk.max.backtrace.time.in.hour=4

# Configure parallel processing
datasource.parallel.processing.enabled=true
```

#### 2. Monitor Resource Usage
- **Monitor CPU and memory usage during data ingestion**
- **Watch disk space utilization**
- **Monitor network bandwidth consumption**

#### 3. Schedule Data Collection
- **Spread data collection across time windows**
- **Avoid peak business hours for large backfills**
- **Configure appropriate refresh schedules**

### Maintenance and Monitoring

#### 1. Regular Health Checks
```bash
# Daily health check script
#!/bin/bash
echo "=== UBA Data Source Health Check ==="
echo "Date: $(date)"

# Check data source status
echo "Checking data source logs..."
grep -c "events processed" /var/vcap/sys/log/caspida-datasource/*.log

# Check for errors
echo "Checking for errors..."
grep -c ERROR /var/vcap/sys/log/caspida-datasource/*.log

# Check UBA service status
echo "UBA service status..."
/opt/caspida/bin/Caspida status
```

#### 2. Performance Monitoring
- **Monitor EPS trends over time**
- **Track data source reliability**
- **Monitor identity resolution effectiveness**

#### 3. Capacity Planning
- **Track data growth trends**
- **Plan for seasonal variations**
- **Monitor storage utilization**

## Common Issues and Solutions

### Issue: Data Source Shows "Suspended" Status

**Cause**: Invalid or missing UBA license

**Solution**:
1. Verify UBA license validity:
   ```
   UBA Interface > Settings > License
   ```
2. Upload valid license if needed
3. Restart UBA services:
   ```bash
   /opt/caspida/bin/Caspida stop-all
   /opt/caspida/bin/Caspida start-all
   ```

### Issue: Poor Identity Resolution Quality

**Cause**: Insufficient or poor quality identity resolution data

**Solution**:
1. **Add missing data sources**: DNS, DHCP, Authentication
2. **Improve data quality**: Ensure consistent field mapping
3. **Adjust IDR thresholds**: Fine-tune identity resolution parameters
4. **Review exclusions**: Check IDR exclusion rules

### Issue: High Memory Usage During Data Ingestion

**Cause**: Large data volumes or inefficient queries

**Solution**:
1. **Optimize Splunk queries**: Add time restrictions and filters
2. **Enable micro-batching**: Reduce memory pressure
3. **Increase JVM heap**: Allocate more memory to UBA
4. **Schedule data collection**: Spread load over time

### Issue: Inconsistent User-Device Mappings

**Cause**: Conflicting or incomplete identity resolution data

**Solution**:
1. **Review HR data accuracy**: Ensure user records are current
2. **Check assets data**: Verify device ownership information
3. **Validate authentication data**: Ensure login events are captured
4. **Tune IDR parameters**: Adjust confidence thresholds

## Conclusion

Successful UBA deployment depends heavily on proper data source configuration. By following this guide and implementing best practices, you can:

- **Ensure comprehensive threat detection capabilities**
- **Achieve accurate identity resolution**
- **Minimize false positives through rich contextual data**
- **Enable effective security operations**

### Next Steps

1. **Plan your data source implementation based on priority**
2. **Implement critical data sources first (HR and Assets)**
3. **Add identity resolution sources**
4. **Gradually add use case-specific sources**
5. **Monitor and optimize performance continuously**

### Additional Resources

- [Splunk UBA Data Sources Documentation](https://docs.splunk.com/Documentation/UBA/latest/GetDataIn/Datasources)
- [UBA Connector Documentation](https://docs.splunk.com/Documentation/UBA/latest/GetDataIn/AddSplunkEvents)
- [UBA Troubleshooting Guide](./Splunk_UBA_Troubleshooting_Guide.md)
- [UBA Deployment Guide](./Splunk_UBA_Deployment_Guide.md)

---

*Document Version: 1.0*  
*Created: June 18, 2025*  
*Author: UBA Certificate Tools Suite*  
*Last Updated: June 18, 2025*
