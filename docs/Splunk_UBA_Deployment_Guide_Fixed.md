# Splunk UBA 5.4.2 Deployment Guide

This guide provides essential steps to deploy Splunk User Behavior Analytics (UBA) 5.4.2 on Red Hat Enterprise Linux (RHEL) 8.10. It includes hardware requirements, installation steps, SSL certificate management, data source configuration, and validation checklists for a successful deployment.

## 1. System Requirements

### Hardware Requirements
- **CPU**: 16 CPU cores minimum per node
- **Memory**: 64 GB RAM minimum per node
- **Storage**:
  - **Disk 1**: 100 GB dedicated disk space for UBA installation
  - **Disk 2**: 1 TB additional disk space for metadata storage
  - **Disk 3**: 1 TB additional disk space for each node running Spark services
- **Network**: At least one 1 Gb ethernet interface per node
- **IOPS**: Disk subsystem must support average 1200 IOPS

### Operating System Requirements
- **RHEL 8.10**: Target operating system for this deployment
- **Kernel Version**: 4.18.0-553.36.1.el8_10.x86_64 (tested)

> ⚠️ **Important**: Installing Splunk UBA on hardened operating systems is not supported.

## 2. Networking Requirements

### Static IP Address Configuration
All Splunk UBA servers must have static IP addresses assigned. DHCP is not supported.

### Required Ports and Firewall Configuration
Configure firewall rules to allow the following ports:

#### External Access Ports
- **SSH**: 22 (for administrative access)
- **HTTPS**: 443 (for web interface access)

#### Internal Cluster Communication Ports
- **SSH**: 22
- **Redis**: 6379, 16379
- **PostgreSQL**: 5432
- **Zookeeper**: 2181, 2888, 3888
- **Apache Kafka**: 9092, 9901, 9093, 32768-65535
- **Job Manager**: 9002
- **Time Series Database (InfluxDB)**: 8086
- **Apache Impala**: 21000, 21050, 25000, 25010, 25020
- **Apache Spark**: 7077, 8080, 8081
- **Hadoop HDFS**: 8020, 8090, 9866, 9867, 9864, 9868, 9870
- **Hive Metastore**: 9090, 9095
- **Kubernetes/etcd**: 2379, 2380, 5000, 6443, 10250, 10251, 10252, 10255, 30000-32767

#### Splunk Platform Communication Ports
- **HTTPS authentication**: 443
- **HTTP authentication**: 80
- **HTTP Event Collector**: 8088 (or 443 for Splunk Cloud)
- **REST services**: 8089
- **Splunk Universal Forwarder**: 9997

#### Outbound Ports
- **UBA telemetry**: 9997 (to *.splunkcloud.com)

### DNS and Hostname Configuration
1. **Configure hostname resolution:**
   ```bash
   # Ensure all nodes can resolve each other by hostname
   host <hostname>
   nslookup <hostname>
   
   # Add entries to /etc/hosts if DNS is not available
   echo "192.168.1.10 uba-node1.domain.com uba-node1" >> /etc/hosts
   ```

2. **Verify network interface configuration:**
   ```bash
   # Check firewall zone assignment
   sudo firewall-cmd --get-zone-of-interface=<interface_name>
   
   # Verify default route is set
   sudo ip route | grep "default"
   ```

3. **Set proper network zone:**
   ```bash
   # Ensure the UBA interface is in the "public" zone
   sudo firewall-cmd --zone=public --add-interface=<interface_name> --permanent
   sudo firewall-cmd --reload
   ```

## 3. Pre-Installation Tasks

### Configure Permissions and Prepare the User
1. Add the caspida user:
   ```bash
   groupadd --gid 2018 caspida
   useradd --uid 2018 --gid 2018 -m -d /home/caspida -c "Caspida User" -s /bin/bash caspida
   passwd caspida
   ```

2. Enable sudo permissions:
   ```bash
   # Edit the /etc/sudoers file using visudo
   # Comment the line "Defaults requiretty" if it exists
   # Add these lines at the end:
   caspida ALL=(ALL) NOPASSWD:ALL
   Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin
   ```

3. Validate the UMASK value:
   ```bash
   umask  # Should return 0002 or 0022
   grep -i "^UMASK" /etc/login.defs  # Verify setting
   ```

### Prepare Storage
1. Find 1TB disks:
   ```bash
   fdisk -l
   ```

2. Partition and format disks (assuming /dev/sdb and /dev/sdc):
   ```bash
   # For /dev/sdb
   parted -a optimal /dev/sdb
     mklabel gpt
     mkpart primary ext4 2048s 100%
     align-check opt 1
     quit
   mkfs -t ext4 /dev/sdb1

   # For /dev/sdc
   parted -a optimal /dev/sdc
     mklabel gpt
     mkpart primary ext4 2048s 100%
     align-check opt 1
     quit
   mkfs -t ext4 /dev/sdc1
   ```

3. Get block IDs and mount disks:
   ```bash
   blkid -o value -s UUID /dev/sdb1
   blkid -o value -s UUID /dev/sdc1
   
   # Create mount directories
   mkdir -p /var/vcap /var/vcap2
   
   # Add to /etc/fstab
   # UUID=<sdb1-uuid> /var/vcap ext4 defaults 0 0
   # UUID=<sdc1-uuid> /var/vcap2 ext4 defaults 0 0
   
   # Mount the file systems
   mount -a
   
   # Set permissions
   chmod 755 /var/vcap /var/vcap2
   chown root:root /var/vcap /var/vcap2
   ```

### Configure the Environment
1. Create caspida software directory:
   ```bash
   mkdir /opt/caspida
   chown caspida:caspida /opt/caspida
   chmod 755 /opt/caspida
   ```

2. Set PostgreSQL environment variables:
   ```bash
   # Add to /etc/locale.conf:
   LANG="en_US.UTF-8"
   LC_CTYPE="en_US.UTF-8"
   
   # Apply changes
   source /etc/locale.conf
   ```

3. Verify hostname resolution:
   ```bash
   host <hostname>
   ```

4. Set SELinux to permissive mode:
   ```bash
   # Edit /etc/sysconfig/selinux and set:
   SELINUX=permissive
   ```

5. Configure system date, time and timezone:
   ```bash
   timedatectl status
   timedatectl set-timezone UTC  # Set to match Splunk Enterprise
   ```

6. Configure kernel for bridge networking:
   ```bash
   # Verify if bridge-nf-call-iptables exists and is set to 1
   cat /proc/sys/net/bridge/bridge-nf-call-iptables
   
   # If it doesn't exist:
   modprobe br_netfilter
   echo br_netfilter > /etc/modules-load.d/br_net_filter.conf
   sysctl -w net.bridge.bridge-nf-call-iptables=1
   echo net.bridge.bridge-nf-call-iptables=1 > /etc/sysctl.d/splunkuba-bridge.conf
   ```

## 4. Installation

### Obtain and Prepare Installation Package
1. Download UBA software package:
   ```bash
   # Download to /home/caspida directory:
   # splunk-uba-software-installation-package_542.tgz
   ```

2. Extract the package:
   ```bash
   cd /home/caspida
   tar -xvzf splunk-uba-software-installation-package_542.tgz
   ```

### Single Server Installation
1. Login as caspida user:
   ```bash
   su - caspida
   ```

2. Extract the UBA platform files:
   ```bash
   tar -xvf Splunk-UBA-Platform-5.4.2-*.tgz -C /opt/caspida
   ```

3. Run the installation script:
   ```bash
   cd /opt/caspida/bin
   ./INSTALL.sh -s
   ```

4. Follow the interactive prompts:
   - Enter network interface (e.g., eth0)
   - Enter IP address for Splunk UBA webUI
   - Set admin password
   - Confirm installation

### Distributed Server Installation
1. Install on management node first:
   ```bash
   cd /opt/caspida/bin
   ./INSTALL.sh -c
   ```

2. During installation, provide:
   - List of all node hostnames or IPs (comma-separated)
   - Network interface name
   - IP address for Splunk UBA webUI
   - Admin password

3. Install on each remaining node:
   ```bash
   cd /opt/caspida/bin
   ./INSTALL.sh -n
   ```

## 5. Post-Installation Configuration

### Verify Installation
1. Access the Splunk UBA web interface: `https://<ip_address>`
2. Log in with admin credentials
3. Check the health status:
   ```bash
   /opt/caspida/bin/utils/uba_health_check.sh
   ```

### Secure Default Account
1. Change the admin password:
   ```
   # Log in to Splunk UBA UI
   # Go to Manage > UBA Accounts
   # Edit the admin user and change password
   ```

### Basic Service Management
- Start all services:
  ```bash
  /opt/caspida/bin/Caspida start-all
  ```
  
- Stop all services:
  ```bash
  /opt/caspida/bin/Caspida stop-all
  ```
  
- Restart UI:
  ```bash
  sudo service caspida-ui restart
  ```

## 6. Configure Splunk UBA

### Upload Splunk UBA License
After installation, you must upload a valid license file:

1. Access the Splunk UBA web interface
2. Navigate to **Manage > License**
3. Click **Choose File** and select your license file
4. Click **Open** to upload

**Important:** Without a valid license, UBA will not ingest data. Data sources will show as "Suspended."

### (Optional) Enable FIPS Compliance
Federal Information Processing Standard (FIPS) compliance is available for UBA 5.4.0 and higher.

#### For RHEL 8.10 Systems:
1. Check current FIPS status:
   ```bash
   sudo fips-mode-setup --check
   ```

2. Enable FIPS mode:
   ```bash
   sudo fips-mode-setup --enable
   ```

3. Reboot the system:
   ```bash
   sudo reboot
   ```

4. Verify FIPS is enabled:
   ```bash
   sudo fips-mode-setup --check
   cat /proc/sys/crypto/fips_enabled  # Should return 1
   ```

**Note:** Enable FIPS on each UBA node before running installation/upgrade scripts.

### SSL Certificate Management

#### Updating the Default Self-Signed Certificate
The self-signed certificate included with Splunk UBA expires 365 days after the Splunk UBA web interface is accessed for the first time.

1. Regenerate the default self-signed certificate:
   ```bash
   rm /var/vcap/store/caspida/certs/my-root-ca.crt.pem
   /opt/caspida/bin/CaspidaCert.sh US CA "San Francisco" Splunk "" "" /var/vcap/store/caspida/certs/
   ```

#### Creating and Installing Third-Party Certificates
For production environments, you should replace the self-signed certificate with a third-party signed certificate.

##### Generate a Certificate Signing Request (CSR)

1. Stop the Splunk UBA services:
   ```bash
   sudo service caspida-resourcesmonitor stop
   sudo service caspida-ui stop
   ```

2. Get host information:
   ```bash
   hostname -s  # Short hostname
   hostname -d  # Domain name
   ```

3. Generate certificates:
   ```bash
   sudo /opt/caspida/bin/CaspidaCert.sh <country> <state> <location> <org> <domain> <"short hostname"> /var/vcap/store/caspida/certs/mycerts
   ```
   Example:
   ```bash
   sudo /opt/caspida/bin/CaspidaCert.sh US CA SanFrancisco Splunk sv.splunk.com "uba-17" /var/vcap/store/caspida/certs/mycerts
   ```

4. Update uba-site.properties:
   ```bash
   # Add the following to /etc/caspida/local/conf/uba-site.properties
   ui.auth.rootca=/var/vcap/store/caspida/certs/mycerts/my-root-ca.crt.pem
   ui.auth.privateKey=/var/vcap/store/caspida/certs/mycerts/my-server.key.pem
   ui.auth.serverCert=/var/vcap/store/caspida/certs/mycerts/my-server.crt.pem
   ```

5. Generate CSR for the certificate authority:
   ```bash
   cd /var/vcap/store/caspida/certs/mycerts
   sudo openssl req -new -key my-server.key.pem -out myCACertificate.csr
   ```

6. Set permissions:
   ```bash
   sudo chmod 644 /var/vcap/store/caspida/certs/mycerts/*
   ```

7. Start services:
   ```bash
   sudo service caspida-ui start
   sudo service caspida-resourcesmonitor start
   ```

8. Submit the CSR to your certificate authority and obtain signed certificates.

#### Installing Third-Party Signed Certificates

1. Stop services:
   ```bash
   sudo service caspida-resourcesmonitor stop
   sudo service caspida-ui stop
   ```

2. Back up existing certificates:
   ```bash
   sudo cp -p /var/vcap/store/caspida/certs/my-server.crt.pem /var/vcap/store/caspida/certs/my-server.crt.pem_backup
   sudo cp -p /var/vcap/store/caspida/certs/my-root-ca.crt.pem /var/vcap/store/caspida/certs/my-root-ca.crt.pem_backup
   ```

3. Install new certificates:
   ```bash
   sudo mv -f /path/to/your/signed/certificate.pem /var/vcap/store/caspida/certs/mycerts/my-server.crt.pem
   sudo mv -f /path/to/your/root/certificate.pem /var/vcap/store/caspida/certs/mycerts/my-root-ca.crt.pem
   ```

4. Set permissions:
   ```bash
   sudo chmod 644 /var/vcap/store/caspida/certs/mycerts/*
   ```

5. For distributed deployments, synchronize configuration:
   ```bash
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   ```

6. Start services:
   ```bash
   sudo service caspida-ui start
   sudo service caspida-resourcesmonitor start
   ```

7. Verify certificate installation by accessing the UBA web interface.

#### Handling Subject Alternative Names (SAN)
If Chrome reports ERR_CERT_COMMON_NAME_INVALID, you need to include Subject Alternative Names:

1. Create directory and configuration:
   ```bash
   mkdir -p /opt/caspida/conf/deployment/templates/local_conf/ssl
   ```

2. Create openssl-altname.cnf:
   ```bash
   cat > /opt/caspida/conf/deployment/templates/local_conf/ssl/openssl-altname.cnf << 'EOF'
   [ req ]
   default_bits       = 2048
   distinguished_name = req_distinguished_name
   attributes        = req_attributes
   [ req_distinguished_name ]
   countryName                = Country Name (2 letter code)
   stateOrProvinceName        = State or Province Name (full name)
   localityName               = Locality Name (eg, city)
   organizationName           = Organization Name (eg, company)
   organizationalUnitName     = Organizational Unit Name (eg, section)
   commonName                 = Common Name (e.g. server FQDN or YOUR name)
   [req_attributes]
   subjectAltName             = Alternative DNS names, Email adresses or IPs (comma separated)
   EOF
   ```

3. Generate CSR with SANs:
   ```bash
   openssl req -sha256 -new -key my-server.key.pem -out myCACertificate.csr -config /opt/caspida/conf/deployment/templates/local_conf/ssl/openssl-altname.cnf
   ```
   When prompted for alternative names, enter: `DNS:hostname.domain.com, DNS:hostname, IP:192.168.0.1`

4. Verify SANs in the CSR:
   ```bash
   openssl req -text -noout -verify -in myCACertificate.csr | grep DNS
   ```

#### Replace Job Manager Certificate
For communication between UBA components:

1. Stop services:
   ```bash
   /opt/caspida/bin/Caspida stop
   ```

2. Generate the keystore:
   ```bash
   cd /opt/caspida/bin/jobmanager
   sudo ./generate-keystore.sh
   ```

3. Start services:
   ```bash
   /opt/caspida/bin/Caspida start
   ```

## 7. Manage User Accounts and Authentication

### User Account Roles
UBA supports multiple user roles with different privilege levels:

- **Admin (uba_admin)**: Full system administration access
- **Analyst (uba_analyst)**: Security analysis capabilities  
- **Content Developer (uba_content_developer)**: Custom content creation
- **PII Unmask (uba_pii_unmask)**: Access to unmasked PII data
- **User (uba_user)**: Basic viewing permissions

### Configure Single Sign-On (SSO)
For enterprise authentication integration:

1. **Prepare SSO configuration:**
   - Obtain identity provider metadata file
   - Ensure DNS resolution for identity provider
   - Configure role mappings

2. **Configure SSO in UBA:**
   ```
   # Navigate to Manage > Settings > Authentication
   # Select "Single Sign-On" authentication type
   # Upload identity provider metadata file
   # Configure role mappings
   ```

3. **Supported identity providers:**
   - Microsoft Active Directory Federation Services (ADFS)
   - Microsoft Entra ID (Azure AD)
   - OneLogin
   - Generic SAML 2.0 providers

4. **Test SSO configuration:**
   - Verify role assignments
   - Test user login flow
   - Validate group mappings

### Configure Splunk Platform Authentication
For Splunk Enterprise/Cloud integration:

1. **Create service account in Splunk:**
   ```bash
   # On Splunk Enterprise
   # Navigate to Settings > Access controls > Users
   # Create user with appropriate roles
   ```

2. **Configure in UBA:**
   ```
   # Navigate to Data Sources > Add Data Source
   # Select "Splunk Data"
   # Enter Splunk credentials
   # Test connection
   ```

## 8. Backup and Restore Configuration

### Configure Automated Incremental Backups
For disaster recovery and high availability:

1. Set backup properties in uba-site.properties:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   backup.filesystem.enabled=true
   backup.filesystem.directory=/backup
   backup.filesystem.full.interval=1 week
   ```

2. Synchronize changes in distributed deployment:
   ```bash
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   ```

3. Create and configure backup directory:
   ```bash
   sudo mkdir -p /backup
   sudo chown caspida:caspida /backup
   sudo chmod 755 /backup
   ```

4. Verify backup configuration:
   ```bash
   grep backup.filesystem /etc/caspida/local/conf/uba-site.properties
   ```

### Manual Full Backup Procedure
For major upgrades or migrations:

1. Stop all services:
   ```bash
   /opt/caspida/bin/Caspida stop-all
   ```

2. Run backup script:
   ```bash
   /opt/caspida/bin/utils/backup.sh -d /backup -a
   ```
   Options:
   - `-d /backup`: Backup directory path
   - `-a`: Create archive
   - `-c`: Include container data
   - `-s`: Skip regular backups for selective backup

3. Start all services after backup:
   ```bash
   /opt/caspida/bin/Caspida start-all
   ```

4. Verify backup was successful:
   ```bash
   ls -la /backup/
   ```

### Restore Procedure
In case of system failure or migration:

1. Stop all services:
   ```bash
   /opt/caspida/bin/Caspida stop-all
   ```

2. Run restore script:
   ```bash
   /opt/caspida/bin/utils/restore.sh -d /backup/<backup-timestamp> -a
   ```
   Options:
   - `-d /backup/<backup-timestamp>`: Path to backup directory
   - `-a`: Restore from archive
   - `-c`: Include container data
   - `-s`: Selective restore

3. Start all services after restore:
   ```bash
   /opt/caspida/bin/Caspida start-all
   ```

## 9. Configure Warm Standby for High Availability

For critical deployments requiring high availability:

1. Configure warm standby properties:
   ```bash
   # On primary system, edit /etc/caspida/local/conf/uba-site.properties
   replication.enabled=true
   replication.primary.host=<primary-hostname>
   replication.standby.host=<standby-hostname>
   ```

2. Setup replication on primary node:
   ```bash
   /opt/caspida/bin/replication/setup standby -m primary -r
   ```

3. Setup replication on standby node:
   ```bash
   /opt/caspida/bin/replication/setup standby -m standby -r
   ```

4. Initiate full synchronization:
   ```bash
   curl -X POST -k -H "Authorization: Bearer $(grep '^\s*jobmanager.restServer.auth.user.token=' /opt/caspida/conf/uba-default.properties | cut -d'=' -f2)" https://localhost:9002/jobs/trigger?name=ReplicationCoordinator
   ```

5. Verify synchronization status:
   ```bash
   psql -d caspidadb -c 'select * from replication'
   ```

## 10. Monitor Splunk UBA

### Health Monitoring
Regular health monitoring is critical for maintaining optimal performance:

1. **Run health check script:**
   ```bash
   /opt/caspida/bin/utils/uba_health_check.sh
   ```

2. **Access Health Monitor dashboard:**
   ```
   # Navigate to System > Health Monitor in UBA UI
   ```

3. **Monitor key metrics:**
   - System resource utilization (CPU, memory, disk)
   - Service status and uptime
   - Data ingestion rates (EPS)
   - Queue depths and processing delays
   - Certificate expiration dates

4. **Set up automated monitoring:**
   ```bash
   # Configure resource monitor
   sudo service caspida-resourcesmonitor start
   
   # Monitor logs
   tail -f /var/log/caspida/monitor/resourcesMonitor.out
   ```

### Performance Optimization
Optimize UBA performance based on workload:

1. **Adjust data ingestion parameters:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   splunk.live.micro.batching.interval.seconds=60
   splunk.live.micro.batching.delay.seconds=180
   connector.splunk.max.backtrace.time.in.hour=4
   ```

2. **Configure anomaly retention:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   persistence.anomalies.trashed.maintain.days=90
   entity.score.lookbackWindowMonths=2
   ```

3. **Optimize threat rule processing:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   rule.engine.process.timeout.min=60
   ```

4. **Monitor and adjust container resources:**
   ```bash
   # Check container resource usage
   docker stats
   
   # Adjust Docker network if needed
   system.docker.networkcidr=172.18.0.0/16
   ```

### Collect Diagnostic Data
For troubleshooting and support:

1. **Generate diagnostic bundle:**
   ```
   # Navigate to System > Download Diagnostics
   # Select components to include
   # Download generated bundle
   ```

2. **Manual log collection:**
   ```bash
   # Key log locations
   /var/vcap/sys/log/caspida-ui/
   /var/vcap/sys/log/caspida-jobmanager/
   /var/vcap/sys/log/caspida-datasource/
   /var/log/caspida/
   ```

## 11. Customize Splunk UBA

### Configure Internal IP Ranges
For proper classification of internal vs external traffic:

1. Edit the EntityValidations.json file:
   ```bash
   cd /etc/caspida/local/conf/etl/configuration
   vi EntityValidations.json
   ```

2. Add your internal IP ranges in CIDR notation:
   ```json
   "internalIPRange": ["199.79.0.0/16", "220.200.0.0/16"]
   ```

3. Optionally add office location mapping:
   ```json
   "internalGeoAttributions": [
     {"cidr": "10.0.0.0/8", "location": {"city": "San Jose", "countryCode": "US", "latitude": 37.3382, "longitude": -121.8863}},
     {"cidr": "172.16.0.0/16", "location": {"city": "New York", "countryCode": "US", "latitude": 40.788614, "longitude": -73.9696091}}
   ]
   ```

4. Validate the configuration:
   ```bash
   /opt/caspida/bin/status/check_entity_validations.sh -v
   ```

5. Synchronize changes across nodes:
   ```bash
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf/etl/configuration
   ```

### Geo-Location Settings
For accurate location-based analytics:

1. Navigate to Manage > Settings > Geo Location

2. Configure default office location with:
   - Latitude and longitude coordinates
   - Location name
   - Enable "Show Geo Maps" option

### Email Alerts Configuration
For system alerts and notifications:

1. First set up email output connector:
   ```
   # Navigate to Manage > Output Connectors > Add Output Connector > Email
   ```

2. Configure system alerts:
   - Navigate to Manage > Settings > Alerts
   - Add administrator email addresses (one per line)
   - Enable "Alert when processing stops" option
   - Set minimum EPS threshold
   - Set alert interval in seconds

### Customize Anomaly and Threat Parameters

1. Set entity score lookback window:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   entity.score.lookbackWindowMonths=2
   ```

2. Configure anomaly retention period:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   persistence.anomalies.trashed.maintain.days=90
   ```

3. Set anomaly purge batch size:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   persistance.anomalies.trashed.del.limit=300000
   ```

4. Configure threat rule engine timeout:
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   rule.engine.process.timeout.min=60
   ```

5. Synchronize and restart required services:
   ```bash
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   /opt/caspida/bin/Caspida stop-containers
   /opt/caspida/bin/Caspida start-containers
   ```

### Masking PII Information
For compliance with privacy regulations:

1. Navigate to Manage > Settings > PII

2. Configure masking for sensitive fields:
   - User information
   - Threat information
   - Device information

3. Set masking level:
   - Full masking: Complete obfuscation
   - Partial masking: Show limited identifiable information

### Disable UI Timeout (Optional)
For installations that need continuous monitoring:

1. Set timeout property (in milliseconds):
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   # To disable timeout:
   ui.idleTimeout=0
   # For 1-hour timeout:
   ui.idleTimeout=3600000
   ```

2. Restart UI service:
   ```bash
   sudo service caspida-ui restart
   ```

## 12. Data Source Configuration

### Required Data Sources
For effective threat detection, the following data sources should be configured in priority order:

#### 1. HR Data Source
This is critical for user contextual information and proper identity resolution.

1. Configure HR data source:
   ```
   # Navigate to Data Sources > Add Data Source > HR Data Source
   ```

2. Required fields mapping:
   - User ID (required)
   - Full Name
   - Email Address
   - Manager ID (for reporting hierarchy)
   - Title/Role
   - Department
   - Location
   - Start Date
   - Termination Date

3. Configure refresh schedule:
   - By default, HR data is refreshed daily at 2:00 AM

#### 2. Assets Data Source
For proper device-to-user mapping and network asset inventory.

1. Configure assets data source:
   ```
   # Navigate to Data Sources > Add Data Source > Assets Data Source
   ```

2. Required fields mapping:
   - Asset ID (hostname or MAC)
   - IP Address
   - Owner (User ID)
   - Asset Type
   - Location (optional)

3. Configure multi-value fields if needed:
   ```bash
   # Set delimiter in uba-site.properties
   attribution.keyvalue.delimiter=,
   ```

#### 3. Authentication Data Source
For detecting credential abuse and suspicious logins.

1. Configure authentication data source:
   ```
   # Navigate to Data Sources > Add Data Source > Authentication Data
   # Select appropriate source type (Active Directory, VPN, etc.)
   ```

2. Required fields mapping:
   - User ID
   - Success/Failure status
   - Timestamp
   - Source IP
   - Event Type (login, logout, etc.)

#### 4. Network/Proxy Data
For detecting unusual communication patterns or data exfiltration.

1. Configure proxy data source:
   ```
   # Navigate to Data Sources > Add Data Source > Proxy/Web Data
   ```

2. Field mapping:
   - User ID
   - Source IP
   - Destination IP/URL
   - Timestamp
   - Bytes Transferred

### Splunk Data Source Configuration
For ingesting data from Splunk Enterprise or Splunk Cloud:

1. Add Splunk data source:
   ```
   # Navigate to Data Sources > Add Data Source > Splunk Data
   ```

2. Enter connection details:
   - Splunk Host
   - Splunk Management Port
   - Username
   - Password
   - Connection Protocol (HTTP/HTTPS)

3. Select data ingestion method:
   - Micro-batching (default) - Recommended for most deployments
   - Configure in uba-site.properties:
     ```bash
     splunk.live.micro.batching=true
     splunk.live.micro.batching.delay.seconds=180
     splunk.live.micro.batching.interval.seconds=60
     connector.splunk.max.backtrace.time.in.hour=4
     ```

### SSL Certificate Validation for Data Sources
For secure data source connections:

1. Enable SSL certificate validation:
   ```bash
   # In uba-site.properties
   validate.splunk.ssl.certificate=true
   ```

2. Import SSL certificates for HTTPS data sources:
   ```bash
   # Copy Splunk certificate
   scp user@splunk-host:/opt/splunk/etc/auth/ca.pem.default /home/caspida/

   # Import certificate to Java keystore
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -import -trustcacerts -alias SplunkESRootCA -file ~/ca.pem.default
   ```

3. Restart services:
   ```bash
   /opt/caspida/bin/Caspida stop-all
   /opt/caspida/bin/Caspida start-all
   ```

### Validate Data Ingestion
1. Check data source status:
   ```
   # Navigate to Data Sources > [Data Source Name]
   ```

2. Verify EPS (Events Per Second) is non-zero

3. Check event processing in UBA:
   ```bash
   # Check processing logs
   tail -f /var/vcap/sys/log/caspida-datasource/caspida-datasource.stderr.log
   ```

4. Validate identity resolution:
   ```
   # Navigate to Manage > IDR Exclusions
   # Ensure user-device associations are properly established
   ```

## 13. Send Data from Splunk UBA

### Send UBA Data to Splunk Enterprise Security
For integration with Splunk ES:

1. **Configure ES integration:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   uba.splunkes.retry.delay.minutes=5
   uba.sys.audit.push.splunk.enabled=true
   identity.resolution.export.enabled=true
   ```

2. **Configure threat synchronization:**
   - UBA automatically sends threats to Splunk ES
   - Threats appear as notables in ES
   - Configure sync frequency as needed

3. **Send user and device associations:**
   - Enable identity resolution export
   - Data appears in Session Center dashboard in ES

### Send Threats via Email
Configure email notifications for threats:

1. **Set up email output connector:**
   ```
   # Navigate to Manage > Output Connectors > Add Output Connector > Email
   ```

2. **Configure SMTP settings:**
   - SMTP server hostname
   - Port (typically 25, 587, or 465)
   - Authentication credentials
   - SSL/TLS settings

3. **Create threat notification rules:**
   - Configure which threats trigger emails
   - Set recipient lists
   - Customize email templates

### Send Threats to ServiceNow
For ITSM integration:

1. **Configure ServiceNow connector:**
   ```
   # Navigate to Manage > Output Connectors > Add Output Connector > ServiceNow
   ```

2. **Provide ServiceNow details:**
   - ServiceNow instance URL
   - Username and password
   - Table name (typically incident)

3. **Configure threat mapping:**
   - Map UBA threat fields to ServiceNow fields
   - Set priority and category mappings

## 14. Security Hardening and Best Practices

### Secure Default Account
After installation, immediately secure the default admin account:

1. **Change default admin password:**
   ```
   # Navigate to Manage > UBA Accounts
   # Edit admin user
   # Set strong password
   ```

2. **Restrict sudo access (optional):**
   ```bash
   # Edit /etc/sudoers to limit caspida user permissions
   # Remove NOPASSWD:ALL if desired
   # Add specific command permissions only
   ```

### Third-Party Security Agents
Install security agents only AFTER UBA installation:

1. **Exclude UBA directories from scanning:**
   ```bash
   # Add these paths to security agent exclusions:
   /var/vcap/store/docker/overlay2/
   /opt/caspida/
   /var/vcap/
   ```

2. **Monitor resource impact:**
   ```bash
   # Check if security agents cause high CPU usage
   top
   htop
   ```

### Regular Security Updates
Apply OS security patches regularly on RHEL 8.10:

```bash
# Stop UBA services
/opt/caspida/bin/Caspida stop-all

# Check for security updates
sudo yum updateinfo list security all

# Apply security updates
sudo yum update --security -y
sudo yum --security update-minimal

# Reboot if required
sudo reboot

# Start UBA services
/opt/caspida/bin/Caspida start-all
```

### Certificate Security
Maintain certificate security:

1. **Monitor certificate expiration:**
   ```bash
   # Check certificate validity
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -text -noout | grep -E 'Not Before|Not After'
   ```

2. **Set up certificate renewal alerts:**
   - Monitor certificates that expire within 30 days
   - Configure automated renewal if possible
   - Plan certificate replacement procedures

3. **Secure certificate storage:**
   ```bash
   # Ensure proper permissions
   chmod 644 /var/vcap/store/caspida/certs/*/*
   chown root:root /var/vcap/store/caspida/certs/*/*
   ```

## 15. Troubleshooting

For comprehensive troubleshooting procedures covering installation issues, service problems, data source issues, SSL certificate problems, performance issues, and emergency recovery procedures, refer to the separate **Splunk_UBA_Troubleshooting_Guide.md** document.

### Quick Reference - Common Commands
```bash
# Check service status
/opt/caspida/bin/Caspida status

# Run health check
/opt/caspida/bin/utils/uba_health_check.sh

# Emergency service restart
/opt/caspida/bin/Caspida stop-all
/opt/caspida/bin/Caspida start-all

# Reset admin password
/opt/caspida/bin/admin_password_reset.sh
```

### Common Log Locations
- UI: `/var/vcap/sys/log/caspida-ui/caspida-ui.stderr.log`
- Job Manager: `/var/vcap/sys/log/caspida-jobmanager/caspida-jobmanager.stderr.log`
- Data Sources: `/var/vcap/sys/log/caspida-datasource/caspida-datasource.stderr.log`
- System: `/var/log/caspida/caspida.out`

## 16. Advanced Administration

### Managing UBA Configuration Properties
Configure UBA by editing `/etc/caspida/local/conf/uba-site.properties`:

1. **Environment Properties:**
   ```bash
   # Docker network CIDR (avoid network conflicts)
   system.docker.networkcidr=172.18.0.0/16
   
   # UI idle timeout (30 minutes default)
   ui.idleTimeout=1800000
   ```

2. **Splunk ES Integration:**
   ```bash
   # Threat sync frequency
   uba.splunkes.retry.delay.minutes=5
   
   # Enable audit events to Splunk ES
   uba.sys.audit.push.splunk.enabled=true
   
   # Send user/device associations to ES
   identity.resolution.export.enabled=true
   ```

3. **Event Drilldown Properties:**
   ```bash
   # Anomaly threshold for caching SPL
   triggering.event.pre.calculate.links.anomaly.threshold=8
   
   # Timeout for SPL retrieval
   triggering.event.timeout.millis=300000
   
   # Enable reverse identity resolution
   triggering.event.enable.reverse.ir=false
   ```

4. **Data Ingestion Properties:**
   ```bash
   # Micro-batching settings
   splunk.live.micro.batching=true
   splunk.live.micro.batching.delay.seconds=180
   splunk.live.micro.batching.interval.seconds=60
   
   # Backfill window
   connector.splunk.max.backtrace.time.in.hour=4
   
   # Input timezone for file-based sources
   parser.global.input_timezone=UTC
   ```

### Start and Stop Services
Common service management commands:

1. **Service Control:**
   ```bash
   # Stop/start all UBA services
   /opt/caspida/bin/Caspida stop
   /opt/caspida/bin/Caspida start
   
   # Stop/start all services including platform services
   /opt/caspida/bin/Caspida stop-all
   /opt/caspida/bin/Caspida start-all
   
   # Individual service management
   sudo service caspida-ui restart
   sudo service caspida-resourcesmonitor restart
   ```

2. **Container Management:**
   ```bash
   # Stop/start containers only
   /opt/caspida/bin/Caspida stop-containers
   /opt/caspida/bin/Caspida start-containers
   
   # Data source management
   /opt/caspida/bin/Caspida stop-datasources
   /opt/caspida/bin/Caspida start-datasources
   ```

3. **Configuration Synchronization:**
   ```bash
   # Sync configuration changes across cluster
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   ```

### Change Service Passwords
For changing passwords of UBA services:

1. **Generate new password:**
   ```bash
   /opt/caspida/bin/password_manager.sh generate
   ```

2. **Update specific service password:**
   ```bash
   /opt/caspida/bin/password_manager.sh update <service_name>
   ```

3. **Restart affected services:**
   ```bash
   /opt/caspida/bin/Caspida restart
   ```

### Change IP Address or Hostname
If you need to change the IP address or hostname:

1. **Update network configuration on OS level**

2. **Update UBA configuration:**
   ```bash
   # Edit uba-site.properties
   uiServer.host=<new-hostname-or-ip>
   ```

3. **Update deployment configuration:**
   ```bash
   # Edit deployment configuration
   vi /opt/caspida/conf/deployment/caspida-deployment.conf
   ```

4. **Synchronize and restart:**
   ```bash
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   /opt/caspida/bin/Caspida restart
   ```

## 17. Deployment Summary and Next Steps

### Deployment Validation
Use the comprehensive **Splunk_UBA_Deployment_Checklist.md** document to validate all deployment tasks. This checklist covers:

- Pre-installation validation (hardware, OS, network, storage)
- Installation process verification  
- Configuration validation
- Data source setup confirmation
- Security and authentication validation
- Performance and monitoring setup
- Final production readiness sign-off

### Post-Deployment Activities

1. **Monitor Initial Operation:**
   - Review system health for first 24-48 hours
   - Monitor data ingestion rates and processing
   - Verify anomaly and threat detection begins

2. **Optimization and Tuning:**
   - Adjust performance parameters based on actual workload
   - Fine-tune anomaly detection thresholds
   - Optimize data retention policies

3. **User Training:**
   - Train security analysts on UBA interface
   - Provide documentation for common tasks
   - Establish escalation procedures

4. **Ongoing Maintenance:**
   - Establish regular backup verification
   - Schedule periodic security updates
   - Plan for certificate renewals
   - Monitor system capacity and plan for scaling

### Key Resources

- **Splunk UBA Documentation:** Official Splunk UBA documentation on docs.splunk.com
- **Splunk Community:** answers.splunk.com for community support
- **Splunk Support:** support.splunk.com for enterprise support
- **Splunk Professional Services:** For advanced implementation assistance
- **Troubleshooting Guide:** Splunk_UBA_Troubleshooting_Guide.md for detailed issue resolution

### Emergency Procedures

Keep the following information readily available:

1. **Admin Password Reset Procedure:**
   ```bash
   /opt/caspida/bin/admin_password_reset.sh
   ```

2. **Emergency Service Restart:**
   ```bash
   /opt/caspida/bin/Caspida stop-all
   /opt/caspida/bin/Caspida start-all
   ```

3. **Health Check Command:**
   ```bash
   /opt/caspida/bin/utils/uba_health_check.sh
   ```

4. **Log Locations:**
   - UI: `/var/vcap/sys/log/caspida-ui/`
   - Job Manager: `/var/vcap/sys/log/caspida-jobmanager/`
   - Data Sources: `/var/vcap/sys/log/caspida-datasource/`
   - System: `/var/log/caspida/`

### Support Information

**Version:** Splunk UBA 5.4.2 on RHEL 8.10  
**Document Version:** 1.0  
**Last Updated:** June 2025

For technical support, gather the following information:
- UBA version and build number
- RHEL 8.10 version and kernel information
- Deployment topology (single/distributed)
- Description of issue with relevant log entries
- Output of health check script

---

**Deployment Complete!** Your Splunk UBA 5.4.2 environment is now ready for production use.

> **Note:** For comprehensive deployment validation, refer to the separate **Splunk_UBA_Deployment_Checklist.md** document.
> 
> **Troubleshooting:** For detailed troubleshooting procedures, refer to **Splunk_UBA_Troubleshooting_Guide.md**.
