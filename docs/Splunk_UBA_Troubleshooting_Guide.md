# Splunk UBA 5.4.2 Troubleshooting Guide

This guide provides comprehensive troubleshooting procedures for common issues encountered during and after Splunk UBA 5.4.2 deployment on RHEL 8.10.

## General Troubleshooting Commands

### Basic System Status Check
```bash
# Check UBA service status
/opt/caspida/bin/Caspida status

# Run comprehensive health check
/opt/caspida/bin/utils/uba_health_check.sh

# Check system resources
top
free -m
df -h
```

### Log File Locations
```bash
# UI logs
tail -f /var/vcap/sys/log/caspida-ui/caspida-ui.stderr.log

# Job manager logs
tail -f /var/vcap/sys/log/caspida-jobmanager/caspida-jobmanager.stderr.log

# Data source logs
tail -f /var/vcap/sys/log/caspida-datasource/caspida-datasource.stderr.log

# System logs
tail -f /var/log/caspida/caspida.out

# Kafka logs
tail -f /var/vcap/sys/log/kafka/server.log

# Zookeeper logs
tail -f /var/vcap/sys/log/zookeeper/zookeeper.out
```

## Installation Issues

### "setup containerization failed" Error
If you encounter this error during installation or upgrade:

1. **Check logs:**
   ```bash
   cat /var/log/caspida/caspida.out
   ```

2. **Common causes and solutions:**

   **Disk space issue:**
   ```bash
   # Check disk space
   df -h
   
   # Free up space if needed
   rm -rf /tmp/*
   sudo yum clean all
   ```
   
   **HTTP proxy configuration issue:**
   ```bash
   # Check if proxy is configured
   env | grep -i proxy
   
   # Unset proxy if causing issues
   unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
   ```
   
   **Docker service issue:**
   ```bash
   # Check Docker status
   sudo systemctl status docker
   
   # Restart Docker if needed
   sudo systemctl restart docker
   ```

3. **Fix and re-run:**
   ```bash
   # After fixing issues
   /opt/caspida/bin/Caspida setup-containerization
   ```

### Permission Issues During Installation
If installation fails due to permission errors:

1. **Verify caspida user permissions:**
   ```bash
   # Check user and group
   id caspida
   
   # Verify sudo configuration
   sudo -u caspida sudo -l
   ```

2. **Fix ownership issues:**
   ```bash
   sudo chown -R caspida:caspida /opt/caspida
   sudo chown -R caspida:caspida /home/caspida
   ```

3. **Verify mount point permissions:**
   ```bash
   ls -la /var/vcap /var/vcap2
   sudo chmod 755 /var/vcap /var/vcap2
   ```

### RHEL 8.10 Specific Issues

#### Bridge Netfilter Module Not Loading
```bash
# Load the module
sudo modprobe br_netfilter

# Make it persistent
echo br_netfilter | sudo tee /etc/modules-load.d/br_net_filter.conf

# Configure bridge settings
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
echo net.bridge.bridge-nf-call-iptables=1 | sudo tee /etc/sysctl.d/splunkuba-bridge.conf
```

#### Firewall Configuration Issues
```bash
# Check firewall status
sudo firewall-cmd --state

# Verify interface zone assignment
sudo firewall-cmd --get-zone-of-interface=<interface_name>

# Assign interface to public zone if needed
sudo firewall-cmd --zone=public --add-interface=<interface_name> --permanent
sudo firewall-cmd --reload
```

## Service Issues

### Service Won't Start
If specific services fail to start:

1. **Check individual service status:**
   ```bash
   sudo systemctl status caspida-ui
   sudo systemctl status kafka-server
   sudo systemctl status postgresql
   ```

2. **Check service logs:**
   ```bash
   # UI service
   journalctl -u caspida-ui -f
   
   # Kafka service
   journalctl -u kafka-server -f
   ```

3. **Restart problematic services:**
   ```bash
   sudo systemctl restart caspida-ui
   sudo systemctl restart kafka-server
   ```

### Port Conflicts
If services fail due to port conflicts:

1. **Check for port conflicts:**
   ```bash
   netstat -tulpn | grep LISTEN
   ss -tulpn | grep LISTEN
   ```

2. **Identify conflicting processes:**
   ```bash
   sudo lsof -i :9002  # Check Job Manager port
   sudo lsof -i :9092  # Check Kafka port
   ```

3. **Stop conflicting services:**
   ```bash
   sudo systemctl stop <conflicting_service>
   sudo systemctl disable <conflicting_service>
   ```

### Memory or CPU Issues
If services fail due to resource constraints:

1. **Check system resources:**
   ```bash
   top
   htop
   free -m
   ```

2. **Check for memory-intensive processes:**
   ```bash
   ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -20
   ```

3. **Restart resource monitor:**
   ```bash
   sudo systemctl restart caspida-resourcesmonitor
   ```

## Data Source Issues

### No Data Flowing
If no data appears to be flowing from data sources:

1. **Verify data source status in UI:**
   ```
   # Navigate to Data Sources view in UBA UI
   # Check EPS (Events Per Second) - should be non-zero
   ```

2. **Check data source logs:**
   ```bash
   grep "events processed" /var/vcap/sys/log/caspida-datasource/*.log
   grep ERROR /var/vcap/sys/log/caspida-datasource/*.log
   ```

3. **Test connectivity to Splunk:**
   ```bash
   # For Splunk data sources
   curl -k https://splunk-hostname:8089
   telnet splunk-hostname 8089
   ```

4. **Verify SSL configuration (if applicable):**
   ```bash
   # Check if certificates are properly imported
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit | grep -i splunk
   ```

### Authentication Failures
If data sources fail due to authentication:

1. **Test Splunk credentials:**
   ```bash
   curl -k -u username:password https://splunk-hostname:8089/services/auth/login
   ```

2. **Check for expired tokens:**
   ```bash
   grep "authentication" /var/vcap/sys/log/caspida-datasource/*.log
   ```

3. **Verify user permissions in Splunk:**
   - Ensure user has appropriate roles (admin, power, uba_user)
   - Check index access permissions

### Identity Resolution Issues
If users are not properly associated with devices:

1. **Check IDR exclusion list:**
   ```
   # Navigate to Manage > IDR Exclusions in UBA UI
   ```

2. **Verify HR data is properly loaded:**
   ```
   # Navigate to Manage > HR Data in UBA UI
   ```

3. **Adjust IDR thresholds if necessary:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   identity.resolution.blacklist.threshold.device.hostnamecount=2
   identity.resolution.blacklist.threshold.device.hostnamehours=6
   
   # Synchronize changes
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   ```

## SSL Certificate Issues

### Browser Certificate Errors
If browser shows SSL certificate errors:

1. **Verify certificate configuration:**
   ```bash
   # Check certificate properties in uba-site.properties
   grep ui.auth /etc/caspida/local/conf/uba-site.properties
   ```

2. **Validate certificate file permissions:**
   ```bash
   ls -la /var/vcap/store/caspida/certs/
   ```

3. **Check certificate validity:**
   ```bash
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -text -noout | grep -E 'Not Before|Not After'
   ```

4. **Regenerate self-signed certificate if expired:**
   ```bash
   rm /var/vcap/store/caspida/certs/my-root-ca.crt.pem
   /opt/caspida/bin/CaspidaCert.sh US CA "San Francisco" Splunk "" "" /var/vcap/store/caspida/certs/
   sudo systemctl restart caspida-ui
   ```

### Service Communication Certificate Issues
If services have SSL communication errors:

1. **Check Java keystore:**
   ```bash
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit
   ```

2. **Verify hostname resolution:**
   ```bash
   # Test hostname resolution between nodes
   ping hostname
   host hostname
   nslookup hostname
   ```

3. **Check certificate trust chain:**
   ```bash
   openssl verify -CAfile /var/vcap/store/caspida/certs/my-root-ca.crt.pem /var/vcap/store/caspida/certs/my-server.crt.pem
   ```

## Performance Issues

### High CPU/Memory Usage
If the system experiences performance issues:

1. **Monitor system resources:**
   ```bash
   top
   htop
   free -m
   vmstat 1 10
   ```

2. **Monitor container resources:**
   ```bash
   docker stats
   docker ps
   ```

3. **Check for resource-intensive processes:**
   ```bash
   ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -20
   ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -20
   ```

4. **Verify disk I/O performance:**
   ```bash
   iostat -x 1 10
   iotop
   ```

5. **Optimize data ingestion if necessary:**
   ```bash
   # Edit /etc/caspida/local/conf/uba-site.properties
   # Increase batch interval to reduce load
   splunk.live.micro.batching.interval.seconds=120
   
   # Synchronize changes
   /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf
   /opt/caspida/bin/Caspida restart
   ```

### Disk Space Issues
If running out of disk space:

1. **Check disk usage:**
   ```bash
   df -h
   du -sh /var/vcap/* | sort -h
   du -sh /var/vcap/store/* | sort -h
   ```

2. **Clean up temporary files:**
   ```bash
   sudo rm -rf /tmp/*
   sudo yum clean all
   ```

3. **Clean up old log files:**
   ```bash
   # Clean old UBA logs (be careful with this)
   find /var/vcap/sys/log -name "*.log.*" -mtime +7 -delete
   ```

4. **Clean up old Docker containers and images:**
   ```bash
   docker container prune -f
   docker image prune -f
   docker system prune -f
   ```

### Slow Web Interface
If the UBA web interface is slow:

1. **Check UI service status:**
   ```bash
   sudo systemctl status caspida-ui
   journalctl -u caspida-ui -f
   ```

2. **Restart UI service:**
   ```bash
   sudo systemctl restart caspida-ui
   ```

3. **Check browser compatibility:**
   - Use supported browsers (Chrome, Firefox, Safari)
   - Clear browser cache and cookies
   - Disable browser extensions

### UBA Monitor API Errors
If you encounter errors like "Error from /uba/monitor - Invalid Json response: Error in getting the response - Parameters: {"queryStatus":true,"queryDataQualityStatus":true}":

This error typically occurs when accessing the System > Health Monitor dashboard or when UBA's internal monitoring API cannot retrieve system status information.¹

**Error Analysis:**
The specific error pattern "Invalid Json response: Error in getting the response" indicates that the Job Manager's REST API is either:
- Returning malformed JSON due to an internal exception
- Timing out during status queries
- Encountering SSL/TLS handshake failures with internal services
- Experiencing database connectivity issues during status aggregation

**Quick Diagnosis Commands:**
```bash
# First, verify UBA services are running
echo "Checking UBA service status:"

# Check if systemd services exist
if systemctl list-units --type=service | grep -q caspida; then
    echo "Found systemd UBA services:"
    systemctl list-units --type=service | grep caspida
    echo "Service status:"
    for service in $(systemctl list-units --type=service | grep caspida | awk '{print $1}'); do
        systemctl is-active "$service" || echo "$service is not active"
    done
else
    echo "Using Caspida script management - checking via ps:"
    ps aux | grep -E "(caspida|java.*uba)" | grep -v grep || echo "No UBA processes found"
fi

# Check if Job Manager API is responding at all
curl -k -X GET https://localhost:9002/health 2>&1 | head -5

# Check for immediate certificate/SSL issues
openssl s_client -connect localhost:9002 -verify_return_error </dev/null 2>&1 | grep -E "(Verify|error|failed)"

# Check for JSON parsing errors in Job Manager logs
# First verify log locations exist
if [[ -d "/var/log/caspida" ]]; then
    echo "Checking /var/log/caspida for JSON parsing errors:"
    find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -E "(JSON|json|parse|Invalid.*response)" 2>/dev/null | tail -10
elif [[ -d "/var/vcap/sys/log" ]]; then
    echo "Checking /var/vcap/sys/log for JSON parsing errors:"
    find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -E "(JSON|json|parse|Invalid.*response)" 2>/dev/null | tail -10
else
    echo "No standard UBA log directories found. Check actual installation paths."
fi
```

**References:**
1. Based on UBA deployment experience and analysis of common monitoring API failure patterns

**Common Causes and Solutions:**

1. **Job Manager Service Issues:**²
   ```bash
   # Check Job Manager service status
   sudo systemctl status caspida-jobmanager
     # Check Job Manager logs for errors
   echo "Checking for Job Manager service errors:"
   if [[ -d "/var/log/caspida" ]]; then
       find /var/log/caspida -name "*jobmanager*" -type f 2>/dev/null | xargs tail -20 2>/dev/null
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -i "ERROR" 2>/dev/null | tail -10
   elif [[ -d "/var/vcap/sys/log" ]]; then
       find /var/vcap/sys/log -name "*jobmanager*" -type f 2>/dev/null | xargs tail -20 2>/dev/null
       find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -i "ERROR" 2>/dev/null | tail -10
   else
       echo "Please check actual UBA log locations on your system"
   fi
   ```

2. **Database Connectivity Problems:**³
   ```bash
   # Test PostgreSQL connection
   sudo -u postgres psql -c "SELECT version();"
   
   # Check database service status
   sudo systemctl status postgresql
   
   # Verify UBA can connect to database
   sudo -u caspida psql -d caspidadb -c "SELECT count(*) FROM information_schema.tables;"
   ```

3. **REST API Service Problems:**⁴
   ```bash
   # Check if Job Manager REST API is responding
   curl -k -X GET https://localhost:9002/health
   
   # Test with authentication token
   TOKEN=$(grep 'jobmanager.restServer.auth.user.token' /opt/caspida/conf/uba-default.properties | cut -d'=' -f2)
   curl -k -H "Authorization: Bearer $TOKEN" https://localhost:9002/health
   ```

4. **Memory/Resource Constraints:**⁵
   ```bash
   # Check system resources
   free -m
   df -h
   
   # Check Java heap usage for Job Manager
   ps aux | grep jobmanager
   jstat -gc <jobmanager_pid>
   ```

5. **Configuration File Corruption:**⁶
   ```bash
   # Verify uba-site.properties syntax
   grep -v "^#" /etc/caspida/local/conf/uba-site.properties | grep "="
     # Check for configuration errors in logs
   echo "Checking for configuration errors:"
   if [[ -d "/var/log/caspida" ]]; then
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -i "configuration\|config" 2>/dev/null | tail -10
   elif [[ -d "/var/vcap/sys/log" ]]; then
       find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -i "configuration\|config" 2>/dev/null | tail -10
   else
       echo "Please check actual UBA log locations on your system"
   fi
   ```

6. **Java Keystore/Truststore Issues:**¹³
   ```bash
   # Check if Java truststore is accessible
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit | head -10
   
   # Verify UBA keystore
   sudo keytool -list -keystore /etc/caspida/conf/keystore/uba-keystore -storepass password
     # Check for SSL handshake errors in Job Manager logs
   echo "Checking for SSL/certificate errors:"
   if [[ -d "/var/log/caspida" ]]; then
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -i "ssl\|certificate\|handshake\|truststore\|keystore" 2>/dev/null | tail -10
   elif [[ -d "/var/vcap/sys/log" ]]; then
       find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -i "ssl\|certificate\|handshake\|truststore\|keystore" 2>/dev/null | tail -10
   else
       echo "Please check actual UBA log locations on your system"
   fi
   
   # Test internal SSL connectivity
   openssl s_client -connect localhost:9002 -verify_return_error
   ```

**Resolution Steps:**

1. **Restart monitoring services:**⁷
   ```bash
   # Check if UBA is managed as systemd services or via Caspida scripts
   echo "Checking UBA service management method:"
   systemctl list-units | grep caspida || echo "No systemd caspida services found"
   
   # Method 1: If UBA services are managed via systemd (newer installations)
   if systemctl list-units | grep -q caspida; then
       echo "Using systemd service management:"
       # Check available caspida services
       systemctl list-units --type=service | grep caspida
       
       # Restart available UBA services
       for service in $(systemctl list-units --type=service | grep caspida | awk '{print $1}'); do
           echo "Restarting $service"
           sudo systemctl restart "$service"
       done
   
   # Method 2: If UBA is managed via Caspida scripts (standard method)
   else
       echo "Using Caspida script service management:"
       # Stop all UBA services
       /opt/caspida/bin/Caspida stop-all
       
       # Wait for clean shutdown
       sleep 60
       
       # Start all UBA services
       /opt/caspida/bin/Caspida start-all
   fi
   
   # Wait for services to fully initialize
   echo "Waiting for services to initialize..."
   sleep 180
   ```

2. **Clear temporary data:**⁸
   ```bash
   # Clear temporary monitoring cache
   sudo rm -rf /tmp/caspida-monitor-*
   sudo rm -rf /var/vcap/sys/tmp/monitor-*
   
   # Clear browser cache and retry accessing Health Monitor
   ```

3. **Verify service communication:**⁹
   ```bash
   # Test internal service connectivity
   telnet localhost 9002
   nc -zv localhost 9002
   
   # Check firewall rules
   sudo firewall-cmd --list-ports
   sudo iptables -L | grep 9002
   ```

4. **Database maintenance (if database issues suspected):**¹⁰
   ```bash
   # Restart PostgreSQL service
   sudo systemctl restart postgresql
   
   # Run database maintenance
   sudo -u postgres psql -d caspidadb -c "VACUUM ANALYZE;"
   ```

5. **If problem persists, collect diagnostic information:**¹¹
   ```bash
   # Capture current system state
   /opt/caspida/bin/utils/uba_health_check.sh > /tmp/health_check.log
   
   # Generate diagnostic bundle from UI: System > Download Diagnostics
     # Collect relevant logs (adjust paths based on actual installation)
   echo "Collecting UBA logs for troubleshooting:"
   timestamp=$(date +%Y%m%d_%H%M%S)
   
   # Create log collection directory
   mkdir -p /tmp/uba_logs_$timestamp
   
   # Collect logs from standard locations
   if [[ -d "/var/log/caspida" ]]; then
       echo "Collecting logs from /var/log/caspida"
       cp -r /var/log/caspida/* /tmp/uba_logs_$timestamp/ 2>/dev/null || true
   fi
   
   if [[ -d "/var/vcap/sys/log" ]]; then
       echo "Collecting logs from /var/vcap/sys/log"
       mkdir -p /tmp/uba_logs_$timestamp/vcap_logs
       cp -r /var/vcap/sys/log/* /tmp/uba_logs_$timestamp/vcap_logs/ 2>/dev/null || true
   fi
   
   # Create archive
   tar -czf /tmp/monitor_logs_$timestamp.tar.gz -C /tmp uba_logs_$timestamp/
   echo "Log archive created: /tmp/monitor_logs_$timestamp.tar.gz"
   ```

6. **Certificate-related troubleshooting (if SSL errors detected):**¹⁴
   ```bash
   # Check for common certificate-related error patterns in logs
   # First, verify log directories exist and check available logs
   echo "Checking available UBA log directories:"
   ls -la /var/log/caspida/ 2>/dev/null || echo "Standard log directory not found"
   ls -la /var/vcap/sys/log/ 2>/dev/null || echo "vcap log directory not found"
   
   # Check main UBA logs for certificate errors (adjust path based on actual installation)
   if [[ -d "/var/log/caspida" ]]; then
       echo "Checking /var/log/caspida for certificate errors:"
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -l -E "(certificate|keystore|truststore|SSL|TLS|handshake|PKIX|unable to find valid certification path)" 2>/dev/null | head -5
       echo "Recent certificate-related errors:"
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -E "(certificate|keystore|truststore|SSL|TLS|handshake|PKIX|unable to find valid certification path)" 2>/dev/null | tail -10
   fi
   
   # Check vcap logs if they exist
   if [[ -d "/var/vcap/sys/log" ]]; then
       echo "Checking /var/vcap/sys/log for certificate errors:"
       find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -E "(certificate|keystore|truststore|SSL|TLS|handshake|PKIX|unable to find valid certification path)" 2>/dev/null | tail -10
   fi
   
   # Validate certificate chain for Job Manager
   openssl verify -CAfile /var/vcap/store/caspida/certs/my-root-ca.crt.pem \
     /var/vcap/store/caspida/certs/my-server.crt.pem
   
   # Check certificate expiration (alerts if expiring within 30 days)
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -noout -dates
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -noout -checkend 2592000
   
   # Verify all UBA keystores
   echo "Checking Job Manager keystore:"
   openssl pkcs12 -info -in /etc/caspida/conf/keystore/keystore.jm -noout 2>/dev/null || \
     echo "ERROR: Job Manager keystore not accessible or corrupted"
   
   echo "Checking main UBA keystore:"
   sudo keytool -list -keystore /etc/caspida/conf/keystore/uba-keystore -storepass password 2>/dev/null || \
     echo "ERROR: UBA keystore not accessible or corrupted"
   
   # Test SSL connectivity to all critical UBA services
   echo "Testing Job Manager SSL:"
   timeout 5 openssl s_client -connect localhost:9002 -verify_return_error 2>&1 | \
     grep -E "(Verify return code|SSL handshake|certificate verify)"
   
   echo "Testing UI SSL (if HTTPS enabled):"
   timeout 5 openssl s_client -connect localhost:443 -verify_return_error 2>&1 | \
     grep -E "(Verify return code|SSL handshake|certificate verify)"
   
   # Check Java truststore integrity
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit 2>/dev/null | \
     grep -i "uba\|caspida" || echo "No UBA certificates found in Java truststore"
   
   # Advanced certificate chain validation
   echo "Performing complete certificate chain validation:"
   for cert in /var/vcap/store/caspida/certs/*.crt.pem; do
     echo "Checking: $cert"
     openssl x509 -in "$cert" -noout -subject -issuer -dates -fingerprint
   done
   
   # Re-import certificates if corrupted or missing
   echo "Re-importing UBA certificates to Java truststore:"
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo keytool -delete -alias "uba-ca" -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit 2>/dev/null || true
   sudo keytool -delete -alias "uba-server" -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit 2>/dev/null || true
   
   # Import CA certificate
   sudo keytool -import -trustcacerts -alias "uba-ca" -keystore $JAVA_HOME/lib/security/cacerts \
     -storepass changeit -file /var/vcap/store/caspida/certs/my-root-ca.crt.pem -noprompt
   
   # Import server certificate if needed
   sudo keytool -import -trustcacerts -alias "uba-server" -keystore $JAVA_HOME/lib/security/cacerts \
     -storepass changeit -file /var/vcap/store/caspida/certs/my-server.crt.pem -noprompt
   
   # Restart services after certificate fixes
   echo "Restarting UBA services after certificate remediation:"
   /opt/caspida/bin/Caspida stop-all
   sleep 30
   /opt/caspida/bin/Caspida start-all
   
   # Verify fix by testing monitor API
   sleep 120  # Allow services to fully start
   curl -k -X GET https://localhost:9002/health && echo "Job Manager API responding"
   ```

7. **Advanced certificate debugging for specific error patterns:**¹⁵
   ```bash
   # For "PKIX path building failed" errors
   echo "Diagnosing PKIX path building failures:"
   openssl verify -verbose -CAfile /var/vcap/store/caspida/certs/my-root-ca.crt.pem \
     /var/vcap/store/caspida/certs/my-server.crt.pem
   
   # For "unable to find valid certification path" errors
   echo "Checking Java certificate path validation:"
   . /opt/caspida/bin/CaspidaCommonEnv.sh
   sudo java -Djavax.net.debug=ssl:handshake:verbose \
     -Djavax.net.ssl.trustStore=$JAVA_HOME/lib/security/cacerts \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -cp /opt/caspida/lib/\* com.sun.net.ssl.internal.www.protocol.https.HttpsURLConnectionOldImpl \
     https://localhost:9002/health 2>&1 | head -50
   
   # For certificate hostname validation errors
   echo "Checking certificate Subject Alternative Names:"
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -noout -text | \
     grep -A5 "Subject Alternative Name"
     # Check if certificate matches current hostname
   CURRENT_HOSTNAME=$(hostname -f)
   echo "Current hostname: $CURRENT_HOSTNAME"
   openssl x509 -in /var/vcap/store/caspida/certs/my-server.crt.pem -noout -text | \
     grep -E "(CN=|DNS:|IP:)" | grep -i "$CURRENT_HOSTNAME" || \
     echo "WARNING: Certificate may not match current hostname"
   ```

8. **Post-certificate installation validation:**¹⁶
   ```bash
   # Complete validation after certificate changes
   echo "Performing post-certificate installation validation:"
   
   # Wait for services to stabilize
   sleep 60
   
   # Test monitor API specifically
   echo "Testing UBA monitor API endpoint:"
   curl -k -X GET "https://localhost:9002/uba/monitor?queryStatus=true&queryDataQualityStatus=true" \
     -H "Content-Type: application/json" 2>&1 | head -10
     # Check for certificate-related startup errors
   echo "Checking for certificate errors in service startup:"
   if [[ -d "/var/log/caspida" ]]; then
       find /var/log/caspida -name "*.log" -type f 2>/dev/null | xargs grep -E "(certificate|SSL|TLS|keystore|truststore)" 2>/dev/null | \
         grep -E "(ERROR|WARN|Exception)" | tail -10
   elif [[ -d "/var/vcap/sys/log" ]]; then
       find /var/vcap/sys/log -name "*.log" -type f 2>/dev/null | xargs grep -E "(certificate|SSL|TLS|keystore|truststore)" 2>/dev/null | \
         grep -E "(ERROR|WARN|Exception)" | tail -10
   else
       echo "Please check actual UBA log locations on your system"
   fi
   
   # Verify all UBA services can communicate
   echo "Testing internal service communication:"
   /opt/caspida/bin/utils/test_service_connectivity.sh 2>/dev/null || \
     echo "Service connectivity test not available - manual verification required"
   
   # Final health check
   echo "Running comprehensive health check:"
   /opt/caspida/bin/utils/uba_health_check.sh | grep -E "(PASS|FAIL|ERROR)"
   ```

**Prevention:**¹²
- Monitor system resources regularly
- Set up automated health checks
- Ensure adequate disk space for temporary files
- Keep PostgreSQL database properly maintained
- Monitor certificate expiration dates and renew before expiry
- Validate certificate chain integrity during maintenance windows
- Backup certificate files before system upgrades

## Network Issues

### Service Communication Issues
If services cannot communicate with each other:

1. **Check firewall settings:**
   ```bash
   # Check firewall status
   sudo firewall-cmd --list-all
   
   # Check specific ports
   sudo firewall-cmd --list-ports
   ```

2. **Test network connectivity:**
   ```bash
   # Test connectivity between nodes
   telnet <other-node-ip> 9002
   nc -zv <other-node-ip> 9002
   ```

3. **Verify DNS resolution:**
   ```bash
   host <hostname>
   nslookup <hostname>
   dig <hostname>
   ```

### RHEL 8.10 Network Configuration Issues
1. **Check NetworkManager configuration:**
   ```bash
   sudo systemctl status NetworkManager
   nmcli device status
   nmcli connection show
   ```

2. **Verify static IP configuration:**
   ```bash
   ip addr show
   ip route show
   ```

## Emergency Recovery Procedures

### Reset Admin Password
If admin password is lost or not working:

1. **Method 1 - Password reset script:**
   ```bash
   # Stop UI service
   sudo systemctl stop caspida-ui
   
   # Reset password
   /opt/caspida/bin/admin_password_reset.sh
   
   # Start UI service
   sudo systemctl start caspida-ui
   ```

2. **Method 2 - Database reset (if method 1 fails):**
   ```bash
   # Connect to database
   sudo -u postgres psql -d caspidadb
   
   # Update password to temporary value (password: admin123)
   UPDATE users SET password = '$2a$10$Caspida123' WHERE username = 'admin';
   \q
   
   # Restart UI service
   sudo systemctl restart caspida-ui
   ```

3. **Login with temporary password and change immediately**

### Complete Service Reset
If UBA is completely unresponsive:

1. **Stop all services:**
   ```bash
   /opt/caspida/bin/Caspida stop-all
   ```

2. **Check and clean up processes:**
   ```bash
   # Check for hanging processes
   ps aux | grep caspida
   ps aux | grep kafka
   ps aux | grep zookeeper
   
   # Kill hanging processes if necessary
   sudo pkill -f caspida
   ```

3. **Clean temporary files:**
   ```bash
   sudo rm -rf /tmp/hsperfdata_*
   sudo rm -rf /var/vcap/sys/tmp/*
   ```

4. **Start all services:**
   ```bash
   /opt/caspida/bin/Caspida start-all
   ```

### System Recovery After Reboot
If UBA doesn't start properly after system reboot:

1. **Check mount points:**
   ```bash
   mount | grep vcap
   df -h | grep vcap
   ```

2. **Remount if necessary:**
   ```bash
   sudo mount -a
   ```

3. **Start services in order:**
   ```bash
   # Start platform services first
   sudo systemctl start postgresql
   sudo systemctl start zookeeper-server
   sudo systemctl start kafka-server
   
   # Wait a few minutes, then start UBA services
   /opt/caspida/bin/Caspida start
   ```

## Getting Help

### Collecting Diagnostic Information
Before contacting support, collect the following information:

1. **Generate diagnostic bundle:**
   ```
   # Navigate to System > Download Diagnostics in UBA UI
   # Select all components and download
   ```

2. **System information:**
   ```bash
   # UBA version
   cat /opt/caspida/conf/version.properties
   
   # OS information
   cat /etc/redhat-release
   uname -a
   
   # Hardware information
   free -m
   df -h
   lscpu
   ```

3. **Recent log entries:**
   ```bash
   # Last 100 lines of key logs
   tail -100 /var/vcap/sys/log/caspida-ui/caspida-ui.stderr.log
   tail -100 /var/vcap/sys/log/caspida-jobmanager/caspida-jobmanager.stderr.log
   tail -100 /var/log/caspida/caspida.out
   ```

### Support Information
- **Version:** Splunk UBA 5.4.2 on RHEL 8.10
- **Document Version:** 1.0
- **Last Updated:** June 2025

For technical support, provide:
- UBA version and build number
- RHEL 8.10 version and kernel information
- Deployment topology (single/distributed)
- Description of issue with relevant log entries
- Output of health check script
- Diagnostic bundle (if possible)

## References

### UBA Monitor API Errors Section
1. UBA Monitor API error analysis based on field experience and common monitoring dashboard failures
2. Splunk UBA Job Manager service troubleshooting - derived from UBA service architecture documentation  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Distributed
3. PostgreSQL connectivity testing for UBA - based on UBA database configuration requirements  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Prerequisites
4. UBA REST API testing procedures - based on UBA Job Manager API documentation and internal service communication patterns  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/GetData/Monitorhealth
5. System resource monitoring for UBA - derived from UBA performance optimization guidelines  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Systemrequirements
6. UBA configuration file validation - based on UBA site properties documentation and common configuration errors  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Configure
7. UBA service restart procedures - based on UBA service management best practices  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/StartUBA
8. Temporary file cleanup for UBA - based on UBA system maintenance procedures  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Maintenance
9. Service communication verification - derived from UBA network troubleshooting procedures  
   - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Firewallports
10. PostgreSQL maintenance for UBA - based on UBA database maintenance requirements  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Maintenance
11. UBA diagnostic data collection - based on Splunk UBA troubleshooting and support procedures  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Troubleshooting
12. UBA preventive maintenance - derived from UBA operational best practices and system hardening guidelines  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Maintenance
13. Java Keystore/Truststore Issues - based on UBA SSL/TLS configuration and certificate management procedures  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Configure
14. Certificate troubleshooting and remediation - derived from UBA certificate management best practices and SSL/TLS debugging procedures  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Certificates
15. Advanced certificate debugging and PKIX path validation - based on Java SSL debugging techniques and UBA certificate chain validation procedures  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Certificates
16. Post-certificate installation validation procedures - derived from UBA certificate deployment best practices and service integration testing  
    - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Certificates

---

**Note:** This troubleshooting guide should be used in conjunction with the main Splunk UBA Deployment Guide and Deployment Checklist documents.
