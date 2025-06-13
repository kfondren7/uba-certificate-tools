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

---

**Note:** This troubleshooting guide should be used in conjunction with the main Splunk UBA Deployment Guide and Deployment Checklist documents.
