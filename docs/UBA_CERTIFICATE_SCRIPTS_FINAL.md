# UBA Certificate Management Scripts - Final Clean Version

# UBA Certificate Management Scripts - Final Clean Version

## Current Status: ✅ PRODUCTION READY

**All major issues have been resolved:**

✅ **FIPS Compliance Issues** - Fixed OpenSSL FIPS-disabled algorithms  
✅ **Command Line Formatting** - Corrected OpenSSL and keytool command syntax  
✅ **Missing Parameters** - Added all required keytool flags  
✅ **End-to-End Testing** - Validated with dry-run mode successfully  

The scripts are now ready for production use in FIPS-enabled environments.

## 🎯 **Core Production Scripts**

### Primary Certificate Management Tools

| Script | Purpose | Key Features |
|--------|---------|--------------|
| **`generate_test_certs.sh`** | Generate test certificates | • Root CA and server certificates<br>• PKCS#12 keystores<br>• Configurable validity and hostnames |
| **`install_uba_certs.sh`** | Install and manage certificates | • **Remote Splunk certificate pulling**<br>• UI, Job Manager, and truststore management<br>• Dry-run mode and comprehensive backup |
| **`validate_uba_certs.sh`** | Validate certificate installation | • Health checking and expiration monitoring<br>• Service status validation<br>• Comprehensive reporting |

### Supporting Scripts

| Script | Purpose |
|--------|---------|
| **`demo_certificate_workflow.sh`** | Complete workflow demonstration |
| **`cert_tools_summary.sh`** | Usage instructions and examples |
| **`example_cert_install.sh`** | Interactive installation guide |

## 🚀 **Quick Start Guide**

### 1. Generate Test Certificates
```bash
./generate_test_certs.sh --hostname $(hostname -f) --days 365
```

### 2. Install Certificates (with Splunk Integration)
```bash
# Pull certificates from Splunk instances
./install_uba_certs.sh -s /tmp/certs \
    --pull-from 192.168.1.239:8000 \
    --pull-from splunk-sh1.company.com:8089 \
    --test-connectivity --dry-run

# Install from local certificates  
./install_uba_certs.sh -s /tmp/uba_test_certs --dry-run
```

### 3. Validate Installation
```bash
export JAVA_HOME=/etc/alternatives/jre_openjdk
./validate_uba_certs.sh
```

## 🔧 **Key Features**

✅ **Java Environment Detection** - Compatible with CaspidaCommonEnv.sh logic  
✅ **Remote Certificate Pulling** - Pull from Splunk web (8000) and management (8089) ports  
✅ **Comprehensive Safety** - Backups, dry-run mode, validation  
✅ **UBA Integration** - Updates uba-site.properties, Job Manager keystore, Java truststore  
✅ **RHEL/CentOS Compatible** - Tested on Red Hat Enterprise Linux 8.10  

## 📁 **File Locations**

- **Scripts**: `/root/*.sh`
- **UBA Certificates**: `/var/vcap/store/caspida/certs/my_certs/`
- **Backups**: `/opt/caspida/cert_backups/`
- **Logs**: `/var/log/caspida/uba_cert_install_*.log`

## 🎉 **Ready for Production**

All test scripts and temporary files have been cleaned up. The remaining scripts are production-ready and fully documented for UBA certificate management with Splunk integration.

---
*Last updated: June 12, 2025*
