# UBA Kafka and JobManager Keystore/Truststore Analysis

**Analysis Date:** June 17, 2025  
**System:** Splunk UBA (User Behavior Analytics)  
**Working Directory:** /opt/caspida

## Executive Summary

The UBA system employs multiple keystores and truststores for different components, with a centralized UBA keystore that consolidates certificates from various sources. The system uses both SSL/TLS for secure communication and SASL for authentication.

## Keystore/Truststore Inventory

### 1. Primary Keystores

#### JobManager Keystore
- **Location:** `/opt/caspida/conf/jobconf/keystore.jm`
- **Type:** JKS (Java KeyStore)
- **Password:** `password`
- **Usage:** JobManager HTTPS server (port 9002)
- **Contents:** 
  - `jmserver` (PrivateKeyEntry) - Server certificate for JobManager
- **Configuration:** Referenced in `/opt/caspida/conf/jobconf/jobmgr.yml`

#### Kafka Server Keystore
- **Location:** `/opt/caspida/conf/kafka/auth/server.keystore.jks`
- **Type:** JKS
- **Password:** `caspida123`
- **Key Password:** `caspida123`
- **Usage:** Kafka broker SSL/TLS communication
- **Contents:**
  - `caroot` (trustedCertEntry) - Root CA certificate
  - `localhost` (PrivateKeyEntry) - Server certificate for Kafka broker
- **Configuration:** Referenced in `/opt/caspida/conf/kafka/kafka.properties`

#### UBA Unified Keystore
- **Location:** `/opt/caspida/conf/keystore/uba-keystore`
- **Type:** JKS
- **Password:** `password`
- **Usage:** Centralized certificate store for various UBA components
- **Contents:**
  - `jmserver` (PrivateKeyEntry) - Copied from JobManager keystore
  - `kubernetes api server certificate` (trustedCertEntry) - K8s API server cert
  - `uba management server certificate` (trustedCertEntry) - UBA server cert
  - `uba-server` (PrivateKeyEntry) - UBA server private key

### 2. System Truststores

#### Java System Truststore
- **Location:** `/usr/lib/jvm/java-1.8.0-openjdk/jre/lib/security/cacerts`
- **Password:** `changeit` (default)
- **Usage:** System-wide trusted certificates for Java applications
- **Special Certificates:**
  - `SplunkESRootCA` - Splunk Enterprise Security root CA (when SSL validation enabled)

## SSL/TLS Configuration Details

### Kafka SSL Configuration

#### Server Configuration (`/opt/caspida/conf/kafka/kafka.properties`)
```properties
ssl.keystore.location=/opt/caspida/conf/kafka/auth/server.keystore.jks
ssl.keystore.password=caspida123
ssl.key.password=caspida123
ssl.enabled.protocols=TLSv1.2
ssl.cipher.suites=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384...
```

#### Client Configuration
- **SSL Broker List:** `uba.mynetworksettings.com:9093`
- **Regular Broker List:** `uba.mynetworksettings.com:9092`
- **Property:** `system.messaging.kafka.ssl.brokerlist` in uba-env.properties

### JobManager SSL Configuration

#### Server Configuration (`/opt/caspida/conf/jobconf/jobmgr.yml`)
```yaml
server:
  type: simple
  connector:
    type: https
    port: 9002
    keyStorePath: /etc/caspida/conf/jobconf/keystore.jm
    keyStorePassword: password
    keyStoreType: JKS
    validateCerts: false
    validatePeers: false
```

## Component Relationships

### 1. Kafka Ecosystem
```
Kafka Broker (Port 9092/9093)
├── Uses: /opt/caspida/conf/kafka/auth/server.keystore.jks
├── SSL Port: 9093
├── SASL Mechanism: PLAIN
└── JAAS Config: /opt/caspida/conf/kafka/kafka_server_jaas.conf (referenced but not found)

Kafka Clients (Various UBA components)
├── Connect to: uba.mynetworksettings.com:9092 (non-SSL)
├── Connect to: uba.mynetworksettings.com:9093 (SSL)
├── No explicit truststore configuration found
└── Likely uses Java system truststore by default
```

### 2. JobManager Ecosystem
```
JobManager Server (Port 9002)
├── Uses: /opt/caspida/conf/jobconf/keystore.jm
├── HTTPS only
├── Self-signed or internal CA certificates
└── validateCerts: false (bypasses cert validation)

JobManager Clients
├── Various UBA components connecting to JobManager REST API
├── URL: https://<jobmanager-host>:9002
└── Certificate validation disabled in configuration
```

### 3. UBA Unified Keystore System
```
UBA Keystore Setup Process
├── Copies JobManager keystore as base
├── Imports Kubernetes API server certificate
├── Imports UBA server certificate
└── Distributes to cluster nodes via rsync
```

## Security Mechanisms

### 1. Authentication Methods
- **Kafka:** SASL PLAIN mechanism for inter-broker communication
- **JobManager:** HTTPS with certificate-based authentication (validation disabled)
- **JMX:** Separate authentication via `/opt/caspida/conf/kafka/auth/jmxremote.properties`

### 2. Certificate Validation
- **Kafka SSL:** Enabled for encryption, certificate validation not explicitly configured
- **JobManager:** Certificate validation explicitly disabled (`validateCerts: false`)
- **Splunk Connectivity:** Configurable via `validate.splunk.ssl.certificate` property

### 3. Protocol Security
- **Kafka:** TLSv1.2 only
- **JobManager:** TLS configuration not explicitly specified
- **Cipher Suites:** Modern, secure cipher suites configured for Kafka

## File Locations Summary

### Active Configuration Files
```
/opt/caspida/conf/jobconf/keystore.jm              # JobManager keystore
/opt/caspida/conf/kafka/auth/server.keystore.jks   # Kafka server keystore  
/opt/caspida/conf/keystore/uba-keystore             # UBA unified keystore
/opt/caspida/conf/jobconf/jobmgr.yml                # JobManager SSL config
/opt/caspida/conf/kafka/kafka.properties            # Kafka SSL config
/opt/caspida/conf/uba-env.properties                # Kafka broker lists
```

### JMX Security
```
/opt/caspida/conf/kafka/auth/jmxremote.properties   # JMX SSL/auth config
/opt/caspida/conf/kafka/auth/jmxremote.password     # JMX passwords
/opt/caspida/conf/kafka/auth/jmxremote.access       # JMX access controls
```

### Certificate Files
```
/opt/caspida/conf/kafka/auth/ca-cert                # Kafka CA certificate
/var/vcap/store/caspida/certs/my-server.crt.pem     # UBA server cert (referenced but not found)
/etc/kubernetes/pki/apiserver.crt                   # K8s API cert (referenced but not found)
```

## Security Recommendations

### 1. Certificate Management
- **Current State:** Mixed certificate sources with some validation disabled
- **Recommendation:** Implement proper CA hierarchy and enable certificate validation
- **Action:** Replace self-signed certificates with CA-signed certificates

### 2. Truststore Configuration
- **Current State:** No explicit truststore configuration for Kafka clients
- **Recommendation:** Configure explicit truststores for all SSL connections
- **Action:** Create and distribute truststore containing necessary CA certificates

### 3. Authentication Strengthening
- **Current State:** SASL PLAIN authentication for Kafka
- **Recommendation:** Consider upgrading to SASL_SSL with stronger mechanisms
- **Action:** Evaluate SCRAM-SHA-256 or Kerberos authentication

### 4. Certificate Rotation
- **Current State:** Manual certificate management
- **Recommendation:** Implement automated certificate rotation
- **Action:** Set up certificate lifecycle management process

## Backup Information
- **Certificate Backups:** Located in `/opt/caspida/cert_backups/` with timestamped directories
- **Keystore Backups:** Multiple timestamped backups of keystore.jm found
- **Backup Frequency:** Appears to be created during system operations/upgrades

## Environment Variables and System Properties
- **JAVA_HOME:** `/usr/lib/jvm/java-1.8.0-openjdk`
- **Kafka JVM Options:** Set via `KAFKA_OPTS` in `/opt/caspida/etc/init.d/kafka-server`
- **SSL Debug:** No SSL debugging enabled by default
- **System Properties:** No explicit javax.net.ssl.* properties found in startup scripts

---
**Note:** This analysis was performed on a UBA system where some referenced certificate files were not accessible or found. The system appears to be configured but may have missing certificate files in expected locations.
