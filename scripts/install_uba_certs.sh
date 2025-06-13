#!/bin/bash

###############################################################################
# UBA Certificate Management Script
# 
# Purpose: Install and configure CA certificates for UBA instance and search heads
# Author: System Administrator
# Date: June 11, 2025
# Version: 1.0
#
# Usage: ./install_uba_certs.sh -s <source_cert_directory> [options]
#
# Reference:
# - https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Certificate
# - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/ReplaceJMcert
# - https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Properties
###############################################################################

set -euo pipefail

###############################################################################
# Java Environment Detection (from CaspidaCommonEnv.sh)
###############################################################################

detect_java_home() {
    log_debug "Auto-detecting Java installation..."
    
    # Use the exact same logic as CaspidaCommonEnv.sh
    local PLATFORM="Ubuntu"
    
    # Detect platform like CaspidaCommonEnv.sh
    if [ -f /usr/bin/lsb_release ]; then
        if /usr/bin/lsb_release -a 2>&1 | grep -q "Red Hat"; then
            PLATFORM="Red Hat"
        elif /usr/bin/lsb_release -a 2>&1 | grep -q "Oracle Linux"; then
            PLATFORM="Red Hat"
        fi
    else
        if [ -f /etc/issue ] && cat /etc/issue | grep -q "Red Hat"; then
            PLATFORM="Red Hat"
        elif [ -f /etc/oracle-release ] && cat /etc/oracle-release | grep -q "Oracle Linux"; then
            PLATFORM="Red Hat"
        fi
    fi
    
    # Set JAVA_HOME using exact CaspidaCommonEnv.sh logic
    export JAVA_HOME=/usr/lib/jvm/default-java
    if [ -d "/usr/lib/jvm/java-8-openjdk-amd64" ]; then
        export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
    elif [ -d "/usr/lib/jvm/java-8-oracle/" ]; then
        export JAVA_HOME=/usr/lib/jvm/java-8-oracle/
    fi
    
    if [ "${PLATFORM}" = "Red Hat" ]; then
        if [ -d /etc/alternatives/jre_openjdk ]; then
            export JAVA_HOME=/etc/alternatives/jre_openjdk
        elif [ -d /usr/lib/jvm/default-java ]; then
            export JAVA_HOME=/usr/lib/jvm/default-java
        else
            # non-standard default
            export JAVA_HOME=/usr/java/default
        fi
    fi
    
    # Verify that Java and keytool are executable
    if [ ! -x "$JAVA_HOME/bin/java" ]; then
        log_error "Java executable not found at $JAVA_HOME/bin/java"
        log_error "Consider using --java-home option to specify correct path"
        exit 1
    fi
    
    if [ ! -x "$JAVA_HOME/bin/keytool" ]; then
        log_error "Keytool not found at $JAVA_HOME/bin/keytool"
        log_error "Consider using --java-home option to specify correct path"
        exit 1
    fi
    
    log "Auto-detected JAVA_HOME: $JAVA_HOME"
}

# Initialize Java environment
# Note: Java environment will be initialized in check_prerequisites() based on CUSTOM_JAVA_HOME setting

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/caspida/uba_cert_install_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/opt/caspida/cert_backups/$(date +%Y%m%d_%H%M%S)"

# UBA paths
UBA_CERTS_DIR="/var/vcap/store/caspida/certs"
UBA_CUSTOM_CERTS_DIR="/var/vcap/store/caspida/certs/my_certs"
UBA_SITE_PROPERTIES="/etc/caspida/local/conf/uba-site.properties"
UBA_KEYSTORE_JM="/etc/caspida/conf/jobconf/keystore.jm"
# Missing: UBA-specific keystore for internal cluster communication
UBA_KEYSTORE="/etc/caspida/conf/keystore/uba-keystore"
# Missing: Kafka keystores for data ingestion
KAFKA_KEYSTORE_CONFIG="/opt/caspida/conf/kafka/kafka.properties"
KAFKA_TRUSTSTORE="/opt/caspida/conf/kafka/auth/server.truststore.jks"
JAVA_CACERTS="${JAVA_HOME}/lib/security/cacerts"

# Default configuration
CERT_SOURCE_DIR=""
CUSTOM_JAVA_HOME=""  # Allow manual JAVA_HOME specification
GENERATE_PKCS12=true
PKCS12_PASSWORD="password"
INSTALL_UI_CERTS=true
INSTALL_JM_CERTS=true
INSTALL_SEARCH_HEAD_CERTS=true
# Missing: UBA internal keystore and Kafka keystores
INSTALL_UBA_KEYSTORE=true
INSTALL_KAFKA_CERTS=false  # Optional, only if Kafka ingestion is used
VALIDATE_CERTS=true
RESTART_SERVICES=true
DRY_RUN=false
VERBOSE=false

# Remote certificate pulling configuration
declare -a SPLUNK_HOSTS=()
TEST_CONNECTIVITY=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

###############################################################################
# Logging and output functions
###############################################################################

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" | tee -a "$LOG_FILE" >&2
}

log_warn() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $*" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*" | tee -a "$LOG_FILE"
    fi
}

print_status() {
    echo -e "${BLUE}[STATUS]${NC} $*"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

check_keystore_access() {
    local keystore_file="$1"
    local keystore_pass="$2"
    local keystore_type="$3"  # "JKS" or "PKCS12"
    
    # Check if file exists
    if [[ ! -f "$keystore_file" ]]; then
        log_debug "Keystore file does not exist: $keystore_file (will be created)"
        return 0  # This is okay, we can create it
    fi
    
    # Check if we can read the keystore
    if ! "$JAVA_HOME/bin/keytool" -list -keystore "$keystore_file" -storepass "$keystore_pass" &>/dev/null; then
        log_error "Cannot access keystore: $keystore_file (wrong password or corrupted file)"
        return 1
    fi
    
    log_debug "Keystore access verified: $keystore_file"
    return 0
}

check_java_cacerts_access() {
    if [[ ! -f "$JAVA_CACERTS" ]]; then
        log_error "Java cacerts file not found: $JAVA_CACERTS"
        log_error "Please verify JAVA_HOME is set correctly: $JAVA_HOME"
        return 1
    fi
    
    if [[ ! -w "$JAVA_CACERTS" ]]; then
        log_error "Cannot write to Java cacerts file: $JAVA_CACERTS"
        log_error "Please run as root or check file permissions"
        return 1
    fi
    
    # Test access with default password
    if ! "$JAVA_HOME/bin/keytool" -list -keystore "$JAVA_CACERTS" -storepass "changeit" &>/dev/null; then
        log_error "Cannot access Java cacerts with default password"
        return 1
    fi
    
    log_debug "Java cacerts access verified: $JAVA_CACERTS"
    return 0
}

###############################################################################
# Usage and help functions
###############################################################################

usage() {
    cat << EOF
Usage: $SCRIPT_NAME -s <source_cert_directory> [options]

DESCRIPTION:
    Install and configure CA certificates for UBA instance and search heads.
    Supports PEM format certificates with automatic PKCS12 generation and
    Java keystore integration. Can also pull certificates from remote Splunk instances.

REQUIRED OPTIONS:
    -s, --source-dir DIR        Source directory containing PEM certificates

OPTIONAL OPTIONS:
    --java-home PATH            Specify custom JAVA_HOME path (skips auto-detection)
    --no-pkcs12                 Skip PKCS12 generation (default: generate)
    --pkcs12-password PASS      PKCS12 password (default: "password")
    --no-ui-certs              Skip UI certificate installation
    --no-jm-certs              Skip Job Manager certificate installation
    --no-search-head-certs     Skip search head certificate installation
    --no-uba-keystore          Skip UBA internal keystore installation
    --enable-kafka-certs       Enable Kafka certificate installation (default: disabled)
    --no-validation            Skip certificate validation
    --no-restart               Skip service restart
    --pull-from HOST[:PORT]     Pull certificate from Splunk instance (can be used multiple times)
    --test-connectivity         Test connectivity to Splunk instances before pulling certificates
    --dry-run                  Show what would be done without making changes
    -v, --verbose              Enable verbose output
    -h, --help                 Show this help message

CERTIFICATE REQUIREMENTS:
    - Certificates must be in PEM format
    - Private keys must be named: <hostname>.key or <hostname>_private.key
    - Certificates must be named: <hostname>.crt or <hostname>_cert.pem
    - Root CA certificates should be named: root-ca.crt or ca-bundle.crt

EXAMPLES:
    # Install all certificates from /opt/certs directory
    $SCRIPT_NAME -s /opt/certs

    # Use custom Java installation
    $SCRIPT_NAME -s /opt/certs --java-home /usr/lib/jvm/java-11-openjdk

    # Use custom Java installation with specific components
    $SCRIPT_NAME -s /opt/certs --java-home /usr/java/jdk1.8.0_321 --no-search-head-certs

    # Install only UI certificates with custom password
    $SCRIPT_NAME -s /opt/certs --no-jm-certs --no-search-head-certs --pkcs12-password mypass

    # Pull certificates from Splunk instances and install
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239:8000 --pull-from splunk.company.com:8089

    # Test connectivity to Splunk instances
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239:8000 --test-connectivity --dry-run

    # Dry run to see what would be done
    $SCRIPT_NAME -s /opt/certs --dry-run

    # Verbose installation with validation
    $SCRIPT_NAME -s /opt/certs -v

SPLUNK CERTIFICATE PULLING:
    # Pull from standard Splunk web interface (port 8000)
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239

    # Pull from Splunk management port (8089)
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239:8089

    # Pull from multiple instances
    $SCRIPT_NAME -s /tmp/certs --pull-from host1:8000 --pull-from host2:8000 --pull-from host3:8089

FILES MANAGED:
    - UBA Site Properties: $UBA_SITE_PROPERTIES
    - Job Manager Keystore: $UBA_KEYSTORE_JM
    - UBA Internal Keystore: $UBA_KEYSTORE (CRITICAL FOR CLUSTER COMMUNICATION)
    - Java CA Certificates: $JAVA_CACERTS
    - Custom Certificates: $UBA_CUSTOM_CERTS_DIR
    - Kafka Keystores: $KAFKA_KEYSTORE_CONFIG, $KAFKA_TRUSTSTORE (if enabled)

EOF
}

###############################################################################
# Validation functions
###############################################################################

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as caspida user or root
    if [[ "$EUID" -ne 0 ]] && [[ "$(whoami)" != "caspida" ]]; then
        log_error "This script must be run as root or caspida user"
        exit 1
    fi
    
    # Initialize Java environment - either custom or auto-detect
    if [[ -n "$CUSTOM_JAVA_HOME" ]]; then
        log "Using custom JAVA_HOME: $CUSTOM_JAVA_HOME"
        export JAVA_HOME="$CUSTOM_JAVA_HOME"
        
        # Validate custom JAVA_HOME
        if [[ ! -d "$JAVA_HOME" ]]; then
            log_error "Custom JAVA_HOME directory does not exist: $JAVA_HOME"
            exit 1
        fi
        
        if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
            log_error "Java executable not found at: $JAVA_HOME/bin/java"
            exit 1
        fi
        
        if [[ ! -x "$JAVA_HOME/bin/keytool" ]]; then
            log_error "Keytool not found at: $JAVA_HOME/bin/keytool"
            exit 1
        fi
        
        log "Custom Java installation validated: $JAVA_HOME"
    else
        log "Auto-detecting Java installation..."
        detect_java_home
    fi
    
    # Update JAVA_CACERTS path now that JAVA_HOME is set
    JAVA_CACERTS="${JAVA_HOME}/lib/security/cacerts"
    log "Final Java configuration:"
    log "  JAVA_HOME: $JAVA_HOME"
    log "  Java version: $("$JAVA_HOME/bin/java" -version 2>&1 | head -n1 | cut -d'"' -f2)"
    log "  Java cacerts: $JAVA_CACERTS"
    
    # Check OpenSSL
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is required but not installed"
        exit 1
    fi
    
    # Check UBA installation
    if [[ ! -d "/opt/caspida" ]]; then
        log_error "UBA installation not found at /opt/caspida"
        exit 1
    fi
    
    # Create required directories
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p "$UBA_CUSTOM_CERTS_DIR" "$BACKUP_DIR" "$(dirname "$LOG_FILE")"
        chown caspida:caspida "$UBA_CUSTOM_CERTS_DIR" 2>/dev/null || true
    fi
    
    log "Prerequisites check completed successfully"
}

validate_certificate() {
    local cert_file="$1"
    local private_key="$2"
    
    log_debug "Validating certificate: $cert_file"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    # Check certificate format
    if ! openssl x509 -in "$cert_file" -text -noout &> /dev/null; then
        log_error "Invalid certificate format: $cert_file"
        return 1
    fi
    
    # Check private key if provided
    if [[ -n "$private_key" ]] && [[ -f "$private_key" ]]; then
        if ! openssl rsa -in "$private_key" -check -noout &> /dev/null; then
            log_error "Invalid private key format: $private_key"
            return 1
        fi
        
        # Verify key-certificate pair using FIPS-compliant SHA256
        cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" | openssl sha256)
        key_modulus=$(openssl rsa -noout -modulus -in "$private_key" | openssl sha256)
        
        if [[ "$cert_modulus" != "$key_modulus" ]]; then
            log_error "Certificate and private key do not match"
            return 1
        fi
    fi
    
    # Get certificate information
    local subject=$(openssl x509 -noout -subject -in "$cert_file" | sed 's/subject=//')
    local issuer=$(openssl x509 -noout -issuer -in "$cert_file" | sed 's/issuer=//')
    local not_after=$(openssl x509 -noout -dates -in "$cert_file" | grep 'notAfter' | cut -d= -f2)
    
    log_debug "Certificate Subject: $subject"
    log_debug "Certificate Issuer: $issuer"
    log_debug "Certificate Expires: $not_after"
    
    # Check expiration
    local exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo "0")
    local now_epoch=$(date +%s)
    
    if [[ "$exp_epoch" -le "$now_epoch" ]]; then
        log_error "Certificate has expired: $cert_file"
        return 1
    fi
    
    local days_until_exp=$(( (exp_epoch - now_epoch) / 86400 ))
    if [[ "$days_until_exp" -lt 30 ]]; then
        log_warn "Certificate expires in $days_until_exp days: $cert_file"
    fi
    
    log_debug "Certificate validation successful: $cert_file"
    return 0
}

discover_certificates() {
    local source_dir="$1"
    
    log "Discovering certificates in: $source_dir"
    
    if [[ ! -d "$source_dir" ]]; then
        log_error "Source directory does not exist: $source_dir"
        exit 1
    fi
    
    # Arrays to store discovered certificates
    declare -gA CERT_FILES
    declare -gA KEY_FILES
    declare -ga CA_FILES
    
    # Find certificate files
    while IFS= read -r -d '' file; do
        local basename=$(basename "$file")
        local name_without_ext="${basename%.*}"
        
        case "$basename" in
            *.crt|*.pem|*cert.pem)
                if [[ "$basename" =~ ^(root-ca|ca-bundle|ca-cert) ]]; then
                    CA_FILES+=("$file")
                    log_debug "Found CA certificate: $file"
                else
                    CERT_FILES["$name_without_ext"]="$file"
                    log_debug "Found certificate: $file"
                fi
                ;;
            *.key|*private.key|*_private.key)
                KEY_FILES["$name_without_ext"]="$file"
                log_debug "Found private key: $file"
                ;;
        esac
    done < <(find "$source_dir" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.key" \) -print0)
    
    local cert_count=${#CERT_FILES[@]}
    local key_count=${#KEY_FILES[@]}
    local ca_count=${#CA_FILES[@]}
    log "Discovery complete. Found $cert_count certificates, $key_count keys, $ca_count CA certificates"
}

###############################################################################
# Remote certificate retrieval functions
###############################################################################

pull_splunk_certificates() {
    local splunk_hosts=("$@")
    local pull_dir="$CERT_SOURCE_DIR/pulled_certs"
    
    if [[ ${#splunk_hosts[@]} -eq 0 ]]; then
        log_error "No Splunk hosts specified for certificate retrieval"
        return 1
    fi
    
    log "Pulling certificates from ${#splunk_hosts[@]} Splunk instance(s)..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would pull certificates from: ${splunk_hosts[*]}"
        return 0
    fi
    
    # Create directory for pulled certificates
    mkdir -p "$pull_dir"
    
    local pulled_count=0
    local failed_count=0
    
    for host_url in "${splunk_hosts[@]}"; do
        log "Processing Splunk instance: $host_url"
        
        # Parse URL to extract hostname and port
        local hostname=""
        local port="8000"
        
        # Remove protocol if present
        local clean_url="${host_url#https://}"
        clean_url="${clean_url#http://}"
        
        # Extract hostname and port
        if [[ "$clean_url" =~ ^([^:]+):([0-9]+)$ ]]; then
            hostname="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        elif [[ "$clean_url" =~ ^([^:]+)$ ]]; then
            hostname="${BASH_REMATCH[1]}"
            port="8000"  # Default Splunk web port
        else
            log_error "Invalid URL format: $host_url"
            ((failed_count++))
            continue
        fi
        
        log_debug "Extracting certificate from $hostname:$port"
        
        # Create safe filename for this host
        local safe_hostname="${hostname//[^a-zA-Z0-9.-]/_}"
        local cert_file="$pull_dir/${safe_hostname}_${port}.crt"
        local info_file="$pull_dir/${safe_hostname}_${port}_info.txt"
        
        # Pull certificate using OpenSSL
        if timeout 10 openssl s_client -connect "${hostname}:${port}" -servername "$hostname" </dev/null 2>/dev/null | openssl x509 -outform PEM > "$cert_file" 2>/dev/null; then
            
            # Validate the certificate
            if openssl x509 -in "$cert_file" -text -noout &>/dev/null; then
                log "Successfully pulled certificate from $hostname:$port"
                
                # Extract certificate information
                cat > "$info_file" << EOF
Certificate Information for $hostname:$port
==========================================
Retrieved: $(date)
Source: $host_url

Certificate Details:
EOF
                
                # Add certificate subject and validity
                openssl x509 -in "$cert_file" -noout -text | grep -A2 "Subject:" >> "$info_file"
                openssl x509 -in "$cert_file" -noout -text | grep -A2 "Issuer:" >> "$info_file"
                openssl x509 -in "$cert_file" -noout -text | grep -A2 "Validity" >> "$info_file"
                openssl x509 -in "$cert_file" -noout -text | grep -A10 "Subject Alternative Name" >> "$info_file" 2>/dev/null || echo "No Subject Alternative Names found" >> "$info_file"
                
                # Check if it's a self-signed certificate
                local subject=$(openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//')
                local issuer=$(openssl x509 -in "$cert_file" -noout -issuer | sed 's/issuer=//')
                
                if [[ "$subject" == "$issuer" ]]; then
                    echo "Note: This is a self-signed certificate" >> "$info_file"
                    log_warn "Certificate from $hostname:$port is self-signed"
                fi
                
                # Check expiration
                local expiry_date=$(openssl x509 -in "$cert_file" -noout -dates | grep 'notAfter' | cut -d= -f2)
                local exp_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
                local now_epoch=$(date +%s)
                local days_until_exp=$(( (exp_epoch - now_epoch) / 86400 ))
                
                echo "Expires in: $days_until_exp days ($expiry_date)" >> "$info_file"
                
                if [[ "$days_until_exp" -lt 30 ]]; then
                    log_warn "Certificate from $hostname:$port expires in $days_until_exp days"
                fi
                
                # Set proper permissions
                chmod 644 "$cert_file" "$info_file"
                
                ((pulled_count++))
                
                log_debug "Certificate info saved to: $info_file"
                
            else
                log_error "Invalid certificate retrieved from $hostname:$port"
                rm -f "$cert_file" "$info_file"
                ((failed_count++))
            fi
            
        else
            log_error "Failed to retrieve certificate from $hostname:$port"
            log_error "Please verify the hostname/IP and port are correct and accessible"
            rm -f "$cert_file" "$info_file"
            ((failed_count++))
        fi
    done
    
    log "Certificate retrieval completed: $pulled_count successful, $failed_count failed"
    
    if [[ "$pulled_count" -gt 0 ]]; then
        log "Pulled certificates stored in: $pull_dir"
        log "Certificate details:"
        ls -la "$pull_dir"/*.crt 2>/dev/null || true
        
        # Add pulled certificates to CA_FILES array for installation
        while IFS= read -r -d '' cert_file; do
            CA_FILES+=("$cert_file")
            log_debug "Added pulled certificate to CA list: $cert_file"
        done < <(find "$pull_dir" -name "*.crt" -print0 2>/dev/null)
        
        log "Added $pulled_count certificate(s) to CA certificate list for installation"
    fi
    
    return $(( failed_count > 0 ? 1 : 0 ))
}

validate_splunk_connectivity() {
    local splunk_hosts=("$@")
    
    log "Validating connectivity to Splunk instances..."
    
    local reachable_count=0
    local unreachable_count=0
    
    for host_url in "${splunk_hosts[@]}"; do
        # Parse URL
        local clean_url="${host_url#https://}"
        clean_url="${clean_url#http://}"
        
        local hostname=""
        local port="8000"
        
        if [[ "$clean_url" =~ ^([^:]+):([0-9]+)$ ]]; then
            hostname="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        elif [[ "$clean_url" =~ ^([^:]+)$ ]]; then
            hostname="${BASH_REMATCH[1]}"
        fi
        
        log_debug "Testing connectivity to $hostname:$port"
        
        # Test basic connectivity
        if timeout 5 bash -c "echo >/dev/tcp/$hostname/$port" 2>/dev/null; then
            log "✓ $hostname:$port is reachable"
            ((reachable_count++))
            
            # Test HTTPS specifically if possible
            if command -v curl &>/dev/null; then
                if curl -k -s --connect-timeout 5 --max-time 10 "https://${hostname}:${port}" >/dev/null 2>&1; then
                    log_debug "HTTPS service confirmed on $hostname:$port"
                else
                    log_warn "Port $port is open but HTTPS may not be available on $hostname"
                fi
            fi
        else
            log_error "✗ $hostname:$port is not reachable"
            ((unreachable_count++))
        fi
    done
    
    log "Connectivity test completed: $reachable_count reachable, $unreachable_count unreachable"
    
    return $(( unreachable_count > 0 ? 1 : 0 ))
}

###############################################################################
# Certificate processing functions
###############################################################################

backup_existing_certs() {
    log "Creating backup of existing certificates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would backup certificates to $BACKUP_DIR"
        return 0
    fi
    
    # Backup UBA certificates
    if [[ -d "$UBA_CERTS_DIR" ]]; then
        cp -r "$UBA_CERTS_DIR" "$BACKUP_DIR/original_certs" 2>/dev/null || true
    fi
    
    # Backup Job Manager keystore
    if [[ -f "$UBA_KEYSTORE_JM" ]]; then
        cp "$UBA_KEYSTORE_JM" "$BACKUP_DIR/keystore.jm.backup" 2>/dev/null || true
    fi
    
    # Backup site properties
    if [[ -f "$UBA_SITE_PROPERTIES" ]]; then
        cp "$UBA_SITE_PROPERTIES" "$BACKUP_DIR/uba-site.properties.backup" 2>/dev/null || true
    fi
    
    log "Backup completed: $BACKUP_DIR"
}

generate_pkcs12() {
    local cert_file="$1"
    local key_file="$2"
    local output_file="$3"
    local alias="${4:-server}"
    
    log "Generating PKCS12 file: $output_file"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would generate PKCS12 file"
        return 0
    fi
    
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
        log_error "Certificate or key file missing for PKCS12 generation"
        return 1
    fi
    
    # Use FIPS-compatible algorithms and proper command formatting
    openssl pkcs12 -export -in "$cert_file" -inkey "$key_file" -name "$alias" -out "$output_file" -password "pass:$PKCS12_PASSWORD" -keypbe AES-256-CBC -certpbe AES-256-CBC
    
    chmod 600 "$output_file"
    chown caspida:caspida "$output_file" 2>/dev/null || true
    
    log "PKCS12 file generated successfully: $output_file"
}

install_ui_certificates() {
    log "Installing UI certificates..."
    
    # Find UBA server certificate
    local uba_hostname=$(hostname -s)
    local cert_file=""
    local key_file=""
    
    # Try to find matching certificate
    for name in "$uba_hostname" "uba" "server" "$(hostname -f)"; do
        if [[ -n "${CERT_FILES[$name]:-}" ]]; then
            cert_file="${CERT_FILES[$name]}"
            key_file="${KEY_FILES[$name]:-}"
            break
        fi
    done
    
    if [[ -z "$cert_file" ]]; then
        log_warn "No matching certificate found for UBA server"
        return 1
    fi
    
    if [[ -z "$key_file" ]]; then
        log_error "Private key not found for certificate: $cert_file"
        return 1
    fi
    
    if [[ "$VALIDATE_CERTS" == "true" ]]; then
        if ! validate_certificate "$cert_file" "$key_file"; then
            log_error "Certificate validation failed for UI certificates"
            return 1
        fi
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would install UI certificates"
        return 0
    fi
    
    # Copy certificates to custom location
    local custom_cert="$UBA_CUSTOM_CERTS_DIR/my-server.crt.pem"
    local custom_key="$UBA_CUSTOM_CERTS_DIR/my-server.key.pem"
    local custom_ca="$UBA_CUSTOM_CERTS_DIR/my-root-ca.crt.pem"
    
    cp "$cert_file" "$custom_cert"
    cp "$key_file" "$custom_key"
    
    # Install CA certificate if available
    if [[ "${#CA_FILES[@]}" -gt 0 ]]; then
        cp "${CA_FILES[0]}" "$custom_ca"
    fi
    
    # Note: Ownership and permissions will be set centrally after all certificate installation
    
    # Update uba-site.properties
    update_site_properties "$custom_ca" "$custom_key" "$custom_cert"
    
    log "UI certificates installed successfully"
}

install_job_manager_certificates() {
    log "Installing Job Manager certificates..."
    
    # Validate keystore access before proceeding (if keystore exists)
    if [[ -f "$UBA_KEYSTORE_JM" ]]; then
        if ! check_keystore_access "$UBA_KEYSTORE_JM" "$PKCS12_PASSWORD" "JKS"; then
            log_error "Cannot access existing Job Manager keystore, aborting installation"
            return 1
        fi
    fi
    
    # Find appropriate certificate for Job Manager
    local jm_cert=""
    local jm_key=""
    local uba_hostname=$(hostname -s)
    
    # Try to find matching certificate
    for name in "$uba_hostname" "uba" "server" "jobmanager" "jm" "$(hostname -f)"; do
        if [[ -n "${CERT_FILES[$name]:-}" ]]; then
            jm_cert="${CERT_FILES[$name]}"
            jm_key="${KEY_FILES[$name]:-}"
            break
        fi
    done
    
    if [[ -z "$jm_cert" ]] || [[ -z "$jm_key" ]]; then
        log_warn "No matching certificate/key pair found for Job Manager"
        return 1
    fi
    
    if [[ "$VALIDATE_CERTS" == "true" ]]; then
        if ! validate_certificate "$jm_cert" "$jm_key"; then
            log_error "Certificate validation failed for Job Manager"
            return 1
        fi
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would install Job Manager certificates"
        return 0
    fi
    
    # Generate PKCS12 for Job Manager
    local pkcs12_file="$UBA_CUSTOM_CERTS_DIR/jobmanager.p12"
    generate_pkcs12 "$jm_cert" "$jm_key" "$pkcs12_file" "jmserver"
    
    # Backup existing keystore
    if [[ -f "$UBA_KEYSTORE_JM" ]]; then
        cp "$UBA_KEYSTORE_JM" "$UBA_KEYSTORE_JM.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Check if keystore exists and create if needed
    if [[ ! -f "$UBA_KEYSTORE_JM" ]]; then
        log "Creating new Job Manager keystore: $UBA_KEYSTORE_JM"
        mkdir -p "$(dirname "$UBA_KEYSTORE_JM")"
    fi
    
    # Check if jmserver alias exists and delete if present
    if "$JAVA_HOME/bin/keytool" -list -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD" -alias "jmserver" &>/dev/null; then
        log "Removing existing 'jmserver' certificate from keystore"
        "$JAVA_HOME/bin/keytool" -delete -alias "jmserver" -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD"
        if [[ $? -eq 0 ]]; then
            log "Successfully removed existing 'jmserver' certificate"
        else
            log_error "Failed to remove existing 'jmserver' certificate"
            return 1
        fi
    else
        log "No existing 'jmserver' certificate found (this is normal for new installations)"
    fi
    
    # Import new certificate with proper parameters
    "$JAVA_HOME/bin/keytool" -importkeystore -destkeystore "$UBA_KEYSTORE_JM" -srckeystore "$pkcs12_file" -srcstoretype PKCS12 -deststorepass "$PKCS12_PASSWORD" -srcstorepass "$PKCS12_PASSWORD" -srcalias "jmserver" -destalias "jmserver" -noprompt
    
    # Verify import
    if "$JAVA_HOME/bin/keytool" -list -v -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD" | grep -q "jmserver"; then
        log "Job Manager certificate installed successfully"
    else
        log_error "Failed to install Job Manager certificate"
        return 1
    fi
}

install_search_head_certificates() {
    log "Installing search head certificates to Java truststore..."
    
    if [[ "${#CA_FILES[@]}" -eq 0 ]]; then
        log_warn "No CA certificates found for search head trust"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would install search head certificates"
        return 0
    fi
    
    # Validate Java cacerts access before proceeding
    if ! check_java_cacerts_access; then
        log_error "Cannot access Java cacerts, aborting CA certificate installation"
        return 1
    fi
    
    # Backup Java cacerts
    cp "$JAVA_CACERTS" "$JAVA_CACERTS.backup.$(date +%Y%m%d_%H%M%S)"
    
    local cert_count=0
    for ca_file in "${CA_FILES[@]}"; do
        if [[ "$VALIDATE_CERTS" == "true" ]]; then
            if ! validate_certificate "$ca_file" ""; then
                log_warn "Skipping invalid CA certificate: $ca_file"
                continue
            fi
        fi
        
        local alias="uba_ca_$(basename "$ca_file" .crt)_$cert_count"
        
        # Check if certificate with same alias exists and remove if present
        if "$JAVA_HOME/bin/keytool" -list -keystore "$JAVA_CACERTS" -storepass "changeit" -alias "$alias" &>/dev/null; then
            log "Removing existing CA certificate with alias '$alias'"
            "$JAVA_HOME/bin/keytool" -delete -alias "$alias" -keystore "$JAVA_CACERTS" -storepass "changeit"
            if [[ $? -eq 0 ]]; then
                log "Successfully removed existing CA certificate '$alias'"
            else
                log_warn "Failed to remove existing CA certificate '$alias', continuing anyway"
            fi
        else
            log_debug "No existing CA certificate found with alias '$alias'"
        fi
        
        # Import CA certificate with proper parameters
        "$JAVA_HOME/bin/keytool" -import -trustcacerts -alias "$alias" -file "$ca_file" -keystore "$JAVA_CACERTS" -storepass "changeit" -noprompt
        
        if [[ $? -eq 0 ]]; then
            log "Imported CA certificate: $ca_file (alias: $alias)"
            ((cert_count++))
        else
            log_error "Failed to import CA certificate: $ca_file"
        fi
    done
    
    log "Installed $cert_count CA certificates to Java truststore"
}

install_uba_keystore_certificates() {
    log "Installing certificates to UBA internal keystore..."
    
    # Validate keystore access before proceeding (if keystore exists)
    if [[ -f "$UBA_KEYSTORE" ]]; then
        if ! check_keystore_access "$UBA_KEYSTORE" "password" "JKS"; then
            log_error "Cannot access existing UBA keystore, aborting installation"
            return 1
        fi
    fi
    
    # Find appropriate certificate for UBA internal communication
    local uba_cert=""
    local uba_key=""
    local uba_hostname=$(hostname -s)
    
    # Try to find matching certificate
    for name in "$uba_hostname" "uba" "server" "$(hostname -f)"; do
        if [[ -n "${CERT_FILES[$name]:-}" ]]; then
            uba_cert="${CERT_FILES[$name]}"
            uba_key="${KEY_FILES[$name]:-}"
            break
        fi
    done
    
    if [[ -z "$uba_cert" ]] || [[ -z "$uba_key" ]]; then
        log_warn "No matching certificate/key pair found for UBA keystore"
        return 1
    fi
    
    if [[ "$VALIDATE_CERTS" == "true" ]]; then
        if ! validate_certificate "$uba_cert" "$uba_key"; then
            log_error "Certificate validation failed for UBA keystore"
            return 1
        fi
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would install UBA keystore certificates"
        return 0
    fi
    
    # Generate PKCS12 for UBA keystore
    local pkcs12_file="$UBA_CUSTOM_CERTS_DIR/uba-internal.p12"
    generate_pkcs12 "$uba_cert" "$uba_key" "$pkcs12_file" "uba-server"
    
    # Backup existing keystore
    if [[ -f "$UBA_KEYSTORE" ]]; then
        cp "$UBA_KEYSTORE" "$UBA_KEYSTORE.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create keystore directory if needed
    mkdir -p "$(dirname "$UBA_KEYSTORE")"
    
    # Check if uba-server alias exists and delete if present
    if [[ -f "$UBA_KEYSTORE" ]] && "$JAVA_HOME/bin/keytool" -list -keystore "$UBA_KEYSTORE" -storepass "password" -alias "uba-server" &>/dev/null; then
        log "Removing existing 'uba-server' certificate from UBA keystore"
        "$JAVA_HOME/bin/keytool" -delete -alias "uba-server" -keystore "$UBA_KEYSTORE" -storepass "password"
    fi
    
    # Import new certificate
    "$JAVA_HOME/bin/keytool" -importkeystore -destkeystore "$UBA_KEYSTORE" -srckeystore "$pkcs12_file" -srcstoretype PKCS12 -deststorepass "password" -srcstorepass "$PKCS12_PASSWORD" -srcalias "uba-server" -destalias "uba-server" -noprompt
    
    # Verify import
    if "$JAVA_HOME/bin/keytool" -list -v -keystore "$UBA_KEYSTORE" -storepass "password" | grep -q "uba-server"; then
        log "UBA keystore certificate installed successfully"
        
        # Sync keystore with all UBA nodes (per documentation)
        if [[ -f "/opt/caspida/bin/Caspida" ]]; then
            sudo -u caspida /opt/caspida/bin/Caspida setup-uba-keystore 2>/dev/null || {
                log_warn "Failed to sync UBA keystore - may need manual sync across cluster nodes"
            }
        fi
    else
        log_error "Failed to install UBA keystore certificate"
        return 1
    fi
}

install_kafka_certificates() {
    log "Installing Kafka certificates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would install Kafka certificates"
        return 0
    fi
    
    # This function would handle Kafka keystore/truststore setup
    # Implementation depends on specific Kafka SSL requirements
    log_warn "Kafka certificate installation not yet implemented"
    log_warn "Refer to UBA documentation for manual Kafka SSL setup if using Kafka ingestion"
}

update_site_properties() {
    local root_ca="$1"
    local private_key="$2"
    local server_cert="$3"
    
    log "Updating UBA site properties..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would update site properties"
        return 0
    fi
    
    # Ensure directory exists
    mkdir -p "$(dirname "$UBA_SITE_PROPERTIES")"
    
    # Create or update properties file
    if [[ ! -f "$UBA_SITE_PROPERTIES" ]]; then
        cat > "$UBA_SITE_PROPERTIES" << EOF
##
# UBA Site Properties - Certificate Configuration
# Generated by $SCRIPT_NAME on $(date)
##

EOF
    fi
    
    # Remove existing certificate properties and their comment blocks
    sed -i '/^# Certificate configuration - Added/,/^ui\.auth\.serverCert=/d' "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    sed -i '/^ui\.auth\./d' "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    
    # Remove any trailing empty lines
    sed -i '/^$/N;/^\n$/d' "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    
    # Add new certificate properties
    cat >> "$UBA_SITE_PROPERTIES" << EOF

# Certificate configuration - Added $(date)
ui.auth.rootca=$root_ca
ui.auth.privateKey=$private_key
ui.auth.serverCert=$server_cert

EOF
    
    chown caspida:caspida "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    chmod 644 "$UBA_SITE_PROPERTIES"
    
    log "Site properties updated successfully"
}

###############################################################################
# Service management functions
###############################################################################

sync_cluster_config() {
    log "Synchronizing cluster configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would sync cluster configuration"
        return 0
    fi
    
    # Sync site properties
    if [[ -f "/opt/caspida/bin/Caspida" ]]; then
        sudo -u caspida /opt/caspida/bin/Caspida sync-cluster /etc/caspida/local/conf 2>/dev/null || {
            log_warn "Failed to sync cluster configuration - may be single node deployment"
        }
        
        # Sync job configuration if Job Manager certs were updated
        if [[ "$INSTALL_JM_CERTS" == "true" ]]; then
            sudo -u caspida /opt/caspida/bin/Caspida sync-cluster /etc/caspida/conf/jobconf/ 2>/dev/null || {
                log_warn "Failed to sync job configuration"
            }
        fi
    fi
}

restart_uba_services() {
    log "Restarting UBA services..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restart UBA services"
        return 0
    fi
    
    local services_to_restart=()
    
    if [[ "$INSTALL_UI_CERTS" == "true" ]]; then
        services_to_restart+=("caspida-ui" "caspida-resourcesmonitor")
    fi
    
    if [[ "$INSTALL_JM_CERTS" == "true" ]]; then
        services_to_restart+=("caspida-jobmanager")
    fi
    
    # Start services (they were already stopped before certificate installation)
    for service in "${services_to_restart[@]}"; do
        log "Starting service: $service"
        systemctl start "$service" 2>/dev/null || {
            service "$service" start 2>/dev/null || log_error "Failed to start $service"
        }
    done
    
    log "Service restart completed"
}

stop_uba_services() {
    log "Stopping UBA services before certificate installation..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would stop UBA services"
        return 0
    fi
    
    local services_to_stop=()
    
    if [[ "$INSTALL_UI_CERTS" == "true" ]]; then
        services_to_stop+=("caspida-ui" "caspida-resourcesmonitor")
    fi
    
    if [[ "$INSTALL_JM_CERTS" == "true" ]]; then
        services_to_stop+=("caspida-jobmanager")
    fi
    
    # Stop services before certificate installation (per Splunk docs)
    for service in "${services_to_stop[@]}"; do
        log "Stopping service: $service"
        systemctl stop "$service" 2>/dev/null || {
            service "$service" stop 2>/dev/null || log_warn "Failed to stop $service"
        }
    done
    
    # Small delay to ensure clean shutdown
    sleep 5
    
    log "Service stop completed"
}

set_certificate_ownership() {
    local cert_dir="$1"
    
    log "Setting proper ownership and permissions for certificate files..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would set certificate ownership and permissions"
        return 0
    fi
    
    # Set ownership to caspida:caspida for all certificate files
    if [[ -d "$cert_dir" ]]; then
        chown -R caspida:caspida "$cert_dir" 2>/dev/null || {
            log_warn "Failed to set ownership on some files in $cert_dir"
        }
        
        # Set proper permissions per Splunk documentation
        find "$cert_dir" -type f -name "*.pem" -exec chmod 644 {} \; 2>/dev/null || true
        find "$cert_dir" -type f -name "*.crt" -exec chmod 644 {} \; 2>/dev/null || true
        find "$cert_dir" -type f -name "*.key" -exec chmod 600 {} \; 2>/dev/null || true
        find "$cert_dir" -type f -name "*.p12" -exec chmod 600 {} \; 2>/dev/null || true
        
        log "Certificate ownership and permissions set successfully"
    else
        log_warn "Certificate directory not found: $cert_dir"
    fi
}

###############################################################################
# Main processing functions
###############################################################################

process_certificates() {
    log "Starting certificate processing..."
    
    # Discover certificates in source directory
    discover_certificates "$CERT_SOURCE_DIR"
    
    if [[ "${#CERT_FILES[@]}" -eq 0 ]]; then
        log_error "No certificates found in source directory: $CERT_SOURCE_DIR"
        exit 1
    fi
    
    # Create backup
    backup_existing_certs
    
    # Stop UBA services before certificate installation (per Splunk docs)
    stop_uba_services
    
    local install_errors=0
    
    # Install UI certificates
    if [[ "$INSTALL_UI_CERTS" == "true" ]]; then
        if ! install_ui_certificates; then
            ((install_errors++))
        fi
    fi
    
    # Install Job Manager certificates
    if [[ "$INSTALL_JM_CERTS" == "true" ]]; then
        if ! install_job_manager_certificates; then
            ((install_errors++))
        fi
    fi
    
    # Install search head certificates
    if [[ "$INSTALL_SEARCH_HEAD_CERTS" == "true" ]]; then
        if ! install_search_head_certificates; then
            ((install_errors++))
        fi
    fi
    
    # Install UBA internal keystore certificates (MISSING CRITICAL COMPONENT)
    if [[ "$INSTALL_UBA_KEYSTORE" == "true" ]]; then
        if ! install_uba_keystore_certificates; then
            ((install_errors++))
        fi
    fi
    
    # Install Kafka certificates (if enabled)
    if [[ "$INSTALL_KAFKA_CERTS" == "true" ]]; then
        if ! install_kafka_certificates; then
            ((install_errors++))
        fi
    fi

    if [[ "$install_errors" -gt 0 ]]; then
        log_warn "$install_errors certificate installation(s) had errors"
    fi
    
    # Set proper ownership and permissions for all certificate files
    set_certificate_ownership "$UBA_CUSTOM_CERTS_DIR"
    
    # Sync cluster configuration
    sync_cluster_config
    
    # Restart services if requested
    if [[ "$RESTART_SERVICES" == "true" ]] && [[ "$install_errors" -eq 0 ]]; then
        restart_uba_services
    fi
    
    log "Certificate processing completed"
}

###############################################################################
# Main script execution
###############################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--source-dir)
                CERT_SOURCE_DIR="$2"
                shift 2
                ;;
            --java-home)
                CUSTOM_JAVA_HOME="$2"
                shift 2
                ;;
            --no-pkcs12)
                GENERATE_PKCS12=false
                shift
                ;;
            --pkcs12-password)
                PKCS12_PASSWORD="$2"
                shift 2
                ;;
            --no-ui-certs)
                INSTALL_UI_CERTS=false
                shift
                ;;
            --no-jm-certs)
                INSTALL_JM_CERTS=false
                shift
                ;;
            --no-search-head-certs)
                INSTALL_SEARCH_HEAD_CERTS=false
                shift
                ;;
            --no-uba-keystore)
                INSTALL_UBA_KEYSTORE=false
                shift
                ;;
            --enable-kafka-certs)
                INSTALL_KAFKA_CERTS=true
                shift
                ;;
            --no-validation)
                VALIDATE_CERTS=false
                shift
                ;;
            --no-restart)
                RESTART_SERVICES=false
                shift
                ;;
            --pull-from)
                SPLUNK_HOSTS+=("$2")
                shift 2
                ;;
            --test-connectivity)
                TEST_CONNECTIVITY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$CERT_SOURCE_DIR" ]]; then
        print_error "Source certificate directory is required"
        usage
        exit 1
    fi
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
    # Print banner
    print_status "UBA Certificate Installation Script v$SCRIPT_VERSION"
    print_status "Source Directory: $CERT_SOURCE_DIR"
    if [[ -n "$CUSTOM_JAVA_HOME" ]]; then
        print_status "Custom JAVA_HOME: $CUSTOM_JAVA_HOME"
    fi
    print_status "Log File: $LOG_FILE"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Run main processing
    log "Starting UBA certificate installation process"
    log "Source directory: $CERT_SOURCE_DIR"
    if [[ -n "$CUSTOM_JAVA_HOME" ]]; then
        log "Using custom JAVA_HOME: $CUSTOM_JAVA_HOME"
    fi
    log "Configuration: UI=$INSTALL_UI_CERTS, JM=$INSTALL_JM_CERTS, SearchHead=$INSTALL_SEARCH_HEAD_CERTS, UBA_Keystore=$INSTALL_UBA_KEYSTORE"
    
    # Handle remote certificate pulling if requested
    if [[ ${#SPLUNK_HOSTS[@]} -gt 0 ]]; then
        log "Remote certificate pulling requested for ${#SPLUNK_HOSTS[@]} host(s)"
        
        # Test connectivity if requested
        if [[ "$TEST_CONNECTIVITY" == "true" ]]; then
            log "Testing connectivity to Splunk instances..."
            if ! validate_splunk_connectivity "${SPLUNK_HOSTS[@]}"; then
                if [[ "$DRY_RUN" == "false" ]]; then
                    print_warning "Some Splunk hosts are unreachable. Continue anyway? (y/N)"
                    read -r response
                    if [[ ! "$response" =~ ^[Yy]$ ]]; then
                        print_error "Aborted due to connectivity issues"
                        exit 1
                    fi
                fi
            fi
        fi
        
        # Pull certificates from remote Splunk instances
        log "Pulling certificates from Splunk instances: ${SPLUNK_HOSTS[*]}"
        if ! pull_splunk_certificates "${SPLUNK_HOSTS[@]}"; then
            print_warning "Some certificate retrievals failed, but continuing with available certificates"
        fi
    fi
    
    check_prerequisites
    process_certificates
    
    print_success "Certificate installation completed successfully"
    log "Script execution completed"
    
    # Display next steps
    cat << EOF

NEXT STEPS:
1. Verify UBA web interface is accessible with new certificate
2. Check service logs for any certificate-related errors:
   - tail -f /var/log/caspida/ui/ui.log
   - tail -f /var/log/caspida/jobmanager/jobmanager.log
3. Test connectivity to search heads
4. Monitor system for 24-48 hours to ensure stability

BACKUP LOCATION: $BACKUP_DIR
LOG FILE: $LOG_FILE

EOF
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
