#!/bin/bash

###############################################################################
# UBA Certificate Management Script
# 
# Purpose: Install and configure CA certificates for UBA instance and search heads
# Author: System Administrator
# Date: June 13, 2025
# Version: 1.1
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
# Global Variables and Configuration
###############################################################################

# Script metadata
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.1"

# Default paths (will be updated after Java detection)
JAVA_HOME=""
JAVA_CACERTS=""

# UBA installation paths
readonly UBA_CERTS_DIR="/var/vcap/store/caspida/certs"
readonly UBA_CUSTOM_CERTS_DIR="/var/vcap/store/caspida/certs/my_certs"
readonly UBA_SITE_PROPERTIES="/etc/caspida/local/conf/uba-site.properties"
readonly UBA_KEYSTORE_JM="/etc/caspida/conf/jobconf/keystore.jm"
readonly UBA_KEYSTORE="/etc/caspida/conf/keystore/uba-keystore"
readonly KAFKA_KEYSTORE_CONFIG="/opt/caspida/conf/kafka/kafka.properties"
readonly KAFKA_TRUSTSTORE="/opt/caspida/conf/kafka/auth/server.truststore.jks"

# Runtime configuration (will be set by arguments)
CERT_SOURCE_DIR=""
CUSTOM_JAVA_HOME=""
LOG_FILE=""
BACKUP_DIR=""

# Feature flags (defaults that can be overridden by arguments)
GENERATE_PKCS12=true
INSTALL_UI_CERTS=true
INSTALL_JM_CERTS=true
INSTALL_SEARCH_HEAD_CERTS=true
INSTALL_UBA_KEYSTORE=true
INSTALL_KAFKA_CERTS=false
VALIDATE_CERTS=true
RESTART_SERVICES=true
VERBOSE=false
DRY_RUN=false
TEST_CONNECTIVITY=false

# Security configuration
readonly PKCS12_PASSWORD="password"
readonly JKS_PASSWORD="password"

# Certificate storage arrays
declare -gA CERT_FILES
declare -gA KEY_FILES  
declare -ga CA_FILES

# Remote certificate pulling
declare -a SPLUNK_HOSTS=()

# Service management
readonly UBA_SYSTEMD_SERVICES=("caspida-jobmanager" "caspida-ui" "caspida-resourcesmonitor")
SERVICE_MANAGEMENT_METHOD=""
JAVA_CACERTS_NEEDS_SUDO=""

###############################################################################
# Utility Functions
###############################################################################

# Logging functions
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp [INFO] $message" | tee -a "${LOG_FILE:-/dev/null}"
}

log_error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp [ERROR] $message" | tee -a "${LOG_FILE:-/dev/null}" >&2
}

log_warn() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp [WARN] $message" | tee -a "${LOG_FILE:-/dev/null}"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="$1"
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "$timestamp [DEBUG] $message" | tee -a "${LOG_FILE:-/dev/null}"
    fi
}

# Status output functions
print_status() {
    echo "[STATUS] $1"
}

print_success() {
    echo -e "\033[32m[SUCCESS]\033[0m $1"
}

print_error() {
    echo -e "\033[31m[ERROR]\033[0m $1" >&2
}

print_warning() {
    echo -e "\033[33m[WARNING]\033[0m $1"
}

###############################################################################
# Environment Setup Functions
###############################################################################

# Initialize runtime variables that depend on timestamp
initialize_runtime_variables() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    LOG_FILE="/var/log/caspida/uba_cert_install_${timestamp}.log"
    BACKUP_DIR="/opt/caspida/cert_backups/${timestamp}"
    
    # Create log directory
    sudo mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    sudo chown caspida:caspida "$(dirname "$LOG_FILE")" 2>/dev/null || true
}

# Java environment detection (from CaspidaCommonEnv.sh)
detect_java_home() {
    log_debug "Auto-detecting Java installation..."
    
    local platform="Ubuntu"
    
    # Detect platform like CaspidaCommonEnv.sh
    if [[ -f /usr/bin/lsb_release ]]; then
        if /usr/bin/lsb_release -a 2>&1 | grep -q "Red Hat\|Oracle Linux"; then
            platform="Red Hat"
        fi
    elif [[ -f /etc/issue ]] && grep -q "Red Hat" /etc/issue; then
        platform="Red Hat"
    elif [[ -f /etc/oracle-release ]] && grep -q "Oracle Linux" /etc/oracle-release; then
        platform="Red Hat"
    fi
    
    # Set JAVA_HOME using exact CaspidaCommonEnv.sh logic
    if [[ "$platform" == "Red Hat" ]]; then
        # Red Hat/CentOS/Oracle Linux Java paths
        local java_paths=(
            "/usr/lib/jvm/java-1.8.0-openjdk"
            "/usr/lib/jvm/java-8-openjdk"
            "/etc/alternatives/java_sdk"
            "/etc/alternatives/java_sdk_1.8.0"
            "/usr/lib/jvm/default-java"
        )
    else
        # Ubuntu/Debian Java paths
        local java_paths=(
            "/usr/lib/jvm/java-8-openjdk-amd64"
            "/usr/lib/jvm/java-8-oracle"
            "/usr/lib/jvm/default-java"
            "/etc/alternatives/java_sdk"
        )
    fi
    
    for java_path in "${java_paths[@]}"; do
        if [[ -d "$java_path" && -x "$java_path/bin/java" ]]; then
            export JAVA_HOME="$java_path"
            log_debug "Found Java at: $JAVA_HOME"
            return 0
        fi
    done
    
    log_error "Java executable not found at any expected location"
    log_error "Consider using --java-home option to specify correct path"
    return 1
}

# Validate and set Java environment
setup_java_environment() {
    if [[ -n "$CUSTOM_JAVA_HOME" ]]; then
        log "Using custom JAVA_HOME: $CUSTOM_JAVA_HOME"
        if [[ ! -d "$CUSTOM_JAVA_HOME" ]] || [[ ! -x "$CUSTOM_JAVA_HOME/bin/java" ]]; then
            log_error "Invalid JAVA_HOME specified: $CUSTOM_JAVA_HOME"
            return 1
        fi
        export JAVA_HOME="$CUSTOM_JAVA_HOME"
    else
        if ! detect_java_home; then
            return 1
        fi
    fi
    
    # Update JAVA_CACERTS path now that JAVA_HOME is set
    JAVA_CACERTS="$JAVA_HOME/lib/security/cacerts"
    
    # Validate Java installation
    local java_version
    if java_version=$("$JAVA_HOME/bin/java" -version 2>&1 | head -1 | cut -d'"' -f2); then
        log "Final Java configuration:"
        log "  JAVA_HOME: $JAVA_HOME"
        log "  Java version: $java_version"
        log "  Java cacerts: $JAVA_CACERTS"
        
        if [[ "$CUSTOM_JAVA_HOME" ]]; then
            log "Custom Java installation validated: $JAVA_HOME"
        fi
        return 0
    else
        log_error "Java validation failed for: $JAVA_HOME"
        return 1
    fi
}

###############################################################################
# Access Testing Functions  
###############################################################################

# Test keystore access
check_keystore_access() {
    local keystore_file="$1"
    local keystore_pass="$2"
    local store_type="${3:-JKS}"
    
    if [[ ! -f "$keystore_file" ]]; then
        log_debug "Keystore file does not exist: $keystore_file"
        return 1
    fi
    
    # Test read access
    if [[ ! -r "$keystore_file" ]]; then
        log_error "Cannot read keystore file: $keystore_file"
        return 1
    fi
    
    # Test write access if needed
    if [[ ! -w "$keystore_file" ]]; then
        log_debug "Keystore file is read-only: $keystore_file"
    else
        log_debug "Keystore has write access"
    fi
    
    # Test keystore access with keytool
    if "$JAVA_HOME/bin/keytool" -list -keystore "$keystore_file" -storepass "$keystore_pass" -storetype "$store_type" &>/dev/null; then
        log_debug "Keystore access verified successfully"
        return 0
    else
        log_debug "Cannot access keystore with provided password"
        return 1
    fi
}

# Test Java cacerts access
check_java_cacerts_access() {
    if [[ ! -f "$JAVA_CACERTS" ]]; then
        log_error "Java cacerts file not found: $JAVA_CACERTS"
        log_error "Please verify JAVA_HOME is set correctly: $JAVA_HOME"
        return 1
    fi
    
    # Check write access
    if [[ -w "$JAVA_CACERTS" ]]; then
        log_debug "Direct write access to Java cacerts: $JAVA_CACERTS"
        export JAVA_CACERTS_NEEDS_SUDO=false
    else
        # Test sudo access
        if sudo test -w "$JAVA_CACERTS" 2>/dev/null; then
            log "Java cacerts requires sudo access: $JAVA_CACERTS"
            export JAVA_CACERTS_NEEDS_SUDO=true
        else
            log_error "Cannot write to Java cacerts file even with sudo: $JAVA_CACERTS"
            log_error "Please check file permissions and sudo access"
            return 1
        fi
    fi
    
    # Test keytool access
    local keytool_cmd="\"$JAVA_HOME/bin/keytool\" -list -keystore \"$JAVA_CACERTS\" -storepass \"changeit\""
    if [[ "$JAVA_CACERTS_NEEDS_SUDO" == "true" ]]; then
        if ! sudo bash -c "$keytool_cmd" &>/dev/null; then
            log_error "Cannot access Java cacerts with sudo even with correct password"
            return 1
        fi
    else
        if ! "$JAVA_HOME/bin/keytool" -list -keystore "$JAVA_CACERTS" -storepass "changeit" &>/dev/null; then
            log_error "Cannot access Java cacerts with direct access"
            return 1
        fi
    fi
    
    log_debug "Java cacerts access verified: $JAVA_CACERTS (sudo: $JAVA_CACERTS_NEEDS_SUDO)"
    return 0
}

###############################################################################
# Certificate Discovery and Validation Functions
###############################################################################

# Validate certificate
validate_certificate() {
    local cert_file="$1"
    local key_file="$2"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    # Basic certificate validation
    if ! openssl x509 -in "$cert_file" -text -noout &>/dev/null; then
        log_error "Invalid certificate format: $cert_file"
        return 1
    fi
    
    # Get certificate details for logging
    local subject=$(openssl x509 -in "$cert_file" -subject -noout | sed 's/subject=//')
    local issuer=$(openssl x509 -in "$cert_file" -issuer -noout | sed 's/issuer=//')
    local expiry=$(openssl x509 -in "$cert_file" -enddate -noout | sed 's/notAfter=//')
    
    log_debug "Certificate Subject: $subject"
    log_debug "Certificate Issuer: $issuer"  
    log_debug "Certificate Expires: $expiry"
    
    # Validate private key if provided
    if [[ -n "$key_file" && -f "$key_file" ]]; then
        if ! openssl rsa -in "$key_file" -check -noout &>/dev/null; then
            log_error "Invalid private key format: $key_file"
            return 1
        fi
        
        # Check if certificate and key match
        local cert_modulus=$(openssl x509 -in "$cert_file" -modulus -noout)
        local key_modulus=$(openssl rsa -in "$key_file" -modulus -noout)
        
        if [[ "$cert_modulus" != "$key_modulus" ]]; then
            log_error "Certificate and private key do not match"
            return 1
        fi
    fi
    
    log_debug "Certificate validation successful: $cert_file"
    return 0
}

# Discover certificates in source directory
discover_certificates() {
    local source_dir="$1"
    
    if [[ ! -d "$source_dir" ]]; then
        log_error "Source directory not found: $source_dir"
        return 1
    fi
    
    log "Discovering certificates in: $source_dir"
    
    # Initialize arrays for this discovery session
    CERT_FILES=()
    KEY_FILES=()
    CA_FILES=()
    
    # Find and categorize certificate files
    while IFS= read -r -d '' file; do
        local basename=$(basename "$file")
        local name_without_ext="${basename%.*}"
        
        case "$basename" in
            *ca*.crt|*CA*.crt|root-ca.*|ca-bundle.*|*-ca.*)
                CA_FILES+=("$file")
                log_debug "Found CA certificate: $file"
                ;;
            *.crt|*.pem|*cert.pem|*_cert.*)
                CERT_FILES["$name_without_ext"]="$file"
                log_debug "Found certificate: $file"
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
# Service Management Functions
###############################################################################

# Check if UBA is managed via systemd
check_systemd_management() {
    # First check if systemd services are actually active
    local active_systemd_services=0
    for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            ((active_systemd_services++))
        fi
    done
    
    # If any systemd services are active, we're using systemd
    if [[ $active_systemd_services -gt 0 ]]; then
        log "Detected active systemd service management for UBA"
        SERVICE_MANAGEMENT_METHOD="systemd"
        return 0
    fi
    
    # Check if systemd services are available but not active
    if systemctl list-units --type=service --all 2>/dev/null | grep -q caspida; then
        log "Systemd services are available but not active - will use systemd"
        SERVICE_MANAGEMENT_METHOD="systemd"
        return 0
    fi
    
    # Default to traditional management
    log "Using traditional script management for UBA"
    SERVICE_MANAGEMENT_METHOD="traditional"
    return 1
}

# Stop UBA services
stop_uba_services() {
    log "Stopping UBA services..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would stop UBA services"
        return 0
    fi
    
    # Determine management method
    check_systemd_management
    
    if [[ "$SERVICE_MANAGEMENT_METHOD" == "systemd" ]]; then
        local stop_errors=0
        for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log "Stopping $service..."
                if ! sudo systemctl stop "$service" 2>/dev/null; then
                    log_warn "Failed to stop $service"
                    ((stop_errors++))
                fi
            else
                log "Service $service is already inactive"
            fi
        done
        
        if [[ $stop_errors -gt 0 ]]; then
            log_warn "$stop_errors service(s) failed to stop via systemctl"
            return 1
        fi
    else
        # Traditional management
        if [[ -x "/opt/caspida/bin/Caspida" ]]; then
            if /opt/caspida/bin/Caspida status >/dev/null 2>&1; then
                log "Stopping UBA services via traditional scripts..."
                if ! /opt/caspida/bin/Caspida stop-all; then
                    log_warn "Failed to stop UBA services via Caspida script"
                    return 1
                fi
            else
                log "UBA services appear to be already stopped"
                return 0
            fi
        else
            log_error "Caspida management script not found at /opt/caspida/bin/Caspida"
            return 1
        fi
    fi
    
    # Wait for services to stop
    log "Waiting for services to fully stop..."
    sleep 10
    
    log "All UBA services stopped successfully"
    return 0
}

# Start UBA services
start_uba_services() {
    log "Starting UBA services..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would start UBA services"
        return 0
    fi
    
    # Use the tracked service management method
    local method_to_use="$SERVICE_MANAGEMENT_METHOD"
    if [[ -z "$method_to_use" ]]; then
        check_systemd_management
        method_to_use="$SERVICE_MANAGEMENT_METHOD"
    fi
    
    if [[ "$method_to_use" == "systemd" ]]; then
        local start_errors=0
        for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                log "Starting $service..."
                if ! sudo systemctl start "$service" 2>/dev/null; then
                    log_warn "Failed to start $service via systemd"
                    ((start_errors++))
                fi
            else
                log "Service $service is already active"
            fi
        done
        
        if [[ $start_errors -gt 0 ]]; then
            log_warn "$start_errors service(s) failed to start via systemd"
            return 1
        fi
    else
        # Traditional management
        if [[ -x "/opt/caspida/bin/Caspida" ]]; then
            if ! /opt/caspida/bin/Caspida status >/dev/null 2>&1; then
                log "Starting UBA services via traditional scripts..."
                local start_output
                if start_output=$(/opt/caspida/bin/Caspida start-all 2>&1); then
                    log "Successfully started UBA services via Caspida script"
                    log_debug "Start output: $start_output"
                    SERVICE_MANAGEMENT_METHOD="traditional"
                else
                    local exit_code=$?
                    log_warn "UBA services start command exited with code: $exit_code"
                    log_debug "Start output: $start_output"
                    SERVICE_MANAGEMENT_METHOD="traditional"
                fi
            else
                log "UBA services appear to be already running"
                return 0
            fi
        else
            log_error "Caspida management script not found at /opt/caspida/bin/Caspida"
            return 1
        fi
    fi
    
    # Wait for services to start and verify
    log "Waiting for services to fully start..."
    sleep 30
    
    # Verify services started correctly using the same method
    local verification_attempts=3
    local attempt=1
    
    while [[ $attempt -le $verification_attempts ]]; do
        log "Verifying services are running (attempt $attempt/$verification_attempts)..."
        
        if [[ "$SERVICE_MANAGEMENT_METHOD" == "systemd" ]]; then
            local not_running=0
            for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
                if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                    log_warn "$service is not yet running"
                    ((not_running++))
                fi
            done
            
            if [[ $not_running -eq 0 ]]; then
                log "All systemd services are running"
                break
            elif [[ $attempt -eq $verification_attempts ]]; then
                log_warn "$not_running systemd service(s) failed to start properly after $verification_attempts attempts"
                return 1
            fi
        else
            # Traditional management - check via Caspida script
            if /opt/caspida/bin/Caspida status >/dev/null 2>&1; then
                log "UBA services verification successful via traditional method"
                break
            elif [[ $attempt -eq $verification_attempts ]]; then
                log_warn "UBA services may not have started properly after $verification_attempts attempts (traditional method)"
                return 1
            fi
        fi
        
        log "Services still starting, waiting additional 30 seconds..."
        sleep 30
        ((attempt++))
    done
    
    log "All UBA services started successfully"
    return 0
}

# Restart UBA services
restart_uba_services() {
    log "Restarting UBA services..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restart UBA services"
        return 0
    fi
    
    if ! stop_uba_services; then
        log_warn "Failed to stop UBA services, attempting to start anyway"
    fi
    
    # Wait between stop and start
    log "Waiting between stop and start operations..."
    sleep 5
    
    if ! start_uba_services; then
        log_error "Failed to start UBA services after restart"
        return 1
    fi
    
    log "UBA services restarted successfully"
    return 0
}

###############################################################################
# Certificate Installation Functions
###############################################################################

# Generate PKCS12 file from certificate and key
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
    
    # Use FIPS-compatible algorithms
    openssl pkcs12 -export -in "$cert_file" -inkey "$key_file" -name "$alias" \
        -out "$output_file" -password "pass:$PKCS12_PASSWORD" \
        -keypbe AES-256-CBC -certpbe AES-256-CBC
    
    chmod 600 "$output_file"
    sudo chown caspida:caspida "$output_file" 2>/dev/null || true
    
    log "PKCS12 file generated successfully: $output_file"
}

# Backup existing certificates
backup_existing_certs() {
    log "Creating backup of existing certificates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would backup certificates to $BACKUP_DIR"
        return 0
    fi
    
    # Create backup directory with proper ownership
    if ! sudo mkdir -p "$BACKUP_DIR"; then
        log_error "Failed to create backup directory: $BACKUP_DIR"
        return 1
    fi
    
    sudo chown caspida:caspida "$BACKUP_DIR"
    
    # Backup existing certificates and keystores
    if [[ -d "$UBA_CERTS_DIR" ]]; then
        if cp -r "$UBA_CERTS_DIR" "$BACKUP_DIR/original_certs" 2>/dev/null; then
            sudo chown -R caspida:caspida "$BACKUP_DIR/original_certs"
            log "Backed up UBA certificates to: $BACKUP_DIR/original_certs"
        fi
    fi
    
    if [[ -f "$UBA_KEYSTORE_JM" ]]; then
        if cp "$UBA_KEYSTORE_JM" "$BACKUP_DIR/keystore.jm.backup" 2>/dev/null; then
            sudo chown caspida:caspida "$BACKUP_DIR/keystore.jm.backup"
            log "Backed up Job Manager keystore to: $BACKUP_DIR/keystore.jm.backup"
        fi
    fi
    
    if [[ -f "$UBA_SITE_PROPERTIES" ]]; then
        if cp "$UBA_SITE_PROPERTIES" "$BACKUP_DIR/uba-site.properties.backup" 2>/dev/null; then
            sudo chown caspida:caspida "$BACKUP_DIR/uba-site.properties.backup"
            log "Backed up site properties to: $BACKUP_DIR/uba-site.properties.backup"
        fi
    fi
    
    # Set final permissions
    sudo chmod -R 640 "$BACKUP_DIR"/* 2>/dev/null || true
    sudo chmod 750 "$BACKUP_DIR" 2>/dev/null || true
    
    log "Backup completed with proper ownership: $BACKUP_DIR"
}

# Set proper ownership for certificate files
set_certificate_ownership() {
    local cert_dir="$1"
    
    if [[ -z "$cert_dir" ]]; then
        log_error "Certificate directory not specified for ownership setting"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would set certificate ownership for: $cert_dir"
        return 0
    fi
    
    if [[ -d "$cert_dir" ]]; then
        log "Setting proper ownership and permissions for certificate files in: $cert_dir"
        
        # Set ownership to caspida:caspida
        if sudo chown -R caspida:caspida "$cert_dir" 2>/dev/null; then
            log "Certificate directory ownership set to caspida:caspida"
        else
            log_warn "Failed to set ownership for certificate directory"
        fi
        
        # Set secure permissions: 640 for files, 750 for directories
        if find "$cert_dir" -type f -exec chmod 640 {} \; 2>/dev/null && \
           find "$cert_dir" -type d -exec chmod 750 {} \; 2>/dev/null; then
            log "Certificate file permissions set: files=640, dirs=750"
        else
            log_warn "Failed to set some permissions for certificate files"
        fi
        
        log "Certificate ownership and permissions set successfully"
    else
        log_warn "Certificate directory not found: $cert_dir"
    fi
}

# Install UI certificates
install_ui_certificates() {
    log "Installing UI certificates..."
    
    # Find UBA server certificate
    local uba_hostname=$(hostname -s)
    local cert_file=""
    local key_file=""
    
    # Try to find matching certificate
    for name in "$uba_hostname" "uba" "server" "$(hostname -f)" "test-host"; do
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
    
    # Set proper ownership for UI certificate files
    sudo chown caspida:caspida "$custom_cert" "$custom_key" 2>/dev/null || true
    chmod 640 "$custom_cert" "$custom_key" 2>/dev/null || true
    
    # Install CA certificate if available
    if [[ "${#CA_FILES[@]}" -gt 0 ]]; then
        cp "${CA_FILES[0]}" "$custom_ca"
        sudo chown caspida:caspida "$custom_ca" 2>/dev/null || true
        chmod 640 "$custom_ca" 2>/dev/null || true
    fi
    
    # Update uba-site.properties
    update_site_properties "$custom_ca" "$custom_key" "$custom_cert"
    
    log "UI certificates installed successfully"
}

# Install Job Manager certificates
install_job_manager_certificates() {
    log "Installing Job Manager certificates..."
    
    # Find Job Manager certificate (try same patterns as UI)
    local uba_hostname=$(hostname -s)
    local jm_cert=""
    local jm_key=""
    
    for name in "$uba_hostname" "uba" "server" "$(hostname -f)" "test-host"; do
        if [[ -n "${CERT_FILES[$name]:-}" ]]; then
            jm_cert="${CERT_FILES[$name]}"
            jm_key="${KEY_FILES[$name]:-}"
            break
        fi
    done
    
    if [[ -z "$jm_cert" ]]; then
        log_warn "No matching certificate found for Job Manager"
        return 1
    fi
    
    if [[ -z "$jm_key" ]]; then
        log_error "Private key not found for certificate: $jm_cert"
        return 1
    fi
    
    # Validate keystore access
    if [[ -f "$UBA_KEYSTORE_JM" ]]; then
        if ! check_keystore_access "$UBA_KEYSTORE_JM" "$PKCS12_PASSWORD" "JKS"; then
            log_debug "Keystore access verified: $UBA_KEYSTORE_JM"
        fi
    fi
    
    if [[ "$VALIDATE_CERTS" == "true" ]]; then
        if ! validate_certificate "$jm_cert" "$jm_key"; then
            log_error "Certificate validation failed for Job Manager certificates"
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
        local backup_file="$UBA_KEYSTORE_JM.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$UBA_KEYSTORE_JM" "$backup_file"
        sudo chown caspida:caspida "$backup_file" 2>/dev/null || true
        log "Backed up Job Manager keystore to: $backup_file"
    fi
    
    # Create keystore directory if needed
    if [[ ! -f "$UBA_KEYSTORE_JM" ]]; then
        log "Creating new Job Manager keystore: $UBA_KEYSTORE_JM"
        sudo mkdir -p "$(dirname "$UBA_KEYSTORE_JM")"
        sudo chown caspida:caspida "$(dirname "$UBA_KEYSTORE_JM")" 2>/dev/null || true
    fi
    
    # Remove existing alias if present
    if "$JAVA_HOME/bin/keytool" -list -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD" -alias "jmserver" &>/dev/null; then
        log "Removing existing 'jmserver' certificate from keystore"
        "$JAVA_HOME/bin/keytool" -delete -alias "jmserver" -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD"
        if [[ $? -eq 0 ]]; then
            log "Successfully removed existing 'jmserver' certificate"
        else
            log_error "Failed to remove existing 'jmserver' certificate"
            return 1
        fi
    fi
    
    # Import new certificate
    "$JAVA_HOME/bin/keytool" -importkeystore -destkeystore "$UBA_KEYSTORE_JM" -srckeystore "$pkcs12_file" \
        -srcstoretype PKCS12 -deststorepass "$PKCS12_PASSWORD" -srcstorepass "$PKCS12_PASSWORD" \
        -srcalias "jmserver" -destalias "jmserver" -noprompt
    
    # Verify import
    if "$JAVA_HOME/bin/keytool" -list -v -keystore "$UBA_KEYSTORE_JM" -storepass "$PKCS12_PASSWORD" | grep -q "jmserver"; then
        log "Job Manager certificate installed successfully"
        return 0
    else
        log_error "Failed to verify Job Manager certificate installation"
        return 1
    fi
}

# Install search head certificates to Java truststore
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
    
    if ! check_java_cacerts_access; then
        log_error "Cannot access Java cacerts, aborting CA certificate installation"
        return 1
    fi
    
    # Backup Java cacerts
    local backup_file="$JAVA_CACERTS.backup.$(date +%Y%m%d_%H%M%S)"
    if [[ "$JAVA_CACERTS_NEEDS_SUDO" == "true" ]]; then
        if ! sudo cp "$JAVA_CACERTS" "$backup_file"; then
            log_error "Failed to backup Java cacerts with sudo"
            return 1
        fi
        sudo chown caspida:caspida "$backup_file" 2>/dev/null || true
    else
        if ! cp "$JAVA_CACERTS" "$backup_file"; then
            log_error "Failed to backup Java cacerts"
            return 1
        fi
        sudo chown caspida:caspida "$backup_file" 2>/dev/null || true
    fi
    log "Java cacerts backed up to: $backup_file"
    
    local cert_count=0
    for ca_file in "${CA_FILES[@]}"; do
        if [[ "$VALIDATE_CERTS" == "true" ]]; then
            if ! validate_certificate "$ca_file" ""; then
                log_warn "Skipping invalid CA certificate: $ca_file"
                continue
            fi
        fi
        
        local alias="uba_ca_$(basename "$ca_file" .crt)_$cert_count"
        
        # Import CA certificate
        local keytool_cmd="\"$JAVA_HOME/bin/keytool\" -import -alias \"$alias\" -file \"$ca_file\" -keystore \"$JAVA_CACERTS\" -storepass \"changeit\" -noprompt"
        
        if [[ "$JAVA_CACERTS_NEEDS_SUDO" == "true" ]]; then
            if sudo bash -c "$keytool_cmd"; then
                log "CA certificate imported successfully: $ca_file"
                ((cert_count++))
            else
                log_warn "Failed to import CA certificate: $ca_file"
            fi
        else
            if "$JAVA_HOME/bin/keytool" -import -alias "$alias" -file "$ca_file" -keystore "$JAVA_CACERTS" -storepass "changeit" -noprompt; then
                log "CA certificate imported successfully: $ca_file"
                ((cert_count++))
            else
                log_warn "Failed to import CA certificate: $ca_file"
            fi
        fi
    done
    
    if [[ $cert_count -gt 0 ]]; then
        log "Search head certificates installation completed: $cert_count certificates imported"
        return 0
    else
        log_error "No CA certificates were successfully imported"
        return 1
    fi
}

# Update UBA site properties
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
    sudo mkdir -p "$(dirname "$UBA_SITE_PROPERTIES")"
    sudo chown caspida:caspida "$(dirname "$UBA_SITE_PROPERTIES")" 2>/dev/null || true
    
    # Create or update properties file
    if [[ ! -f "$UBA_SITE_PROPERTIES" ]]; then
        cat > "$UBA_SITE_PROPERTIES" << EOF
##
# UBA Site Properties - Certificate Configuration
# Generated by $SCRIPT_NAME on $(date)
##

EOF
    fi
    
    # Remove existing certificate properties
    sed -i '/^# Certificate configuration - Added/,/^ui\.auth\.serverCert=/d' "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    sed -i '/^ui\.auth\./d' "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    
    # Add new certificate properties
    cat >> "$UBA_SITE_PROPERTIES" << EOF

# Certificate configuration - Added $(date)
ui.auth.rootca=$root_ca
ui.auth.privateKey=$private_key
ui.auth.serverCert=$server_cert

EOF
    
    sudo chown caspida:caspida "$UBA_SITE_PROPERTIES" 2>/dev/null || true
    chmod 644 "$UBA_SITE_PROPERTIES"
    
    log "Site properties updated successfully"
}

###############################################################################
# Usage and Help Functions
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
    -j, --java-home PATH        Custom JAVA_HOME path (auto-detected if not specified)
    -l, --log-file FILE         Custom log file path (default: timestamped in /var/log/caspida/)
    -b, --backup-dir DIR        Custom backup directory (default: timestamped in /opt/caspida/cert_backups/)
    
FEATURE FLAGS:
    --no-ui                     Skip UI certificate installation
    --no-job-manager           Skip Job Manager certificate installation  
    --no-search-head           Skip search head certificate installation
    --no-uba-keystore          Skip UBA internal keystore installation
    --enable-kafka             Enable Kafka certificate installation (disabled by default)
    --no-validation            Skip certificate validation
    --no-restart               Skip service restart after installation
    
REMOTE CERTIFICATE OPTIONS:
    --pull-from HOST[:PORT]     Pull certificates from remote Splunk instance
                               (can be specified multiple times, default port: 8000)
    --test-connectivity         Test connectivity to specified hosts without installing
    
EXECUTION OPTIONS:
    --dry-run                   Show what would be done without making changes
    -v, --verbose              Enable verbose output
    -h, --help                 Show this help message

EXAMPLES:
    # Basic certificate installation
    $SCRIPT_NAME -s /path/to/certificates

    # Installation with custom Java and verbose output
    $SCRIPT_NAME -s /path/to/certificates --java-home /usr/lib/jvm/java-8-oracle -v

    # Pull certificates from Splunk instances and install
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239:8000 --pull-from splunk.company.com:8089

    # Test connectivity to Splunk instances
    $SCRIPT_NAME -s /tmp/certs --pull-from 192.168.1.239:8000 --test-connectivity --dry-run

    # Dry run to see what would be done
    $SCRIPT_NAME -s /opt/certs --dry-run

FILES MANAGED:
    - UBA Site Properties: $UBA_SITE_PROPERTIES
    - Job Manager Keystore: $UBA_KEYSTORE_JM
    - UBA Internal Keystore: $UBA_KEYSTORE
    - Java CA Certificates: \$JAVA_HOME/lib/security/cacerts
    - Custom Certificates: $UBA_CUSTOM_CERTS_DIR

For more information, see the UBA documentation at:
https://docs.splunk.com/Documentation/UBA/latest/Install/Certificate
EOF
}

###############################################################################
# Argument Parsing Function
###############################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--source-dir)
                CERT_SOURCE_DIR="$2"
                shift 2
                ;;
            -j|--java-home)
                CUSTOM_JAVA_HOME="$2"
                shift 2
                ;;
            -l|--log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            -b|--backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --no-ui)
                INSTALL_UI_CERTS=false
                shift
                ;;
            --no-job-manager)
                INSTALL_JM_CERTS=false
                shift
                ;;
            --no-search-head)
                INSTALL_SEARCH_HEAD_CERTS=false
                shift
                ;;
            --no-uba-keystore)
                INSTALL_UBA_KEYSTORE=false
                shift
                ;;
            --enable-kafka)
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
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$CERT_SOURCE_DIR" ]]; then
        log_error "Source directory is required. Use -s or --source-dir"
        usage
        exit 1
    fi
}

###############################################################################
# Main Execution Function
###############################################################################

main() {
    # Initialize runtime variables first
    initialize_runtime_variables
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Print status information
    print_status "UBA Certificate Installation Script v$SCRIPT_VERSION"
    print_status "Source Directory: $CERT_SOURCE_DIR"
    [[ -n "$CUSTOM_JAVA_HOME" ]] && print_status "Custom JAVA_HOME: $CUSTOM_JAVA_HOME"
    print_status "Log File: $LOG_FILE"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Start logging
    log "Starting UBA certificate installation process"
    log "Source directory: $CERT_SOURCE_DIR"
    [[ -n "$CUSTOM_JAVA_HOME" ]] && log "Using custom JAVA_HOME: $CUSTOM_JAVA_HOME"
    log "Configuration: UI=$INSTALL_UI_CERTS, JM=$INSTALL_JM_CERTS, SearchHead=$INSTALL_SEARCH_HEAD_CERTS, UBA_Keystore=$INSTALL_UBA_KEYSTORE"
    
    # Setup Java environment
    log "Checking prerequisites..."
    if ! setup_java_environment; then
        log_error "Java environment setup failed"
        exit 1
    fi
    
    # Test access to existing keystores
    log "Testing existing UBA keystore access..."
    if ! check_java_cacerts_access; then
        log_error "Java cacerts access check failed"
        exit 1
    fi
    
    # Test connectivity if requested
    if [[ "$TEST_CONNECTIVITY" == "true" ]]; then
        log "Test connectivity mode - exiting after connectivity tests"
        exit 0
    fi
    
    # Discover certificates
    log "Starting certificate processing..."
    if ! discover_certificates "$CERT_SOURCE_DIR"; then
        log_error "Certificate discovery failed"
        exit 1
    fi
    
    # Check if certificates were found
    if [[ "${#CERT_FILES[@]}" -eq 0 ]]; then
        log_error "No certificates found in source directory: $CERT_SOURCE_DIR"
        exit 1
    fi
    
    # Create required directories
    if [[ "$DRY_RUN" == "false" ]]; then
        sudo mkdir -p "$UBA_CUSTOM_CERTS_DIR" "$BACKUP_DIR" "$(dirname "$LOG_FILE")"
        sudo chown caspida:caspida "$UBA_CUSTOM_CERTS_DIR" "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true
    fi
    
    # Backup existing certificates
    if ! backup_existing_certs; then
        log_error "Failed to backup existing certificates"
        exit 1
    fi
    
    # Stop UBA services if restart is enabled
    if [[ "$RESTART_SERVICES" == "true" ]]; then
        if ! stop_uba_services; then
            log_warn "Failed to stop UBA services, continuing anyway"
        fi
    fi
    
    # Install certificates based on configuration
    local install_errors=0
    
    if [[ "$INSTALL_UI_CERTS" == "true" ]]; then
        if ! install_ui_certificates; then
            log_error "UI certificate installation failed"
            ((install_errors++))
        fi
    fi
    
    if [[ "$INSTALL_JM_CERTS" == "true" ]]; then
        if ! install_job_manager_certificates; then
            log_error "Job Manager certificate installation failed"
            ((install_errors++))
        fi
    fi
    
    if [[ "$INSTALL_SEARCH_HEAD_CERTS" == "true" ]]; then
        if ! install_search_head_certificates; then
            log_error "Search head certificate installation failed"
            ((install_errors++))
        fi
    fi
    
    # Set proper ownership for certificate files
    if ! set_certificate_ownership "$UBA_CUSTOM_CERTS_DIR"; then
        log_warn "Failed to set proper ownership for certificate directory"
    fi
    
    # Check for installation errors
    if [[ $install_errors -gt 0 ]]; then
        log_error "$install_errors certificate installation(s) failed"
        if [[ "$RESTART_SERVICES" == "true" ]]; then
            log "Attempting to start services anyway..."
        else
            exit 1
        fi
    fi
    
    # Restart services if requested
    if [[ "$RESTART_SERVICES" == "true" ]]; then
        if ! restart_uba_services; then
            log_error "Failed to restart UBA services"
            exit 1
        fi
    fi
    
    # Final success message
    print_success "UBA certificate installation completed successfully"
    log "Certificate installation process completed successfully"
    log "Log file: $LOG_FILE"
    log "Backup directory: $BACKUP_DIR"
    
    return 0
}

###############################################################################
# Script Entry Point
###############################################################################

# Only run main function if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
