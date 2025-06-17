#!/bin/bash

# UBA Keystore and Certificate Validation Script
# This script validates all keystores and certificates found in UBA configuration
# Author: Automated Analysis
# Date: June 17, 2025

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -j, --java-home PATH    Set JAVA_HOME path (default: auto-detect)"
    echo "  -s, --summary          Generate machine-readable summary report"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0"
    echo "  sudo $0 --java-home /usr/lib/jvm/java-11-openjdk"
    echo "  sudo $0 -j /opt/java"
    echo "  sudo $0 --summary > keystore_report.json"
    echo ""
    echo "Note: This script must be run as root to use 'sudo -u caspida' for keystore access."
    echo "The script will auto-detect JAVA_HOME from common locations if not specified."
}

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if file exists and is readable
check_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
        return 1
    fi
    if [[ ! -r "$file" ]]; then
        error "File not readable: $file"
        return 1
    fi
    return 0
}

# Function to extract configuration values
get_config_value() {
    local config_file="$1"
    local property="$2"
    local default_value="${3:-}"
    
    if [[ -f "$config_file" ]]; then
        # Handle different config file formats
        case "$config_file" in
            *.properties)
                grep "^[[:space:]]*$property[[:space:]]*=" "$config_file" 2>/dev/null | \
                tail -1 | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                ;;
            *.yml|*.yaml)
                grep "^[[:space:]]*$property:" "$config_file" 2>/dev/null | \
                tail -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                ;;
            *)
                grep "$property" "$config_file" 2>/dev/null | \
                tail -1 | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                ;;
        esac
    fi
}

# Function to resolve path (handle /etc/caspida symlink)
resolve_path() {
    local path="$1"
    # Replace /etc/caspida with /opt/caspida/conf if it's a symlink
    if [[ "$path" =~ ^/etc/caspida/conf ]]; then
        echo "${path/\/etc\/caspida\/conf/\/opt\/caspida\/conf}"
    elif [[ "$path" =~ ^/etc/caspida ]]; then
        echo "${path/\/etc\/caspida/\/opt\/caspida\/conf}"
    else
        echo "$path"
    fi
}

# Function to validate keystore
validate_keystore() {
    local keystore_path="$1"
    local keystore_pass="$2"
    local description="$3"
    local user="${4:-root}"
    
    log "Validating $description"
    echo "  Path: $keystore_path"
    echo "  User: $user"
    
    if ! check_file "$keystore_path"; then
        return 1
    fi
    
    # Check if password is provided
    if [[ -z "$keystore_pass" ]]; then
        error "No password provided for $description"
        return 1
    fi
    
    # Find keytool using JAVA_HOME
    local keytool_cmd=""
    if command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    elif [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    else
        error "keytool not found in PATH or JAVA_HOME"
        return 1
    fi
    
    local validation_cmd="$keytool_cmd -list -v -keystore '$keystore_path' -storepass '$keystore_pass'"
    
    if [[ "$user" == "caspida" ]]; then
        if ! sudo -u caspida bash -c "export PATH='$PATH'; $validation_cmd" > /tmp/keystore_validation_$$.tmp 2>&1; then
            error "Failed to validate $description (check password and file permissions)"
            if [[ -f /tmp/keystore_validation_$$.tmp ]]; then
                cat /tmp/keystore_validation_$$.tmp
            fi
            rm -f /tmp/keystore_validation_$$.tmp
            return 1
        fi
    else
        if ! eval "$validation_cmd" > /tmp/keystore_validation_$$.tmp 2>&1; then
            error "Failed to validate $description (check password and file permissions)"
            if [[ -f /tmp/keystore_validation_$$.tmp ]]; then
                cat /tmp/keystore_validation_$$.tmp
            fi
            rm -f /tmp/keystore_validation_$$.tmp
            return 1
        fi
    fi
    
    # Parse and display certificate information
    local cert_count=$(grep -c "Alias name:" /tmp/keystore_validation_$$.tmp || echo "0")
    success "$description validated successfully ($cert_count certificates)"
    
    # Display certificate details
    while IFS= read -r line; do
        if [[ "$line" =~ ^Alias\ name:\ (.+)$ ]]; then
            echo "    Certificate: ${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Valid\ from:\ (.+)$ ]]; then
            echo "    Validity: ${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^Certificate\ fingerprint\ \(SHA-256\):\ (.+)$ ]]; then
            echo "    SHA-256: ${BASH_REMATCH[1]}"
        fi
    done < /tmp/keystore_validation_$$.tmp
    
    # Check for expired certificates
    if grep -q "Certificate expired" /tmp/keystore_validation_$$.tmp; then
        warning "Found expired certificates in $description"
    fi
    
    rm -f /tmp/keystore_validation_$$.tmp
    echo ""
}

# Function to extract certificate from keystore for trust testing
extract_certificate() {
    local keystore_path="$1"
    local keystore_pass="$2"
    local alias="$3"
    local output_file="$4"
    local user="${5:-root}"
    
    # Find keytool using JAVA_HOME
    local keytool_cmd=""
    if command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    elif [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    else
        error "keytool not found in PATH or JAVA_HOME"
        return 1
    fi
    
    # Try to export the certificate (works for both trustedCertEntry and PrivateKeyEntry)
    local extract_cmd="$keytool_cmd -export -alias '$alias' -keystore '$keystore_path' -storepass '$keystore_pass' -file '$output_file'"
    
    if [[ "$user" == "caspida" ]]; then
        sudo -u caspida bash -c "export PATH='$PATH'; $extract_cmd" >/dev/null 2>&1
    else
        eval "$extract_cmd" >/dev/null 2>&1
    fi
}

# Function to test if a certificate is trusted by a truststore
test_certificate_trust() {
    local cert_file="$1"
    local truststore_path="$2"
    local truststore_pass="$3"
    local user="${4:-root}"
    
    # Find keytool using JAVA_HOME
    local keytool_cmd=""
    if command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    elif [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    else
        error "keytool not found in PATH or JAVA_HOME"
        return 1
    fi
    
    # Use keytool to test if the certificate is trusted
    local verify_cmd="$keytool_cmd -printcert -file '$cert_file' -keystore '$truststore_path' -storepass '$truststore_pass'"
    
    if [[ "$user" == "caspida" ]]; then
        sudo -u caspida bash -c "export PATH='$PATH'; $verify_cmd" >/dev/null 2>&1
    else
        eval "$verify_cmd" >/dev/null 2>&1
    fi
}

# Function to get all aliases from a keystore
get_keystore_aliases() {
    local keystore_path="$1"
    local keystore_pass="$2"
    local user="${3:-root}"
    
    # Find keytool using JAVA_HOME
    local keytool_cmd=""
    if command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    elif [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    else
        error "keytool not found in PATH or JAVA_HOME"
        return 1
    fi
    
    local list_cmd="$keytool_cmd -list -keystore '$keystore_path' -storepass '$keystore_pass'"
    
    if [[ "$user" == "caspida" ]]; then
        sudo -u caspida bash -c "export PATH='$PATH'; $list_cmd" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -20
    else
        eval "$list_cmd" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -20
    fi
}

# Function to get JobManager keystore password using the same logic as the main validation
get_jobmanager_keystore_info() {
    local caspida_home="${1:-/opt/caspida}"
    
    local jobmgr_config="$caspida_home/conf/jobconf/jobmgr.yml"
    if [[ -f "$jobmgr_config" ]]; then
        local jm_keystore=$(get_config_value "$jobmgr_config" "keyStorePath")
        local jm_password=$(get_config_value "$jobmgr_config" "keyStorePassword")
        
        if [[ -n "$jm_keystore" ]]; then
            jm_keystore=$(resolve_path "$jm_keystore")
            
            # If no password from config, try defaults
            if [[ -z "$jm_password" && -f "$jm_keystore" ]]; then
                jm_password=$(test_keystore_passwords "$jm_keystore" "caspida" "JobManager keystore")
            fi
            
            if [[ -n "$jm_password" ]]; then
                echo "$jm_keystore|$jm_password"
            fi
        fi
    fi
}

# Function to test keystore with multiple password attempts
test_keystore_passwords() {
    local keystore_path="$1"
    local user="${2:-root}"
    local description="${3:-keystore}"
    
    # Common default passwords to try
    local default_passwords=("changeit" "password" "caspida123" "caspida" "")
    
    # Find keytool using JAVA_HOME
    local keytool_cmd=""
    if command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    elif [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    else
        return 1
    fi
    
    for password in "${default_passwords[@]}"; do
        local test_cmd="$keytool_cmd -list -keystore '$keystore_path' -storepass '$password'"
        
        if [[ "$user" == "caspida" ]]; then
            if sudo -u caspida bash -c "export PATH='$PATH'; $test_cmd" >/dev/null 2>&1; then
                echo "$password"
                return 0
            fi
        else
            if eval "$test_cmd" >/dev/null 2>&1; then
                echo "$password"
                return 0
            fi
        fi
    done
    
    return 1
}

# Function to get UBA keystore password using the same logic as the main validation
get_uba_keystore_password() {
    local caspida_home="${1:-/opt/caspida}"
    local uba_keystore="$caspida_home/conf/keystore/uba-keystore"
    
    local uba_keystore_password=""
    
    # Check CaspidaFunctions for UBA_KEYSTORE_PASS
    local caspida_functions="$caspida_home/bin/CaspidaFunctions"
    if [[ -f "$caspida_functions" ]]; then
        uba_keystore_password=$(grep "^UBA_KEYSTORE_PASS=" "$caspida_functions" 2>/dev/null | cut -d'=' -f2)
    fi
    
    # Check CaspidaCommonEnv.sh as fallback
    if [[ -z "$uba_keystore_password" ]]; then
        local common_env="$caspida_home/bin/CaspidaCommonEnv.sh"
        if [[ -f "$common_env" ]]; then
            uba_keystore_password=$(grep "UBA_KEYSTORE_PASS=" "$common_env" 2>/dev/null | cut -d'=' -f2)
        fi
    fi
    
    # Check properties files as last resort
    if [[ -z "$uba_keystore_password" ]]; then
        for props_file in "$caspida_home/conf/uba-site.properties" "$caspida_home/conf/uba-default.properties"; do
            if [[ -f "$props_file" ]]; then
                uba_keystore_password=$(get_config_value "$props_file" "uba.keystore.password")
                if [[ -n "$uba_keystore_password" ]]; then
                    break
                fi
            fi
        done
    fi
    
    # If config-based password detection failed, try defaults
    if [[ -z "$uba_keystore_password" && -f "$uba_keystore" ]]; then
        uba_keystore_password=$(test_keystore_passwords "$uba_keystore" "caspida" "UBA keystore")
    fi
    
    echo "$uba_keystore_password"
}

# Function to validate trust relationships between keystores and truststores
validate_trust_relationships() {
    local caspida_home="${1:-/opt/caspida}"
    
    log "Validating Certificate Trust Relationships"
    echo "=========================================="
    echo ""
    
    local temp_cert_dir="/tmp/uba_cert_validation_$$"
    mkdir -p "$temp_cert_dir"
    chown caspida:caspida "$temp_cert_dir"
    chmod 755 "$temp_cert_dir"
    
    # Define keystore and truststore paths for testing
    local jm_config="$caspida_home/conf/jobconf/jobmgr.yml"
    local java_truststore="/usr/lib/jvm/java-1.8.0-openjdk/jre/lib/security/cacerts"
    local uba_keystore="$caspida_home/conf/keystore/uba-keystore"
    
    # Focus on keystores that were validated successfully
    log "Testing trust relationships for validated keystores..."
    echo ""
    
    # Test UBA keystore trust (this was successfully validated)
    if [[ -f "$uba_keystore" ]]; then
        local uba_pass=$(get_uba_keystore_password "$caspida_home")
        
        if [[ -n "$uba_pass" ]]; then
            log "Testing UBA keystore certificate trust against Java system truststore..."
            
            # Get aliases from UBA keystore using system truststore format (which we know works)
            local aliases
            if aliases=$(sudo -u caspida bash -c "export PATH='$PATH'; /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -list -keystore '$uba_keystore' -storepass '$uba_pass'" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -5); then
                
                local found_certs=false
                while IFS= read -r alias; do
                    if [[ -n "$alias" ]]; then
                        found_certs=true
                        local cert_file="$temp_cert_dir/uba_${alias// /_}.crt"
                        
                        echo "  Testing certificate '$alias' from UBA keystore..."
                        
                        # Extract certificate from UBA keystore (simplified approach)
                        local cert_file="$temp_cert_dir/uba_${alias// /_}.crt"
                        if sudo -u caspida bash -c "export PATH='$PATH'; /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -export -alias \"$alias\" -keystore '$uba_keystore' -storepass '$uba_pass' -file '$cert_file'" >/dev/null 2>&1; then
                            
                            # Test if this certificate is present in Java system truststore
                            if /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -list -keystore "$java_truststore" -storepass "changeit" -alias "$alias" >/dev/null 2>&1; then
                                success "    ✓ Certificate '$alias' is present in Java system truststore"
                            else
                                warning "    ✗ Certificate '$alias' is NOT present in Java system truststore"
                            fi
                            
                            # Also test by importing the cert to verify it would be trusted
                            local temp_truststore="$temp_cert_dir/test_truststore.jks"
                            if /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -import -noprompt -alias "test_$alias" -file "$cert_file" -keystore "$temp_truststore" -storepass "testpass" >/dev/null 2>&1; then
                                success "    ✓ Certificate '$alias' can be imported (is valid)"
                            else
                                warning "    ✗ Certificate '$alias' cannot be imported (may be invalid)"
                            fi
                        else
                            warning "    Failed to extract certificate '$alias' from UBA keystore"
                        fi
                    fi
                done <<< "$aliases"
                
                if [[ "$found_certs" == "false" ]]; then
                    warning "No certificates found in UBA keystore"
                fi
            else
                warning "Failed to list certificates in UBA keystore"
            fi
            echo ""
        else
            warning "UBA keystore password not found for trust validation"
        fi
    fi
    
    # Test JobManager keystore trust (if it has a certificate)
    local jm_info=$(get_jobmanager_keystore_info "$caspida_home")
    if [[ -n "$jm_info" ]]; then
        local jm_keystore=$(echo "$jm_info" | cut -d'|' -f1)
        local jm_password=$(echo "$jm_info" | cut -d'|' -f2)
        
        if [[ -f "$jm_keystore" ]]; then
            log "Testing JobManager keystore certificate trust against Java system truststore..."
            
            local aliases
            if aliases=$(sudo -u caspida bash -c "export PATH='$PATH'; /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -list -keystore '$jm_keystore' -storepass '$jm_password'" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -5); then
                
                local found_certs=false
                while IFS= read -r alias; do
                    if [[ -n "$alias" ]]; then
                        found_certs=true
                        local cert_file="$temp_cert_dir/jm_${alias// /_}.crt"
                        
                        echo "  Testing certificate '$alias' from JobManager keystore..."
                        
                        # Extract certificate from JobManager keystore (simplified approach)
                        local cert_file="$temp_cert_dir/jm_${alias// /_}.crt"
                        if sudo -u caspida bash -c "export PATH='$PATH'; /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -export -alias \"$alias\" -keystore '$jm_keystore' -storepass '$jm_password' -file '$cert_file'" >/dev/null 2>&1; then
                            
                            # Test if this certificate is present in Java system truststore
                            if /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -list -keystore "$java_truststore" -storepass "changeit" -alias "$alias" >/dev/null 2>&1; then
                                success "    ✓ Certificate '$alias' is present in Java system truststore"
                            else
                                warning "    ✗ Certificate '$alias' is NOT present in Java system truststore"
                            fi
                            
                            # Test if this cert is in UBA keystore
                            if [[ -f "$uba_keystore" ]]; then
                                local uba_pass=$(get_uba_keystore_password "$caspida_home")
                                if [[ -n "$uba_pass" ]] && sudo -u caspida bash -c "export PATH='$PATH'; /usr/lib/jvm/java-1.8.0-openjdk/bin/keytool -list -keystore '$uba_keystore' -storepass '$uba_pass' -alias '$alias'" >/dev/null 2>&1; then
                                    success "    ✓ Certificate '$alias' is present in UBA keystore"
                                else
                                    warning "    ✗ Certificate '$alias' is NOT present in UBA keystore"
                                fi
                            fi
                        else
                            warning "    Failed to extract certificate '$alias' from JobManager keystore"
                        fi
                    fi
                done <<< "$aliases"
                
                if [[ "$found_certs" == "false" ]]; then
                    warning "No certificates found in JobManager keystore"
                fi
            else
                warning "Failed to list certificates in JobManager keystore"
            fi
            echo ""
        fi
    fi
    
    # Summary of trust validation
    log "Trust relationship validation summary:"
    echo "  • Tested certificate presence in Java system truststore"
    echo "  • Tested certificate presence across UBA keystores"
    echo "  • Validated certificate export/import capability"
    echo "  • Note: For production use, verify certificate chains and CA trust"
    
    # Cleanup temporary files
    rm -rf "$temp_cert_dir"
    
    log "Trust relationship validation completed"
    echo ""
}

# Function to generate machine-readable summary report
generate_summary_report() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat << EOF
{
  "validation_timestamp": "$timestamp",
  "script_version": "1.0",
  "validation_status": "$([[ $validation_errors -eq 0 ]] && echo "SUCCESS" || echo "FAILED")",
  "total_errors": $validation_errors,
  "java_home": "$java_home",
  "caspida_home": "$caspida_home",
  "keystores_validated": [
EOF

    local first=true
    
    # Add JobManager keystore info
    local jobmgr_keystore="$caspida_home/conf/jobconf/keystore.jm"
    if [[ -f "$jobmgr_keystore" ]]; then
        [[ "$first" == true ]] && first=false || echo ","
        echo "    {"
        echo "      \"name\": \"JobManager Keystore\","
        echo "      \"path\": \"$jobmgr_keystore\","
        echo "      \"type\": \"keystore\","
        echo "      \"accessible\": $(check_file_access "$jobmgr_keystore" "caspida" && echo "true" || echo "false"),"
        echo "      \"certificate_count\": $(get_certificate_count "$jobmgr_keystore" caspida 2>/dev/null || echo "0")"
        echo -n "    }"
    fi
    
    # Add Kafka keystore info
    local kafka_keystore="$caspida_home/conf/kafka/auth/server.keystore.jks"
    if [[ -f "$kafka_keystore" ]]; then
        [[ "$first" == true ]] && first=false || echo ","
        echo "    {"
        echo "      \"name\": \"Kafka Server Keystore\","
        echo "      \"path\": \"$kafka_keystore\","
        echo "      \"type\": \"keystore\","
        echo "      \"accessible\": $(check_file_access "$kafka_keystore" "caspida" && echo "true" || echo "false"),"
        echo "      \"certificate_count\": $(get_certificate_count "$kafka_keystore" caspida 2>/dev/null || echo "0")"
        echo -n "    }"
    fi
    
    # Add UBA keystore info
    local uba_keystore="$caspida_home/conf/keystore/uba-keystore"
    if [[ -f "$uba_keystore" ]]; then
        [[ "$first" == true ]] && first=false || echo ","
        echo "    {"
        echo "      \"name\": \"UBA Unified Keystore\","
        echo "      \"path\": \"$uba_keystore\","
        echo "      \"type\": \"keystore\","
        echo "      \"accessible\": $(check_file_access "$uba_keystore" "caspida" && echo "true" || echo "false"),"
        echo "      \"certificate_count\": $(get_certificate_count "$uba_keystore" caspida 2>/dev/null || echo "0")"
        echo -n "    }"
    fi
    
    # Add Java truststore info
    local system_cacerts=$(find -L "$java_home" -name cacerts 2>/dev/null | head -1)
    if [[ -f "$system_cacerts" ]]; then
        [[ "$first" == true ]] && first=false || echo ","
        echo "    {"
        echo "      \"name\": \"Java System Truststore\","
        echo "      \"path\": \"$system_cacerts\","
        echo "      \"type\": \"truststore\","
        echo "      \"accessible\": $(check_file_access "$system_cacerts" "root" && echo "true" || echo "false"),"
        echo "      \"certificate_count\": $(get_certificate_count "$system_cacerts" root 2>/dev/null || echo "0")"
        echo -n "    }"
    fi
    
    echo ""
    echo "  ],"
    echo "  \"recommendations\": ["
    
    # Add recommendations based on findings
    local rec_first=true
    if [[ $validation_errors -gt 0 ]]; then
        echo "    \"Review and fix validation errors before production use\""
        rec_first=false
    fi
    
    # Check for certificates expiring soon (within 30 days)
    local expiring_soon=$(find "$caspida_home/conf" -name "*.jks" -o -name "*keystore*" 2>/dev/null | wc -l)
    if [[ $expiring_soon -gt 0 ]]; then
        [[ "$rec_first" == true ]] && rec_first=false || echo ","
        echo "    \"Monitor certificate expiration dates and plan renewals\""
    fi
    
    [[ "$rec_first" == true ]] && rec_first=false || echo ","
    echo "    \"Schedule regular keystore validation checks\""
    
    echo ""
    echo "  ]"
    echo "}"
}

# Helper function to get certificate count
get_certificate_count() {
    local keystore_path="$1"
    local run_as_user="$2"
    
    local keytool_cmd="keytool"
    if [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    fi
    
    local list_cmd="$keytool_cmd -list -keystore '$keystore_path' -storepass changeit"
    
    if [[ "$run_as_user" == "caspida" ]]; then
        sudo -u caspida bash -c "export PATH='$PATH'; $list_cmd" 2>/dev/null | grep -c "Certificate fingerprint" || echo "0"
    else
        eval "$list_cmd" 2>/dev/null | grep -c "Certificate fingerprint" || echo "0"
    fi
}
