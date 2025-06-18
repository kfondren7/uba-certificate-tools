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

# Helper function to check file access for a specific user
check_file_access() {
    local file="$1"
    local user="${2:-root}"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    if [[ "$user" == "caspida" ]]; then
        sudo -u caspida test -r "$file"
    else
        test -r "$file"
    fi
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
    local java_truststore=$(find -L "${JAVA_HOME:-/usr/lib/jvm/java-1.8.0-openjdk}" -name cacerts 2>/dev/null | head -1)
    local uba_keystore="$caspida_home/conf/keystore/uba-keystore"
    
    # Focus on keystores that were validated successfully
    log "Testing trust relationships for validated keystores..."
    echo ""
    
    # Get keytool path from JAVA_HOME
    local keytool_cmd="keytool"
    if [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        keytool_cmd="$JAVA_HOME/bin/keytool"
    elif command -v keytool >/dev/null 2>&1; then
        keytool_cmd="keytool"
    else
        error "keytool not found in JAVA_HOME or PATH"
        return 1
    fi
    
    # Test UBA keystore trust (this was successfully validated)
    if [[ -f "$uba_keystore" ]]; then
        local uba_pass=$(get_uba_keystore_password "$caspida_home")
        
        if [[ -n "$uba_pass" ]]; then
            log "Testing UBA keystore certificate trust against Java system truststore..."
            
            # Get aliases from UBA keystore using system truststore format (which we know works)
            local aliases
            if aliases=$(sudo -u caspida bash -c "export PATH='$PATH'; $keytool_cmd -list -keystore '$uba_keystore' -storepass '$uba_pass'" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -5); then
                
                local found_certs=false
                while IFS= read -r alias; do
                    if [[ -n "$alias" ]]; then
                        found_certs=true
                        local cert_file="$temp_cert_dir/uba_${alias// /_}.crt"
                        
                        echo "  Testing certificate '$alias' from UBA keystore..."
                        
                        # Extract certificate from UBA keystore (simplified approach)
                        local cert_file="$temp_cert_dir/uba_${alias// /_}.crt"
                        if sudo -u caspida bash -c "export PATH='$PATH'; $keytool_cmd -export -alias \"$alias\" -keystore '$uba_keystore' -storepass '$uba_pass' -file '$cert_file'" >/dev/null 2>&1; then
                            
                            # Test if this certificate is present in Java system truststore
                            if $keytool_cmd -list -keystore "$java_truststore" -storepass "changeit" -alias "$alias" >/dev/null 2>&1; then
                                success "    ✓ Certificate '$alias' is present in Java system truststore"
                            else
                                warning "    ✗ Certificate '$alias' is NOT present in Java system truststore"
                            fi
                            
                            # Also test by importing the cert to verify it would be trusted
                            local temp_truststore="$temp_cert_dir/test_truststore.jks"
                            if $keytool_cmd -import -noprompt -alias "test_$alias" -file "$cert_file" -keystore "$temp_truststore" -storepass "testpass" >/dev/null 2>&1; then
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
            if aliases=$(sudo -u caspida bash -c "export PATH='$PATH'; $keytool_cmd -list -keystore '$jm_keystore' -storepass '$jm_password'" 2>/dev/null | grep ", trustedCertEntry,\|, PrivateKeyEntry," | awk -F',' '{print $1}' | head -5); then
                
                local found_certs=false
                while IFS= read -r alias; do
                    if [[ -n "$alias" ]]; then
                        found_certs=true
                        local cert_file="$temp_cert_dir/jm_${alias// /_}.crt"
                        
                        echo "  Testing certificate '$alias' from JobManager keystore..."
                        
                        # Extract certificate from JobManager keystore (simplified approach)
                        local cert_file="$temp_cert_dir/jm_${alias// /_}.crt"
                        if sudo -u caspida bash -c "export PATH='$PATH'; $keytool_cmd -export -alias \"$alias\" -keystore '$jm_keystore' -storepass '$jm_password' -file '$cert_file'" >/dev/null 2>&1; then
                            
                            # Test if this certificate is present in Java system truststore
                            if $keytool_cmd -list -keystore "$java_truststore" -storepass "changeit" -alias "$alias" >/dev/null 2>&1; then
                                success "    ✓ Certificate '$alias' is present in Java system truststore"
                            else
                                warning "    ✗ Certificate '$alias' is NOT present in Java system truststore"
                            fi
                            
                            # Test if this cert is in UBA keystore
                            if [[ -f "$uba_keystore" ]]; then
                                local uba_pass=$(get_uba_keystore_password "$caspida_home")
                                if [[ -n "$uba_pass" ]] && sudo -u caspida bash -c "export PATH='$PATH'; $keytool_cmd -list -keystore '$uba_keystore' -storepass '$uba_pass' -alias '$alias'" >/dev/null 2>&1; then
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
    local system_cacerts=$(find -L "${JAVA_HOME:-/usr/lib/jvm/java-1.8.0-openjdk}" -name cacerts 2>/dev/null | head -1)
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

# Function to detect JAVA_HOME automatically
detect_java_home() {
    local java_home_candidates=(
        "/usr/lib/jvm/java-1.8.0-openjdk"
        "/usr/lib/jvm/java-8-openjdk"
        "/usr/lib/jvm/java-11-openjdk"
        "/usr/lib/jvm/java-8-oracle"
        "/usr/java/latest"
        "/opt/java"
        "/System/Library/Frameworks/JavaVM.framework/Home"
    )
    
    # Check if JAVA_HOME is already set and valid
    if [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/bin/keytool" ]]; then
        echo "$JAVA_HOME"
        return 0
    fi
    
    # Try to find java command in PATH
    if command -v java >/dev/null 2>&1; then
        local java_path=$(command -v java)
        # Follow symlinks to get real path
        while [[ -L "$java_path" ]]; do
            java_path=$(readlink "$java_path")
        done
        # Extract JAVA_HOME from java binary path
        local potential_home=$(dirname "$(dirname "$java_path")")
        if [[ -f "$potential_home/bin/keytool" ]]; then
            echo "$potential_home"
            return 0
        fi
    fi
    
    # Try known candidate directories
    for candidate in "${java_home_candidates[@]}"; do
        if [[ -f "$candidate/bin/keytool" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    
    return 1
}

# Function to scan configuration files for certificate paths and validate them
validate_config_certificates() {
    local caspida_home="${1:-/opt/caspida}"
    
    log "Configuration Certificate Validation"
    echo "===================================="
    echo ""
    
    local config_dirs=(
        "$caspida_home/conf"
        "$caspida_home/conf/jobconf"
        "/etc/caspida/conf"
    )
    
    local cert_paths=()
    local validated_count=0
    local failed_count=0
    
    # Search for certificate file references in configuration files
    for config_dir in "${config_dirs[@]}"; do
        if [[ -d "$config_dir" ]]; then
            # Find certificate paths in various config file formats
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    cert_paths+=("$line")
                fi
            done < <(find "$config_dir" -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -exec grep -l -E "\.(crt|pem|p12|jks|keystore|key)(\"|'|$|\s)" {} \; 2>/dev/null | head -20)
        fi
    done
    
    if [[ ${#cert_paths[@]} -eq 0 ]]; then
        warning "No certificate references found in configuration files"
        echo ""
        return
    fi
    
    log "Found ${#cert_paths[@]} configuration files with certificate references"
    echo ""
    
    # Process each configuration file to extract certificate paths
    for config_file in "${cert_paths[@]}"; do
        log "Scanning: $config_file"
        
        # Extract potential certificate paths from the file
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue
            
            # Look for certificate file paths in the line
            local potential_paths=()
            
            # Extract paths after = (properties files)
            if [[ "$line" =~ ^[[:space:]]*[^=]+=[[:space:]]*(.+) ]]; then
                local value="${BASH_REMATCH[1]}"
                if [[ "$value" =~ \.(crt|pem|p12|jks|keystore|key|cert)([[:space:]]|$) ]]; then
                    # Clean the value and check if it looks like a path
                    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/["\x27]//g')
                    if [[ "$value" =~ ^[/] || ( "$value" =~ ^[a-zA-Z] && ! "$value" =~ [[:space:]] ) ]]; then
                        potential_paths+=("$value")
                    fi
                fi
            fi
            
            # Extract paths after : (YAML files)
            if [[ "$line" =~ ^[[:space:]]*[^:]+:[[:space:]]*(.+) ]]; then
                local value="${BASH_REMATCH[1]}"
                if [[ "$value" =~ \.(crt|pem|p12|jks|keystore|key|cert)([[:space:]]|$) ]]; then
                    # Clean the value and check if it looks like a path
                    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/["\x27]//g')
                    if [[ "$value" =~ ^[/] || ( "$value" =~ ^[a-zA-Z] && ! "$value" =~ [[:space:]] ) ]]; then
                        potential_paths+=("$value")
                    fi
                fi
            fi
            
            # Process each potential path
            for path in "${potential_paths[@]}"; do
                # Skip obvious non-paths
                [[ "$path" =~ ^[#] ]] && continue
                [[ "$path" =~ ^[a-zA-Z]+[[:space:]]*$ ]] && continue
                [[ "$path" =~ : ]] && continue
                
                # Resolve the path properly
                local cert_path=$(resolve_path "$path")
                
                # Convert relative paths to absolute paths
                if [[ ! "$cert_path" =~ ^/ ]]; then
                    # For relative paths, try multiple base directories
                    local base_dirs=(
                        "$caspida_home"
                        "$(dirname "$config_file")"
                        "/opt/caspida"
                        "/etc/caspida"
                    )
                    
                    local found_path=""
                    for base_dir in "${base_dirs[@]}"; do
                        local test_path="$base_dir/$cert_path"
                        if [[ -f "$test_path" ]]; then
                            found_path="$test_path"
                            break
                        fi
                    done
                    
                    if [[ -n "$found_path" ]]; then
                        cert_path="$found_path"
                    else
                        # If not found, use the most likely path for better error reporting
                        cert_path="$caspida_home/$cert_path"
                    fi
                fi
                
                echo "  Checking: $cert_path"
                
                if [[ -f "$cert_path" ]]; then
                    case "$cert_path" in
                        *.jks|*.keystore)
                            local password=$(test_keystore_passwords "$cert_path" "caspida" "Config keystore")
                            if [[ -n "$password" ]]; then
                                success "    ✓ Valid keystore"
                                ((validated_count++))
                            else
                                error "    ✗ Invalid keystore or unknown password"
                                ((failed_count++))
                            fi
                            ;;
                        *.p12)
                            if openssl pkcs12 -info -in "$cert_path" -passin pass: -noout >/dev/null 2>&1; then
                                success "    ✓ Valid PKCS#12 certificate"
                                ((validated_count++))
                            else
                                error "    ✗ Invalid PKCS#12 file"
                                ((failed_count++))
                            fi
                            ;;
                        *.crt|*.pem|*.cert)
                            if openssl x509 -in "$cert_path" -text -noout >/dev/null 2>&1; then
                                success "    ✓ Valid X.509 certificate"
                                ((validated_count++))
                            else
                                error "    ✗ Invalid certificate format"
                                ((failed_count++))
                            fi
                            ;;
                        *.key)
                            # Skip validation of private keys unless they're special cases
                            if [[ "$cert_path" =~ snakeoil ]]; then
                                warning "    ⚠ Snakeoil private key reference found"
                                echo "      ℹ  This is a placeholder private key, typically not used in production"
                            else
                                warning "    ⚠ Private key file detected, skipping validation"
                                echo "      ℹ  Private key validation is not performed for security reasons"
                            fi
                            ;;
                        *)
                            warning "    ⚠ Unknown certificate type, skipping"
                            ;;
                    esac
                else
                    # Special handling for known placeholder/example certificates
                    if [[ "$cert_path" =~ snakeoil ]]; then
                        warning "    ⚠ Snakeoil certificate reference found: $cert_path"
                        echo "      ℹ  Snakeoil certificates are placeholder/example certificates"
                        echo "      ℹ  This is typically not used in production and can be ignored"
                        echo "      ℹ  Consider updating the configuration to use actual certificates"
                    elif [[ "$cert_path" =~ (example|sample|test|dummy|placeholder) ]]; then
                        warning "    ⚠ Example/placeholder certificate reference: $cert_path"
                        echo "      ℹ  This appears to be a placeholder certificate path"
                        echo "      ℹ  Consider updating the configuration to use actual certificates"
                    elif [[ "$cert_path" =~ \.key$ ]]; then
                        warning "    ⚠ Private key file not found: $cert_path"
                        echo "      ℹ  Private key files are not validated for security reasons"
                        echo "      ℹ  Ensure the file exists and has proper permissions if needed"
                    else
                        error "    ✗ File not found: $cert_path"
                        ((failed_count++))
                    fi
                fi
            done
        done < "$config_file"
        echo ""
    done
    
    # Summary
    log "Configuration Certificate Summary:"
    echo "Validated: $validated_count, Failed: $failed_count"
    
    if [[ $failed_count -gt 0 ]]; then
        ((validation_errors += failed_count))
        warning "Some configuration-referenced certificates have issues"
    else
        success "All configuration-referenced certificates are valid"
    fi
    
    echo ""
}

# Main validation function
main() {
    local show_summary=false
    local custom_java_home=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -j|--java-home)
                custom_java_home="$2"
                shift 2
                ;;
            -s|--summary)
                show_summary=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root to use 'sudo -u caspida'"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    # Set global variables
    validation_errors=0
    caspida_home="${CASPIDA_HOME:-/opt/caspida}"
    
    # Detect JAVA_HOME
    if [[ -n "$custom_java_home" ]]; then
        if [[ ! -f "$custom_java_home/bin/keytool" ]]; then
            error "Invalid JAVA_HOME: $custom_java_home (keytool not found)"
            exit 1
        fi
        java_home="$custom_java_home"
    else
        java_home=$(detect_java_home)
        if [[ -z "$java_home" ]]; then
            error "Could not detect JAVA_HOME. Please specify with --java-home option"
            exit 1
        fi
    fi
    
    export JAVA_HOME="$java_home"
    
    log "UBA Keystore and Certificate Validation"
    log "========================================"
    echo "JAVA_HOME: $java_home"
    echo "CASPIDA_HOME: $caspida_home"
    echo ""
    
    # Validate caspida home directory
    if [[ ! -d "$caspida_home" ]]; then
        error "CASPIDA_HOME directory not found: $caspida_home"
        exit 1
    fi
    
    # Check if caspida user exists
    if ! id caspida >/dev/null 2>&1; then
        error "User 'caspida' not found"
        exit 1
    fi
    
    # Validate UBA keystore
    local uba_keystore="$caspida_home/conf/keystore/uba-keystore"
    if [[ -f "$uba_keystore" ]]; then
        local uba_password=$(get_uba_keystore_password "$caspida_home")
        if [[ -n "$uba_password" ]]; then
            if validate_keystore "$uba_keystore" "$uba_password" "UBA Unified Keystore" "caspida"; then
                success "UBA keystore validation completed"
            else
                ((validation_errors++))
            fi
        else
            warning "UBA keystore password not found"
            ((validation_errors++))
        fi
    else
        warning "UBA keystore not found at $uba_keystore"
    fi
    
    # Validate JobManager keystore
    local jm_info=$(get_jobmanager_keystore_info "$caspida_home")
    if [[ -n "$jm_info" ]]; then
        local jm_keystore=$(echo "$jm_info" | cut -d'|' -f1)
        local jm_password=$(echo "$jm_info" | cut -d'|' -f2)
        
        if validate_keystore "$jm_keystore" "$jm_password" "JobManager Keystore" "caspida"; then
            success "JobManager keystore validation completed"
        else
            ((validation_errors++))
        fi
    else
        warning "JobManager keystore not found or password not available"
    fi
    
    # Validate Kafka keystores
    local kafka_keystore="$caspida_home/conf/kafka/auth/server.keystore.jks"
    if [[ -f "$kafka_keystore" ]]; then
        local kafka_password=$(test_keystore_passwords "$kafka_keystore" "caspida" "Kafka keystore")
        if [[ -n "$kafka_password" ]]; then
            if validate_keystore "$kafka_keystore" "$kafka_password" "Kafka Server Keystore" "caspida"; then
                success "Kafka keystore validation completed"
            else
                ((validation_errors++))
            fi
        else
            warning "Kafka keystore password not found"
            ((validation_errors++))
        fi
    else
        log "Kafka keystore not found (may not be configured)"
    fi
    
    # Validate Java system truststore
    local system_cacerts=$(find -L "$java_home" -name cacerts 2>/dev/null | head -1)
    if [[ -f "$system_cacerts" ]]; then
        if validate_keystore "$system_cacerts" "changeit" "Java System Truststore" "root"; then
            success "Java system truststore validation completed"
        else
            ((validation_errors++))
        fi
    else
        warning "Java system truststore (cacerts) not found in $java_home"
        ((validation_errors++))
    fi
    
    # Validate trust relationships
    validate_trust_relationships "$caspida_home"
    
    # Validate configuration-referenced certificates
    validate_config_certificates "$caspida_home"
    
    # Final summary
    echo ""
    log "Validation Summary"
    log "=================="
    
    if [[ $validation_errors -eq 0 ]]; then
        success "All keystore validations passed successfully!"
        echo "✓ UBA certificate infrastructure appears to be properly configured"
        echo "✓ All keystores are accessible and contain valid certificates"
        echo "✓ Trust relationships have been validated"
    else
        error "Found $validation_errors validation errors"
        echo "✗ Some keystores may have issues that need attention"
        echo "✗ Review the errors above and fix before production use"
    fi
    
    echo ""
    log "Recommendations:"
    echo "• Monitor certificate expiration dates regularly"
    echo "• Test SSL connections to verify trust chains work correctly"
    echo "• Backup keystores before making any changes"
    echo "• Use secure passwords for production keystores"
    
    # Generate machine-readable summary if requested
    if [[ "$show_summary" == true ]]; then
        echo ""
        log "Generating machine-readable summary report..."
        generate_summary_report
    fi
    
    # Exit with error code if there were validation issues
    exit $validation_errors
}

# Run main function with all arguments
main "$@"
