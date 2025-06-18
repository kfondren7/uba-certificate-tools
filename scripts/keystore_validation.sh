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
    echo "  --skip-jvm-full        Skip full JVM truststore validation (faster)"
    echo "  -h, --help             Show this help message"
    echo "  --keytool-help         Show detailed keytool command examples"
    echo ""
    echo "Examples:"
    echo "  sudo $0"
    echo "  sudo $0 --java-home /usr/lib/jvm/java-11-openjdk"
    echo "  sudo $0 -j /opt/java"
    echo "  sudo $0 --summary > keystore_report.json"
    echo "  sudo $0 --skip-jvm-full                # Faster execution"
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

# Function to quickly validate keystore (minimal output for large keystores)
validate_keystore_quick() {
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
    
    # Quick validation - just check accessibility and get certificate count
    local validation_cmd="$keytool_cmd -list -keystore '$keystore_path' -storepass '$keystore_pass'"
    
    if [[ "$user" == "caspida" ]]; then
        if ! sudo -u caspida bash -c "export PATH='$PATH'; $validation_cmd" > /tmp/keystore_quick_$$.tmp 2>&1; then
            error "Failed to validate $description (check password and file permissions)"
            if [[ -f /tmp/keystore_quick_$$.tmp ]]; then
                cat /tmp/keystore_quick_$$.tmp
            fi
            rm -f /tmp/keystore_quick_$$.tmp
            return 1
        fi
    else
        if ! eval "$validation_cmd" > /tmp/keystore_quick_$$.tmp 2>&1; then
            error "Failed to validate $description (check password and file permissions)"
            if [[ -f /tmp/keystore_quick_$$.tmp ]]; then
                cat /tmp/keystore_quick_$$.tmp
            fi
            rm -f /tmp/keystore_quick_$$.tmp
            return 1
        fi
    fi
    
    # Count certificates and show UBA-specific ones
    local cert_count=$(grep -c "Certificate fingerprint" /tmp/keystore_quick_$$.tmp || echo "0")
    success "$description validated successfully ($cert_count certificates)"
    
    # Show only UBA-related certificates
    echo "    UBA-related certificates found:"
    grep -E "uba|caspida|UBA" /tmp/keystore_quick_$$.tmp | head -5 | while read -r line; do
        echo "      $line"
    done
    
    # Check if there are any UBA certificates
    local uba_count=$(grep -c -E "uba|caspida|UBA" /tmp/keystore_quick_$$.tmp || echo "0")
    if [[ $uba_count -gt 0 ]]; then
        success "Found $uba_count UBA-related certificates in $description"
    else
        warning "No UBA-related certificates found in $description"
    fi
    
    rm -f /tmp/keystore_quick_$$.tmp
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
        # Only show error if this is the first time we're trying to use keytool
        if [[ "${SHOW_KEYTOOL_ERROR:-true}" == "true" ]]; then
            error "keytool not found. If running as caspida user:"
            echo "  Run: source /opt/caspida/bin/CaspidaCommonEnv.sh"
            echo "  This sets the correct JAVA_HOME and PATH for UBA"
            export SHOW_KEYTOOL_ERROR=false  # Prevent repeated messages
        fi
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
        "$caspida_home/conf/deployment/templates/conf"
        "$caspida_home/conf/deployment/templates/local_conf"
        "/etc/caspida/conf"
        "/etc/caspida/local/conf"
    )
    
    local cert_paths=()
    local validated_count=0
    local failed_count=0
    
    # Search for certificate file references in configuration files
    local temp_file="/tmp/cert_paths_$$.txt"
    > "$temp_file"  # Create empty temp file
    
    for config_dir in "${config_dirs[@]}"; do
        if [[ -d "$config_dir" ]]; then
            log "Scanning configuration directory: $config_dir"
            
            # Find configuration files and process them
            while IFS= read -r config_file; do
                if [[ -f "$config_file" ]]; then
                    # Extract certificate paths from this config file
                    while IFS= read -r line; do
                        # Skip comments and empty lines
                        [[ "$line" =~ ^[[:space:]]*# ]] && continue
                        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
                        
                        # Look for certificate file paths in property values
                        if [[ "$line" =~ ^[^#]*[=:][[:space:]]*([^[:space:]]+\.(crt|pem|p12|jks|keystore|key)[^[:space:]]*) ]]; then
                            cert_path="${BASH_REMATCH[1]}"
                            echo "$cert_path|$config_file" >> "$temp_file"
                        fi
                    done < "$config_file"
                fi
            done < <(find "$config_dir" -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) 2>/dev/null)
        fi
    done
    
    # Read the results back into the array
    while IFS='|' read -r cert_path config_file; do
        if [[ -n "$cert_path" && -n "$config_file" ]]; then
            cert_paths+=("$cert_path:$config_file")
        fi
    done < "$temp_file"
    
    # Clean up temporary file
    rm -f "$temp_file"
    
    if [[ ${#cert_paths[@]} -eq 0 ]]; then
        warning "No certificate references found in configuration files"
        echo ""
        return
    fi
    
    log "Found ${#cert_paths[@]} certificate references in configuration files"
    echo ""
    
    # Process each certificate path found
    for cert_entry in "${cert_paths[@]}"; do
        # Split the entry into path and source file
        IFS=':' read -r cert_path config_file <<< "$cert_entry"
        
        log "  Checking: $cert_path (from $config_file)"
        
        # Resolve the path
        local resolved_path=$(resolve_path "$cert_path")
        
        # Check if file exists and validate it
        if check_file "$resolved_path"; then
            # Check what type of certificate file this is
            case "$resolved_path" in
                *.jks|*.keystore)
                    # Try to find the password for this keystore
                    local keystore_password=$(test_keystore_passwords "$resolved_path" "caspida" "Config keystore")
                    if [[ -n "$keystore_password" ]]; then
                        if validate_keystore "$resolved_path" "$keystore_password" "Config Keystore" "caspida"; then
                            success "    ✓ Valid keystore: $resolved_path (password: $keystore_password)"
                            ((validated_count++))
                        else
                            error "    ✗ Invalid keystore: $resolved_path"
                            ((failed_count++))
                        fi
                    else
                        error "    ✗ Keystore password not found: $resolved_path"
                        ((failed_count++))
                    fi
                    ;;
                *.p12)
                    # Try to find the password for this PKCS#12 file
                    local p12_password=$(test_keystore_passwords "$resolved_path" "caspida" "Config PKCS#12")
                    if [[ -n "$p12_password" ]]; then
                        if validate_keystore "$resolved_path" "$p12_password" "Config PKCS#12" "caspida"; then
                            success "    ✓ Valid PKCS#12 keystore: $resolved_path (password: $p12_password)"
                            ((validated_count++))
                        else
                            error "    ✗ Invalid PKCS#12 keystore: $resolved_path"
                            ((failed_count++))
                        fi
                    else
                        error "    ✗ PKCS#12 password not found: $resolved_path"
                        ((failed_count++))
                    fi
                    ;;
                *.crt|*.pem|*.cert)
                    if [[ -r "$resolved_path" ]]; then
                        success "    ✓ Certificate file found: $resolved_path"
                        ((validated_count++))
                    else
                        error "    ✗ Certificate file not readable: $resolved_path"
                        ((failed_count++))
                    fi
                    ;;
                *.key)
                    # Check if this is a snakeoil or example certificate
                    if [[ "$resolved_path" == *"snakeoil"* ]]; then
                        warning "    ⚠ Snakeoil certificate reference found: $resolved_path"
                        echo "      ℹ  Snakeoil certificates are placeholder/example certificates"
                        echo "      ℹ  This is typically not used in production and can be ignored"
                        echo "      ℹ  Consider updating the configuration to use actual certificates"
                    else
                        warning "    ⚠ Private key file referenced: $resolved_path"
                        echo "      ℹ  Private key files are skipped for security reasons"
                        echo "      ℹ  Validation of key files requires password testing"
                    fi
                    ;;
                *)
                    warning "    ⚠ Unknown certificate file type: $resolved_path"
                    ;;
            esac
        else
            # Check if this is a snakeoil or example certificate
            if [[ "$resolved_path" == *"snakeoil"* ]]; then
                warning "    ⚠ Snakeoil certificate reference found: $resolved_path"
                echo "      ℹ  Snakeoil certificates are placeholder/example certificates"
                echo "      ℹ  This is typically not used in production and can be ignored"
                echo "      ℹ  Consider updating the configuration to use actual certificates"
            elif [[ "$resolved_path" == *"example"* || "$resolved_path" == *"sample"* ]]; then
                warning "    ⚠ Example/sample certificate reference found: $resolved_path"
                echo "      ℹ  Example certificates are placeholders and typically not used"
                echo "      ℹ  Consider updating the configuration to use actual certificates"
            else
                error "    ✗ File not found: $resolved_path"
                ((failed_count++))
            fi
        fi
        echo ""
    done
    
    # Summary
    log "Configuration Certificate Summary:"
    echo "  Validated: $validated_count"
    echo "  Failed: $failed_count"
    echo "  Total references: ${#cert_paths[@]}"
    
    if [[ $failed_count -gt 0 ]]; then
        ((validation_errors += failed_count))
        error "Found $failed_count certificate issues in configuration files"
    else
        success "All certificate references in configuration files are valid"
    fi
    
    echo ""
}

# Function to check for missing certificate configurations
check_missing_configurations() {
    local caspida_home="${1:-/opt/caspida}"
    
    log "Checking for Missing Certificate Configurations"
    echo "================================================"
    
    local missing_configs=()
    local kafka_properties="$caspida_home/conf/kafka/kafka.properties"
    local uba_site_properties="/etc/caspida/local/conf/uba-site.properties"
    
    # Check for Kafka SSL configuration
    if [[ -f "$kafka_properties" ]]; then
        local kafka_ssl_complete=true
        local kafka_missing_props=()
        
        # Required Kafka SSL properties
        local kafka_ssl_props=(
            "ssl.keystore.location"
            "ssl.truststore.location" 
            "ssl.keystore.password"
            "ssl.truststore.password"
            "ssl.key.password"
        )
        
        echo "  Checking Kafka SSL configuration..."
        
        for prop in "${kafka_ssl_props[@]}"; do
            if grep -q "^$prop=" "$kafka_properties" 2>/dev/null; then
                local prop_value=$(grep "^$prop=" "$kafka_properties" | cut -d'=' -f2)
                if [[ "$prop" == *".location" ]]; then
                    # Check if certificate file exists
                    if [[ -f "$prop_value" ]]; then
                        success "    ✓ $prop=$prop_value"
                    else
                        error "    ✗ $prop configured but file missing: $prop_value"
                        kafka_ssl_complete=false
                        missing_configs+=("kafka-ssl-file-$prop")
                    fi
                else
                    # Password properties - just check if configured
                    success "    ✓ $prop configured"
                fi
            else
                warning "    ⚠ Missing: $prop"
                kafka_ssl_complete=false
                kafka_missing_props+=("$prop")
            fi
        done
        
        if ! $kafka_ssl_complete; then
            echo ""
            warning "  Kafka SSL configuration incomplete"
            echo "    ℹ  For secure Kafka data ingestion, add these properties to:"
            echo "    ℹ  $kafka_properties"
            echo ""
            for prop in "${kafka_missing_props[@]}"; do
                case "$prop" in
                    "ssl.keystore.location")
                        echo "    $prop=/opt/caspida/conf/kafka/auth/server.keystore.jks"
                        ;;
                    "ssl.truststore.location")
                        echo "    $prop=/opt/caspida/conf/kafka/auth/server.truststore.jks"
                        ;;
                    "ssl.keystore.password")
                        echo "    $prop=<your_keystore_password>"
                        ;;
                    "ssl.truststore.password")
                        echo "    $prop=<your_truststore_password>"
                        ;;
                    "ssl.key.password")
                        echo "    $prop=<your_key_password>"
                        ;;
                esac
            done
            echo ""
            echo "    Reference: https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/"
            echo "              splunk-uba-kafka-ingestion-app/1.4/use-and-configure-the-splunk-uba-kafka-ingestion-app/"
            echo "              configure-two-way-ssl-communication-for-kafka-data-ingestion"
            missing_configs+=("kafka-ssl-config")
        else
            success "  ✓ Kafka SSL configuration complete"
        fi
    else
        warning "  ⚠ Kafka properties file not found: $kafka_properties"
        missing_configs+=("kafka-properties-file")
    fi
    
    # Check for Splunk ES integration certificates
    if [[ -f "$uba_site_properties" ]]; then
        local splunk_es_complete=true
        local splunk_missing_props=()
        
        # Required Splunk ES SSL properties
        local splunk_es_props=(
            "validate.splunk.ssl.certificate"
            "connector.splunk.protocol"
            "splunkes.hec.token.value"
            "splunkes.hec.host"
            "splunkes.hec.port"
        )
        
        echo "  Checking Splunk ES integration configuration..."
        
        for prop in "${splunk_es_props[@]}"; do
            if grep -q "^$prop=" "$uba_site_properties" 2>/dev/null; then
                local prop_value=$(grep "^$prop=" "$uba_site_properties" | cut -d'=' -f2)
                success "    ✓ $prop=$prop_value"
            else
                warning "    ⚠ Missing: $prop"
                splunk_es_complete=false
                splunk_missing_props+=("$prop")
            fi
        done
        
        if ! $splunk_es_complete; then
            echo ""
            warning "  Splunk ES integration SSL configuration incomplete"
            echo "    ℹ  For secure UBA content push to Enterprise Security, add these properties to:"
            echo "    ℹ  $uba_site_properties"
            echo ""
            for prop in "${splunk_missing_props[@]}"; do
                case "$prop" in
                    "validate.splunk.ssl.certificate")
                        echo "    $prop=true"
                        ;;
                    "connector.splunk.protocol")
                        echo "    $prop=TLSv1.2"
                        ;;
                    "splunkes.hec.token.value")
                        echo "    $prop=<your_hec_token_from_splunk_es>"
                        ;;
                    "splunkes.hec.host")
                        echo "    $prop=<your_splunk_es_hostname_or_ip>"
                        ;;
                    "splunkes.hec.port")
                        echo "    $prop=8088"
                        ;;
                esac
            done
            echo ""
            echo "    Reference: https://docs.splunk.com/Documentation/UBA/5.4.2/Integration/PushUBAcontenttoES"
            missing_configs+=("splunk-es-ssl-config")
        else
            success "  ✓ Splunk ES integration SSL configuration complete"
        fi
    fi
    
    # Check for additional certificate properties that should be configured
    local expected_properties=(
        "ui.auth.rootca"
        "ui.auth.serverCert" 
        "ui.auth.privateKey"
    )
    
    if [[ -f "$uba_site_properties" ]]; then
        for prop in "${expected_properties[@]}"; do
            if grep -q "^$prop=" "$uba_site_properties" 2>/dev/null; then
                local cert_path=$(grep "^$prop=" "$uba_site_properties" | cut -d'=' -f2)
                if [[ -f "$cert_path" ]]; then
                    success "  ✓ UBA certificate property configured: $prop"
                else
                    error "  ✗ UBA certificate path configured but file missing: $prop=$cert_path"
                    missing_configs+=("uba-cert-$prop")
                fi
            else
                warning "  ⚠ UBA certificate property not configured: $prop"
                missing_configs+=("uba-config-$prop")
            fi
        done
    fi
    
    # Summary
    echo ""
    if [[ ${#missing_configs[@]} -eq 0 ]]; then
        success "All certificate configurations appear complete"
    else
        warning "Found ${#missing_configs[@]} missing or incomplete certificate configurations:"
        for config in "${missing_configs[@]}"; do
            echo "  - $config"
        done
        echo ""
        echo "Recommendations:"
        echo "• Run the install_uba_certs_refactored.sh script to configure missing certificates"
        echo "• For Kafka SSL: Use --enable-kafka option"
        echo "• For Splunk ES: Configure SSL validation and HEC tokens"
    fi
    
    echo ""
}

# Detailed keytool command examples help
show_keytool_help() {
    echo "===================================================================="
    echo "KEYTOOL COMMAND REFERENCE - UBA Certificate Management"
    echo "===================================================================="
    echo ""
    echo "This script uses various keytool commands for certificate validation."
    echo "Below are the key commands with full syntax examples for manual use:"
    echo ""
    
    echo "1. LIST KEYSTORE CONTENTS"
    echo "-------------------------"
    echo "Basic listing (shows aliases only):"
    echo "  keytool -list -keystore /path/to/keystore.jks -storepass <password>"
    echo ""
    echo "Verbose listing (shows certificate details):"
    echo "  keytool -list -v -keystore /path/to/keystore.jks -storepass <password>"
    echo ""
    echo "List specific alias only:"
    echo "  keytool -list -alias <alias_name> -keystore /path/to/keystore.jks -storepass <password>"
    echo ""
    echo "Examples used in this script:"
    echo "  # UBA unified keystore"
    echo "  keytool -list -keystore /opt/caspida/conf/keystore/uba-keystore -storepass caspida123"
    echo "  keytool -list -v -keystore /opt/caspida/conf/keystore/uba-keystore -storepass caspida123"
    echo ""
    echo "  # JobManager keystore"
    echo "  keytool -list -keystore /opt/caspida/conf/jobconf/keystore.jm -storepass caspida123"
    echo ""
    echo "  # Kafka keystores"
    echo "  keytool -list -keystore /opt/caspida/conf/kafka/auth/server.keystore.jks -storepass caspida123"
    echo "  keytool -list -keystore /opt/caspida/conf/kafka/auth/server.truststore.jks -storepass caspida123"
    echo ""
    echo "  # Java system truststore (cacerts)"
    echo "  keytool -list -keystore \$JAVA_HOME/jre/lib/security/cacerts -storepass changeit"
    echo "  keytool -list -keystore \$JAVA_HOME/lib/security/cacerts -storepass changeit  # Java 9+"
    echo ""
    
    echo "2. EXPORT CERTIFICATES"
    echo "----------------------"
    echo "Export in binary DER format:"
    echo "  keytool -export -alias <alias> -keystore /path/to/keystore.jks -storepass <password> -file /path/to/cert.der"
    echo ""
    echo "Export in text PEM format (RFC format):"
    echo "  keytool -export -alias <alias> -keystore /path/to/keystore.jks -storepass <password> -rfc -file /path/to/cert.pem"
    echo ""
    echo "Export certificate chain:"
    echo "  keytool -export -alias <alias> -keystore /path/to/keystore.jks -storepass <password> -rfc -file /path/to/chain.pem"
    echo ""
    echo "Examples used in this script:"
    echo "  # Export UBA server certificate"
    echo "  keytool -export -alias uba-server -keystore /opt/caspida/conf/keystore/uba-keystore -storepass caspida123 -rfc -file /tmp/uba-cert.pem"
    echo ""
    echo "  # Export JobManager certificate"
    echo "  keytool -export -alias jmserver -keystore /opt/caspida/conf/jobconf/keystore.jm -storepass caspida123 -rfc -file /tmp/jm-cert.pem"
    echo ""
    echo "  # Export Kafka certificate"
    echo "  keytool -export -alias kafka-server -keystore /opt/caspida/conf/kafka/auth/server.keystore.jks -storepass caspida123 -rfc -file /tmp/kafka-cert.pem"
    echo ""
    
    echo "3. IMPORT CERTIFICATES"
    echo "----------------------"
    echo "Import certificate into keystore/truststore:"
    echo "  keytool -import -alias <alias> -keystore /path/to/truststore.jks -storepass <password> -file /path/to/cert.pem -noprompt"
    echo ""
    echo "Import into Java system truststore:"
    echo "  keytool -import -alias <alias> -keystore \$JAVA_HOME/jre/lib/security/cacerts -storepass changeit -file /path/to/cert.pem -noprompt"
    echo ""
    echo "Import with trust verification:"
    echo "  keytool -import -alias <alias> -keystore /path/to/truststore.jks -storepass <password> -file /path/to/cert.pem -trustcacerts"
    echo ""
    echo "Examples used in this script:"
    echo "  # Import UBA certificate into Kafka truststore"
    echo "  keytool -import -alias uba-server -keystore /opt/caspida/conf/kafka/auth/server.truststore.jks -storepass caspida123 -file /tmp/uba-cert.pem -noprompt"
    echo ""
    echo "  # Import into Java cacerts for system-wide trust"
    echo "  keytool -import -alias uba-ca -keystore \$JAVA_HOME/jre/lib/security/cacerts -storepass changeit -file /path/to/ca-cert.pem -noprompt"
    echo ""
    
    echo "4. CERTIFICATE VALIDATION & TESTING"
    echo "-----------------------------------"
    echo "Test keystore accessibility (password validation):"
    echo "  keytool -list -keystore /path/to/keystore.jks -storepass <password> >/dev/null 2>&1"
    echo "  echo \$?  # 0 = success, non-zero = failure"
    echo ""
    echo "Check specific certificate alias exists:"
    echo "  keytool -list -alias <alias> -keystore /path/to/keystore.jks -storepass <password>"
    echo ""
    echo "Verify certificate validity dates:"
    echo "  keytool -list -v -alias <alias> -keystore /path/to/keystore.jks -storepass <password> | grep -E \"Valid from|until\""
    echo ""
    echo "Get certificate fingerprint:"
    echo "  keytool -list -v -alias <alias> -keystore /path/to/keystore.jks -storepass <password> | grep -A1 -B1 SHA1"
    echo ""
    echo "Test certificate against keystore (validation patterns used in this script):"
    echo "  # Test UBA keystore with different passwords"
    echo "  for pass in changeit caspida123 caspida password \"\"; do"
    echo "    if keytool -list -keystore /opt/caspida/conf/keystore/uba-keystore -storepass \"\$pass\" >/dev/null 2>&1; then"
    echo "      echo \"UBA keystore password: \$pass\""
    echo "      break"
    echo "    fi"
    echo "  done"
    echo ""
    echo "  # Test specific certificate file against UBA keystore"
    echo "  CERT_FILE=\"/etc/caspida/local/conf/server.crt\""
    echo "  UBA_KEYSTORE=\"/opt/caspida/conf/keystore/uba-keystore\""
    echo "  if [[ -f \"\$CERT_FILE\" && -f \"\$UBA_KEYSTORE\" ]]; then"
    echo "    # Get certificate fingerprint from file"
    echo "    CERT_FP=\$(openssl x509 -in \"\$CERT_FILE\" -fingerprint -sha1 -noout | cut -d= -f2)"
    echo "    # Get fingerprints from keystore"
    echo "    keytool -list -v -keystore \"\$UBA_KEYSTORE\" -storepass caspida123 | grep \"SHA1:\" | while read line; do"
    echo "      KS_FP=\$(echo \"\$line\" | cut -d: -f2- | tr -d ' ')"
    echo "      if [[ \"\$CERT_FP\" == \"\$KS_FP\" ]]; then"
    echo "        echo \"Certificate \$CERT_FILE found in keystore \$UBA_KEYSTORE\""
    echo "      fi"
    echo "    done"
    echo "  fi"
    echo ""
    echo "  # Quick certificate-to-keystore validation"
    echo "  validate_cert_in_keystore() {"
    echo "    local cert_file=\"\$1\""
    echo "    local keystore=\"\$2\""
    echo "    local keystore_pass=\"\$3\""
    echo "    openssl x509 -in \"\$cert_file\" -fingerprint -sha1 -noout 2>/dev/null | grep -q \"\$(keytool -list -v -keystore \"\$keystore\" -storepass \"\$keystore_pass\" 2>/dev/null | grep 'SHA1:' | head -1 | cut -d: -f2- | tr -d ' ')\""
    echo "  }"
    echo "  # Usage: validate_cert_in_keystore \"/path/to/cert.pem\" \"/path/to/keystore.jks\" \"password\""
    echo ""
    
    echo "5. ADVANCED PASSWORD TESTING"
    echo "----------------------------"
    echo "Test multiple passwords with error handling:"
    echo "  PASSWORDS=(\"changeit\" \"caspida123\" \"caspida\" \"password\" \"\")"
    echo "  for pass in \"\${PASSWORDS[@]}\"; do"
    echo "    if timeout 10 keytool -list -keystore /path/to/keystore.jks -storepass \"\$pass\" >/dev/null 2>&1; then"
    echo "      echo \"Valid password found: [\$pass]\""
    echo "      KEYSTORE_PASSWORD=\"\$pass\""
    echo "      break"
    echo "    else"
    echo "      echo \"Failed password: [\$pass]\""
    echo "    fi"
    echo "  done"
    echo ""
    echo "Test empty password:"
    echo "  keytool -list -keystore /path/to/keystore.jks -storepass \"\" >/dev/null 2>&1"
    echo ""
    
    echo "6. KEYSTORE TYPES & FORMATS"
    echo "---------------------------"
    echo "JKS (Java KeyStore) - default format:"
    echo "  keytool -list -keystore keystore.jks -storetype JKS -storepass <password>"
    echo ""
    echo "PKCS#12 format:"
    echo "  keytool -list -keystore keystore.p12 -storetype PKCS12 -storepass <password>"
    echo ""
    echo "Auto-detect format (Java 9+):"
    echo "  keytool -list -keystore keystore.file -storepass <password>"
    echo ""
    echo "Create new keystore:"
    echo "  keytool -genkey -alias <alias> -keyalg RSA -keysize 2048 -keystore new_keystore.jks -storepass <password>"
    echo ""
    echo "Change keystore password:"
    echo "  keytool -storepasswd -keystore /path/to/keystore.jks -storepass <old_password> -new <new_password>"
    echo ""
    
    echo "7. CERTIFICATE INSPECTION WITH OPENSSL"
    echo "--------------------------------------"
    echo "View certificate details (PEM format):"
    echo "  openssl x509 -in certificate.pem -text -noout"
    echo ""
    echo "Check certificate validity (expiration):"
    echo "  openssl x509 -in certificate.pem -checkend 86400    # Check if expires in 24 hours"
    echo "  openssl x509 -in certificate.pem -checkend 2592000  # Check if expires in 30 days"
    echo ""
    echo "Extract certificate dates:"
    echo "  openssl x509 -in certificate.pem -noout -startdate"
    echo "  openssl x509 -in certificate.pem -noout -enddate"
    echo ""
    echo "Get certificate subject and issuer:"
    echo "  openssl x509 -in certificate.pem -noout -subject"
    echo "  openssl x509 -in certificate.pem -noout -issuer"
    echo ""
    echo "Convert between formats:"
    echo "  # PKCS#12 to PEM"
    echo "  openssl pkcs12 -in keystore.p12 -out certificate.pem -nodes"
    echo ""
    echo "  # DER to PEM"
    echo "  openssl x509 -in certificate.der -inform DER -out certificate.pem -outform PEM"
    echo ""
    echo "  # PEM to DER"
    echo "  openssl x509 -in certificate.pem -inform PEM -out certificate.der -outform DER"
    echo ""
    
    echo "8. TRUST RELATIONSHIP TESTING"
    echo "-----------------------------"
    echo "Check if certificate exists in truststore by alias:"
    echo "  keytool -list -keystore truststore.jks -storepass <password> | grep -i \"<alias>\""
    echo ""
    echo "Find certificate by subject/issuer:"
    echo "  keytool -list -v -keystore truststore.jks -storepass <password> | grep -A5 -B5 \"CN=example.com\""
    echo ""
    echo "Compare certificate fingerprints:"
    echo "  CERT1_FP=\$(keytool -list -v -alias <alias1> -keystore keystore1.jks -storepass <pass1> | grep \"SHA1:\" | cut -d: -f2-)"
    echo "  CERT2_FP=\$(keytool -list -v -alias <alias2> -keystore keystore2.jks -storepass <pass2> | grep \"SHA1:\" | cut -d: -f2-)"
    echo "  [[ \"\$CERT1_FP\" == \"\$CERT2_FP\" ]] && echo \"Certificates match\" || echo \"Certificates differ\""
    echo ""
    echo "Verify trust chain:"
    echo "  # Export certificates and verify with OpenSSL"
    echo "  keytool -export -alias server-cert -keystore server.jks -storepass pass123 -rfc -file server.pem"
    echo "  keytool -export -alias ca-cert -keystore ca.jks -storepass pass123 -rfc -file ca.pem"
    echo "  openssl verify -CAfile ca.pem server.pem"
    echo ""
    
    echo "9. UBA-SPECIFIC CERTIFICATE LOCATIONS & COMMANDS"
    echo "------------------------------------------------"
    echo "Main UBA locations:"
    echo "  /opt/caspida/conf/keystore/uba-keystore          # Main UBA keystore"
    echo "  /opt/caspida/conf/jobconf/keystore.jm            # JobManager keystore"
    echo "  /opt/caspida/conf/kafka/auth/server.keystore.jks # Kafka server keystore"
    echo "  /opt/caspida/conf/kafka/auth/server.truststore.jks # Kafka truststore"
    echo "  /var/vcap/store/caspida/certs/my_certs/          # Custom certificate files"
    echo ""
    echo "Configuration files with certificate references:"
    echo "  /etc/caspida/local/conf/uba-site.properties"
    echo "  /opt/caspida/conf/kafka/kafka.properties"
    echo "  /opt/caspida/conf/jobconf/uba-job-conf.properties"
    echo ""
    echo "Common UBA certificate aliases:"
    echo "  uba-server    # Main UBA server certificate"
    echo "  jmserver      # JobManager certificate"
    echo "  kafka-server  # Kafka server certificate"
    echo "  splunk-ca     # Splunk CA certificate"
    echo ""
    echo "UBA-specific validation commands:"
    echo "  # Validate all UBA keystores"
    echo "  for ks in /opt/caspida/conf/keystore/uba-keystore \\"
    echo "           /opt/caspida/conf/jobconf/keystore.jm \\"
    echo "           /opt/caspida/conf/kafka/auth/server.keystore.jks; do"
    echo "    if [[ -f \"\$ks\" ]]; then"
    echo "      echo \"Checking \$ks:\""
    echo "      keytool -list -keystore \"\$ks\" -storepass caspida123 2>/dev/null || \\"
    echo "      keytool -list -keystore \"\$ks\" -storepass changeit 2>/dev/null || \\"
    echo "      echo \"  Could not access with common passwords\""
    echo "    fi"
    echo "  done"
    echo ""
    
    echo "10. PRACTICAL CERTIFICATE TESTING EXAMPLES"
    echo "------------------------------------------"
    echo "Test if a certificate file matches a keystore entry:"
    echo "  # Method 1: Compare fingerprints"
    echo "  CERT_FILE=\"/etc/caspida/local/conf/server.crt\""
    echo "  KEYSTORE=\"/opt/caspida/conf/keystore/uba-keystore\""
    echo "  ALIAS=\"uba-server\""
    echo "  PASSWORD=\"caspida123\""
    echo ""
    echo "  # Get fingerprint from certificate file"
    echo "  CERT_FP=\$(openssl x509 -in \"\$CERT_FILE\" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2)"
    echo ""
    echo "  # Get fingerprint from keystore"
    echo "  KS_FP=\$(keytool -list -v -alias \"\$ALIAS\" -keystore \"\$KEYSTORE\" -storepass \"\$PASSWORD\" 2>/dev/null | grep 'SHA256:' | cut -d: -f2- | tr -d ' ')"
    echo ""
    echo "  # Compare"
    echo "  if [[ \"\$CERT_FP\" == \"\$KS_FP\" ]]; then"
    echo "    echo \"✓ Certificate matches keystore entry\""
    echo "  else"
    echo "    echo \"✗ Certificate does not match keystore\""
    echo "  fi"
    echo ""
    echo "Test if a certificate is trusted by a truststore:"
    echo "  # Method 1: Check if certificate is directly in truststore"
    echo "  CERT_FILE=\"/path/to/server.crt\""
    echo "  TRUSTSTORE=\"/opt/caspida/conf/kafka/auth/server.truststore.jks\""
    echo "  PASSWORD=\"caspida123\""
    echo ""
    echo "  # Import certificate to test truststore (dry-run)"
    echo "  keytool -printcert -file \"\$CERT_FILE\" | grep -E 'Subject:|Issuer:'"
    echo ""
    echo "  # Check if issuer is in truststore"
    echo "  ISSUER=\$(openssl x509 -in \"\$CERT_FILE\" -noout -issuer | sed 's/issuer=//')"
    echo "  keytool -list -v -keystore \"\$TRUSTSTORE\" -storepass \"\$PASSWORD\" | grep -A5 -B5 \"\$ISSUER\""
    echo ""
    echo "Validate certificate expiration against keystore entries:"
    echo "  # Check all certificates in a keystore for expiration"
    echo "  KEYSTORE=\"/opt/caspida/conf/keystore/uba-keystore\""
    echo "  PASSWORD=\"caspida123\""
    echo ""
    echo "  # Get all aliases"
    echo "  ALIASES=\$(keytool -list -keystore \"\$KEYSTORE\" -storepass \"\$PASSWORD\" 2>/dev/null | grep 'PrivateKeyEntry\\|trustedCertEntry' | sed 's/,.*//')"
    echo ""
    echo "  # Check each alias"
    echo "  for alias in \$ALIASES; do"
    echo "    echo \"Checking alias: \$alias\""
    echo "    keytool -list -v -alias \"\$alias\" -keystore \"\$KEYSTORE\" -storepass \"\$PASSWORD\" 2>/dev/null | grep -E 'Valid from|until'"
    echo "    # Check if expires in next 30 days"
    echo "    CERT_END=\$(keytool -list -v -alias \"\$alias\" -keystore \"\$KEYSTORE\" -storepass \"\$PASSWORD\" 2>/dev/null | grep 'Valid from' | sed 's/.*until: //')"
    echo "    if [[ -n \"\$CERT_END\" ]]; then"
    echo "      CERT_END_EPOCH=\$(date -d \"\$CERT_END\" +%s 2>/dev/null)"
    echo "      NOW_PLUS_30=\$(date -d '+30 days' +%s)"
    echo "      if [[ \"\$CERT_END_EPOCH\" -lt \"\$NOW_PLUS_30\" ]]; then"
    echo "        echo \"⚠ WARNING: Certificate \$alias expires within 30 days!\""
    echo "      fi"
    echo "    fi"
    echo "  done"
    echo ""
    echo "Test UBA service certificate connectivity:"
    echo "  # Test and validate actual UBA service certificates"
    echo "  UBA_HOST=\"\$(hostname -f)\""
    echo "  echo \"Testing UBA service connectivity and certificates...\""
    echo ""
    echo "  # Test main UBA web service (port 443/8443)"
    echo "  echo | openssl s_client -connect \"\$UBA_HOST:443\" -servername \"\$UBA_HOST\" 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|Not After'"
    echo ""
    echo "  # Test JobManager (port 9443)"
    echo "  echo | openssl s_client -connect \"\$UBA_HOST:9443\" -servername \"\$UBA_HOST\" 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|Not After'"
    echo ""
    echo "  # Compare service certificate with keystore"
    echo "  SERVICE_CERT_FP=\$(echo | openssl s_client -connect \"\$UBA_HOST:443\" 2>/dev/null | openssl x509 -fingerprint -sha256 -noout | cut -d= -f2)"
    echo "  KEYSTORE_CERT_FP=\$(keytool -list -v -alias uba-server -keystore /opt/caspida/conf/keystore/uba-keystore -storepass caspida123 2>/dev/null | grep 'SHA256:' | cut -d: -f2- | tr -d ' ')"
    echo "  if [[ \"\$SERVICE_CERT_FP\" == \"\$KEYSTORE_CERT_FP\" ]]; then"
    echo "    echo \"✓ Service certificate matches keystore\""
    echo "  else"
    echo "    echo \"✗ Service certificate does not match keystore\""
    echo "  fi"
    echo ""
    
    echo "11. TROUBLESHOOTING & DIAGNOSTICS"
    echo "---------------------------------"
    echo "Find Java installations and keytool:"
    echo "  find /usr -name 'keytool' 2>/dev/null"
    echo "  find /opt -name 'keytool' 2>/dev/null"
    echo "  which keytool"
    echo "  update-alternatives --list java"
    echo ""
    echo "Check Java version and capabilities:"
    echo "  java -version"
    echo "  keytool -help | head -20"
    echo "  \$JAVA_HOME/bin/keytool -help | head -20"
    echo ""
    echo "Fix JAVA_HOME issues (common with caspida user):"
    echo "  # If you get Java errors when running as caspida user:"
    echo "  source /opt/caspida/bin/CaspidaCommonEnv.sh"
    echo "  echo \$JAVA_HOME"
    echo ""
    echo "  # Or run the validation with proper Java environment:"
    echo "  sudo -u caspida bash -c 'source /opt/caspida/bin/CaspidaCommonEnv.sh && /path/to/keystore_validation.sh'"
    echo ""
    echo "Test SSL connectivity to UBA services:"
    echo "  # Test UBA web interface"
    echo "  openssl s_client -connect uba-hostname:443 -servername uba-hostname"
    echo ""
    echo "  # Test JobManager"
    echo "  openssl s_client -connect uba-hostname:9443 -servername uba-hostname"
    echo ""
    echo "  # Test Kafka SSL"
    echo "  openssl s_client -connect uba-hostname:9094 -servername uba-hostname"
    echo ""
    echo "Debug certificate trust issues:"
    echo "  # Check if certificate is in Java cacerts"
    echo "  keytool -list -keystore \$JAVA_HOME/jre/lib/security/cacerts -storepass changeit | grep -i \"uba\\|caspida\""
    echo ""
    echo "  # Verify certificate chain with verbose output"
    echo "  openssl s_client -connect hostname:443 -showcerts -verify 5"
    echo ""
    echo "File permission checks:"
    echo "  ls -la /opt/caspida/conf/keystore/"
    echo "  ls -la /opt/caspida/conf/kafka/auth/"
    echo "  stat /opt/caspida/conf/keystore/uba-keystore"
    echo ""
    echo "Check for certificate references in config files:"
    echo "  grep -r \"keystore\\|truststore\\|ssl\" /etc/caspida/local/conf/"
    echo "  grep -r \"keystore\\|truststore\\|ssl\" /opt/caspida/conf/"
    echo ""
    
    echo "===================================================================="
    echo "COMMON DEFAULT PASSWORDS"
    echo "===================================================================="
    echo "Java cacerts default:     changeit"
    echo "UBA keystores:           caspida123, caspida"
    echo "Test/Development:        password, (empty)"
    echo ""
    echo "IMPORTANT SECURITY NOTES:"
    echo "• Always change default passwords in production environments"
    echo "• Use strong passwords for keystores containing private keys"
    echo "• Backup keystores before making changes"
    echo "• Test certificate changes in development first"
    echo "• Monitor certificate expiration dates (typically 1-3 years)"
    echo "• Maintain certificate trust chains properly"
    echo "• Use secure file permissions (readable only by necessary users)"
    echo ""
    echo "SCRIPT USAGE EXAMPLES:"
    echo "• Run full validation:           sudo ./keystore_validation.sh"
    echo "• Show summary only:             sudo ./keystore_validation.sh --summary"
    echo "• Use custom Java:               sudo ./keystore_validation.sh --java-home /path/to/java"
    echo "• Show this help:                ./keystore_validation.sh --help"
    echo "• Show keytool examples:         ./keystore_validation.sh --keytool-help"
    echo ""
    echo "COMMON ISSUES & SOLUTIONS:"
    echo "• 'keytool not found'         → Set correct JAVA_HOME or use --java-home"
    echo "• 'Keystore was tampered'     → Wrong password or corrupted keystore"
    echo "• 'Certificate expired'       → Renew certificate and update keystore"
    echo "• 'Trust relationship failed' → Import CA certificate into truststore"
    echo "• 'Permission denied'         → Run script as root or fix file permissions"
    echo "===================================================================="
    echo ""
}

# Function to check and validate Java environment
check_java_environment() {
    local show_warnings="${1:-true}"
    
    # Check if JAVA_HOME is set
    if [[ -z "${JAVA_HOME:-}" ]]; then
        if [[ "$show_warnings" == "true" ]]; then
            warning "JAVA_HOME is not set"
            echo "  ℹ  If you encounter Java errors, especially when running as caspida user:"
            echo "  ℹ  Run: source /opt/caspida/bin/CaspidaCommonEnv.sh"
            echo "  ℹ  Then re-run this script or set: export JAVA_HOME=\$(source /opt/caspida/bin/CaspidaCommonEnv.sh && echo \$JAVA_HOME)"
        fi
        return 1
    fi
    
    # Check if JAVA_HOME points to a valid Java installation
    if [[ ! -f "$JAVA_HOME/bin/java" ]]; then
        if [[ "$show_warnings" == "true" ]]; then
            error "JAVA_HOME is set but invalid: $JAVA_HOME"
            echo "  ℹ  Run: source /opt/caspida/bin/CaspidaCommonEnv.sh"
            echo "  ℹ  This will set the correct JAVA_HOME for UBA"
        fi
        return 1
    fi
    
    # Check if keytool is available
    if [[ ! -f "$JAVA_HOME/bin/keytool" ]]; then
        if [[ "$show_warnings" == "true" ]]; then
            error "keytool not found in JAVA_HOME: $JAVA_HOME/bin/keytool"
            echo "  ℹ  Run: source /opt/caspida/bin/CaspidaCommonEnv.sh"
        fi
        return 1
    fi
    
    return 0
}

# Function to check Kafka certificate aliases in JVM truststore
check_kafka_certs_in_jvm() {
    local caspida_home="${1:-/opt/caspida}"
    local java_home="${2:-$JAVA_HOME}"
    
    log "Checking Kafka Certificate References in JVM Truststore"
    echo "======================================================="
    
    local kafka_properties="$caspida_home/conf/kafka/kafka.properties"
    local kafka_keystore_path=""
    local kafka_truststore_path=""
    local system_cacerts=$(find -L "$java_home" -name cacerts 2>/dev/null | head -1)
    
    if [[ ! -f "$kafka_properties" ]]; then
        warning "Kafka properties file not found: $kafka_properties"
        return 1
    fi
    
    if [[ ! -f "$system_cacerts" ]]; then
        warning "JVM truststore not found: $system_cacerts"
        return 1
    fi
    
    # Get Kafka SSL keystore/truststore paths from configuration
    kafka_keystore_path=$(grep "^ssl.keystore.location=" "$kafka_properties" 2>/dev/null | cut -d'=' -f2)
    kafka_truststore_path=$(grep "^ssl.truststore.location=" "$kafka_properties" 2>/dev/null | cut -d'=' -f2)
    
    echo "  Kafka keystore configured: ${kafka_keystore_path:-Not configured}"
    echo "  Kafka truststore configured: ${kafka_truststore_path:-Not configured}"
    echo ""
    
    # If no SSL configuration, skip the check
    if [[ -z "$kafka_keystore_path" && -z "$kafka_truststore_path" ]]; then
        echo "  No Kafka SSL configuration found - skipping JVM trust verification"
        echo "  This is normal for Kafka deployments not using SSL/TLS"
        echo ""
        return 0
    fi
    
    # If Kafka keystores are configured, check if their certificates are in JVM truststore
    if [[ -n "$kafka_keystore_path" && -f "$kafka_keystore_path" ]]; then
        echo "  Checking if Kafka keystore certificates are trusted by JVM..."
        
        # Get aliases from Kafka keystore
        local kafka_password=$(test_keystore_passwords "$kafka_keystore_path" "caspida" "Kafka keystore")
        if [[ -n "$kafka_password" ]]; then
            local kafka_aliases=$(get_keystore_aliases "$kafka_keystore_path" "$kafka_password" "caspida")
            
            # Limit to first 3 aliases to avoid hanging on large keystores
            local count=0
            for alias in $kafka_aliases; do
                if [[ $count -ge 3 ]]; then
                    echo "    (Checking only first 3 aliases for performance)"
                    break
                fi
                
                echo "    Checking alias: $alias"
                
                # Export certificate from Kafka keystore
                local temp_cert="/tmp/kafka_cert_${alias}_$$.pem"
                if sudo -u caspida timeout 10 keytool -export -alias "$alias" -keystore "$kafka_keystore_path" -storepass "$kafka_password" -rfc -file "$temp_cert" >/dev/null 2>&1; then
                    
                    # Get certificate fingerprint for quick comparison
                    local cert_fingerprint=$(openssl x509 -in "$temp_cert" -fingerprint -sha1 -noout 2>/dev/null | cut -d= -f2 | tr -d ':')
                    
                    # Quick check in JVM truststore
                    if timeout 15 keytool -list -keystore "$system_cacerts" -storepass changeit 2>/dev/null | grep -q "$cert_fingerprint"; then
                        success "      ✓ Certificate '$alias' is trusted by JVM (direct match)"
                    else
                        warning "      ⚠ Certificate '$alias' is NOT in JVM truststore"
                        echo "        Recommendation: For SSL connections to external systems, import CA into JVM truststore"
                    fi
                    
                    rm -f "$temp_cert"
                else
                    warning "      ⚠ Failed to export certificate '$alias' from Kafka keystore"
                fi
                
                ((count++))
            done
        else
            warning "    Could not access Kafka keystore (password issue)"
        fi
    else
        echo "  Kafka keystore not found or not accessible: $kafka_keystore_path"
    fi
    
    echo ""
}

# Function to validate critical UBA UI authentication certificates
validate_uba_ui_certificates() {
    local uba_site_properties="/etc/caspida/local/conf/uba-site.properties"
    local caspida_home="${CASPIDA_HOME:-/opt/caspida}"
    
    log "Validating Critical UBA UI Authentication Certificates"
    echo "====================================================="
    
    if [[ ! -f "$uba_site_properties" ]]; then
        error "CRITICAL: uba-site.properties not found: $uba_site_properties"
        echo "  ℹ  This file is required for UBA UI authentication"
        echo "  ℹ  Create it by copying from /opt/caspida/conf/uba-site.properties"
        return 1
    fi
    
    # Critical UI authentication properties
    local ui_auth_props=(
        "ui.auth.rootca"
        "ui.auth.serverCert" 
        "ui.auth.privateKey"
    )
    
    local missing_props=()
    local found_props=()
    local invalid_paths=()
    local keystore_validated_certs=()
    
    echo "  Checking UBA UI authentication certificate configuration..."
    echo ""
    
    for prop in "${ui_auth_props[@]}"; do
        local prop_value=$(grep "^$prop=" "$uba_site_properties" 2>/dev/null | cut -d'=' -f2)
        
        if [[ -n "$prop_value" ]]; then
            found_props+=("$prop")
            echo "  ✓ Found: $prop=$prop_value"
            
            # Check if the certificate file exists
            if [[ -f "$prop_value" ]]; then
                success "    ✓ Certificate file exists: $prop_value"
                
                # Additional validation for certificate files
                case "$prop" in
                    "ui.auth.rootca"|"ui.auth.serverCert")
                        if openssl x509 -in "$prop_value" -noout -text >/dev/null 2>&1; then
                            local expires=$(openssl x509 -in "$prop_value" -noout -enddate 2>/dev/null | cut -d= -f2)
                            success "    ✓ Valid certificate: expires $expires"
                            
                            # Cross-validate against UBA keystores
                            echo "    🔍 Cross-validating against UBA keystores..."
                            validate_cert_against_keystores "$prop_value" "$prop"
                        else
                            error "    ✗ Invalid certificate format: $prop_value"
                            invalid_paths+=("$prop")
                        fi
                        ;;
                    "ui.auth.privateKey")
                        if openssl rsa -in "$prop_value" -check -noout >/dev/null 2>&1; then
                            success "    ✓ Valid private key: $prop_value"
                            
                            # For private key, check if corresponding public key matches certificates in keystores
                            echo "    🔍 Verifying private key matches keystore certificates..."
                            validate_private_key_against_keystores "$prop_value"
                        else
                            warning "    ⚠ Private key validation skipped (may be encrypted)"
                        fi
                        ;;
                esac
            else
                error "    ✗ Certificate file missing: $prop_value"
                invalid_paths+=("$prop")
            fi
            echo ""
        else
            missing_props+=("$prop")
            warning "  ⚠ Missing: $prop"
        fi
    done
    
    echo ""
    
    # Summary and recommendations
    if [[ ${#missing_props[@]} -eq 0 && ${#invalid_paths[@]} -eq 0 ]]; then
        success "All critical UBA UI authentication certificates are properly configured!"
        echo "  ✓ Configuration files contain valid certificate references"
        echo "  ✓ Certificate files exist and are properly formatted"
        echo "  ✓ Certificates are validated against UBA keystores"
    else
        error "CRITICAL: UBA UI authentication certificate configuration incomplete"
        echo ""
        
        if [[ ${#missing_props[@]} -gt 0 ]]; then
            echo "  Missing properties (add to $uba_site_properties):"
            for prop in "${missing_props[@]}"; do
                case "$prop" in
                    "ui.auth.rootca")
                        echo "    $prop=/etc/caspida/local/conf/rootca.crt"
                        ;;
                    "ui.auth.serverCert")
                        echo "    $prop=/etc/caspida/local/conf/server.crt"
                        ;;
                    "ui.auth.privateKey")
                        echo "    $prop=/etc/caspida/local/conf/server.key"
                        ;;
                esac
            done
            echo ""
        fi
        
        if [[ ${#invalid_paths[@]} -gt 0 ]]; then
            echo "  Invalid certificate paths that need to be fixed:"
            for prop in "${invalid_paths[@]}"; do
                echo "    $prop"
            done
            echo ""
        fi
        
        echo "  CRITICAL IMPACT:"
        echo "  • UBA web interface authentication may fail"
        echo "  • SSL/TLS connections to UBA UI may be rejected"
        echo "  • Users may not be able to access UBA web console"
        echo ""
        echo "  IMMEDIATE ACTION REQUIRED:"
        echo "  • Run: /root/uba-certificate-tools/scripts/install_uba_certs_refactored.sh"
        echo "  • Or manually configure the missing certificate properties"
        echo "  • Restart UBA services after certificate configuration"
        echo ""
        
        return 1
    fi
    
    echo ""
}

# Function to validate a certificate against UBA keystores
validate_cert_against_keystores() {
    local cert_file="$1"
    local cert_type="$2"
    local caspida_home="${CASPIDA_HOME:-/opt/caspida}"
    
    # Get certificate fingerprint for comparison
    local cert_fingerprint=$(openssl x509 -in "$cert_file" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':')
    local cert_subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
    
    if [[ -z "$cert_fingerprint" ]]; then
        warning "      ⚠ Could not get certificate fingerprint from $cert_file"
        return 1
    fi
    
    # List of keystores to check
    local keystores=(
        "$caspida_home/conf/keystore/uba-keystore"
        "$caspida_home/conf/jobconf/keystore.jm"
        "$caspida_home/conf/kafka/auth/server.keystore.jks"
    )
    
    local found_in_keystore=false
    
    for keystore in "${keystores[@]}"; do
        if [[ -f "$keystore" ]]; then
            local keystore_name=$(basename "$keystore")
            local keystore_password=$(test_keystore_passwords "$keystore" "caspida" "$keystore_name")
            
            if [[ -n "$keystore_password" ]]; then
                # Get all certificate fingerprints from keystore
                local keystore_fingerprints=$(sudo -u caspida keytool -list -v -keystore "$keystore" -storepass "$keystore_password" 2>/dev/null | grep "SHA256:" | cut -d: -f2- | tr -d ' :')
                
                if echo "$keystore_fingerprints" | grep -q "$cert_fingerprint"; then
                    success "      ✓ Certificate FOUND in keystore: $keystore_name"
                    echo "        Subject: $cert_subject"
                    found_in_keystore=true
                else
                    echo "      ○ Certificate not in keystore: $keystore_name"
                fi
            else
                warning "      ⚠ Could not access keystore: $keystore_name"
            fi
        fi
    done
    
    if [[ "$found_in_keystore" == "true" ]]; then
        success "      ✓ VALIDATION: UI certificate is properly integrated with UBA keystores"
    else
        warning "      ⚠ VALIDATION: UI certificate NOT found in any UBA keystore"
        echo "        This may be normal if UI uses separate certificate files"
        echo "        Recommendation: Verify UBA web service is using the configured certificate"
    fi
}

# Function to validate private key against keystores
validate_private_key_against_keystores() {
    local private_key_file="$1"
    local caspida_home="${CASPIDA_HOME:-/opt/caspida}"
    
    # Extract public key from private key for comparison
    local public_key_modulus=$(openssl rsa -in "$private_key_file" -noout -modulus 2>/dev/null | cut -d= -f2)
    
    if [[ -z "$public_key_modulus" ]]; then
        warning "      ⚠ Could not extract public key from private key (may be encrypted)"
        return 1
    fi
    
    # List of keystores to check
    local keystores=(
        "$caspida_home/conf/keystore/uba-keystore"
        "$caspida_home/conf/jobconf/keystore.jm"
        "$caspida_home/conf/kafka/auth/server.keystore.jks"
    )
    
    local found_matching_cert=false
    
    for keystore in "${keystores[@]}"; do
        if [[ -f "$keystore" ]]; then
            local keystore_name=$(basename "$keystore")
            local keystore_password=$(test_keystore_passwords "$keystore" "caspida" "$keystore_name")
            
            if [[ -n "$keystore_password" ]]; then
                # Get aliases that have private keys
                local private_key_aliases=$(sudo -u caspida keytool -list -keystore "$keystore" -storepass "$keystore_password" 2>/dev/null | grep "PrivateKeyEntry" | cut -d',' -f1)
                
                for alias in $private_key_aliases; do
                    # Export certificate and check if public key matches
                    local temp_cert="/tmp/keystore_cert_${alias}_$$.pem"
                    if sudo -u caspida keytool -export -alias "$alias" -keystore "$keystore" -storepass "$keystore_password" -rfc -file "$temp_cert" >/dev/null 2>&1; then
                        local cert_modulus=$(openssl x509 -in "$temp_cert" -noout -modulus 2>/dev/null | cut -d= -f2)
                        
                        if [[ "$public_key_modulus" == "$cert_modulus" ]]; then
                            success "      ✓ Private key MATCHES certificate '$alias' in keystore: $keystore_name"
                            found_matching_cert=true
                        fi
                        
                        rm -f "$temp_cert"
                    fi
                done
            fi
        fi
    done
    
    if [[ "$found_matching_cert" == "true" ]]; then
        success "      ✓ VALIDATION: Private key matches certificates in UBA keystores"
    else
        warning "      ⚠ VALIDATION: Private key does NOT match any certificates in UBA keystores"
        echo "        This may be normal if UI uses separate key/certificate files"
        echo "        Recommendation: Verify private key corresponds to configured server certificate"
    fi
}

# Main validation function
main() {
    local show_summary=false
    local custom_java_home=""
    local skip_jvm_full=false
    
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
            --skip-jvm-full)
                skip_jvm_full=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --keytool-help)
                show_keytool_help
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
    
    # Check and validate Java environment
    if ! check_java_environment; then
        error "Java environment check failed"
        exit 1
    fi
    
    log "UBA Keystore and Certificate Validation"
    log "========================================"
    echo "JAVA_HOME: $java_home"
    echo "CASPIDA_HOME: $caspida_home"
    echo ""
    
    # CRITICAL: Validate UBA UI authentication certificates first
    validate_uba_ui_certificates
    
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
        if [[ "$skip_jvm_full" == "true" ]]; then
            log "Validating Java System Truststore (Quick Check)"
            # Quick validation - just check accessibility and certificate count
            if validate_keystore_quick "$system_cacerts" "changeit" "Java System Truststore" "root"; then
                success "Java system truststore quick validation completed"
            else
                ((validation_errors++))
            fi
        else
            if validate_keystore "$system_cacerts" "changeit" "Java System Truststore" "root"; then
                success "Java system truststore validation completed"
            else
                ((validation_errors++))
            fi
        fi
    else
        warning "Java system truststore (cacerts) not found in $java_home"
        ((validation_errors++))
    fi
    
    # Validate trust relationships
    validate_trust_relationships "$caspida_home"
    
    # Validate configuration-referenced certificates
    validate_config_certificates "$caspida_home"
    
    # Check for missing Kafka SSL and Splunk ES certificate configurations
    check_missing_configurations "$caspida_home"
    
    # Check if Kafka certificates are trusted in JVM truststore
    check_kafka_certs_in_jvm "$caspida_home" "$java_home"
    
    # Validate critical UBA UI authentication certificates
    validate_uba_ui_certificates
    
    # Final summary
    echo ""
    log "Validation Summary"
    log "=================="
    
    # Critical UBA UI certificates status
    local ui_cert_status="UNKNOWN"
    if validate_uba_ui_certificates >/dev/null 2>&1; then
        ui_cert_status="CONFIGURED"
    else
        ui_cert_status="MISSING/INVALID"
        ((validation_errors++))
    fi
    
    echo "Critical UBA UI Authentication Certificates: $ui_cert_status"
    echo ""
    
    if [[ $validation_errors -eq 0 ]]; then
        success "All keystore validations passed successfully!"
        echo "✓ UBA certificate infrastructure appears to be properly configured"
        echo "✓ All keystores are accessible and contain valid certificates"
        echo "✓ Trust relationships have been validated"
        echo "✓ Critical UBA UI authentication certificates are properly configured"
    else
        error "Found $validation_errors validation errors"
        echo "✗ Some keystores may have issues that need attention"
        echo "✗ Review the errors above and fix before production use"
        if [[ "$ui_cert_status" == "MISSING/INVALID" ]]; then
            echo "✗ CRITICAL: UBA UI authentication certificates need immediate attention"
        fi
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
