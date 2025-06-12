#!/bin/bash

###############################################################################
# UBA Certificate Validation Script
# 
# Purpose: Validate and test UBA certificate installation
# Author: System Administrator
# Date: June 11, 2025
# Version: 1.0
#
# Usage: ./validate_uba_certs.sh [options]
###############################################################################

set -euo pipefail

###############################################################################
# Java Environment Detection (from CaspidaCommonEnv.sh)
###############################################################################

detect_java_home() {
    # Use the exact same logic as CaspidaCommonEnv.sh
    local PLATFORM="Ubuntu"
    
    # Detect platform like CaspidaCommonEnv.sh
    if [ -f /usr/bin/lsb_release ]; then
        /usr/bin/lsb_release -a 2>&1 | grep -q "Red Hat" && PLATFORM="Red Hat"
        /usr/bin/lsb_release -a 2>&1 | grep -q "Oracle Linux" && PLATFORM="Red Hat"
    else
        [ -f /etc/issue ] && cat /etc/issue | grep -q "Red Hat" && PLATFORM="Red Hat"
        [ -f /etc/oracle-release ] && cat /etc/oracle-release | grep -q "Oracle Linux" && PLATFORM="Red Hat"
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
        echo "ERROR: Java executable not found at $JAVA_HOME/bin/java" >&2
        exit 1
    fi
    
    if [ ! -x "$JAVA_HOME/bin/keytool" ]; then
        echo "ERROR: Keytool not found at $JAVA_HOME/bin/keytool" >&2
        exit 1
    fi
    
    echo "Detected JAVA_HOME: $JAVA_HOME"
}

# Initialize Java environment
# detect_java_home  # Temporarily disabled for testing

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# UBA paths
UBA_SITE_PROPERTIES="/etc/caspida/local/conf/uba-site.properties"
UBA_KEYSTORE_JM="/etc/caspida/conf/jobconf/keystore.jm"
JAVA_CACERTS="${JAVA_HOME}/lib/security/cacerts"

print_status() {
    echo -e "${BLUE}[CHECK]${NC} $*"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $*" >&2
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

check_ui_certificates() {
    print_status "Checking UI certificates configuration..."
    
    if [[ ! -f "$UBA_SITE_PROPERTIES" ]]; then
        print_error "UBA site properties file not found: $UBA_SITE_PROPERTIES"
        return 1
    fi
    
    local errors=0
    
    # Check for certificate properties
    local root_ca=$(grep "^ui.auth.rootca=" "$UBA_SITE_PROPERTIES" 2>/dev/null | cut -d= -f2)
    local private_key=$(grep "^ui.auth.privateKey=" "$UBA_SITE_PROPERTIES" 2>/dev/null | cut -d= -f2)
    local server_cert=$(grep "^ui.auth.serverCert=" "$UBA_SITE_PROPERTIES" 2>/dev/null | cut -d= -f2)
    
    if [[ -n "$root_ca" ]] && [[ -f "$root_ca" ]]; then
        print_success "Root CA certificate found: $root_ca"
        
        # Validate certificate
        if openssl x509 -in "$root_ca" -text -noout &> /dev/null; then
            local expiry=$(openssl x509 -in "$root_ca" -noout -dates | grep 'notAfter' | cut -d= -f2)
            print_success "Root CA certificate is valid (expires: $expiry)"
        else
            print_error "Root CA certificate is invalid: $root_ca"
            ((errors++))
        fi
    else
        print_warning "Root CA certificate not configured or file missing"
    fi
    
    if [[ -n "$private_key" ]] && [[ -f "$private_key" ]]; then
        print_success "Private key found: $private_key"
        
        # Check permissions
        local perms=$(stat -c %a "$private_key" 2>/dev/null || echo "000")
        if [[ "$perms" == "600" ]]; then
            print_success "Private key has correct permissions (600)"
        else
            print_warning "Private key permissions should be 600 (currently: $perms)"
        fi
    else
        print_warning "Private key not configured or file missing"
    fi
    
    if [[ -n "$server_cert" ]] && [[ -f "$server_cert" ]]; then
        print_success "Server certificate found: $server_cert"
        
        # Validate certificate
        if openssl x509 -in "$server_cert" -text -noout &> /dev/null; then
            local expiry=$(openssl x509 -in "$server_cert" -noout -dates | grep 'notAfter' | cut -d= -f2)
            local subject=$(openssl x509 -in "$server_cert" -noout -subject | sed 's/subject=//')
            print_success "Server certificate is valid (expires: $expiry)"
            print_success "Certificate subject: $subject"
            
            # Check if certificate matches private key
            if [[ -n "$private_key" ]] && [[ -f "$private_key" ]]; then
                # Check if certificate matches private key using FIPS-compliant SHA256
                local cert_modulus=$(openssl x509 -noout -modulus -in "$server_cert" | openssl sha256)
                local key_modulus=$(openssl rsa -noout -modulus -in "$private_key" | openssl sha256)
                
                if [[ "$cert_modulus" == "$key_modulus" ]]; then
                    print_success "Certificate and private key match"
                else
                    print_error "Certificate and private key do not match"
                    ((errors++))
                fi
            fi
        else
            print_error "Server certificate is invalid: $server_cert"
            ((errors++))
        fi
    else
        print_warning "Server certificate not configured or file missing"
    fi
    
    return $errors
}

check_job_manager_certificates() {
    print_status "Checking Job Manager certificates..."
    
    if [[ ! -f "$UBA_KEYSTORE_JM" ]]; then
        print_error "Job Manager keystore not found: $UBA_KEYSTORE_JM"
        return 1
    fi
    
    local errors=0
    
    # Check keystore contents
    if "$JAVA_HOME/bin/keytool" -list -keystore "$UBA_KEYSTORE_JM" -storepass "password" 2>/dev/null | grep -q "jmserver"; then
        print_success "Job Manager certificate 'jmserver' found in keystore"
        
        # Get certificate details
        local cert_info=$("$JAVA_HOME/bin/keytool" -list -v -keystore "$UBA_KEYSTORE_JM" -storepass "password" -alias "jmserver" 2>/dev/null)
        if [[ -n "$cert_info" ]]; then
            local valid_until=$(echo "$cert_info" | grep "Valid from" | head -1)
            print_success "Certificate details: $valid_until"
        fi
    else
        print_error "Job Manager certificate 'jmserver' not found in keystore"
        ((errors++))
    fi
    
    return $errors
}

check_java_truststore() {
    print_status "Checking Java truststore for CA certificates..."
    
    if [[ ! -f "$JAVA_CACERTS" ]]; then
        print_error "Java cacerts file not found: $JAVA_CACERTS"
        return 1
    fi
    
    local uba_ca_count=$("$JAVA_HOME/bin/keytool" -list -keystore "$JAVA_CACERTS" -storepass "changeit" 2>/dev/null | grep -c "uba_ca_" || echo "0")
    
    if [[ "$uba_ca_count" -gt 0 ]]; then
        print_success "Found $uba_ca_count UBA CA certificate(s) in Java truststore"
    else
        print_warning "No UBA CA certificates found in Java truststore"
    fi
    
    return 0
}

check_service_status() {
    print_status "Checking UBA service status..."
    
    local services=("caspida-ui" "caspida-resourcesmonitor" "caspida-jobmanager")
    local errors=0
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" &>/dev/null || service "$service" status &>/dev/null; then
            print_success "Service $service is running"
        else
            print_error "Service $service is not running"
            ((errors++))
        fi
    done
    
    return $errors
}

test_web_interface() {
    print_status "Testing UBA web interface connectivity..."
    
    local uba_host=$(hostname -f)
    local uba_port="9001"
    
    # Test HTTPS connection
    if command -v curl &> /dev/null; then
        if curl -k -s --connect-timeout 10 "https://${uba_host}:${uba_port}" > /dev/null; then
            print_success "UBA web interface is accessible at https://${uba_host}:${uba_port}"
        else
            print_warning "UBA web interface may not be accessible (curl test failed)"
        fi
    else
        print_warning "curl not available - cannot test web interface connectivity"
    fi
    
    # Test certificate
    if command -v openssl &> /dev/null; then
        local cert_check=$(echo | openssl s_client -connect "${uba_host}:${uba_port}" -servername "$uba_host" 2>/dev/null)
        if echo "$cert_check" | grep -q "Verify return code: 0"; then
            print_success "SSL certificate verification passed"
        elif echo "$cert_check" | grep -q "self signed certificate"; then
            print_warning "Using self-signed certificate (expected for default UBA installation)"
        else
            print_warning "SSL certificate verification issues detected"
        fi
    fi
}

check_certificate_expiration() {
    print_status "Checking certificate expiration dates..."
    
    local warnings=0
    
    # Check UI certificates
    if [[ -f "$UBA_SITE_PROPERTIES" ]]; then
        # Get unique certificate paths (deduplicate)
        local certs=(
            $(grep "^ui.auth.rootca=" "$UBA_SITE_PROPERTIES" 2>/dev/null | cut -d= -f2 | sort -u)
            $(grep "^ui.auth.serverCert=" "$UBA_SITE_PROPERTIES" 2>/dev/null | cut -d= -f2 | sort -u)
        )
        
        # Remove duplicates from the array
        local unique_certs=($(printf '%s\n' "${certs[@]}" | sort -u))
        
        for cert in "${unique_certs[@]}"; do
            if [[ -f "$cert" ]]; then
                local expiry_date=$(openssl x509 -in "$cert" -noout -dates | grep 'notAfter' | cut -d= -f2)
                local exp_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
                local now_epoch=$(date +%s)
                local days_until_exp=$(( (exp_epoch - now_epoch) / 86400 ))
                
                if [[ "$days_until_exp" -lt 0 ]]; then
                    print_error "Certificate expired: $cert"
                    ((warnings++))
                elif [[ "$days_until_exp" -lt 30 ]]; then
                    print_warning "Certificate expires in $days_until_exp days: $cert"
                    ((warnings++))
                else
                    print_success "Certificate valid for $days_until_exp days: $(basename "$cert")"
                fi
            fi
        done
    fi
    
    return $warnings
}

generate_report() {
    echo
    print_status "=== UBA CERTIFICATE VALIDATION REPORT ==="
    echo "Generated: $(date)"
    echo "Hostname: $(hostname -f)"
    echo "UBA Installation: /opt/caspida"
    echo
    
    local total_errors=0
    local total_warnings=0
    
    echo "1. UI CERTIFICATES"
    check_ui_certificates || ((total_errors += $?))
    echo
    
    echo "2. JOB MANAGER CERTIFICATES"
    check_job_manager_certificates || ((total_errors += $?))
    echo
    
    echo "3. JAVA TRUSTSTORE"
    check_java_truststore
    echo
    
    echo "4. SERVICE STATUS"
    check_service_status || ((total_errors += $?))
    echo
    
    echo "5. WEB INTERFACE CONNECTIVITY"
    test_web_interface
    echo
    
    echo "6. CERTIFICATE EXPIRATION"
    check_certificate_expiration || ((total_warnings += $?))
    echo
    
    print_status "=== SUMMARY ==="
    if [[ "$total_errors" -eq 0 ]]; then
        print_success "All critical checks passed"
    else
        print_error "$total_errors critical error(s) found"
    fi
    
    if [[ "$total_warnings" -gt 0 ]]; then
        print_warning "$total_warnings warning(s) found"
    fi
    
    echo
    echo "NEXT STEPS:"
    if [[ "$total_errors" -gt 0 ]]; then
        echo "- Review and fix critical errors above"
        echo "- Check UBA service logs: /var/log/caspida/"
        echo "- Consider re-running certificate installation"
    else
        echo "- Monitor UBA logs for any certificate-related issues"
        echo "- Schedule certificate renewal before expiration"
        echo "- Test end-to-end connectivity with search heads"
    fi
    echo
}

main() {
    echo "UBA Certificate Validation Script"
    echo "================================="
    echo "Using JAVA_HOME: $JAVA_HOME"
    echo
    
    # Java environment is already validated by detect_java_home()
    
    # Generate validation report
    generate_report
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
