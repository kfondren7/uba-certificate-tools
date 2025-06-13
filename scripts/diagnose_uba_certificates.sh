#!/bin/bash

###############################################################################
# UBA Certificate Diagnostic Script
# 
# Purpose: Diagnose certificate and PKIX path building issues (READ-ONLY)
# Part of: UBA Certificate Tools Project
# Author: GitHub Copilot
# Date: June 13, 2025
# Version: 1.0
#
# Usage: ./diagnose_uba_certificates.sh
#
# This script performs comprehensive read-only diagnostics of:
# - Java environment and keystore access
# - UBA service management detection (systemd vs traditional)
# - Certificate validity and PKIX error analysis  
# - Endpoint connectivity and health checks
# - System certificate store validation
# - Recent error analysis from JobManager logs
#
# Reference:
# - UBA Certificate Tools: /root/uba-certificate-tools/
# - Remediation Script: ./fix_uba_certificate_issues.sh
# - Documentation: ../docs/CERTIFICATE_SCRIPTS_SUMMARY.md
###############################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

log "Starting Splunk UBA Certificate Diagnostics..."

# 1. Check Java Environment
log "=== Java Environment Check ==="
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    success "Java found: $JAVA_VERSION"
    
    # Get JAVA_HOME
    if [[ -n "${JAVA_HOME:-}" ]]; then
        success "JAVA_HOME is set: $JAVA_HOME"
    else
        warn "JAVA_HOME is not set"
        # Try to find Java home
        JAVA_PATH=$(which java)
        if [[ -L "$JAVA_PATH" ]]; then
            JAVA_HOME=$(readlink -f "$JAVA_PATH" | sed 's/\/bin\/java$//')
            log "Detected Java home: $JAVA_HOME"
        fi
    fi
else
    error "Java not found in PATH"
    exit 1
fi

# 2. Check UBA Services Status and Management Method
log "=== UBA Services Status and Management Method ==="

# UBA service names for systemd management (from install_uba_certs.sh)
UBA_SYSTEMD_SERVICES=("caspida-jobmanager" "caspida-ui" "caspida-resourcesmonitor")
UBA_LEGACY_SERVICES=("caspida-platform" "jobmanager" "caspida-ui")

# Function to check if UBA is managed via systemd (from install_uba_certs.sh)
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
        return 0
    fi
    
    # Check if systemd services are available but not active
    if systemctl list-units --type=service --all 2>/dev/null | grep -q caspida; then
        return 0
    fi
    
    # Default to traditional management
    return 1
}

# Detect management method and show service status
if check_systemd_management; then
    success "UBA is managed via systemd services"
    SERVICE_MANAGEMENT_METHOD="systemd"
    
    log "Checking systemd UBA services:"
    for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            success "  $service is running"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            warn "  $service is enabled but not running"
        else
            warn "  $service is not enabled/available"
        fi
    done
    
    # Show which systemd services are actually installed
    log "Available systemd UBA services:"
    for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
        if systemctl list-unit-files --type=service | grep -q "$service"; then
            log "  $service: $(systemctl is-enabled "$service" 2>/dev/null || echo 'not available')"
        fi
    done
else
    log "UBA is managed via traditional scripts"
    SERVICE_MANAGEMENT_METHOD="traditional"
    
    # Check traditional script availability
    if [[ -x "/opt/caspida/bin/Caspida" ]]; then
        success "Caspida management script found: /opt/caspida/bin/Caspida"
        
        # Try to get status via traditional method
        log "Checking UBA status via traditional script:"
        if sudo -u caspida /opt/caspida/bin/Caspida status >/dev/null 2>&1; then
            success "  UBA services appear to be running (traditional)"
            
            # Get detailed status output
            log "UBA service status details:"
            sudo -u caspida /opt/caspida/bin/Caspida status 2>/dev/null | grep -E "(running|stopped|OK|FAILED)" | while read line; do
                log "  $line"
            done
        else
            warn "  UBA services appear to be stopped (traditional)"
        fi
        
        # Show available traditional commands
        log "Available Caspida management commands:"
        log "  $(ls -la /opt/caspida/bin/Caspida 2>/dev/null || echo 'Script not found')"
    else
        warn "Caspida management script not found at /opt/caspida/bin/Caspida"
    fi
    
    # Also check legacy service names for completeness
    log "Checking legacy systemd service names:"
    for service in "${UBA_LEGACY_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            warn "  $service is running (legacy name)"
        else
            log "  $service is not running (legacy name)"
        fi
    done
fi

log "Service Management Method: $SERVICE_MANAGEMENT_METHOD"

# 3. Check UBA Processes and Ports
log "=== UBA Process and Port Check ==="
log "JobManager processes:"
ps aux | grep -i jobmanager | grep -v grep || log "No JobManager processes found"

log "UBA listening ports:"
netstat -tlnp | grep -E ':(9002|80|443|8000|8065)' || log "No UBA ports found listening"

# 4. Check Certificate Files
log "=== Certificate Files Check ==="

# Function to extract keystore password from config files
get_keystore_password_from_config() {
    local config_password=""
    
    # Check JobManager config for keystore password
    if [[ -f "/etc/caspida/conf/jobconf/jobmgr.yml" ]]; then
        config_password=$(grep -i "keyStorePassword:" /etc/caspida/conf/jobconf/jobmgr.yml 2>/dev/null | sed 's/.*keyStorePassword:[[:space:]]*//' | tr -d '"' | tr -d "'" | head -1)
        if [[ -n "$config_password" ]]; then
            log "Found keystore password in jobmgr.yml: $config_password"
            echo "$config_password"
            return 0
        fi
    fi
    
    # Check other common config locations
    for config_file in "/etc/caspida/conf/caspida.conf" "/opt/caspida/conf/caspida.conf" "/etc/caspida/local/conf/caspida.conf"; do
        if [[ -f "$config_file" ]]; then
            config_password=$(grep -i -E "(keystore.*password|ssl.*password)" "$config_file" 2>/dev/null | head -1 | sed 's/.*=//' | tr -d '"' | tr -d "'" | xargs)
            if [[ -n "$config_password" ]]; then
                log "Found potential keystore password in $config_file: $config_password"
                echo "$config_password"
                return 0
            fi
        fi
    done
    
    return 1
}

# Get password from config if available
CONFIG_PASSWORD=$(get_keystore_password_from_config)

# JobManager keystore
JM_KEYSTORE="/etc/caspida/conf/jobconf/keystore.jm"
if [[ -f "$JM_KEYSTORE" ]]; then
    success "JobManager keystore found: $JM_KEYSTORE"
    log "Keystore permissions: $(ls -la "$JM_KEYSTORE")"
    
    # Try to list keystore contents (try different common passwords + config password)
    log "JobManager keystore contents:"
    keystore_passwords=("password" "caspida123" "changeit" "caspida" "splunk" "admin" "123456" "default")
    
    # Add password from config if found
    if [[ -n "$CONFIG_PASSWORD" ]]; then
        keystore_passwords=("$CONFIG_PASSWORD" "${keystore_passwords[@]}")
        log "Using password from configuration file"
    fi
    
    keystore_readable=false
    
    for password in "${keystore_passwords[@]}"; do
        if keytool -list -keystore "$JM_KEYSTORE" -storepass "$password" 2>/dev/null >/dev/null; then
            success "Successfully read JobManager keystore with password: $password"
            # Show brief keystore info
            keytool -list -keystore "$JM_KEYSTORE" -storepass "$password" 2>/dev/null | head -10
            keystore_readable=true
            break
        fi
    done
    
    if [[ "$keystore_readable" == "false" ]]; then
        warn "Could not read JobManager keystore with common passwords"
        log "Tried passwords: ${keystore_passwords[*]}"
        log "If using a custom password, you may need to manually verify the keystore:"
        log "  keytool -list -keystore $JM_KEYSTORE -storepass <your_password>"
    fi
else
    error "JobManager keystore not found: $JM_KEYSTORE"
fi

# Java cacerts
JAVA_CACERTS="${JAVA_HOME}/lib/security/cacerts"
SYSTEM_CACERTS="/etc/pki/ca-trust/extracted/java/cacerts"

for cacerts_path in "$JAVA_CACERTS" "$SYSTEM_CACERTS"; do
    if [[ -f "$cacerts_path" ]]; then
        success "Java cacerts found: $cacerts_path"
        log "Cacerts permissions: $(ls -la "$cacerts_path")"
        
        # Count certificates
        cert_count=$(keytool -list -keystore "$cacerts_path" -storepass changeit 2>/dev/null | grep -c "Certificate fingerprint" || echo "0")
        log "Number of CA certificates: $cert_count"
        
        if [[ $cert_count -lt 50 ]]; then
            warn "Low number of CA certificates in $cacerts_path (expected 100+)"
        else
            success "Good number of CA certificates in cacerts"
        fi
    else
        warn "Java cacerts not found: $cacerts_path"
    fi
done

# 5. Check for PKIX Errors in Logs
log "=== PKIX Error Analysis ==="

# Check JobManager logs
JM_LOG="/var/log/caspida/jobmanager-debug.log"
if [[ -f "$JM_LOG" ]]; then
    success "JobManager log found: $JM_LOG"
    
    # Look for recent PKIX errors (actual errors, not config lines)
    pkix_errors=$(grep -i -E "(pkix.*error|pkix.*exception|unable to find valid certification path|SSLHandshakeException|certificate.*error)" "$JM_LOG" 2>/dev/null | tail -5 || true)
    if [[ -n "$pkix_errors" ]]; then
        warn "Recent PKIX errors found in JobManager log:"
        echo "$pkix_errors"
    else
        success "No recent PKIX errors in JobManager log"
    fi
else
    warn "JobManager log not found: $JM_LOG"
fi

# Check UI logs
UI_LOG="/var/vcap/sys/log/caspida/ui/log.log"
if [[ -f "$UI_LOG" ]]; then
    success "UI log found: $UI_LOG"
    
    # Look for recent SSL/certificate errors
    ssl_errors=$(grep -i -E "(ssl.*error|ssl.*exception|certificate.*error|handshake.*failed)" "$UI_LOG" 2>/dev/null | tail -5 || true)
    if [[ -n "$ssl_errors" ]]; then
        warn "Recent SSL/certificate errors found in UI log:"
        echo "$ssl_errors"
    else
        success "No recent SSL/certificate errors in UI log"
    fi
else
    warn "UI log not found: $UI_LOG"
fi

# 6. Test Endpoint Connectivity
log "=== Endpoint Connectivity Test ==="

# Test JobManager health endpoint
JM_HEALTH_URL="https://localhost:9002/admin/healthcheck"
log "Testing JobManager health endpoint: $JM_HEALTH_URL"

if curl -k -s --connect-timeout 10 "$JM_HEALTH_URL" >/dev/null 2>&1; then
    success "JobManager health endpoint is accessible"
    
    # Get the actual response
    response=$(curl -k -s --connect-timeout 10 "$JM_HEALTH_URL" 2>/dev/null)
    log "Health check response: $response"
else
    error "JobManager health endpoint is not accessible"
fi

# Test local UBA endpoints
UBA_ENDPOINTS=(
    "http://localhost/"
    "https://localhost/"
    "http://localhost:8000/"
    "https://localhost:9002/admin/healthcheck"
)

for endpoint in "${UBA_ENDPOINTS[@]}"; do
    log "Testing endpoint: $endpoint"
    if curl -k -s --connect-timeout 5 "$endpoint" >/dev/null 2>&1; then
        success "Endpoint accessible: $endpoint"
    else
        warn "Endpoint not accessible: $endpoint"
    fi
done

# 7. Check Certificate Validity
log "=== Certificate Validity Check ==="

# Check if any certificates are expired or expiring soon
if [[ -f "$JM_KEYSTORE" ]]; then
    log "Checking JobManager keystore certificate validity:"
    keystore_passwords=("password" "caspida123" "changeit" "caspida" "splunk" "admin" "123456" "default")
    
    # Add password from config if found
    if [[ -n "$CONFIG_PASSWORD" ]]; then
        keystore_passwords=("$CONFIG_PASSWORD" "${keystore_passwords[@]}")
    fi
    
    for password in "${keystore_passwords[@]}"; do
        if keytool -list -v -keystore "$JM_KEYSTORE" -storepass "$password" 2>/dev/null | grep -A 2 -B 2 "Valid from\|until"; then
            break
        fi
    done 2>/dev/null || log "Could not check certificate validity with available passwords"
fi

# 8. Check UBA Configuration
log "=== UBA Configuration Check ==="

UBA_CONFIG="/etc/caspida/conf/jobconf/jobmgr.yml"
if [[ -f "$UBA_CONFIG" ]]; then
    success "JobManager config found: $UBA_CONFIG"
    
    # Check for SSL/TLS configuration
    log "SSL/TLS configuration in jobmgr.yml:"
    grep -i -A 5 -B 5 "ssl\|tls\|keystore\|truststore" "$UBA_CONFIG" || log "No SSL configuration found"
else
    warn "JobManager config not found: $UBA_CONFIG"
fi

# 9. System Certificate Store Check
log "=== System Certificate Store Check ==="

# Check if ca-certificates package is installed
if rpm -q ca-certificates &>/dev/null; then
    success "ca-certificates package is installed"
    ca_version=$(rpm -q ca-certificates)
    log "Version: $ca_version"
else
    warn "ca-certificates package is not installed"
fi

# Check update-ca-trust status
if command -v update-ca-trust &>/dev/null; then
    success "update-ca-trust command is available"
else
    warn "update-ca-trust command is not available"
fi

# 10. Network Connectivity Check
log "=== Network Connectivity Check ==="

# Check if we can resolve common certificate authorities
log "Testing DNS resolution for common CAs:"
for domain in "letsencrypt.org" "digicert.com" "verisign.com"; do
    if nslookup "$domain" &>/dev/null; then
        success "DNS resolution working for $domain"
    else
        warn "DNS resolution failed for $domain"
    fi
done

# Check internet connectivity
log "Testing internet connectivity:"
if ping -c 1 8.8.8.8 &>/dev/null; then
    success "Internet connectivity is working"
else
    warn "Internet connectivity may be limited"
fi

# 11. Generate Summary and Recommendations
log "=== Diagnostic Summary and Recommendations ==="

echo
echo "==================== DIAGNOSTIC SUMMARY ===================="
echo

# Check for common issues and provide recommendations
has_issues=false

# Check 1: PKIX errors present
if [[ -f "$JM_LOG" ]] && grep -q -i -E "(pkix.*path.*build|unable to find valid certification path|SSLHandshakeException)" "$JM_LOG" 2>/dev/null; then
    error "ISSUE: PKIX path building failures detected"
    echo "  → Recommendation: Update Java cacerts truststore"
    echo "  → Command: update-ca-trust && cp /etc/pki/ca-trust/extracted/java/cacerts \$JAVA_HOME/lib/security/cacerts"
    has_issues=true
fi

# Check 2: Low certificate count in cacerts
for cacerts_path in "$JAVA_CACERTS" "$SYSTEM_CACERTS"; do
    if [[ -f "$cacerts_path" ]]; then
        cert_count=$(keytool -list -keystore "$cacerts_path" -storepass changeit 2>/dev/null | grep -c "Certificate fingerprint" || echo "0")
        if [[ $cert_count -lt 50 ]]; then
            error "ISSUE: Low number of CA certificates in $cacerts_path ($cert_count)"
            echo "  → Recommendation: Update ca-certificates package and refresh cacerts"
            echo "  → Commands: yum update ca-certificates && update-ca-trust"
            has_issues=true
        fi
    fi
done

# Check 3: Services not running (updated for proper management method detection)
if [[ "$SERVICE_MANAGEMENT_METHOD" == "systemd" ]]; then
    for service in "${UBA_SYSTEMD_SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            warn "ISSUE: $service is not running (systemd)"
            echo "  → Recommendation: Start the service: systemctl start $service"
            has_issues=true
        fi
    done
else
    # Traditional management
    if [[ -x "/opt/caspida/bin/Caspida" ]]; then
        if sudo -u caspida /opt/caspida/bin/Caspida status >/dev/null 2>&1; then
            # Additional check - look for specific service status
            status_output=$(sudo -u caspida /opt/caspida/bin/Caspida status 2>/dev/null)
            if echo "$status_output" | grep -q "is running\|OK"; then
                # Services are actually running
                log "UBA services are confirmed running via traditional management"
            else
                warn "ISSUE: UBA services are not running (traditional management)"
                echo "  → Recommendation: Start services: sudo -u caspida /opt/caspida/bin/Caspida start-all"
                has_issues=true
            fi
        else
            warn "ISSUE: UBA services are not running (traditional management)"
            echo "  → Recommendation: Start services: sudo -u caspida /opt/caspida/bin/Caspida start-all"
            has_issues=true
        fi
    else
        warn "ISSUE: Cannot determine UBA service status - management script missing"
        echo "  → Recommendation: Check UBA installation and service management method"
        has_issues=true
    fi
fi

# Check 4: Keystore access issues
if [[ -f "$JM_KEYSTORE" ]]; then
    keystore_accessible=false
    keystore_passwords=("password" "caspida123" "changeit" "caspida" "splunk" "admin" "123456" "default")
    
    # Add password from config if found
    if [[ -n "$CONFIG_PASSWORD" ]]; then
        keystore_passwords=("$CONFIG_PASSWORD" "${keystore_passwords[@]}")
    fi
    
    for password in "${keystore_passwords[@]}"; do
        if keytool -list -keystore "$JM_KEYSTORE" -storepass "$password" 2>/dev/null >/dev/null; then
            keystore_accessible=true
            break
        fi
    done
    
    if [[ "$keystore_accessible" == "false" ]]; then
        error "ISSUE: Cannot access JobManager keystore with available passwords"
        echo "  → Tried passwords: ${keystore_passwords[*]}"
        echo "  → Recommendation: Verify keystore password or check file corruption"
        echo "  → Manual test: keytool -list -keystore $JM_KEYSTORE -storepass <your_password>"
        echo "  → Check configuration files for custom keystore password"
        has_issues=true
    fi
fi

if [[ "$has_issues" == "false" ]]; then
    success "No major issues detected in certificate configuration"
    echo "  → System appears to be healthy"
else
    echo
    warn "Issues detected - consider running the remediation script"
    echo "  → Remediation script: ./fix_uba_certificate_issues.sh"
    echo "  → Or use: /root/fix_uba_certificate_issues.sh"
fi

echo
echo "==================== RECENT JOBMANAGER ERRORS ===================="
echo

# Show recent errors from JobManager debug log
JM_LOG="/var/log/caspida/jobmanager-debug.log"
if [[ -f "$JM_LOG" ]]; then
    log "Showing recent errors from JobManager debug log (last 50 lines with errors):"
    echo
    
    # Get recent error lines (last 1000 lines, then filter for errors)
    recent_errors=$(tail -1000 "$JM_LOG" 2>/dev/null | grep -i -E "(error|exception|failed.*|.*pkix.*path.*build|ssl.*handshake.*failed|certificate.*error)" | tail -50 || true)
    
    if [[ -n "$recent_errors" ]]; then
        warn "Recent errors found in JobManager log:"
        echo "----------------------------------------"
        echo "$recent_errors"
        echo "----------------------------------------"
        echo
        
        # Count different types of errors
        pkix_count=$(echo "$recent_errors" | grep -c -i -E "(pkix.*path.*build|unable to find valid certification path)" 2>/dev/null || echo "0")
        ssl_count=$(echo "$recent_errors" | grep -c -i -E "(ssl.*error|handshake.*failed)" 2>/dev/null || echo "0")
        cert_count=$(echo "$recent_errors" | grep -c -i "certificate.*error" 2>/dev/null || echo "0")
        
        log "Error Summary:"
        [[ $pkix_count -gt 0 ]] && warn "  - PKIX/Certificate path errors: $pkix_count"
        [[ $ssl_count -gt 0 ]] && warn "  - SSL/Handshake errors: $ssl_count"
        [[ $cert_count -gt 0 ]] && warn "  - Certificate-related errors: $cert_count"
        
        echo
        if [[ $pkix_count -gt 0 ]]; then
            error "CRITICAL: PKIX path building failures indicate CA certificate trust issues"
            echo "  → This typically means the Java cacerts truststore is missing required CA certificates"
            echo "  → Run the remediation script to fix: /root/fix_uba_certificate_issues.sh"
        fi
    else
        success "No recent errors found in JobManager debug log"
    fi
else
    warn "JobManager debug log not found: $JM_LOG"
fi

echo
echo "==================== END DIAGNOSTIC ===================="
echo

log "Diagnostic completed. Check the summary above for any issues and recommendations."
