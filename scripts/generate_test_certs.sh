#!/bin/bash

###############################################################################
# UBA Test Certificate Generation Script
# 
# Purpose: Generate self-signed certificates for UBA testing
# Author: System Administrator
# Date: June 11, 2025
# Version: 1.0
#
# Usage: ./generate_test_certs.sh [options]
###############################################################################

set -euo pipefail

# Configuration
CERT_DIR="/tmp/uba_test_certs"
KEY_SIZE=2048
CERT_DAYS=365
COUNTRY="US"
STATE="CA"
CITY="San Francisco"
ORG="Splunk Inc"
OU="UBA Test"
UBA_HOSTNAME=$(hostname -f)
UBA_SHORT_HOSTNAME=$(hostname -s)

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $*"
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

usage() {
    cat << EOF
Usage: $0 [options]

OPTIONS:
    --cert-dir DIR      Directory to store certificates (default: $CERT_DIR)
    --hostname NAME     UBA hostname for certificate (default: $UBA_HOSTNAME)
    --days DAYS         Certificate validity in days (default: $CERT_DAYS)
    --key-size SIZE     RSA key size (default: $KEY_SIZE)
    --country CODE      Country code (default: $COUNTRY)
    --state STATE       State/Province (default: $STATE)
    --city CITY         City (default: $CITY)
    --org ORG           Organization (default: $ORG)
    --ou OU             Organizational Unit (default: $OU)
    -h, --help          Show this help

EXAMPLES:
    # Generate certificates with defaults
    $0

    # Generate certificates for specific hostname
    $0 --hostname uba.example.com

    # Generate certificates with custom validity
    $0 --days 730 --hostname uba.internal.com

GENERATED FILES:
    - root-ca.key          Root CA private key
    - root-ca.crt          Root CA certificate
    - ca-bundle.crt        CA bundle (copy of root-ca.crt)
    - server.key           Server private key
    - server.crt           Server certificate
    - \${hostname}.key      Host-specific private key
    - \${hostname}.crt      Host-specific certificate
    - server.p12           PKCS#12 keystore

EOF
}

generate_ca_certificate() {
    print_status "Generating Root CA certificate..."
    
    local ca_key="$CERT_DIR/root-ca.key"
    local ca_cert="$CERT_DIR/root-ca.crt"
    local ca_bundle="$CERT_DIR/ca-bundle.crt"
    
    # Generate CA private key
    openssl genrsa -out "$ca_key" $KEY_SIZE
    chmod 600 "$ca_key"
    
    # Generate CA certificate
    openssl req -new -x509 -key "$ca_key" -out "$ca_cert" -days $CERT_DAYS -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=UBA Root CA"
    
    # Create CA bundle (copy of root CA for compatibility)
    cp "$ca_cert" "$ca_bundle"
    
    print_success "Root CA certificate generated: $ca_cert"
    
    # Display certificate info
    print_status "CA Certificate details:"
    openssl x509 -in "$ca_cert" -noout -text | grep -A2 "Subject:"
    openssl x509 -in "$ca_cert" -noout -text | grep -A2 "Validity"
}

generate_server_certificate() {
    local hostname="$1"
    local cert_name="$2"
    
    print_status "Generating server certificate for: $hostname"
    
    local server_key="$CERT_DIR/${cert_name}.key"
    local server_csr="$CERT_DIR/${cert_name}.csr"
    local server_cert="$CERT_DIR/${cert_name}.crt"
    local ca_key="$CERT_DIR/root-ca.key"
    local ca_cert="$CERT_DIR/root-ca.crt"
    
    # Generate server private key
    openssl genrsa -out "$server_key" $KEY_SIZE
    chmod 600 "$server_key"
    
    # Create certificate extensions file
    local ext_file="$CERT_DIR/${cert_name}.ext"
    cat > "$ext_file" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $hostname
DNS.2 = $UBA_SHORT_HOSTNAME
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Add UBA hostname if different from provided hostname
    if [[ "$hostname" != "$UBA_HOSTNAME" ]]; then
        echo "DNS.4 = $UBA_HOSTNAME" >> "$ext_file"
    fi
    
    # Generate certificate signing request
    openssl req -new -key "$server_key" -out "$server_csr" -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=$hostname"
    
    # Generate server certificate signed by CA
    openssl x509 -req -in "$server_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial -out "$server_cert" -days $CERT_DAYS -extfile "$ext_file"
    
    # Clean up CSR and extensions file
    rm -f "$server_csr" "$ext_file"
    
    print_success "Server certificate generated: $server_cert"
    
    # Display certificate info
    print_status "Server Certificate details:"
    openssl x509 -in "$server_cert" -noout -text | grep -A2 "Subject:"
    openssl x509 -in "$server_cert" -noout -text | grep -A5 "Subject Alternative Name"
}

generate_pkcs12_keystore() {
    local hostname="$1"
    local cert_name="$2"
    
    print_status "Generating PKCS#12 keystore for: $cert_name"
    
    local server_key="$CERT_DIR/${cert_name}.key"
    local server_cert="$CERT_DIR/${cert_name}.crt"
    local ca_cert="$CERT_DIR/root-ca.crt"
    local p12_file="$CERT_DIR/${cert_name}.p12"
    
    # Generate PKCS#12 file with password "password"
    openssl pkcs12 -export -in "$server_cert" -inkey "$server_key" -certfile "$ca_cert" -name "server" -out "$p12_file" -password pass:password
    
    chmod 600 "$p12_file"
    
    print_success "PKCS#12 keystore generated: $p12_file"
}

create_certificate_info() {
    print_status "Creating certificate information file..."
    
    local info_file="$CERT_DIR/CERTIFICATE_INFO.txt"
    
    cat > "$info_file" << EOF
UBA Test Certificates
=====================
Generated: $(date)
Hostname: $UBA_HOSTNAME
Validity: $CERT_DAYS days

FILES GENERATED:
================

Root CA:
- root-ca.key          Root CA private key (keep secure!)
- root-ca.crt          Root CA certificate (install in Java truststore)
- ca-bundle.crt        CA bundle (same as root-ca.crt)

Server Certificates:
- server.key           Generic server private key
- server.crt           Generic server certificate
- $UBA_SHORT_HOSTNAME.key          Host-specific private key
- $UBA_SHORT_HOSTNAME.crt          Host-specific certificate

PKCS#12 Keystores:
- server.p12           Server keystore (password: password)

USAGE INSTRUCTIONS:
===================

1. Install UBA certificates:
   ./install_uba_certs.sh -s $CERT_DIR

2. Manually copy certificates:
   # UI certificates (choose one pair)
   cp root-ca.crt /var/vcap/store/caspida/certs/my_certs/my-root-ca.crt.pem
   cp server.key /var/vcap/store/caspida/certs/my_certs/my-server.key.pem
   cp server.crt /var/vcap/store/caspida/certs/my_certs/my-server.crt.pem

3. Install CA in Java truststore:
   keytool -import -trustcacerts -alias uba_test_ca -file root-ca.crt -keystore \$JAVA_HOME/lib/security/cacerts -storepass changeit

4. Update uba-site.properties:
   ui.auth.rootca=/var/vcap/store/caspida/certs/my_certs/my-root-ca.crt.pem
   ui.auth.privateKey=/var/vcap/store/caspida/certs/my_certs/my-server.key.pem
   ui.auth.serverCert=/var/vcap/store/caspida/certs/my_certs/my-server.crt.pem

CERTIFICATE DETAILS:
====================

EOF
    
    # Add certificate details
    for cert in root-ca.crt server.crt "${UBA_SHORT_HOSTNAME}.crt"; do
        if [[ -f "$CERT_DIR/$cert" ]]; then
            echo "=== $cert ===" >> "$info_file"
            openssl x509 -in "$CERT_DIR/$cert" -noout -text | grep -A2 "Subject:" >> "$info_file"
            openssl x509 -in "$CERT_DIR/$cert" -noout -text | grep -A2 "Validity" >> "$info_file"
            echo "" >> "$info_file"
        fi
    done
    
    print_success "Certificate information saved: $info_file"
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cert-dir)
                CERT_DIR="$2"
                shift 2
                ;;
            --hostname)
                UBA_HOSTNAME="$2"
                UBA_SHORT_HOSTNAME=$(echo "$2" | cut -d. -f1)
                shift 2
                ;;
            --days)
                CERT_DAYS="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --city)
                CITY="$2"
                shift 2
                ;;
            --org)
                ORG="$2"
                shift 2
                ;;
            --ou)
                OU="$2"
                shift 2
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
    
    print_status "UBA Test Certificate Generation"
    print_status "==============================="
    print_status "Certificate Directory: $CERT_DIR"
    print_status "UBA Hostname: $UBA_HOSTNAME"
    print_status "Certificate Validity: $CERT_DAYS days"
    print_status "Key Size: $KEY_SIZE bits"
    
    # Check prerequisites
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL is required but not installed"
        exit 1
    fi
    
    # Create certificate directory
    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR"
    
    # Remove existing certificates
    rm -f *.crt *.key *.p12 *.csr *.ext *.srl CERTIFICATE_INFO.txt
    
    # Generate certificates
    generate_ca_certificate
    generate_server_certificate "$UBA_HOSTNAME" "server"
    generate_server_certificate "$UBA_HOSTNAME" "$UBA_SHORT_HOSTNAME"
    
    # Generate PKCS#12 keystores
    generate_pkcs12_keystore "$UBA_HOSTNAME" "server"
    
    # Create info file
    create_certificate_info
    
    # Set proper permissions
    chmod 644 *.crt *.p12 CERTIFICATE_INFO.txt 2>/dev/null || true
    chmod 600 *.key 2>/dev/null || true
    
    print_success "Certificate generation completed!"
    print_status "Certificates stored in: $CERT_DIR"
    
    echo ""
    print_status "NEXT STEPS:"
    echo "1. Review generated certificates: cat $CERT_DIR/CERTIFICATE_INFO.txt"
    echo "2. Install certificates: ./install_uba_certs.sh -s $CERT_DIR"
    echo "3. Test UBA web interface: https://$UBA_HOSTNAME:9001"
    echo ""
    
    # Display directory contents
    print_status "Generated files:"
    ls -la "$CERT_DIR"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
