#!/bin/bash

###############################################################################
# UBA Certificate Installation Example
# 
# Purpose: Demonstrate certificate installation process for UBA
# Author: System Administrator
# Date: June 11, 2025
###############################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}[STEP]${NC} $*"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/my_certs"

echo "UBA Certificate Installation Example"
echo "===================================="
echo

print_step "1. Preparing certificate directory structure"
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [[ -f "$CERT_DIR/uba-server.crt" ]]; then
    print_info "Certificates already exist in $CERT_DIR"
else
    print_warning "No certificates found in $CERT_DIR"
    echo
    echo "To proceed with certificate installation, you need to:"
    echo "1. Place your PEM-format certificates in: $CERT_DIR"
    echo "2. Ensure proper naming conventions (see README.md)"
    echo "3. Re-run this script"
    echo
    echo "Expected files:"
    echo "  - Server certificate: uba-server.crt, $(hostname -s).crt, or server.crt"
    echo "  - Private key: uba-server.key, $(hostname -s).key, or server.key"
    echo "  - Root CA: root-ca.crt or ca-bundle.crt"
    echo
    exit 1
fi

print_step "2. Validating certificate requirements"

# Check for installation script
if [[ ! -f "$SCRIPT_DIR/install_uba_certs.sh" ]]; then
    print_error "Certificate installation script not found: $SCRIPT_DIR/install_uba_certs.sh"
    exit 1
fi

if [[ ! -x "$SCRIPT_DIR/install_uba_certs.sh" ]]; then
    print_warning "Making installation script executable"
    chmod +x "$SCRIPT_DIR/install_uba_certs.sh"
fi

print_step "3. Running dry-run to preview changes"
echo "Command: $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR --dry-run -v"
echo
"$SCRIPT_DIR/install_uba_certs.sh" -s "$CERT_DIR" --dry-run -v

echo
print_warning "The above was a DRY RUN - no changes were made"
echo

print_step "4. Options for actual installation"
echo "Choose an installation option:"
echo
echo "a) Full installation (UI + Job Manager + Search Head trust)"
echo "   $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR -v"
echo
echo "b) UI certificates only"
echo "   $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR --no-jm-certs --no-search-head-certs -v"
echo
echo "c) Job Manager certificates only"  
echo "   $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR --no-ui-certs --no-search-head-certs -v"
echo
echo "d) Search head trust only"
echo "   $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR --no-ui-certs --no-jm-certs -v"
echo
echo "e) Installation without service restart"
echo "   $SCRIPT_DIR/install_uba_certs.sh -s $CERT_DIR --no-restart -v"
echo

read -p "Do you want to proceed with full installation? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_step "5. Installing certificates"
    "$SCRIPT_DIR/install_uba_certs.sh" -s "$CERT_DIR" -v
    
    print_step "6. Validating installation"
    if [[ -f "$SCRIPT_DIR/validate_uba_certs.sh" ]]; then
        chmod +x "$SCRIPT_DIR/validate_uba_certs.sh" 2>/dev/null || true
        "$SCRIPT_DIR/validate_uba_certs.sh"
    else
        print_warning "Validation script not found - manual verification recommended"
    fi
    
    print_step "7. Post-installation steps"
    echo "Certificate installation completed. Next steps:"
    echo "1. Test UBA web interface: https://$(hostname -f):9001"
    echo "2. Check service logs: tail -f /var/log/caspida/ui/ui.log"
    echo "3. Test search head connectivity"
    echo "4. Monitor for 24-48 hours to ensure stability"
    echo
    print_info "Installation completed successfully!"
else
    print_info "Installation cancelled. Run one of the commands above when ready."
fi

print_step "Additional Tools"
echo "Available certificate management tools:"
echo "- install_uba_certs.sh  : Install and configure certificates"
echo "- validate_uba_certs.sh : Validate certificate installation"
echo "- my_certs/README.md    : Certificate requirements documentation"
echo
echo "For help: $SCRIPT_DIR/install_uba_certs.sh --help"
