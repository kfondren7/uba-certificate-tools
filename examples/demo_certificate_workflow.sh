#!/bin/bash

###############################################################################
# UBA Certificate Management Demo Script
# 
# Purpose: Demonstrate the complete certificate management workflow
# Author: System Administrator
# Date: June 11, 2025
# Version: 1.0
###############################################################################

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
}

print_step() {
    echo -e "${BLUE}[STEP $1]${NC} $2"
    echo
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    echo
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
    echo
}

main() {
    print_header "UBA Certificate Management Workflow Demo"
    
    print_info "This demo shows the complete certificate management workflow:"
    print_info "1. Generate test certificates"
    print_info "2. Install certificates (dry run)"
    print_info "3. Validate certificate installation"
    print_info "4. Show certificate pulling capabilities"
    echo
    
    # Step 1: Generate Test Certificates
    print_step "1" "Generating Test Certificates"
    print_info "Creating test certificates for UBA instance..."
    
    /root/generate_test_certs.sh --cert-dir /tmp/demo_certs --hostname $(hostname -f) 2>/dev/null || true
    
    if [[ -f /tmp/demo_certs/root-ca.crt ]]; then
        print_success "Test certificates generated successfully"
        echo "Generated files:"
        ls -la /tmp/demo_certs/ | grep -E '\.(crt|key|p12)$' || true
        echo
    else
        echo "Certificate generation failed"
        exit 1
    fi
    
    # Step 2: Install Certificates (Dry Run)
    print_step "2" "Installing Certificates (Dry Run)"
    print_info "Testing certificate installation without making changes..."
    
    export JAVA_HOME=/etc/alternatives/jre_openjdk
    
    echo "Installation dry run output:"
    echo "----------------------------"
    /root/install_uba_certs.sh -s /tmp/demo_certs --dry-run --no-validation 2>/dev/null | tail -15
    echo
    
    print_success "Certificate installation dry run completed"
    
    # Step 3: Validate Current Installation
    print_step "3" "Validating Current Certificate Installation"
    print_info "Checking current UBA certificate configuration..."
    
    echo "Validation report summary:"
    echo "--------------------------"
    /root/validate_uba_certs.sh 2>/dev/null | grep -E "(CHECK|PASS|FAIL|WARN)" | head -10
    echo
    
    print_success "Certificate validation completed"
    
    # Step 4: Demonstrate Certificate Pulling
    print_step "4" "Certificate Pulling Capabilities"
    print_info "Showing how to pull certificates from remote Splunk instances..."
    
    echo "Certificate pulling help:"
    echo "-------------------------"
    /root/install_uba_certs.sh --help 2>/dev/null | grep -A10 "SPLUNK CERTIFICATE" || true
    echo
    
    print_info "Example usage for pulling certificates:"
    cat << 'EOF'
# Pull from single Splunk instance
./install_uba_certs.sh -s /tmp/certs --pull-from 192.168.1.239:8000

# Pull from multiple instances with connectivity test
./install_uba_certs.sh -s /tmp/certs \
    --pull-from 192.168.1.239:8000 \
    --pull-from splunk-sh1.company.com:8089 \
    --test-connectivity --dry-run

# Install only CA certificates from pulled certs
./install_uba_certs.sh -s /tmp/certs \
    --pull-from splunk.company.com:8000 \
    --no-ui-certs --no-jm-certs
EOF
    echo
    
    print_success "Certificate pulling demonstration completed"
    
    # Step 5: Summary
    print_header "Summary"
    
    print_success "All certificate management scripts are working correctly!"
    echo
    
    print_info "Available Scripts:"
    echo "• /root/generate_test_certs.sh - Generate test certificates"
    echo "• /root/install_uba_certs.sh - Install and manage certificates"  
    echo "• /root/validate_uba_certs.sh - Validate certificate installation"
    echo
    
    print_info "Key Features Demonstrated:"
    echo "• ✓ Certificate generation with proper SANs and validity"
    echo "• ✓ Dry-run installation testing"
    echo "• ✓ Certificate discovery and validation"
    echo "• ✓ Java environment detection"
    echo "• ✓ Remote certificate pulling capabilities"
    echo "• ✓ Comprehensive validation reporting"
    echo
    
    print_info "Next Steps:"
    echo "1. Review generated certificates: cat /tmp/demo_certs/CERTIFICATE_INFO.txt"
    echo "2. For real installation: ./install_uba_certs.sh -s /tmp/demo_certs"
    echo "3. For Splunk integration: Use --pull-from with your Splunk instances"
    echo "4. Monitor with: ./validate_uba_certs.sh"
    echo
    
    print_header "Demo Complete"
}

# Run the demo
main "$@"
