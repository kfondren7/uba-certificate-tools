#!/bin/bash

###############################################################################
# UBA Certificate Management Tools Summary
# 
# Purpose: Display available certificate management tools and usage
# Author: System Administrator  
# Date: June 11, 2025
###############################################################################

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}    UBA Certificate Management Tools${NC}"
echo -e "${BLUE}===============================================${NC}"
echo

echo -e "${GREEN}AVAILABLE TOOLS:${NC}"
echo

echo -e "${YELLOW}1. install_uba_certs.sh${NC}"
echo "   Purpose: Install and configure CA certificates for UBA"
echo "   Usage:   ./install_uba_certs.sh -s <cert_directory> [options]"
echo "   Example: ./install_uba_certs.sh -s /root/my_certs -v"
echo "   Features:"
echo "   - Validates PEM certificate format"
echo "   - Generates PKCS12 keystores with password 'password'"
echo "   - Updates UBA site properties"
echo "   - Configures Job Manager keystore"
echo "   - Installs CA certs in Java truststore"
echo "   - Supports dry-run mode"
echo

echo -e "${YELLOW}2. validate_uba_certs.sh${NC}"
echo "   Purpose: Validate UBA certificate installation and configuration"
echo "   Usage:   ./validate_uba_certs.sh"
echo "   Features:"
echo "   - Checks UI certificate configuration"
echo "   - Validates Job Manager keystore"
echo "   - Tests Java truststore CA certificates"
echo "   - Verifies service status"
echo "   - Tests web interface connectivity"
echo "   - Checks certificate expiration dates"
echo

echo -e "${YELLOW}3. example_cert_install.sh${NC}"
echo "   Purpose: Interactive certificate installation guide"
echo "   Usage:   ./example_cert_install.sh"
echo "   Features:"
echo "   - Step-by-step installation process"
echo "   - Dry-run preview"
echo "   - Installation options menu"
echo "   - Post-installation validation"
echo

echo -e "${GREEN}CERTIFICATE DIRECTORY STRUCTURE:${NC}"
echo
echo "my_certs/"
echo "├── README.md              # Documentation and requirements"
echo "├── uba-server.crt         # UBA server certificate"
echo "├── uba-server.key         # UBA server private key"  
echo "├── searchhead01.crt       # Search head certificate"
echo "├── searchhead01.key       # Search head private key"
echo "├── root-ca.crt            # Root CA certificate"
echo "└── intermediate-ca.crt    # Intermediate CA (optional)"
echo

echo -e "${GREEN}CERTIFICATE REQUIREMENTS:${NC}"
echo "- Format: PEM (Base64 encoded)"
echo "- Private keys: Unencrypted (no passphrase)"
echo "- Naming: <hostname>.crt/.key or standard patterns"
echo "- Validity: Not expired, properly signed"
echo "- Key matching: Certificate and private key must match"
echo

echo -e "${GREEN}COMMON USAGE PATTERNS:${NC}"
echo

echo -e "${YELLOW}Full Installation:${NC}"
echo "./install_uba_certs.sh -s /root/my_certs"
echo

echo -e "${YELLOW}UI Certificates Only:${NC}"
echo "./install_uba_certs.sh -s /root/my_certs --no-jm-certs --no-search-head-certs"
echo

echo -e "${YELLOW}Job Manager Only:${NC}"
echo "./install_uba_certs.sh -s /root/my_certs --no-ui-certs --no-search-head-certs"
echo

echo -e "${YELLOW}Dry Run (Preview):${NC}"
echo "./install_uba_certs.sh -s /root/my_certs --dry-run -v"
echo

echo -e "${YELLOW}No Service Restart:${NC}"
echo "./install_uba_certs.sh -s /root/my_certs --no-restart"
echo

echo -e "${YELLOW}Validation:${NC}"
echo "./validate_uba_certs.sh"
echo

echo -e "${GREEN}GENERATED FILES:${NC}"
echo "- /var/vcap/store/caspida/certs/my_certs/    # Custom certificate storage"
echo "- /etc/caspida/local/conf/uba-site.properties # UBA configuration"
echo "- /etc/caspida/conf/jobconf/keystore.jm      # Job Manager keystore"
echo "- /usr/lib/jvm/.../lib/security/cacerts      # Java truststore"
echo

echo -e "${GREEN}LOG FILES:${NC}"
echo "- /var/log/caspida/uba_cert_install_*.log    # Installation logs"
echo "- /opt/caspida/cert_backups/                 # Backup location"
echo

echo -e "${GREEN}TROUBLESHOOTING:${NC}"
echo "1. Check logs: tail -f /var/log/caspida/ui/ui.log"
echo "2. Verify services: systemctl status caspida-ui"
echo "3. Test connectivity: curl -k https://\$(hostname -f):9001"
echo "4. Validate setup: ./validate_uba_certs.sh"
echo "5. Restore backup if needed from: /opt/caspida/cert_backups/"
echo

echo -e "${GREEN}DOCUMENTATION REFERENCES:${NC}"
echo "- https://docs.splunk.com/Documentation/UBA/5.4.2/Install/Certificate"
echo "- https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/ReplaceJMcert"
echo "- https://docs.splunk.com/Documentation/UBA/5.4.2/Admin/Properties"
echo

echo -e "${BLUE}===============================================${NC}"
