#!/bin/bash

# OPNsense Security Hardening Script
# Applies security hardening configurations to OPNsense firewall
# Author: Security Infrastructure Team
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="config/environment.conf"
HARDENING_LOG="/tmp/opnsense-hardening-$(date +%Y%m%d-%H%M%S).log"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo -e "${RED}[ERROR]${NC} Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$HARDENING_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$HARDENING_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$HARDENING_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$HARDENING_LOG"
}

generate_ssl_certificate() {
    log_info "Generating SSL certificate configuration..."
    
    # Create certificate configuration
    mkdir -p config/opnsense/ssl
    
    cat > config/opnsense/ssl/certificate.conf << EOF
# OPNsense SSL Certificate Configuration
# Apply this configuration in System → Trust → Authorities

Certificate Authority:
- Method: Create an internal Certificate Authority
- Descriptive name: T-Pot Internal CA
- Key length: 4096
- Digest Algorithm: SHA256
- Lifetime: 3650 days
- Country Code: US
- State or Province: Security
- City: Honeypot
- Organization: T-Pot Infrastructure
- Email Address: admin@tpot.local

Server Certificate:
- Method: Create an internal Certificate
- Descriptive name: OPNsense Web Interface
- Certificate authority: T-Pot Internal CA
- Type: Server Certificate
- Key length: 4096
- Digest Algorithm: SHA256
- Lifetime: 365 days
- Country Code: US
- State or Province: Security
- City: Honeypot
- Organization: T-Pot Infrastructure
- Email Address: admin@tpot.local
- Common Name: opnsense.tpot.local
- Alternative Names: 
  - $OPNSENSE_LAN_IP
  - opnsense
  - firewall
EOF
    
    log_success "SSL certificate configuration generated"
}

generate_firewall_rules() {
    log_info "Generating hardened firewall rules..."
    
    mkdir -p config/opnsense/firewall
    
    cat > config/opnsense/firewall/hardened-rules.xml << EOF
<?xml version="1.0"?>
<!-- OPNsense Hardened Firewall Rules -->
<!-- Import via System → Configuration → Backups -->

<opnsense>
  <filter>
    <!-- WAN Rules -->
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <direction>in</direction>
      <floating>yes</floating>
      <quick>yes</quick>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
      </destination>
      <descr>Block all access to firewall from WAN</descr>
    </rule>
    
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <direction>in</direction>
      <source>
        <address>$TRUSTED_ADMIN_IP</address>
      </source>
      <destination>
        <network>wanip</network>
        <port>$HTTPS_PORT</port>
      </destination>
      <descr>Allow management from trusted IP</descr>
    </rule>
    
    <!-- Honeypot Port Forwards -->
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>22</port>
      </destination>
      <descr>SSH Honeypot</descr>
    </rule>
    
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>80</port>
      </destination>
      <descr>HTTP Honeypot</descr>
    </rule>
    
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>443</port>
      </destination>
      <descr>HTTPS Honeypot</descr>
    </rule>
    
    <!-- LAN Rules -->
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any>1</any>
      </destination>
      <descr>Allow LAN to Internet</descr>
    </rule>
    
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source>
        <network>$MANAGEMENT_NETWORK</network>
      </source>
      <destination>
        <address>$TPOT_IP</address>
        <port>64297</port>
      </destination>
      <descr>Allow T-Pot management access</descr>
    </rule>
    
    <rule>
      <type>block</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <network>wan</network>
      </destination>
      <descr>Block LAN to WAN network</descr>
    </rule>
  </filter>
</opnsense>
EOF
    
    log_success "Hardened firewall rules generated"
}

generate_nat_rules() {
    log_info "Generating NAT rules..."
    
    cat > config/opnsense/firewall/nat-rules.xml << EOF
<?xml version="1.0"?>
<!-- OPNsense NAT Rules for T-Pot Honeypot -->

<opnsense>
  <nat>
    <!-- SSH Honeypot -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>22</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>22</local-port>
      <descr>SSH Honeypot Forward</descr>
    </rule>
    
    <!-- HTTP Honeypot -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>80</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>80</local-port>
      <descr>HTTP Honeypot Forward</descr>
    </rule>
    
    <!-- HTTPS Honeypot -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>443</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>443</local-port>
      <descr>HTTPS Honeypot Forward</descr>
    </rule>
    
    <!-- Additional honeypot services -->
    <!-- Telnet -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>23</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>23</local-port>
      <descr>Telnet Honeypot Forward</descr>
    </rule>
    
    <!-- FTP -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>21</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>21</local-port>
      <descr>FTP Honeypot Forward</descr>
    </rule>
    
    <!-- SMTP -->
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <network>wanip</network>
        <port>25</port>
      </destination>
      <target>$TPOT_IP</target>
      <local-port>25</local-port>
      <descr>SMTP Honeypot Forward</descr>
    </rule>
  </nat>
</opnsense>
EOF
    
    log_success "NAT rules generated"
}

generate_ids_configuration() {
    log_info "Generating IDS/IPS configuration..."
    
    mkdir -p config/opnsense/ids
    
    cat > config/opnsense/ids/suricata-config.yaml << EOF
# Suricata IDS/IPS Configuration for T-Pot Honeypot
# Apply via Services → Intrusion Detection → Administration

# Basic Settings
enabled: true
ips_mode: true  # Enable IPS mode for active blocking
interfaces:
  - wan
  - lan

# Rule Sources
rule_sources:
  - emerging-threats-open
  - abuse.ch
  - sslbl
  - feodo

# Custom Rules
custom_rules: |
  # Honeypot specific rules
  alert tcp any any -> $HONEYPOT_NETWORK any (msg:"Honeypot Access Detected"; sid:1000001; rev:1;)
  alert tcp any any -> $TPOT_IP 22 (msg:"SSH Honeypot Access"; sid:1000002; rev:1;)
  alert tcp any any -> $TPOT_IP 80 (msg:"HTTP Honeypot Access"; sid:1000003; rev:1;)
  alert tcp any any -> $TPOT_IP 443 (msg:"HTTPS Honeypot Access"; sid:1000004; rev:1;)

# Logging
logging:
  level: info
  outputs:
    - eve-log:
        enabled: yes
        filetype: regular
        filename: eve.json
        types:
          - alert
          - http
          - dns
          - tls
          - ssh
          - smtp

# Performance
performance:
  max_pending_packets: 1024
  detect_engine:
    profile: medium
    custom_values:
      - toclient_groups: 3
      - toserver_groups: 25
EOF
    
    log_success "IDS/IPS configuration generated"
}

generate_system_hardening() {
    log_info "Generating system hardening configuration..."
    
    mkdir -p config/opnsense/system
    
    cat > config/opnsense/system/hardening-checklist.md << EOF
# OPNsense System Hardening Checklist

## Web Interface Security

### System → Settings → Administration
- [ ] Protocol: HTTPS only
- [ ] SSL Certificate: Use custom certificate (not self-signed)
- [ ] TCP Port: $HTTPS_PORT (non-standard)
- [ ] Session Timeout: 30 minutes
- [ ] Login Protection: Enable
- [ ] DNS Rebind Check: Enable
- [ ] HTTP Strict Transport Security: Enable
- [ ] Disable HTTP_REFERER enforcement: Disable

### System → Access → Users
- [ ] Change default admin password
- [ ] Create dedicated admin user
- [ ] Disable root login (if possible)
- [ ] Enable two-factor authentication

## SSH Security

### System → Settings → Administration → Secure Shell
- [ ] Secure Shell Server: Enable
- [ ] SSH Port: $SSH_PORT (non-standard)
- [ ] Permit root user login: Disable
- [ ] Authentication Method: Public Key + Password
- [ ] Listen Interfaces: LAN only

## Network Security

### Firewall → Settings → Advanced
- [ ] Firewall Optimization: Conservative
- [ ] Firewall Maximum States: 100000
- [ ] Firewall Maximum Table Entries: 200000
- [ ] Static route filtering: Enable
- [ ] Disable Firewall: Disable
- [ ] Disable Firewall Scrub: Disable

### System → Settings → Tunables
Add the following tunables:
- [ ] net.inet.tcp.blackhole: 2
- [ ] net.inet.udp.blackhole: 1
- [ ] net.inet.ip.random_id: 1
- [ ] net.inet.tcp.drop_synfin: 1

## Logging and Monitoring

### System → Settings → Logging
- [ ] Log Level: Informational
- [ ] Log Firewall Default Blocks: Enable
- [ ] Log Packets Matched by Firewall Rules: Enable
- [ ] Log Bytes Matched by Firewall Rules: Enable

### Services → Intrusion Detection
- [ ] Enable IDS: Yes
- [ ] IPS Mode: Enable
- [ ] Interfaces: WAN, LAN
- [ ] Rule Sources: ET Open, Abuse.ch

## System Updates

### System → Firmware
- [ ] Enable automatic security updates
- [ ] Check for updates weekly
- [ ] Subscribe to security announcements

## Backup and Recovery

### System → Configuration → Backups
- [ ] Configure automatic backups
- [ ] Store backups securely off-site
- [ ] Test restore procedures

## Additional Security Measures

### Services → DHCPv4
- [ ] Enable DHCP Registration: Enable
- [ ] Static ARP: Enable (if applicable)

### VPN → OpenVPN (if enabled)
- [ ] Use strong encryption (AES-256)
- [ ] Enable Perfect Forward Secrecy
- [ ] Use certificate-based authentication
- [ ] Limit concurrent connections

### System → High Availability (if applicable)
- [ ] Configure CARP for failover
- [ ] Sync configurations between nodes
- [ ] Test failover procedures
EOF
    
    log_success "System hardening checklist generated"
}

generate_monitoring_config() {
    log_info "Generating monitoring configuration..."
    
    mkdir -p config/opnsense/monitoring
    
    cat > config/opnsense/monitoring/syslog-config.conf << EOF
# Syslog Configuration for OPNsense
# Apply via System → Settings → Logging

# Remote Syslog Settings (optional)
# Enable if you want to send logs to external SIEM
remote_syslog:
  enabled: false
  server: "192.168.1.100"
  port: 514
  protocol: UDP
  facility: LOCAL0

# Log Rotation
log_rotation:
  max_size: 100M
  max_files: 10
  compress: true

# Specific Log Settings
firewall_logs:
  enabled: true
  level: informational
  include_default_blocks: true
  include_rule_matches: true

system_logs:
  enabled: true
  level: informational
  
dhcp_logs:
  enabled: true
  level: informational

vpn_logs:
  enabled: true
  level: informational
EOF
    
    cat > config/opnsense/monitoring/snmp-config.conf << EOF
# SNMP Configuration for OPNsense Monitoring
# Apply via Services → SNMP

snmp_settings:
  enabled: true
  community: "tpot_readonly"
  contact: "admin@tpot.local"
  location: "T-Pot Honeypot Infrastructure"
  bind_interface: LAN
  
  # Security settings
  version: v2c
  read_only: true
  
  # Allowed hosts
  allowed_hosts:
    - "$MANAGEMENT_NETWORK"
    - "$TPOT_IP"

# OIDs to monitor
monitoring_oids:
  - 1.3.6.1.2.1.1.3.0      # System uptime
  - 1.3.6.1.2.1.2.2.1.10   # Interface input octets
  - 1.3.6.1.2.1.2.2.1.16   # Interface output octets
  - 1.3.6.1.2.1.25.1.1.0   # Host resources
EOF
    
    log_success "Monitoring configuration generated"
}

create_backup_script() {
    log_info "Creating backup script..."
    
    mkdir -p scripts/maintenance
    
    cat > scripts/maintenance/backup-opnsense.sh << 'EOF'
#!/bin/bash

# OPNsense Configuration Backup Script
# Automatically backs up OPNsense configuration

set -euo pipefail

# Configuration
OPNSENSE_IP="10.0.100.1"
BACKUP_DIR="/backup/opnsense"
RETENTION_DAYS="30"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to backup via API (requires API key)
backup_via_api() {
    local api_key="$1"
    local api_secret="$2"
    
    curl -k -u "$api_key:$api_secret" \
        "https://$OPNSENSE_IP/api/core/backup/download/this" \
        -o "$BACKUP_DIR/opnsense-config-$DATE.xml"
}

# Function to backup via web interface (manual)
backup_manual() {
    echo "Manual backup required:"
    echo "1. Go to https://$OPNSENSE_IP/system_backup.php"
    echo "2. Click 'Download configuration as XML'"
    echo "3. Save to $BACKUP_DIR/opnsense-config-$DATE.xml"
}

# Cleanup old backups
cleanup_old_backups() {
    find "$BACKUP_DIR" -name "opnsense-config-*.xml" -mtime +$RETENTION_DAYS -delete
}

# Main backup function
main() {
    echo "Starting OPNsense backup..."
    
    # Check if API credentials are available
    if [[ -n "${OPNSENSE_API_KEY:-}" && -n "${OPNSENSE_API_SECRET:-}" ]]; then
        backup_via_api "$OPNSENSE_API_KEY" "$OPNSENSE_API_SECRET"
        echo "Backup completed via API"
    else
        backup_manual
    fi
    
    # Cleanup old backups
    cleanup_old_backups
    
    echo "Backup process completed"
    echo "Backup location: $BACKUP_DIR"
}

main "$@"
EOF
    
    chmod +x scripts/maintenance/backup-opnsense.sh
    log_success "Backup script created"
}

generate_hardening_report() {
    log_info "Generating hardening report..."
    
    echo "======================================" >> "$HARDENING_LOG"
    echo "OPNSENSE HARDENING CONFIGURATION" >> "$HARDENING_LOG"
    echo "======================================" >> "$HARDENING_LOG"
    echo "Date: $(date)" >> "$HARDENING_LOG"
    echo "Configuration: $CONFIG_FILE" >> "$HARDENING_LOG"
    echo "" >> "$HARDENING_LOG"
    
    echo "Generated Files:" >> "$HARDENING_LOG"
    echo "- SSL Certificate Configuration: config/opnsense/ssl/certificate.conf" >> "$HARDENING_LOG"
    echo "- Firewall Rules: config/opnsense/firewall/hardened-rules.xml" >> "$HARDENING_LOG"
    echo "- NAT Rules: config/opnsense/firewall/nat-rules.xml" >> "$HARDENING_LOG"
    echo "- IDS Configuration: config/opnsense/ids/suricata-config.yaml" >> "$HARDENING_LOG"
    echo "- Hardening Checklist: config/opnsense/system/hardening-checklist.md" >> "$HARDENING_LOG"
    echo "- Monitoring Config: config/opnsense/monitoring/" >> "$HARDENING_LOG"
    echo "- Backup Script: scripts/maintenance/backup-opnsense.sh" >> "$HARDENING_LOG"
    echo "" >> "$HARDENING_LOG"
    
    echo "Next Steps:" >> "$HARDENING_LOG"
    echo "1. Apply SSL certificate configuration" >> "$HARDENING_LOG"
    echo "2. Import firewall and NAT rules" >> "$HARDENING_LOG"
    echo "3. Configure IDS/IPS settings" >> "$HARDENING_LOG"
    echo "4. Follow hardening checklist" >> "$HARDENING_LOG"
    echo "5. Set up monitoring and logging" >> "$HARDENING_LOG"
    echo "6. Configure automated backups" >> "$HARDENING_LOG"
    echo "" >> "$HARDENING_LOG"
    echo "Full log: $HARDENING_LOG" >> "$HARDENING_LOG"
    
    log_success "OPNsense hardening configuration completed!"
    echo
    echo "======================================="
    echo "HARDENING SUMMARY"
    echo "======================================="
    echo "Configuration files generated in config/opnsense/"
    echo "Scripts created in scripts/maintenance/"
    echo "Log file: $HARDENING_LOG"
    echo
    echo "⚠️  IMPORTANT: Apply configurations manually in OPNsense web interface"
    echo "📋 Follow the hardening checklist for complete security"
    echo "🔄 Set up automated backups and monitoring"
    echo
}

main() {
    echo "========================================"
    echo "OPNsense Security Hardening"
    echo "========================================"
    echo
    
    # Initialize log
    echo "OPNsense Security Hardening - $(date)" > "$HARDENING_LOG"
    echo "========================================" >> "$HARDENING_LOG"
    
    # Generate configurations
    generate_ssl_certificate
    generate_firewall_rules
    generate_nat_rules
    generate_ids_configuration
    generate_system_hardening
    generate_monitoring_config
    create_backup_script
    
    # Generate report
    generate_hardening_report
}

# Run main function
main "$@"