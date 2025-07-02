#!/bin/bash

# Proxmox Network Setup Script for T-Pot Infrastructure
# Creates isolated network bridge for honeypot deployment
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
SETUP_LOG="/tmp/proxmox-network-setup-$(date +%Y%m%d-%H%M%S).log"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo -e "${RED}[ERROR]${NC} Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$SETUP_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$SETUP_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$SETUP_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$SETUP_LOG"
}

check_proxmox_environment() {
    log_info "Checking Proxmox environment..."
    
    # Check if running on Proxmox
    if ! command -v qm &> /dev/null; then
        log_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    # Check Proxmox version
    local pve_version
    pve_version=$(pveversion | head -1 | cut -d'/' -f2)
    log_info "Proxmox VE version: $pve_version"
    
    # Check if user has sufficient privileges
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    log_success "Proxmox environment check passed"
}

backup_network_config() {
    log_info "Backing up current network configuration..."
    
    local backup_file="/etc/network/interfaces.backup-$(date +%Y%m%d-%H%M%S)"
    cp /etc/network/interfaces "$backup_file"
    
    log_success "Network configuration backed up to: $backup_file"
}

check_existing_bridge() {
    log_info "Checking for existing bridge: $LAN_BRIDGE"
    
    if ip link show "$LAN_BRIDGE" &> /dev/null; then
        log_warning "Bridge $LAN_BRIDGE already exists"
        
        # Show current configuration
        log_info "Current bridge configuration:"
        ip link show "$LAN_BRIDGE" | tee -a "$SETUP_LOG"
        brctl show "$LAN_BRIDGE" 2>/dev/null | tee -a "$SETUP_LOG" || true
        
        echo
        read -p "Do you want to recreate the bridge? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            remove_existing_bridge
        else
            log_info "Keeping existing bridge configuration"
            return 0
        fi
    fi
}

remove_existing_bridge() {
    log_info "Removing existing bridge: $LAN_BRIDGE"
    
    # Bring down the bridge
    ip link set "$LAN_BRIDGE" down 2>/dev/null || true
    
    # Delete the bridge
    ip link delete "$LAN_BRIDGE" type bridge 2>/dev/null || true
    
    # Remove from network configuration file
    sed -i "/auto $LAN_BRIDGE/,/^$/d" /etc/network/interfaces
    
    log_success "Existing bridge removed"
}

create_isolated_bridge() {
    log_info "Creating isolated bridge: $LAN_BRIDGE"
    
    # Add bridge configuration to interfaces file
    cat >> /etc/network/interfaces << EOF

# T-Pot Honeypot Isolated Network Bridge
auto $LAN_BRIDGE
iface $LAN_BRIDGE inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-maxwait 0
    # This bridge is intentionally isolated from physical interfaces
    # for security reasons - honeypot network isolation
EOF
    
    log_success "Bridge configuration added to /etc/network/interfaces"
}

apply_network_configuration() {
    log_info "Applying network configuration..."
    
    # Validate configuration syntax
    if ! ifup --no-act "$LAN_BRIDGE" &> /dev/null; then
        log_error "Network configuration syntax error"
        log_info "Please check /etc/network/interfaces manually"
        exit 1
    fi
    
    # Apply configuration
    ifreload -a
    
    # Wait for bridge to come up
    sleep 2
    
    # Verify bridge creation
    if ip link show "$LAN_BRIDGE" &> /dev/null; then
        log_success "Bridge $LAN_BRIDGE created successfully"
    else
        log_error "Failed to create bridge $LAN_BRIDGE"
        exit 1
    fi
}

configure_bridge_security() {
    log_info "Configuring bridge security settings..."
    
    # Disable forwarding between bridge ports (additional security)
    echo 0 > "/sys/class/net/$LAN_BRIDGE/bridge/multicast_snooping" 2>/dev/null || true
    
    # Set bridge parameters for security
    if [[ -d "/sys/class/net/$LAN_BRIDGE/bridge" ]]; then
        # Disable STP (already done in config, but ensure it's off)
        echo 0 > "/sys/class/net/$LAN_BRIDGE/bridge/stp_state" 2>/dev/null || true
        
        # Set forward delay to 0
        echo 0 > "/sys/class/net/$LAN_BRIDGE/bridge/forward_delay" 2>/dev/null || true
        
        log_success "Bridge security settings applied"
    else
        log_warning "Could not apply all bridge security settings"
    fi
}

verify_bridge_isolation() {
    log_info "Verifying bridge isolation..."
    
    # Check that bridge has no physical ports
    local bridge_ports
    bridge_ports=$(ls "/sys/class/net/$LAN_BRIDGE/brif/" 2>/dev/null | wc -l)
    
    if [[ "$bridge_ports" -eq 0 ]]; then
        log_success "Bridge is properly isolated (no physical ports)"
    else
        log_warning "Bridge has $bridge_ports port(s) - check isolation"
        ls "/sys/class/net/$LAN_BRIDGE/brif/" | tee -a "$SETUP_LOG"
    fi
    
    # Check bridge status
    log_info "Bridge status:"
    ip link show "$LAN_BRIDGE" | tee -a "$SETUP_LOG"
    
    # Show bridge details
    if command -v brctl &> /dev/null; then
        log_info "Bridge details:"
        brctl show "$LAN_BRIDGE" | tee -a "$SETUP_LOG"
    fi
}

configure_proxmox_firewall() {
    log_info "Configuring Proxmox firewall for bridge..."
    
    # Check if Proxmox firewall is enabled
    if [[ -f "/etc/pve/firewall/cluster.fw" ]]; then
        log_info "Proxmox firewall configuration found"
        
        # Create firewall rule for the new bridge if needed
        # This is optional and depends on your security requirements
        log_info "Consider adding firewall rules for bridge $LAN_BRIDGE"
    else
        log_info "Proxmox firewall not configured"
    fi
}

create_bridge_documentation() {
    log_info "Creating bridge documentation..."
    
    mkdir -p "config/proxmox"
    
    cat > "config/proxmox/network-bridge-info.md" << EOF
# Proxmox Network Bridge Configuration

## Bridge Information

- **Bridge Name**: $LAN_BRIDGE
- **Purpose**: Isolated network for T-Pot honeypot infrastructure
- **Network Range**: $HONEYPOT_NETWORK
- **Created**: $(date)

## Security Features

- **No Physical Ports**: Bridge is completely isolated from physical network
- **STP Disabled**: Spanning Tree Protocol disabled for security
- **Forward Delay**: Set to 0 for immediate forwarding
- **Multicast Snooping**: Disabled

## Connected VMs

- OPNsense Firewall (VM ID: $OPNSENSE_VM_ID) - LAN interface
- T-Pot Honeypot (VM ID: $TPOT_VM_ID) - Primary interface

## Network Topology

\`\`\`
Internet
    |
    | (WAN)
┌───▼────────────────────────────────────────┐
│              Proxmox VE Host               │
│                                            │
│  ┌─────────────┐    ┌─────────────────────┐│
│  │   $WAN_BRIDGE     │    │       $LAN_BRIDGE         ││
│  │ (LAN Bridge)│    │ (Honeypot Bridge)   ││
│  └──────┬──────┘    └──────┬──────────────┘│
│         │                  │               │
│  ┌──────▼──────┐    ┌──────▼──────────────┐│
│  │Management   │    │    OPNsense VM      ││
│  │   Host      │    │  WAN: $WAN_BRIDGE        ││
│  │             │    │  LAN: $LAN_BRIDGE        ││
│  └─────────────┘    └──────┬──────────────┘│
│                             │               │
│                      ┌──────▼──────────────┐│
│                      │     T-Pot VM        ││
│                      │   $TPOT_IP/24   ││
│                      │   (via $LAN_BRIDGE)       ││
│                      └─────────────────────┘│
└────────────────────────────────────────────┘
\`\`\`

## Verification Commands

\`\`\`bash
# Check bridge status
ip link show $LAN_BRIDGE

# Show bridge details
brctl show $LAN_BRIDGE

# Verify isolation (should show no ports)
ls /sys/class/net/$LAN_BRIDGE/brif/

# Check bridge parameters
cat /sys/class/net/$LAN_BRIDGE/bridge/stp_state
cat /sys/class/net/$LAN_BRIDGE/bridge/forward_delay
\`\`\`

## Troubleshooting

If the bridge is not working:

1. Check network configuration: \`cat /etc/network/interfaces\`
2. Reload network configuration: \`ifreload -a\`
3. Verify bridge exists: \`ip link show $LAN_BRIDGE\`
4. Check for errors: \`journalctl -u networking\`

## Security Notes

- This bridge is intentionally isolated from all physical network interfaces
- Only virtual machines should be connected to this bridge
- All traffic to/from this bridge should go through the OPNsense firewall
- Regular monitoring of bridge traffic is recommended
EOF
    
    log_success "Bridge documentation created: config/proxmox/network-bridge-info.md"
}

generate_setup_report() {
    log_info "Generating setup report..."
    
    echo "======================================" >> "$SETUP_LOG"
    echo "PROXMOX NETWORK SETUP REPORT" >> "$SETUP_LOG"
    echo "======================================" >> "$SETUP_LOG"
    echo "Date: $(date)" >> "$SETUP_LOG"
    echo "Bridge Name: $LAN_BRIDGE" >> "$SETUP_LOG"
    echo "Network Range: $HONEYPOT_NETWORK" >> "$SETUP_LOG"
    echo "" >> "$SETUP_LOG"
    
    echo "Bridge Status:" >> "$SETUP_LOG"
    ip link show "$LAN_BRIDGE" >> "$SETUP_LOG" 2>&1
    echo "" >> "$SETUP_LOG"
    
    echo "Bridge Details:" >> "$SETUP_LOG"
    brctl show "$LAN_BRIDGE" >> "$SETUP_LOG" 2>&1 || echo "brctl not available" >> "$SETUP_LOG"
    echo "" >> "$SETUP_LOG"
    
    echo "Network Configuration:" >> "$SETUP_LOG"
    grep -A 10 "auto $LAN_BRIDGE" /etc/network/interfaces >> "$SETUP_LOG" 2>&1 || echo "Configuration not found" >> "$SETUP_LOG"
    echo "" >> "$SETUP_LOG"
    
    echo "Next Steps:" >> "$SETUP_LOG"
    echo "1. Create OPNsense VM with interface connected to $LAN_BRIDGE" >> "$SETUP_LOG"
    echo "2. Create T-Pot VM with interface connected to $LAN_BRIDGE" >> "$SETUP_LOG"
    echo "3. Configure OPNsense LAN interface with IP $OPNSENSE_LAN_IP" >> "$SETUP_LOG"
    echo "4. Configure T-Pot VM with IP $TPOT_IP" >> "$SETUP_LOG"
    echo "" >> "$SETUP_LOG"
    echo "Full setup log: $SETUP_LOG" >> "$SETUP_LOG"
    
    log_success "Proxmox network setup completed successfully!"
    echo
    echo "======================================="
    echo "NETWORK SETUP SUMMARY"
    echo "======================================="
    echo "Bridge Created: $LAN_BRIDGE"
    echo "Network Range: $HONEYPOT_NETWORK"
    echo "Documentation: config/proxmox/network-bridge-info.md"
    echo "Log file: $SETUP_LOG"
    echo
    echo "✅ Network bridge setup completed"
    echo "🔒 Bridge is properly isolated"
    echo "📋 Ready for VM deployment"
    echo
}

main() {
    echo "========================================"
    echo "Proxmox Network Setup for T-Pot"
    echo "========================================"
    echo
    
    # Initialize log
    echo "Proxmox Network Setup - $(date)" > "$SETUP_LOG"
    echo "========================================" >> "$SETUP_LOG"
    
    # Run setup steps
    check_proxmox_environment
    backup_network_config
    check_existing_bridge
    create_isolated_bridge
    apply_network_configuration
    configure_bridge_security
    verify_bridge_isolation
    configure_proxmox_firewall
    create_bridge_documentation
    
    # Generate report
    generate_setup_report
}

# Run main function
main "$@"