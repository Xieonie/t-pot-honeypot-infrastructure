#!/bin/bash

# T-Pot Honeypot Infrastructure Deployment Script
# This script automates the deployment of T-Pot CE with OPNsense on Proxmox VE
# Author: Security Infrastructure Team
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration file
CONFIG_FILE="config/environment.conf"

# Logging
LOG_FILE="/tmp/tpot-deployment-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running on Proxmox
    if ! command -v qm &> /dev/null; then
        log_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    # Check if configuration file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_info "Please copy config/environment.conf.example to config/environment.conf and edit it"
        exit 1
    fi
    
    # Source configuration
    source "$CONFIG_FILE"
    
    # Check required variables
    local required_vars=(
        "PROXMOX_NODE"
        "OPNSENSE_VM_ID"
        "TPOT_VM_ID"
        "WAN_BRIDGE"
        "LAN_BRIDGE"
        "HONEYPOT_NETWORK"
        "OPNSENSE_LAN_IP"
        "TPOT_IP"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable $var is not set in $CONFIG_FILE"
            exit 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

create_network_bridge() {
    log_info "Creating isolated network bridge: $LAN_BRIDGE"
    
    # Check if bridge already exists
    if ip link show "$LAN_BRIDGE" &> /dev/null; then
        log_warning "Bridge $LAN_BRIDGE already exists, skipping creation"
        return 0
    fi
    
    # Create bridge configuration
    cat >> /etc/network/interfaces << EOF

auto $LAN_BRIDGE
iface $LAN_BRIDGE inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-maxwait 0
    # Isolated Honeypot Network Bridge
EOF
    
    # Apply network configuration
    ifreload -a
    
    # Verify bridge creation
    if ip link show "$LAN_BRIDGE" &> /dev/null; then
        log_success "Bridge $LAN_BRIDGE created successfully"
    else
        log_error "Failed to create bridge $LAN_BRIDGE"
        exit 1
    fi
}

download_isos() {
    log_info "Downloading required ISO images..."
    
    local iso_dir="/var/lib/vz/template/iso"
    
    # OPNsense ISO
    if [[ ! -f "$iso_dir/opnsense.iso" ]]; then
        log_info "Downloading OPNsense ISO..."
        wget -O "$iso_dir/opnsense.iso.bz2" \
            "https://mirror.ams1.nl.leaseweb.net/opnsense/releases/23.7/OPNsense-23.7-OpenSSL-dvd-amd64.iso.bz2"
        bunzip2 "$iso_dir/opnsense.iso.bz2"
        mv "$iso_dir/OPNsense-23.7-OpenSSL-dvd-amd64.iso" "$iso_dir/opnsense.iso"
        log_success "OPNsense ISO downloaded"
    else
        log_info "OPNsense ISO already exists"
    fi
    
    # Debian ISO
    if [[ ! -f "$iso_dir/debian.iso" ]]; then
        log_info "Downloading Debian ISO..."
        wget -O "$iso_dir/debian.iso" \
            "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.2.0-amd64-netinst.iso"
        log_success "Debian ISO downloaded"
    else
        log_info "Debian ISO already exists"
    fi
}

create_opnsense_vm() {
    log_info "Creating OPNsense VM (ID: $OPNSENSE_VM_ID)..."
    
    # Check if VM already exists
    if qm status "$OPNSENSE_VM_ID" &> /dev/null; then
        log_warning "VM $OPNSENSE_VM_ID already exists, skipping creation"
        return 0
    fi
    
    # Create OPNsense VM
    qm create "$OPNSENSE_VM_ID" \
        --name "opnsense-firewall" \
        --memory 2048 \
        --cores 2 \
        --net0 "virtio,bridge=$WAN_BRIDGE" \
        --net1 "virtio,bridge=$LAN_BRIDGE" \
        --ide2 "local:iso/opnsense.iso,media=cdrom" \
        --scsi0 "local-lvm:20,format=qcow2" \
        --boot "order=ide2" \
        --ostype "other" \
        --description "OPNsense Firewall for T-Pot Honeypot Infrastructure"
    
    log_success "OPNsense VM created successfully"
    log_info "Please complete OPNsense installation manually via console"
    log_info "VM ID: $OPNSENSE_VM_ID"
    log_info "WAN Interface: $WAN_BRIDGE"
    log_info "LAN Interface: $LAN_BRIDGE"
    log_info "LAN IP: $OPNSENSE_LAN_IP"
}

create_tpot_vm() {
    log_info "Creating T-Pot VM (ID: $TPOT_VM_ID)..."
    
    # Check if VM already exists
    if qm status "$TPOT_VM_ID" &> /dev/null; then
        log_warning "VM $TPOT_VM_ID already exists, skipping creation"
        return 0
    fi
    
    # Create T-Pot VM
    qm create "$TPOT_VM_ID" \
        --name "t-pot-honeypot" \
        --memory 8192 \
        --cores 4 \
        --net0 "virtio,bridge=$LAN_BRIDGE" \
        --ide2 "local:iso/debian.iso,media=cdrom" \
        --scsi0 "local-lvm:128,format=qcow2" \
        --boot "order=ide2" \
        --ostype "l26" \
        --description "T-Pot CE Honeypot System"
    
    log_success "T-Pot VM created successfully"
    log_info "Please complete Debian installation manually via console"
    log_info "VM ID: $TPOT_VM_ID"
    log_info "Network: $LAN_BRIDGE"
    log_info "IP Address: $TPOT_IP"
    log_info "Gateway: $OPNSENSE_LAN_IP"
}

configure_proxmox_firewall() {
    log_info "Configuring Proxmox firewall..."
    
    # Enable firewall
    pvesh set /cluster/firewall/options --enable 1 --policy_in DROP --policy_out ACCEPT
    
    # Create security group for management
    pvesh create /cluster/firewall/groups --group management-access
    pvesh create "/cluster/firewall/groups/management-access" \
        --action ACCEPT \
        --type in \
        --source "192.168.1.0/24" \
        --dport "8006,22" \
        --comment "Management access from LAN"
    
    log_success "Proxmox firewall configured"
}

generate_config_files() {
    log_info "Generating configuration files..."
    
    # Create OPNsense configuration template
    mkdir -p config/opnsense
    cat > config/opnsense/initial-setup.txt << EOF
# OPNsense Initial Configuration
# Use these settings during manual setup

WAN Interface: vtnet0 (connected to $WAN_BRIDGE)
LAN Interface: vtnet1 (connected to $LAN_BRIDGE)

LAN Configuration:
- IP Address: $OPNSENSE_LAN_IP
- Subnet: 24
- DHCP Range: ${TPOT_IP%.*}.10 - ${TPOT_IP%.*}.100

Required Port Forwards:
- SSH: WAN:22 -> $TPOT_IP:22
- HTTP: WAN:80 -> $TPOT_IP:80
- HTTPS: WAN:443 -> $TPOT_IP:443
EOF
    
    # Create T-Pot configuration template
    mkdir -p config/t-pot
    cat > config/t-pot/network-setup.txt << EOF
# T-Pot Network Configuration
# Use these settings during Debian installation

IP Address: $TPOT_IP
Netmask: 255.255.255.0
Gateway: $OPNSENSE_LAN_IP
DNS Server: $OPNSENSE_LAN_IP
Hostname: t-pot-honeypot
Domain: local

Post-installation commands:
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git sudo
cd /opt
sudo git clone https://github.com/telekom-security/tpotce
sudo chown -R tpot:tpot tpotce
cd tpotce
sudo ./install.sh
EOF
    
    log_success "Configuration files generated"
}

print_next_steps() {
    log_info "Deployment script completed successfully!"
    echo
    echo "=== NEXT STEPS ==="
    echo
    echo "1. Complete OPNsense Installation:"
    echo "   - Start VM $OPNSENSE_VM_ID"
    echo "   - Follow installation wizard"
    echo "   - Configure interfaces as per config/opnsense/initial-setup.txt"
    echo
    echo "2. Complete T-Pot Installation:"
    echo "   - Start VM $TPOT_VM_ID"
    echo "   - Install Debian with network settings from config/t-pot/network-setup.txt"
    echo "   - Run T-Pot installation script"
    echo
    echo "3. Configure Security:"
    echo "   - Run: ./scripts/security/harden-opnsense.sh"
    echo "   - Run: ./scripts/security/setup-vpn.sh"
    echo
    echo "4. Test Installation:"
    echo "   - Run: ./scripts/testing/connectivity-test.sh"
    echo "   - Run: ./scripts/testing/attack-simulation.sh"
    echo
    echo "=== ACCESS INFORMATION ==="
    echo "OPNsense Web Interface: https://$OPNSENSE_LAN_IP"
    echo "T-Pot Dashboard: https://$TPOT_IP:64297"
    echo
    echo "Log file: $LOG_FILE"
}

main() {
    echo "========================================"
    echo "T-Pot Honeypot Infrastructure Deployment"
    echo "========================================"
    echo
    
    check_prerequisites
    create_network_bridge
    download_isos
    create_opnsense_vm
    create_tpot_vm
    configure_proxmox_firewall
    generate_config_files
    print_next_steps
}

# Run main function
main "$@"