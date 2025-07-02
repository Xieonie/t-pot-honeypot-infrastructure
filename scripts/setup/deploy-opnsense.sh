#!/bin/bash

# T-Pot Infrastructure: OPNsense Deployment Script
# This script automates the deployment of OPNsense firewall for T-Pot honeypot infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
LOG_FILE="/var/log/deploy-opnsense.log"

# OPNsense Configuration
OPNSENSE_VERSION="23.7"
OPNSENSE_ISO_URL="https://mirror.opnsense.org/releases/23.7/OPNsense-23.7-OpenSSL-dvd-amd64.iso"
OPNSENSE_ISO_FILE="OPNsense-23.7-OpenSSL-dvd-amd64.iso"
OPNSENSE_VM_ID="100"
OPNSENSE_VM_NAME="opnsense-firewall"

# VM Specifications
VM_MEMORY="2048"
VM_CORES="2"
VM_DISK_SIZE="20G"
VM_STORAGE="local-lvm"

# Network Configuration
WAN_BRIDGE="vmbr0"
LAN_BRIDGE="vmbr1"
DMZ_BRIDGE="vmbr2"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "${BLUE}$*${NC}"
}

warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

error() {
    log "ERROR" "${RED}$*${NC}"
}

success() {
    log "SUCCESS" "${GREEN}$*${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    # Check if Proxmox VE is installed
    if ! command -v qm &> /dev/null; then
        error "Proxmox VE not found. Please install Proxmox VE first."
        exit 1
    fi
    
    # Check if required tools are available
    local tools=("wget" "curl" "jq")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is not installed. Please install it first."
            exit 1
        fi
    done
    
    # Check available storage
    local available_space=$(df /var/lib/vz --output=avail | tail -n1 | tr -d ' ')
    local required_space=$((5 * 1024 * 1024))  # 5GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        error "Insufficient disk space. At least 5GB required."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Download OPNsense ISO
download_opnsense_iso() {
    local iso_path="/var/lib/vz/template/iso/$OPNSENSE_ISO_FILE"
    
    if [[ -f "$iso_path" ]]; then
        info "OPNsense ISO already exists: $iso_path"
        return 0
    fi
    
    info "Downloading OPNsense ISO..."
    wget -O "$iso_path" "$OPNSENSE_ISO_URL"
    
    if [[ $? -eq 0 ]]; then
        success "OPNsense ISO downloaded successfully"
    else
        error "Failed to download OPNsense ISO"
        exit 1
    fi
}

# Create OPNsense VM
create_opnsense_vm() {
    info "Creating OPNsense VM..."
    
    # Check if VM already exists
    if qm status "$OPNSENSE_VM_ID" &> /dev/null; then
        warn "VM $OPNSENSE_VM_ID already exists. Stopping and removing..."
        qm stop "$OPNSENSE_VM_ID" || true
        qm destroy "$OPNSENSE_VM_ID" || true
    fi
    
    # Create VM
    qm create "$OPNSENSE_VM_ID" \
        --name "$OPNSENSE_VM_NAME" \
        --memory "$VM_MEMORY" \
        --cores "$VM_CORES" \
        --sockets 1 \
        --cpu cputype=host \
        --ostype other \
        --boot order=ide2 \
        --ide2 "local:iso/$OPNSENSE_ISO_FILE,media=cdrom" \
        --scsi0 "$VM_STORAGE:$VM_DISK_SIZE" \
        --scsihw virtio-scsi-pci \
        --net0 virtio,bridge="$WAN_BRIDGE" \
        --net1 virtio,bridge="$LAN_BRIDGE" \
        --net2 virtio,bridge="$DMZ_BRIDGE" \
        --vga qxl \
        --tablet 1 \
        --onboot 1
    
    if [[ $? -eq 0 ]]; then
        success "OPNsense VM created successfully"
    else
        error "Failed to create OPNsense VM"
        exit 1
    fi
}

# Configure VM hardware
configure_vm_hardware() {
    info "Configuring VM hardware..."
    
    # Set VM options
    qm set "$OPNSENSE_VM_ID" \
        --startup order=1,up=30,down=60 \
        --protection 1 \
        --description "OPNsense Firewall for T-Pot Honeypot Infrastructure"
    
    # Configure network interfaces with specific MAC addresses for consistency
    qm set "$OPNSENSE_VM_ID" \
        --net0 virtio,bridge="$WAN_BRIDGE",macaddr=52:54:00:12:34:56 \
        --net1 virtio,bridge="$LAN_BRIDGE",macaddr=52:54:00:12:34:57 \
        --net2 virtio,bridge="$DMZ_BRIDGE",macaddr=52:54:00:12:34:58
    
    success "VM hardware configured"
}

# Start VM and wait for installation
start_vm_installation() {
    info "Starting OPNsense VM for installation..."
    
    qm start "$OPNSENSE_VM_ID"
    
    if [[ $? -eq 0 ]]; then
        success "OPNsense VM started"
        info "Please complete the OPNsense installation manually via the console"
        info "VM ID: $OPNSENSE_VM_ID"
        info "Access the console with: qm monitor $OPNSENSE_VM_ID"
        info ""
        info "Installation steps:"
        info "1. Boot from ISO and follow installation wizard"
        info "2. Configure network interfaces:"
        info "   - WAN: vtnet0 (connected to $WAN_BRIDGE)"
        info "   - LAN: vtnet1 (connected to $LAN_BRIDGE)"
        info "   - DMZ: vtnet2 (connected to $DMZ_BRIDGE)"
        info "3. Set initial passwords and network configuration"
        info "4. Complete installation and reboot"
        info ""
        info "After installation, run the configuration script to apply firewall rules"
    else
        error "Failed to start OPNsense VM"
        exit 1
    fi
}

# Wait for OPNsense to be ready
wait_for_opnsense() {
    info "Waiting for OPNsense to be ready..."
    local max_attempts=60
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if ping -c 1 192.168.1.1 &> /dev/null; then
            success "OPNsense is responding"
            return 0
        fi
        
        ((attempt++))
        info "Attempt $attempt/$max_attempts - waiting for OPNsense..."
        sleep 10
    done
    
    error "OPNsense did not become ready within expected time"
    return 1
}

# Apply initial configuration
apply_initial_config() {
    info "Applying initial OPNsense configuration..."
    
    # Copy configuration files
    local config_source="$CONFIG_DIR/opnsense"
    
    if [[ ! -d "$config_source" ]]; then
        error "OPNsense configuration directory not found: $config_source"
        exit 1
    fi
    
    info "Configuration files are available in: $config_source"
    info "Please apply them manually through the OPNsense web interface"
    info "Web interface: https://192.168.1.1"
    info "Default credentials: root/opnsense"
    
    # List configuration files
    info "Available configuration files:"
    find "$config_source" -name "*.xml" -o -name "*.conf" | while read -r file; do
        info "  - $(basename "$file")"
    done
}

# Create VM template (optional)
create_vm_template() {
    read -p "Do you want to create a template from this VM? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Creating VM template..."
        
        # Stop VM first
        qm stop "$OPNSENSE_VM_ID"
        
        # Convert to template
        qm template "$OPNSENSE_VM_ID"
        
        success "VM template created. You can clone it for additional firewalls."
    fi
}

# Generate deployment report
generate_report() {
    local report_file="/tmp/opnsense-deployment-report.txt"
    
    cat > "$report_file" << EOF
OPNsense Deployment Report
==========================
Date: $(date)
VM ID: $OPNSENSE_VM_ID
VM Name: $OPNSENSE_VM_NAME
Memory: $VM_MEMORY MB
CPU Cores: $VM_CORES
Disk Size: $VM_DISK_SIZE

Network Configuration:
- WAN Interface: vtnet0 (Bridge: $WAN_BRIDGE)
- LAN Interface: vtnet1 (Bridge: $LAN_BRIDGE)
- DMZ Interface: vtnet2 (Bridge: $DMZ_BRIDGE)

Next Steps:
1. Complete OPNsense installation via console
2. Configure network interfaces and basic settings
3. Access web interface at https://192.168.1.1
4. Apply firewall rules from: $CONFIG_DIR/opnsense/
5. Test connectivity and security rules
6. Configure monitoring and logging

Configuration Files:
$(find "$CONFIG_DIR/opnsense" -name "*.xml" -o -name "*.conf" 2>/dev/null | sed 's/^/- /')

Troubleshooting:
- Console access: qm monitor $OPNSENSE_VM_ID
- VM status: qm status $OPNSENSE_VM_ID
- VM configuration: qm config $OPNSENSE_VM_ID
- Log file: $LOG_FILE
EOF

    info "Deployment report generated: $report_file"
}

# Cleanup function
cleanup() {
    info "Cleaning up temporary files..."
    # Add cleanup tasks if needed
}

# Main deployment function
main() {
    info "Starting OPNsense deployment for T-Pot infrastructure"
    
    check_root
    check_prerequisites
    download_opnsense_iso
    create_opnsense_vm
    configure_vm_hardware
    start_vm_installation
    
    info "Waiting for manual installation completion..."
    read -p "Press Enter after completing the OPNsense installation..."
    
    wait_for_opnsense
    apply_initial_config
    create_vm_template
    generate_report
    
    success "OPNsense deployment completed successfully!"
    info "Please review the deployment report and complete the manual configuration steps"
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"