#!/bin/bash

# T-Pot Infrastructure: T-Pot Installation Script
# This script automates the installation and configuration of T-Pot honeypot

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
LOG_FILE="/var/log/install-tpot.log"

# T-Pot Configuration
TPOT_VERSION="23.04"
TPOT_REPO="https://github.com/telekom-security/tpotce.git"
TPOT_INSTALL_DIR="/opt/tpot"
TPOT_DATA_DIR="/data/tpot"

# VM Configuration
TPOT_VM_ID="101"
TPOT_VM_NAME="tpot-honeypot"
VM_MEMORY="8192"
VM_CORES="4"
VM_DISK_SIZE="100G"
VM_STORAGE="local-lvm"
VM_BRIDGE="vmbr2"  # DMZ bridge

# Network Configuration
TPOT_IP="10.0.100.10"
TPOT_NETMASK="255.255.255.0"
TPOT_GATEWAY="10.0.100.1"
TPOT_DNS="10.0.100.1"

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
    local tools=("git" "wget" "curl" "docker" "docker-compose")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            warn "$tool is not installed. Will install during setup."
        fi
    done
    
    # Check available storage
    local available_space=$(df /var/lib/vz --output=avail | tail -n1 | tr -d ' ')
    local required_space=$((20 * 1024 * 1024))  # 20GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        error "Insufficient disk space. At least 20GB required."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Download Ubuntu Server ISO
download_ubuntu_iso() {
    local ubuntu_version="22.04.3"
    local iso_file="ubuntu-${ubuntu_version}-live-server-amd64.iso"
    local iso_url="https://releases.ubuntu.com/22.04/${iso_file}"
    local iso_path="/var/lib/vz/template/iso/$iso_file"
    
    if [[ -f "$iso_path" ]]; then
        info "Ubuntu ISO already exists: $iso_path"
        return 0
    fi
    
    info "Downloading Ubuntu Server ISO..."
    wget -O "$iso_path" "$iso_url"
    
    if [[ $? -eq 0 ]]; then
        success "Ubuntu ISO downloaded successfully"
    else
        error "Failed to download Ubuntu ISO"
        exit 1
    fi
}

# Create T-Pot VM
create_tpot_vm() {
    info "Creating T-Pot VM..."
    
    # Check if VM already exists
    if qm status "$TPOT_VM_ID" &> /dev/null; then
        warn "VM $TPOT_VM_ID already exists. Stopping and removing..."
        qm stop "$TPOT_VM_ID" || true
        qm destroy "$TPOT_VM_ID" || true
    fi
    
    local ubuntu_iso="ubuntu-22.04.3-live-server-amd64.iso"
    
    # Create VM
    qm create "$TPOT_VM_ID" \
        --name "$TPOT_VM_NAME" \
        --memory "$VM_MEMORY" \
        --cores "$VM_CORES" \
        --sockets 1 \
        --cpu cputype=host \
        --ostype l26 \
        --boot order=ide2 \
        --ide2 "local:iso/$ubuntu_iso,media=cdrom" \
        --scsi0 "$VM_STORAGE:$VM_DISK_SIZE" \
        --scsihw virtio-scsi-pci \
        --net0 virtio,bridge="$VM_BRIDGE" \
        --vga qxl \
        --tablet 1 \
        --onboot 1
    
    if [[ $? -eq 0 ]]; then
        success "T-Pot VM created successfully"
    else
        error "Failed to create T-Pot VM"
        exit 1
    fi
}

# Configure VM for T-Pot
configure_tpot_vm() {
    info "Configuring T-Pot VM..."
    
    # Set VM options
    qm set "$TPOT_VM_ID" \
        --startup order=2,up=60,down=30 \
        --protection 1 \
        --description "T-Pot Honeypot - Multi-honeypot platform"
    
    # Configure network with static MAC for consistency
    qm set "$TPOT_VM_ID" \
        --net0 virtio,bridge="$VM_BRIDGE",macaddr=52:54:00:12:34:59
    
    success "T-Pot VM configured"
}

# Start VM for Ubuntu installation
start_ubuntu_installation() {
    info "Starting T-Pot VM for Ubuntu installation..."
    
    qm start "$TPOT_VM_ID"
    
    if [[ $? -eq 0 ]]; then
        success "T-Pot VM started"
        info "Please complete the Ubuntu installation manually via the console"
        info "VM ID: $TPOT_VM_ID"
        info "Access the console with: qm monitor $TPOT_VM_ID"
        info ""
        info "Ubuntu installation configuration:"
        info "- Hostname: tpot-honeypot"
        info "- Username: tpot"
        info "- Network: Static IP $TPOT_IP/$TPOT_NETMASK"
        info "- Gateway: $TPOT_GATEWAY"
        info "- DNS: $TPOT_DNS"
        info "- Install OpenSSH server"
        info "- Minimal installation (no additional packages)"
        info ""
        info "After Ubuntu installation, this script will continue with T-Pot setup"
    else
        error "Failed to start T-Pot VM"
        exit 1
    fi
}

# Wait for Ubuntu to be ready
wait_for_ubuntu() {
    info "Waiting for Ubuntu to be ready..."
    local max_attempts=60
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if ping -c 1 "$TPOT_IP" &> /dev/null; then
            success "Ubuntu is responding"
            return 0
        fi
        
        ((attempt++))
        info "Attempt $attempt/$max_attempts - waiting for Ubuntu..."
        sleep 10
    done
    
    error "Ubuntu did not become ready within expected time"
    return 1
}

# Install T-Pot on the VM
install_tpot_software() {
    info "Installing T-Pot software..."
    
    # Create installation script
    cat > /tmp/tpot-install.sh << 'EOF'
#!/bin/bash

set -euo pipefail

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y git curl wget docker.io docker-compose

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Add tpot user to docker group
usermod -aG docker tpot

# Clone T-Pot repository
git clone https://github.com/telekom-security/tpotce.git /opt/tpot

# Change to T-Pot directory
cd /opt/tpot

# Run T-Pot installer
./install.sh --type=user --conf=STANDARD

# Configure T-Pot
systemctl enable tpot
systemctl start tpot

echo "T-Pot installation completed"
EOF

    # Copy and execute installation script on the VM
    scp /tmp/tpot-install.sh tpot@"$TPOT_IP":/tmp/
    ssh tpot@"$TPOT_IP" "sudo bash /tmp/tpot-install.sh"
    
    if [[ $? -eq 0 ]]; then
        success "T-Pot software installed successfully"
    else
        error "Failed to install T-Pot software"
        exit 1
    fi
}

# Apply custom T-Pot configuration
apply_tpot_config() {
    info "Applying custom T-Pot configuration..."
    
    local config_source="$CONFIG_DIR/t-pot"
    
    if [[ ! -d "$config_source" ]]; then
        error "T-Pot configuration directory not found: $config_source"
        exit 1
    fi
    
    # Copy custom configuration files
    scp -r "$config_source"/* tpot@"$TPOT_IP":/tmp/tpot-config/
    
    # Apply configuration on the VM
    ssh tpot@"$TPOT_IP" << 'EOF'
# Stop T-Pot services
sudo systemctl stop tpot

# Backup original configuration
sudo cp -r /opt/tpot/etc /opt/tpot/etc.backup

# Apply custom configuration
sudo cp -r /tmp/tpot-config/* /opt/tpot/etc/

# Set proper permissions
sudo chown -R tpot:tpot /opt/tpot/etc
sudo chmod -R 644 /opt/tpot/etc

# Restart T-Pot services
sudo systemctl start tpot
EOF

    success "Custom T-Pot configuration applied"
}

# Configure firewall rules
configure_firewall() {
    info "Configuring firewall rules..."
    
    ssh tpot@"$TPOT_IP" << 'EOF'
# Install UFW
sudo apt install -y ufw

# Reset UFW to defaults
sudo ufw --force reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH from management network
sudo ufw allow from 192.168.1.0/24 to any port 22

# Allow T-Pot web interface from management network
sudo ufw allow from 192.168.1.0/24 to any port 64297

# Allow honeypot services from anywhere
sudo ufw allow 23    # Telnet
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw allow 2222  # SSH alternate
sudo ufw allow 8080  # HTTP alternate
sudo ufw allow 53    # DNS
sudo ufw allow 161   # SNMP
sudo ufw allow 1900  # UPnP

# Enable UFW
sudo ufw --force enable

# Show status
sudo ufw status verbose
EOF

    success "Firewall rules configured"
}

# Setup monitoring
setup_monitoring() {
    info "Setting up monitoring..."
    
    ssh tpot@"$TPOT_IP" << 'EOF'
# Install monitoring tools
sudo apt install -y htop iotop nethogs

# Install Prometheus node exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
rm -rf node_exporter-1.6.1.linux-amd64*

# Create node exporter service
sudo tee /etc/systemd/system/node_exporter.service > /dev/null << 'EOL'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=tpot
Group=tpot
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOL

# Enable and start node exporter
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
EOF

    success "Monitoring setup completed"
}

# Verify T-Pot installation
verify_installation() {
    info "Verifying T-Pot installation..."
    
    # Check if T-Pot services are running
    ssh tpot@"$TPOT_IP" "sudo systemctl status tpot" || {
        error "T-Pot service is not running"
        return 1
    }
    
    # Check if web interface is accessible
    if curl -k -s "https://$TPOT_IP:64297" > /dev/null; then
        success "T-Pot web interface is accessible"
    else
        warn "T-Pot web interface is not accessible yet (may take a few minutes to start)"
    fi
    
    # Check if honeypot services are listening
    local services=("22" "23" "80" "443" "2222" "8080")
    for port in "${services[@]}"; do
        if nc -z "$TPOT_IP" "$port" 2>/dev/null; then
            success "Port $port is listening"
        else
            warn "Port $port is not listening"
        fi
    done
    
    success "T-Pot installation verification completed"
}

# Generate installation report
generate_report() {
    local report_file="/tmp/tpot-installation-report.txt"
    
    cat > "$report_file" << EOF
T-Pot Installation Report
=========================
Date: $(date)
VM ID: $TPOT_VM_ID
VM Name: $TPOT_VM_NAME
Memory: $VM_MEMORY MB
CPU Cores: $VM_CORES
Disk Size: $VM_DISK_SIZE

Network Configuration:
- IP Address: $TPOT_IP
- Netmask: $TPOT_NETMASK
- Gateway: $TPOT_GATEWAY
- DNS: $TPOT_DNS

T-Pot Configuration:
- Version: $TPOT_VERSION
- Installation Directory: $TPOT_INSTALL_DIR
- Data Directory: $TPOT_DATA_DIR
- Web Interface: https://$TPOT_IP:64297

Honeypot Services:
- SSH: Port 22, 2222
- Telnet: Port 23
- HTTP: Port 80, 8080
- HTTPS: Port 443
- DNS: Port 53
- SNMP: Port 161
- UPnP: Port 1900

Management Access:
- SSH: ssh tpot@$TPOT_IP
- Web Interface: https://$TPOT_IP:64297
- Logs: /data/tpot/logs/

Next Steps:
1. Access T-Pot web interface and complete initial setup
2. Configure additional honeypot services if needed
3. Set up log forwarding to central SIEM
4. Configure alerting and monitoring
5. Test honeypot functionality

Troubleshooting:
- VM console: qm monitor $TPOT_VM_ID
- Service status: systemctl status tpot
- Docker containers: docker ps
- Logs: journalctl -u tpot -f
- Log file: $LOG_FILE
EOF

    info "Installation report generated: $report_file"
}

# Cleanup function
cleanup() {
    info "Cleaning up temporary files..."
    rm -f /tmp/tpot-install.sh
}

# Main installation function
main() {
    info "Starting T-Pot installation for honeypot infrastructure"
    
    check_root
    check_prerequisites
    download_ubuntu_iso
    create_tpot_vm
    configure_tpot_vm
    start_ubuntu_installation
    
    info "Waiting for Ubuntu installation completion..."
    read -p "Press Enter after completing the Ubuntu installation..."
    
    wait_for_ubuntu
    install_tpot_software
    apply_tpot_config
    configure_firewall
    setup_monitoring
    verify_installation
    generate_report
    
    success "T-Pot installation completed successfully!"
    info "Access the T-Pot web interface at: https://$TPOT_IP:64297"
    info "Please review the installation report and complete any remaining configuration"
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"