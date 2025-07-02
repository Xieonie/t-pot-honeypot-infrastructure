#!/bin/bash

# T-Pot Infrastructure: VPN Setup Script
# This script sets up a secure VPN connection for remote access to T-Pot infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/setup-vpn.log"

# VPN Configuration
VPN_TYPE="wireguard"  # Options: wireguard, openvpn
VPN_SERVER_IP="192.168.1.1"  # OPNsense IP
VPN_NETWORK="10.0.200.0/24"
VPN_PORT="51820"
VPN_DNS="192.168.1.1"

# WireGuard specific
WG_CONFIG_DIR="/etc/wireguard"
WG_KEYS_DIR="/etc/wireguard/keys"
WG_INTERFACE="wg0"

# Client configuration
CLIENT_COUNT=5
CLIENT_PREFIX="tpot-client"

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

# Install WireGuard
install_wireguard() {
    info "Installing WireGuard..."
    
    # Update package lists
    apt update
    
    # Install WireGuard
    apt install -y wireguard wireguard-tools qrencode
    
    # Create directories
    mkdir -p "$WG_CONFIG_DIR" "$WG_KEYS_DIR"
    chmod 700 "$WG_KEYS_DIR"
    
    success "WireGuard installed successfully"
}

# Generate server keys
generate_server_keys() {
    info "Generating server keys..."
    
    # Generate server private key
    wg genkey > "$WG_KEYS_DIR/server_private.key"
    chmod 600 "$WG_KEYS_DIR/server_private.key"
    
    # Generate server public key
    wg pubkey < "$WG_KEYS_DIR/server_private.key" > "$WG_KEYS_DIR/server_public.key"
    
    success "Server keys generated"
}

# Generate client keys
generate_client_keys() {
    info "Generating client keys..."
    
    for i in $(seq 1 $CLIENT_COUNT); do
        local client_name="${CLIENT_PREFIX}-${i}"
        
        # Generate client private key
        wg genkey > "$WG_KEYS_DIR/${client_name}_private.key"
        chmod 600 "$WG_KEYS_DIR/${client_name}_private.key"
        
        # Generate client public key
        wg pubkey < "$WG_KEYS_DIR/${client_name}_private.key" > "$WG_KEYS_DIR/${client_name}_public.key"
        
        # Generate pre-shared key for additional security
        wg genpsk > "$WG_KEYS_DIR/${client_name}_preshared.key"
        chmod 600 "$WG_KEYS_DIR/${client_name}_preshared.key"
        
        info "Generated keys for $client_name"
    done
    
    success "Client keys generated"
}

# Create server configuration
create_server_config() {
    info "Creating server configuration..."
    
    local server_private_key=$(cat "$WG_KEYS_DIR/server_private.key")
    
    cat > "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF
# WireGuard Server Configuration for T-Pot Infrastructure
# Generated on $(date)

[Interface]
# Server private key
PrivateKey = $server_private_key

# Server IP address in VPN network
Address = 10.0.200.1/24

# VPN port
ListenPort = $VPN_PORT

# Enable IP forwarding
PostUp = echo 1 > /proc/sys/net/ipv4/ip_forward
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
PostUp = iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ens18 -j MASQUERADE

# Disable IP forwarding and remove rules on shutdown
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ens18 -j MASQUERADE

# DNS server for clients
DNS = $VPN_DNS

# Save configuration
SaveConfig = false

EOF

    # Add client configurations
    for i in $(seq 1 $CLIENT_COUNT); do
        local client_name="${CLIENT_PREFIX}-${i}"
        local client_ip="10.0.200.$((i + 10))"
        local client_public_key=$(cat "$WG_KEYS_DIR/${client_name}_public.key")
        local client_preshared_key=$(cat "$WG_KEYS_DIR/${client_name}_preshared.key")
        
        cat >> "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF

# Client: $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $client_preshared_key
AllowedIPs = $client_ip/32

EOF
    done
    
    chmod 600 "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    success "Server configuration created"
}

# Create client configurations
create_client_configs() {
    info "Creating client configurations..."
    
    local server_public_key=$(cat "$WG_KEYS_DIR/server_public.key")
    local client_config_dir="$WG_CONFIG_DIR/clients"
    
    mkdir -p "$client_config_dir"
    
    for i in $(seq 1 $CLIENT_COUNT); do
        local client_name="${CLIENT_PREFIX}-${i}"
        local client_ip="10.0.200.$((i + 10))"
        local client_private_key=$(cat "$WG_KEYS_DIR/${client_name}_private.key")
        local client_preshared_key=$(cat "$WG_KEYS_DIR/${client_name}_preshared.key")
        
        cat > "$client_config_dir/${client_name}.conf" << EOF
# WireGuard Client Configuration: $client_name
# Generated on $(date)

[Interface]
# Client private key
PrivateKey = $client_private_key

# Client IP address in VPN network
Address = $client_ip/24

# DNS server
DNS = $VPN_DNS

# Optional: Kill switch (uncomment to enable)
# PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
# PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark \$(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

[Peer]
# Server public key
PublicKey = $server_public_key

# Pre-shared key for additional security
PresharedKey = $client_preshared_key

# Server endpoint
Endpoint = $VPN_SERVER_IP:$VPN_PORT

# Allowed IPs (routes through VPN)
# Full tunnel: 0.0.0.0/0
# Split tunnel for T-Pot access: 192.168.1.0/24, 10.0.100.0/24, 10.0.200.0/24
AllowedIPs = 192.168.1.0/24, 10.0.100.0/24, 10.0.200.0/24

# Keep connection alive
PersistentKeepalive = 25

EOF
        
        chmod 600 "$client_config_dir/${client_name}.conf"
        
        # Generate QR code for mobile clients
        qrencode -t ansiutf8 < "$client_config_dir/${client_name}.conf" > "$client_config_dir/${client_name}_qr.txt"
        qrencode -t png -o "$client_config_dir/${client_name}_qr.png" < "$client_config_dir/${client_name}.conf"
        
        info "Created configuration for $client_name"
    done
    
    success "Client configurations created"
}

# Configure firewall rules
configure_firewall() {
    info "Configuring firewall rules..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw
    fi
    
    # Configure UFW rules for WireGuard
    ufw allow "$VPN_PORT/udp" comment "WireGuard VPN"
    
    # Allow forwarding for VPN traffic
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Add NAT rules to UFW before.rules
    local ufw_before_rules="/etc/ufw/before.rules"
    
    # Backup original file
    cp "$ufw_before_rules" "${ufw_before_rules}.backup"
    
    # Add NAT rules at the beginning of the file
    cat > /tmp/ufw_nat_rules << EOF
# NAT rules for WireGuard VPN
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.200.0/24 -o ens18 -j MASQUERADE
COMMIT

EOF
    
    # Prepend NAT rules to existing before.rules
    cat /tmp/ufw_nat_rules "$ufw_before_rules" > /tmp/new_before_rules
    mv /tmp/new_before_rules "$ufw_before_rules"
    
    # Reload UFW
    ufw --force reload
    
    success "Firewall rules configured"
}

# Start and enable WireGuard service
start_wireguard_service() {
    info "Starting WireGuard service..."
    
    # Enable and start WireGuard interface
    systemctl enable wg-quick@$WG_INTERFACE
    systemctl start wg-quick@$WG_INTERFACE
    
    # Check status
    if systemctl is-active wg-quick@$WG_INTERFACE > /dev/null; then
        success "WireGuard service started successfully"
    else
        error "Failed to start WireGuard service"
        return 1
    fi
    
    # Show interface status
    wg show
}

# Configure OPNsense for VPN (instructions)
configure_opnsense_vpn() {
    info "OPNsense VPN configuration instructions..."
    
    cat << EOF

OPNsense WireGuard Configuration:
=================================

1. Install WireGuard plugin:
   - Go to System > Firmware > Plugins
   - Install os-wireguard plugin

2. Configure WireGuard server:
   - Go to VPN > WireGuard > Local
   - Add new local configuration:
     * Name: T-Pot-VPN
     * Private Key: $(cat "$WG_KEYS_DIR/server_private.key")
     * Listen Port: $VPN_PORT

3. Configure WireGuard peers:
   - Go to VPN > WireGuard > Peers
   - Add peers for each client using their public keys

4. Configure firewall rules:
   - Go to Firewall > Rules > WAN
   - Add rule to allow WireGuard traffic on port $VPN_PORT/UDP
   - Go to Firewall > Rules > WireGuard
   - Add rules to allow VPN clients access to required networks

5. Enable WireGuard:
   - Go to VPN > WireGuard > General
   - Enable WireGuard
   - Apply configuration

EOF

    warn "OPNsense configuration must be completed manually via web interface"
}

# Test VPN connectivity
test_vpn_connectivity() {
    info "Testing VPN connectivity..."
    
    # Check if WireGuard interface is up
    if ip link show "$WG_INTERFACE" > /dev/null 2>&1; then
        success "✅ WireGuard interface is up"
    else
        error "❌ WireGuard interface is not up"
        return 1
    fi
    
    # Check if VPN network is reachable
    if ping -c 3 -W 5 10.0.200.1 > /dev/null 2>&1; then
        success "✅ VPN network is reachable"
    else
        warn "⚠️  VPN network connectivity test failed"
    fi
    
    # Show connected peers
    local connected_peers=$(wg show "$WG_INTERFACE" peers | wc -l)
    info "Connected VPN peers: $connected_peers"
}

# Generate VPN documentation
generate_vpn_documentation() {
    local doc_file="/tmp/vpn-setup-documentation.md"
    
    cat > "$doc_file" << EOF
# T-Pot Infrastructure VPN Setup Documentation

## Overview
This document describes the WireGuard VPN setup for secure remote access to the T-Pot honeypot infrastructure.

## Configuration Details
- **VPN Type**: WireGuard
- **Server IP**: $VPN_SERVER_IP
- **VPN Network**: $VPN_NETWORK
- **VPN Port**: $VPN_PORT
- **DNS Server**: $VPN_DNS

## Server Configuration
- **Config File**: $WG_CONFIG_DIR/$WG_INTERFACE.conf
- **Keys Directory**: $WG_KEYS_DIR
- **Interface**: $WG_INTERFACE

## Client Configurations
Client configuration files are located in: $WG_CONFIG_DIR/clients/

Available clients:
$(for i in $(seq 1 $CLIENT_COUNT); do
    echo "- ${CLIENT_PREFIX}-${i}: 10.0.200.$((i + 10))"
done)

## Usage Instructions

### Server Management
\`\`\`bash
# Start VPN
systemctl start wg-quick@$WG_INTERFACE

# Stop VPN
systemctl stop wg-quick@$WG_INTERFACE

# Check status
systemctl status wg-quick@$WG_INTERFACE
wg show

# View connected peers
wg show $WG_INTERFACE peers
\`\`\`

### Client Setup

#### Desktop/Laptop (Linux)
1. Install WireGuard: \`apt install wireguard\`
2. Copy client configuration to \`/etc/wireguard/\`
3. Start connection: \`wg-quick up client-config\`

#### Mobile (Android/iOS)
1. Install WireGuard app from app store
2. Scan QR code from \`$WG_CONFIG_DIR/clients/\*_qr.png\`
3. Activate tunnel in app

#### Windows
1. Download WireGuard for Windows
2. Import client configuration file
3. Activate tunnel

## Security Considerations
- All connections use strong encryption (ChaCha20Poly1305)
- Pre-shared keys provide additional security layer
- Split tunneling configured for T-Pot access only
- Regular key rotation recommended (every 6 months)

## Troubleshooting

### Common Issues
1. **Connection fails**: Check firewall rules and port forwarding
2. **No internet access**: Verify routing and NAT configuration
3. **DNS issues**: Check DNS server configuration

### Diagnostic Commands
\`\`\`bash
# Check interface status
ip addr show $WG_INTERFACE

# Check routing
ip route show table all

# Check firewall rules
iptables -L -n -v

# View WireGuard logs
journalctl -u wg-quick@$WG_INTERFACE
\`\`\`

## Maintenance
- Monitor connection logs regularly
- Update WireGuard software periodically
- Rotate keys every 6 months
- Review and update firewall rules as needed

## Files and Locations
- Server config: $WG_CONFIG_DIR/$WG_INTERFACE.conf
- Client configs: $WG_CONFIG_DIR/clients/
- Keys: $WG_KEYS_DIR/
- Logs: /var/log/setup-vpn.log

Generated on: $(date)
EOF

    success "VPN documentation generated: $doc_file"
}

# Cleanup function
cleanup() {
    info "Cleaning up temporary files..."
    rm -f /tmp/ufw_nat_rules /tmp/new_before_rules
}

# Main VPN setup function
main() {
    info "Starting T-Pot infrastructure VPN setup"
    
    check_root
    
    case "$VPN_TYPE" in
        "wireguard")
            install_wireguard
            generate_server_keys
            generate_client_keys
            create_server_config
            create_client_configs
            configure_firewall
            start_wireguard_service
            configure_opnsense_vpn
            test_vpn_connectivity
            generate_vpn_documentation
            ;;
        "openvpn")
            error "OpenVPN setup not implemented yet"
            exit 1
            ;;
        *)
            error "Unsupported VPN type: $VPN_TYPE"
            exit 1
            ;;
    esac
    
    success "VPN setup completed successfully!"
    
    info "Next steps:"
    info "1. Configure OPNsense WireGuard plugin (see instructions above)"
    info "2. Distribute client configurations to users"
    info "3. Test connectivity from client devices"
    info "4. Monitor VPN usage and security"
    
    info "Client configurations available in: $WG_CONFIG_DIR/clients/"
    info "QR codes for mobile devices: $WG_CONFIG_DIR/clients/*_qr.png"
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"