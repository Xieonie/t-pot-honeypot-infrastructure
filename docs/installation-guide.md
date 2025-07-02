# T-Pot CE Honeypot Installation Guide 🍯🔒

A comprehensive step-by-step guide for installing and configuring T-Pot Community Edition with OPNsense firewall on Proxmox VE.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Network Architecture](#network-architecture)
- [Proxmox Network Setup](#proxmox-network-setup)
- [OPNsense VM Deployment](#opnsense-vm-deployment)
- [T-Pot VM Installation](#t-pot-vm-installation)
- [Security Configuration](#security-configuration)
- [Validation and Testing](#validation-and-testing)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Proxmox Host** | 16GB RAM, 4 Cores, 500GB | 32GB RAM, 8 Cores, 1TB |
| **T-Pot VM** | 8GB RAM, 4 vCPUs, 128GB | 16GB RAM, 6 vCPUs, 256GB |
| **OPNsense VM** | 2GB RAM, 2 vCPUs, 20GB | 4GB RAM, 2 vCPUs, 40GB |

### Network Requirements

- Management network (e.g., 192.168.1.0/24)
- Public IP address for internet exposure
- Administrative access to router/firewall

### Software Versions

- Proxmox VE 8.0+
- OPNsense 23.7+
- T-Pot CE 23.04+
- Debian 12 (Bookworm)

## Network Architecture

### Overview

```
Internet (Public IP)
        |
        | WAN Interface
┌───────▼─────────────────────────────────────┐
│            Proxmox VE Host                  │
│                                             │
│ ┌─────────────┐      ┌─────────────────────┐│
│ │   vmbr0     │      │       vmbr1         ││
│ │ LAN Bridge  │      │ Honeypot Bridge     ││
│ │192.168.1.x  │      │  10.0.100.0/24     ││
│ └──────┬──────┘      └──────┬──────────────┘│
│        │                    │               │
│ ┌──────▼──────┐      ┌──────▼──────────────┐│
│ │ Management  │      │    OPNsense VM      ││
│ │    Host     │      │ WAN: vmbr0 (DHCP)  ││
│ │             │      │ LAN: vmbr1 (Static)││
│ └─────────────┘      └──────┬──────────────┘│
│                             │               │
│                      ┌──────▼──────────────┐│
│                      │     T-Pot VM        ││
│                      │   10.0.100.10/24   ││
│                      │   Gateway: .1       ││
│                      └─────────────────────┘│
└─────────────────────────────────────────────┘
```

### IP Address Plan

| Component | Interface | IP Address | Purpose |
|-----------|-----------|------------|---------|
| Proxmox Host | vmbr0 | 192.168.1.100 | Management |
| OPNsense | WAN (vmbr0) | DHCP/Static | Internet access |
| OPNsense | LAN (vmbr1) | 10.0.100.1/24 | Honeypot gateway |
| T-Pot VM | eth0 (vmbr1) | 10.0.100.10/24 | Honeypot services |

## Proxmox Network Setup

### 1. Create Isolated Bridge

1. **Access Proxmox Web Interface**
   ```
   https://PROXMOX-IP:8006
   ```

2. **Navigate to Network Configuration**
   - Go to `Datacenter` → `Node` → `System` → `Network`

3. **Create New Bridge**
   ```
   Name: vmbr1
   IPv4/CIDR: <leave empty>
   Bridge ports: <leave empty>
   Comment: Isolated Honeypot Network
   VLAN aware: No
   ```

4. **Apply Configuration**
   ```bash
   # SSH to Proxmox host
   ifreload -a
   
   # Verify bridges
   ip link show type bridge
   ```

### 2. Configure Firewall (Optional)

```bash
# Enable Proxmox firewall
# Datacenter → Firewall → Options
Firewall: Yes
Input Policy: DROP
Output Policy: ACCEPT
Forward Policy: DROP

# Create security group for management
# Datacenter → Firewall → Security Group
Name: management-access
Rules:
- Direction: in, Action: ACCEPT, Source: 192.168.1.0/24, Dest Port: 8006,22
```

## OPNsense VM Deployment

### 1. Download OPNsense ISO

```bash
# Download latest OPNsense ISO
cd /var/lib/vz/template/iso/
wget https://mirror.ams1.nl.leaseweb.net/opnsense/releases/23.7/OPNsense-23.7-OpenSSL-dvd-amd64.iso.bz2
bunzip2 OPNsense-23.7-OpenSSL-dvd-amd64.iso.bz2
```

### 2. Create OPNsense VM

```bash
# Create VM via CLI (alternative to web interface)
qm create 100 \
  --name opnsense-firewall \
  --memory 2048 \
  --cores 2 \
  --net0 virtio,bridge=vmbr0 \
  --net1 virtio,bridge=vmbr1 \
  --ide2 local:iso/OPNsense-23.7-OpenSSL-dvd-amd64.iso,media=cdrom \
  --scsi0 local-lvm:20,format=qcow2 \
  --boot order=ide2 \
  --ostype other
```

### 3. Install OPNsense

1. **Start VM and connect via console**
2. **Follow installation wizard**
   - Select "Install (UFS)"
   - Choose keyboard layout
   - Set root password
   - Complete installation and reboot

3. **Initial interface assignment**
   ```
   WAN Interface: vtnet0 (connected to vmbr0)
   LAN Interface: vtnet1 (connected to vmbr1)
   ```

### 4. Configure Network Interfaces

#### 4.1 Configure WAN Interface

```bash
# Access OPNsense console
# Option 2) Set interface IP address
# Select WAN interface (1)

# For DHCP:
Configure IPv4 address WAN interface via DHCP? (y/n): y

# For Static IP:
Configure IPv4 address WAN interface via DHCP? (y/n): n
Enter the new WAN IPv4 address: 192.168.1.200
Enter the new WAN IPv4 subnet bit count: 24
Enter the new WAN IPv4 upstream gateway address: 192.168.1.1
```

#### 4.2 Configure LAN Interface

```bash
# Option 2) Set interface IP address
# Select LAN interface (2)

Configure IPv4 address LAN interface via DHCP? (y/n): n
Enter the new LAN IPv4 address: 10.0.100.1
Enter the new LAN IPv4 subnet bit count: 24
Enter the new LAN IPv4 upstream gateway address: <press Enter>

Do you want to enable the DHCP server on LAN? (y/n): y
Enter the start address of the IPv4 client address range: 10.0.100.10
Enter the end address of the IPv4 client address range: 10.0.100.100
```

### 5. Web Interface Configuration

1. **Access OPNsense Web Interface**
   ```
   URL: https://10.0.100.1
   Username: root
   Password: <set during installation>
   ```

2. **Run Setup Wizard**
   - General Information
   - Time Server Settings
   - Configure WAN Interface
   - Configure LAN Interface
   - Set Admin Password

### 6. Firewall Rules Configuration

#### 6.1 LAN Rules

```bash
# Firewall → Rules → LAN

# Rule 1: Allow LAN to Internet
Action: Pass
Interface: LAN
Source: LAN net (10.0.100.0/24)
Destination: any
Description: "Allow outbound internet access"

# Rule 2: Allow Management Access to T-Pot
Action: Pass
Interface: LAN
Source: 192.168.1.0/24
Destination: 10.0.100.10
Destination Port: 64297
Description: "Allow T-Pot management access"

# Rule 3: Block LAN to WAN Network
Action: Block
Interface: LAN
Source: LAN net
Destination: WAN net
Description: "Block access to WAN network"
```

#### 6.2 WAN Rules

```bash
# Firewall → Rules → WAN

# Rule 1: Block Management Access
Action: Block
Interface: WAN
Source: any
Destination: This Firewall
Description: "Block direct firewall access"

# Rule 2: Allow Management from Trusted IP
Action: Pass
Interface: WAN
Source: <YOUR_MANAGEMENT_IP>
Destination: This Firewall
Destination Port: 443, 22
Description: "Allow management from trusted source"
```

### 7. NAT/Port Forwarding

```bash
# Firewall → NAT → Port Forward

# SSH Honeypot
Interface: WAN
Protocol: TCP
Source: any
Destination: WAN address
Destination port: 22
Redirect target IP: 10.0.100.10
Redirect target port: 22
Description: "SSH Honeypot"

# HTTP Honeypot
Interface: WAN
Protocol: TCP
Source: any
Destination: WAN address
Destination port: 80
Redirect target IP: 10.0.100.10
Redirect target port: 80
Description: "HTTP Honeypot"

# HTTPS Honeypot
Interface: WAN
Protocol: TCP
Source: any
Destination: WAN address
Destination port: 443
Redirect target IP: 10.0.100.10
Redirect target port: 443
Description: "HTTPS Honeypot"

# Additional honeypot ports (customize as needed)
# Telnet: 23, FTP: 21, SMTP: 25, DNS: 53, etc.
```

## T-Pot VM Installation

### 1. Download Debian ISO

```bash
# Download Debian 12 netinst ISO
cd /var/lib/vz/template/iso/
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.2.0-amd64-netinst.iso
```

### 2. Create T-Pot VM

```bash
# Create VM via CLI
qm create 101 \
  --name t-pot-honeypot \
  --memory 8192 \
  --cores 4 \
  --net0 virtio,bridge=vmbr1 \
  --ide2 local:iso/debian-12.2.0-amd64-netinst.iso,media=cdrom \
  --scsi0 local-lvm:128,format=qcow2 \
  --boot order=ide2 \
  --ostype l26
```

### 3. Install Debian Base System

1. **Start VM and connect via console**
2. **Debian Installation**
   - Select "Install" (not graphical)
   - Choose language, country, keyboard
   - Configure network manually:
     ```
     IP address: 10.0.100.10
     Netmask: 255.255.255.0
     Gateway: 10.0.100.1
     Name server: 10.0.100.1
     ```
   - Set hostname: `t-pot-honeypot`
   - Set domain: `local`
   - Set root password
   - Create user account: `tpot`
   - Partition disks (use entire disk)
   - Select software: SSH server, standard system utilities
   - Install GRUB bootloader

### 4. Post-Installation Configuration

```bash
# SSH to T-Pot VM
ssh tpot@10.0.100.10

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget git sudo ufw

# Configure sudo for tpot user
sudo usermod -aG sudo tpot

# Verify network connectivity
ping -c 3 8.8.8.8
ping -c 3 google.com
```

### 5. Install T-Pot

#### 5.1 Download T-Pot

```bash
# Clone T-Pot repository
cd /opt
sudo git clone https://github.com/telekom-security/tpotce
sudo chown -R tpot:tpot tpotce
cd tpotce
```

#### 5.2 Run Installation

```bash
# Start T-Pot installation
sudo ./install.sh

# Installation options:
# Type: STANDARD
# User: admin
# Password: <secure password>
```

#### 5.3 Installation Process

The installation will:
1. Install Docker and Docker Compose
2. Download honeypot containers
3. Configure services
4. Set up web interface
5. Configure firewall rules

**Note**: Installation takes 30-60 minutes depending on internet speed.

### 6. Post-Installation Verification

```bash
# Check T-Pot status
sudo systemctl status tpot

# Check Docker containers
sudo docker ps

# Check logs
sudo docker logs tpot_nginx_1

# Verify web interface
curl -k https://localhost:64297
```

## Security Configuration

### 1. T-Pot Hardening

#### 1.1 Restrict Web Interface Access

```bash
# Edit nginx configuration
sudo nano /opt/tpot/etc/nginx/nginx.conf

# Add IP restrictions
location / {
    allow 192.168.1.0/24;  # Management network
    allow 10.0.100.1;      # OPNsense
    deny all;
    # ... rest of configuration
}

# Restart nginx
sudo docker restart tpot_nginx_1
```

#### 1.2 Configure Automatic Updates

```bash
# Create update script
sudo nano /opt/tpot/bin/auto-update.sh

#!/bin/bash
# Auto-update script for T-Pot

# Update system packages
apt update && apt upgrade -y

# Update T-Pot
cd /opt/tpotce
git pull
./update.sh

# Make executable
sudo chmod +x /opt/tpot/bin/auto-update.sh

# Add to crontab
sudo crontab -e
# Add line: 0 3 * * 0 /opt/tpot/bin/auto-update.sh >> /var/log/tpot-update.log 2>&1
```

### 2. OPNsense Hardening

#### 2.1 Secure Web Interface

```bash
# System → Settings → Administration
Protocol: HTTPS
SSL Certificate: Generate new self-signed certificate
TCP Port: 8443 (non-standard)
Session Timeout: 30 minutes
Login Protection: Enable
```

#### 2.2 SSH Configuration

```bash
# System → Settings → Administration → Secure Shell
Secure Shell Server: Enable
SSH Port: 2222
Permit root user login: Disable
Authentication Method: Public Key + Password
```

### 3. Network Security

#### 3.1 Enable Intrusion Detection

```bash
# Services → Intrusion Detection → Administration
Enable IDS: Yes
IDS Mode: IPS (Inline)
Interfaces: WAN, LAN
Rulesets: ET Open, Abuse.ch
```

#### 3.2 Configure Logging

```bash
# System → Settings → Logging
Log Level: Informational
Log Destinations: Local, Remote Syslog (optional)
```

## Validation and Testing

### 1. Network Connectivity Tests

```bash
# From management host (192.168.1.x)
# Test 1: OPNsense WAN reachable
ping 192.168.1.200  # OPNsense WAN IP

# Test 2: OPNsense LAN not directly reachable
ping 10.0.100.1     # Should timeout

# Test 3: T-Pot not directly reachable
ping 10.0.100.10    # Should timeout
```

### 2. Port Forwarding Tests

```bash
# Test honeypot services from external network
nmap -p 22,80,443 <PUBLIC_IP>

# Expected results:
# 22/tcp   open  ssh
# 80/tcp   open  http
# 443/tcp  open  https
```

### 3. Web Interface Access

```bash
# T-Pot Dashboard (from management network)
https://10.0.100.10:64297

# OPNsense Interface (from management network)
https://10.0.100.1:8443
```

### 4. Log Verification

```bash
# Check T-Pot logs
sudo docker logs tpot_cowrie_1     # SSH honeypot
sudo docker logs tpot_dionaea_1    # Multi-protocol honeypot
sudo docker logs tpot_suricata_1   # Network IDS

# Check OPNsense logs
# System → Log Files → Firewall
# System → Log Files → System
```

## Next Steps

1. **Configure Monitoring**: Set up Grafana dashboards and alerts
2. **Implement Backup**: Regular backup of configurations and logs
3. **Security Hardening**: Apply additional security measures
4. **Attack Simulation**: Test honeypot functionality
5. **Documentation**: Document custom configurations

## Troubleshooting

For common issues and solutions, see [Troubleshooting Guide](troubleshooting.md).

---

**⚠️ Security Warning**: This setup creates an intentionally vulnerable system. Ensure proper isolation and monitoring at all times.