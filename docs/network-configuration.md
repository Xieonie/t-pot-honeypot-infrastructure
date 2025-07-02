# Network Configuration Guide 🌐

This guide covers the network configuration for the T-Pot honeypot infrastructure, including VLAN setup, firewall rules, and network isolation.

## 📋 Overview

The T-Pot infrastructure uses a segmented network architecture to ensure proper isolation between the honeypot environment and production networks.

### Network Topology

```
Internet
    │
    ▼
[OPNsense Firewall]
    │
    ├── Management Network (192.168.1.0/24)
    │   ├── Proxmox VE Host
    │   └── Admin Workstation
    │
    └── Honeypot Network (10.0.100.0/24)
        └── T-Pot VM
```

## 🔧 Network Segments

### Management Network (VLAN 10)
- **Subnet**: 192.168.1.0/24
- **Gateway**: 192.168.1.1
- **Purpose**: Administrative access to infrastructure
- **Devices**:
  - Proxmox VE Host: 192.168.1.10
  - OPNsense Management: 192.168.1.1
  - Admin Workstation: 192.168.1.100

### Honeypot Network (VLAN 100)
- **Subnet**: 10.0.100.0/24
- **Gateway**: 10.0.100.1
- **Purpose**: Isolated honeypot environment
- **Devices**:
  - T-Pot VM: 10.0.100.10
  - Additional honeypots: 10.0.100.11-50

## 🛡️ Firewall Rules

### Inbound Rules (WAN → Honeypot)
```
# Allow specific honeypot services from internet
pass in on WAN proto tcp from any to 10.0.100.10 port { 22, 23, 80, 443, 2222, 8080 }
pass in on WAN proto udp from any to 10.0.100.10 port { 53, 161, 1900 }

# Block all other traffic to honeypot network
block in on WAN from any to 10.0.100.0/24
```

### Inter-VLAN Rules
```
# Block honeypot access to management network
block from 10.0.100.0/24 to 192.168.1.0/24

# Allow management access to honeypot for monitoring
pass from 192.168.1.0/24 to 10.0.100.0/24 port { 22, 64297 }
```

### Outbound Rules (Honeypot → Internet)
```
# Allow limited outbound for updates and logging
pass out on WAN proto tcp from 10.0.100.0/24 to any port { 80, 443, 53 }
pass out on WAN proto udp from 10.0.100.0/24 to any port 53

# Log all outbound connections
pass out log on WAN from 10.0.100.0/24 to any
```

## 🔌 Interface Configuration

### OPNsense Interface Setup

#### WAN Interface
```bash
# Configure WAN interface
ifconfig em0 inet <PUBLIC_IP>/24
route add default <ISP_GATEWAY>
```

#### LAN Interface (Management)
```bash
# Configure LAN interface for management
ifconfig em1 inet 192.168.1.1/24
```

#### DMZ Interface (Honeypot)
```bash
# Configure DMZ interface for honeypots
ifconfig em2 inet 10.0.100.1/24
```

### Proxmox Network Configuration

#### Bridge Configuration
```bash
# /etc/network/interfaces
auto lo
iface lo inet loopback

# Management bridge
auto vmbr0
iface vmbr0 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0

# Honeypot bridge
auto vmbr1
iface vmbr1 inet manual
    bridge-ports ens19
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
```

## 🏷️ VLAN Configuration

### Switch VLAN Setup
```bash
# Management VLAN
vlan 10 name "Management"
vlan 10 ports 1-8 tagged

# Honeypot VLAN
vlan 100 name "Honeypot"
vlan 100 ports 9-16 tagged
```

### OPNsense VLAN Configuration
```bash
# Create VLAN interfaces
ifconfig em1.10 create
ifconfig em1.10 inet 192.168.1.1/24
ifconfig em1.10 description "Management VLAN"

ifconfig em1.100 create
ifconfig em1.100 inet 10.0.100.1/24
ifconfig em1.100 description "Honeypot VLAN"
```

## 🔍 Network Monitoring

### Traffic Analysis Points
1. **WAN Interface**: Monitor all inbound attacks
2. **Honeypot Interface**: Analyze attack patterns
3. **Management Interface**: Ensure no unauthorized access

### Monitoring Tools
- **ntopng**: Real-time traffic analysis
- **Suricata**: Intrusion detection
- **pflog**: Firewall log analysis

### Key Metrics to Monitor
- Connection attempts per minute
- Unique source IPs
- Attack vectors and payloads
- Data exfiltration attempts

## 🚨 Security Considerations

### Network Isolation
- **Physical Separation**: Use dedicated network interfaces
- **VLAN Segmentation**: Logical separation at Layer 2
- **Firewall Rules**: Strict access controls

### Monitoring Requirements
- **24/7 Monitoring**: Continuous network surveillance
- **Alerting**: Immediate notification of anomalies
- **Logging**: Comprehensive traffic logs

### Incident Response
- **Isolation Procedures**: Rapid network disconnection
- **Evidence Preservation**: Traffic capture and analysis
- **Threat Intelligence**: IOC extraction and sharing

## 🔧 Troubleshooting

### Common Issues

#### Connectivity Problems
```bash
# Test network connectivity
ping -c 4 192.168.1.1    # Test management gateway
ping -c 4 10.0.100.1     # Test honeypot gateway
ping -c 4 8.8.8.8        # Test internet connectivity
```

#### VLAN Issues
```bash
# Verify VLAN configuration
ip link show | grep vlan
bridge vlan show
```

#### Firewall Rules
```bash
# Check firewall logs
tail -f /var/log/filter.log
pfctl -s rules | grep honeypot
```

### Performance Optimization
- **Buffer Sizes**: Increase network buffers for high traffic
- **CPU Affinity**: Bind network interrupts to specific cores
- **Queue Management**: Implement traffic shaping

## 📚 Additional Resources

- [OPNsense Documentation](https://docs.opnsense.org/)
- [Proxmox VE Network Configuration](https://pve.proxmox.com/wiki/Network_Configuration)
- [VLAN Best Practices](https://www.cisco.com/c/en/us/support/docs/lan-switching/vlan/10023-4.html)
- [Network Security Monitoring](https://www.sans.org/white-papers/37477/)