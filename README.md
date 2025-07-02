# T-Pot CE Honeypot Infrastructure 🍯🔒

A comprehensive guide for deploying T-Pot Community Edition honeypot in an isolated network environment with OPNsense firewall on Proxmox VE.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Proxmox](https://img.shields.io/badge/Proxmox-VE-orange)
![T-Pot](https://img.shields.io/badge/T--Pot-CE-green)
![OPNsense](https://img.shields.io/badge/OPNsense-Firewall-red)

## 🎯 Project Overview

This repository provides a complete infrastructure-as-code solution for deploying a secure honeypot environment using:

- **T-Pot CE**: Multi-honeypot platform with 20+ honeypot services
- **OPNsense**: Enterprise firewall for network isolation and traffic control
- **Proxmox VE**: Virtualization platform for hosting the entire infrastructure

### Key Features

- ✅ **Complete Network Isolation** from production LAN
- ✅ **Controlled Internet Exposure** through dedicated firewall
- ✅ **Secure-by-Default** configuration
- ✅ **Comprehensive Monitoring** and logging
- ✅ **Attack Simulation** and testing tools
- ✅ **Automated Deployment** scripts

## 🏗️ Architecture

```
Internet
    |
    | (WAN)
┌───▼────────────────────────────────────────┐
│              Proxmox VE Host               │
│                                            │
│  ┌─────────────┐    ┌─────────────────────┐│
│  │   vmbr0     │    │       vmbr1         ││
│  │ (LAN Bridge)│    │ (Honeypot Bridge)   ││
│  │192.168.1.0/24│   │  10.0.100.0/24     ││
│  └──────┬──────┘    └──────┬──────────────┘│
│         │                  │               │
│  ┌──────▼──────┐    ┌──────▼──────────────┐│
│  │Management   │    │    OPNsense VM      ││
│  │   Host      │    │  WAN: vmbr0        ││
│  │             │    │  LAN: vmbr1        ││
│  └─────────────┘    └──────┬──────────────┘│
│                             │               │
│                      ┌──────▼──────────────┐│
│                      │     T-Pot VM        ││
│                      │   10.0.100.10/24   ││
│                      │   (via vmbr1)       ││
│                      └─────────────────────┘│
└────────────────────────────────────────────┘
```

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/t-pot-honeypot-infrastructure.git
   cd t-pot-honeypot-infrastructure
   ```

2. **Review configuration**
   ```bash
   cp config/environment.conf.example config/environment.conf
   # Edit configuration file with your settings
   ```

3. **Run deployment script**
   ```bash
   chmod +x scripts/deploy-infrastructure.sh
   ./scripts/deploy-infrastructure.sh
   ```

4. **Access T-Pot dashboard**
   ```
   https://10.0.100.10:64297
   ```

## 📚 Documentation

- [📖 Complete Installation Guide](docs/installation-guide.md)
- [🔧 Network Configuration](docs/network-configuration.md)
- [🛡️ Security Hardening](docs/security-hardening.md)
- [🧪 Testing and Validation](docs/testing-guide.md)
- [🔍 Monitoring and Analysis](docs/monitoring-guide.md)
- [❗ Troubleshooting](docs/troubleshooting.md)

## 🛠️ Repository Structure

```
t-pot-honeypot-infrastructure/
├── README.md
├── docs/                           # Comprehensive documentation
│   ├── installation-guide.md
│   ├── network-configuration.md
│   ├── security-hardening.md
│   ├── testing-guide.md
│   ├── monitoring-guide.md
│   └── troubleshooting.md
├── config/                         # Configuration templates
│   ├── environment.conf.example
│   ├── opnsense/
│   │   ├── firewall-rules.xml
│   │   ├── nat-rules.xml
│   │   └── interfaces.conf
│   ├── proxmox/
│   │   ├── network-config.conf
│   │   └── vm-templates/
│   └── t-pot/
│       ├── custom-config.yml
│       └── docker-compose.override.yml
├── scripts/                        # Automation scripts
│   ├── deploy-infrastructure.sh
│   ├── setup/
│   │   ├── create-proxmox-network.sh
│   │   ├── deploy-opnsense.sh
│   │   └── install-tpot.sh
│   ├── testing/
│   │   ├── connectivity-test.sh
│   │   ├── attack-simulation.sh
│   │   └── monitoring-check.sh
│   ├── maintenance/
│   │   ├── backup-configs.sh
│   │   ├── update-systems.sh
│   │   └── health-check.sh
│   └── security/
│       ├── harden-opnsense.sh
│       ├── setup-vpn.sh
│       └── security-audit.sh
├── monitoring/                     # Monitoring configurations
│   ├── grafana-dashboards/
│   │   ├── honeypot-overview.json
│   │   ├── network-traffic.json
│   │   └── security-events.json
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── alert-rules.yml
│   └── elk-stack/
│       ├── logstash.conf
│       └── kibana-dashboards/
├── templates/                      # VM and container templates
│   ├── opnsense-vm.json
│   ├── tpot-vm.json
│   └── docker-compose.yml
└── tools/                         # Utility tools
    ├── network-scanner.py
    ├── log-analyzer.sh
    └── threat-intel-collector.py
```

## 📋 Prerequisites

### Hardware Requirements
- **Proxmox VE Host**: Minimum 16GB RAM, 4 CPU Cores, 500GB Storage
- **Internet Connection**: Public IP address for honeypot exposure

### Software Requirements
- Proxmox VE 8.0+
- OPNsense 23.7+
- T-Pot CE 23.04+

### Network Requirements
- Management network (e.g., 192.168.1.0/24)
- Isolated honeypot network (10.0.100.0/24)
- Public IP address for internet exposure

## 🔒 Security Considerations

⚠️ **Important Security Notes:**

1. **Legal Compliance**: Ensure honeypot operation is legal in your jurisdiction
2. **Network Isolation**: Never allow direct connections between honeypot and production networks
3. **Monitoring**: Continuously monitor all honeypot activities
4. **Updates**: Regularly update all components
5. **Incident Response**: Prepare for potential compromise scenarios

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [T-Pot Community](https://github.com/telekom-security/tpotce) for the excellent honeypot platform
- [OPNsense Project](https://opnsense.org/) for the robust firewall solution
- [Proxmox](https://www.proxmox.com/) for the virtualization platform

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/YOUR_USERNAME/t-pot-honeypot-infrastructure/issues)
- 💬 [Discussions](https://github.com/YOUR_USERNAME/t-pot-honeypot-infrastructure/discussions)

---

**Disclaimer**: This project is for educational and research purposes only. Users are responsible for all legal and security aspects of deployment.