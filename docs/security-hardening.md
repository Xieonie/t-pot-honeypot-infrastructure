# Security Hardening Guide 🔒

This guide provides comprehensive security hardening procedures for all components of the T-Pot honeypot infrastructure.

## 📋 Overview

Security hardening is critical for honeypot infrastructure to prevent compromise of the host systems while maintaining the honeypot's attractiveness to attackers.

## 🖥️ Proxmox VE Hardening

### System Updates
```bash
# Update system packages
apt update && apt upgrade -y

# Enable automatic security updates
apt install unattended-upgrades
dpkg-reconfigure unattended-upgrades
```

### SSH Hardening
```bash
# /etc/ssh/sshd_config
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin
```

### Firewall Configuration
```bash
# Enable UFW firewall
ufw enable
ufw default deny incoming
ufw default allow outgoing

# Allow management access
ufw allow from 192.168.1.0/24 to any port 22
ufw allow from 192.168.1.0/24 to any port 8006  # Proxmox web interface
```

### File System Security
```bash
# Mount options in /etc/fstab
/dev/mapper/pve-root / ext4 defaults,nodev,nosuid 0 1
/tmp /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
/var/tmp /var/tmp tmpfs defaults,nodev,nosuid,noexec 0 0
```

### Kernel Hardening
```bash
# /etc/sysctl.d/99-security.conf
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
```

## 🛡️ OPNsense Hardening

### Initial Setup
```bash
# Change default passwords
passwd root
passwd admin

# Disable unused services
service dhcpd stop
service dhcpd disable
```

### Web Interface Security
```bash
# Enable HTTPS only
# System → Settings → Administration
- Protocol: HTTPS
- SSL Certificate: Generate new certificate
- Session Timeout: 240 minutes
- Anti-lockout: Enabled
```

### Firewall Rules Hardening
```bash
# Default deny all
# Create explicit allow rules only for required traffic
# Enable logging for all rules
# Implement rate limiting for honeypot services
```

### System Hardening
```bash
# /etc/sysctl.conf
net.inet.ip.forwarding=1
net.inet.ip.fastforwarding=0
net.inet.ip.redirect=0
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
net.inet.icmp.drop_redirect=1
net.inet.icmp.log_redirect=1
```

## 🍯 T-Pot VM Hardening

### Base System Security
```bash
# Update T-Pot system
sudo apt update && sudo apt upgrade -y

# Configure automatic updates
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
```

### Docker Security
```bash
# /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
```

### Container Isolation
```bash
# Run containers with security options
docker run --security-opt=no-new-privileges:true \
           --security-opt=apparmor:docker-default \
           --read-only \
           --tmpfs /tmp \
           honeypot-image
```

### Resource Limits
```bash
# /etc/systemd/system/tpot.service
[Service]
MemoryLimit=4G
CPUQuota=200%
TasksMax=1000
```

## 🔐 Access Control

### Multi-Factor Authentication
```bash
# Install Google Authenticator
apt install libpam-google-authenticator

# Configure PAM
echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd

# Enable in SSH config
echo "ChallengeResponseAuthentication yes" >> /etc/ssh/sshd_config
```

### Certificate-Based Authentication
```bash
# Generate CA certificate
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Generate client certificates
openssl genrsa -out client-key.pem 4096
openssl req -subj '/CN=admin' -new -key client-key.pem -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca-key.pem -out client-cert.pem
```

### Role-Based Access Control
```bash
# Create user groups
groupadd honeypot-admin
groupadd honeypot-analyst
groupadd honeypot-readonly

# Assign users to groups
usermod -a -G honeypot-admin admin
usermod -a -G honeypot-analyst analyst
usermod -a -G honeypot-readonly observer
```

## 📊 Monitoring and Logging

### Centralized Logging
```bash
# Configure rsyslog for centralized logging
echo "*.* @@192.168.1.50:514" >> /etc/rsyslog.conf

# Configure log rotation
cat > /etc/logrotate.d/honeypot << EOF
/var/log/honeypot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF
```

### File Integrity Monitoring
```bash
# Install and configure AIDE
apt install aide
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily checks
echo "0 2 * * * root /usr/bin/aide --check" >> /etc/crontab
```

### Security Monitoring
```bash
# Install fail2ban
apt install fail2ban

# Configure jail for SSH
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
```

## 🚨 Incident Response

### Automated Response
```bash
#!/bin/bash
# /usr/local/bin/incident-response.sh

# Isolate compromised system
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

# Preserve evidence
dd if=/dev/sda of=/mnt/evidence/disk-image.dd bs=4M
tar -czf /mnt/evidence/logs-$(date +%Y%m%d).tar.gz /var/log/

# Send alert
echo "SECURITY INCIDENT: System compromised at $(date)" | \
    mail -s "URGENT: Security Incident" admin@company.com
```

### Recovery Procedures
```bash
# Automated backup restoration
#!/bin/bash
# /usr/local/bin/restore-system.sh

# Stop all services
systemctl stop tpot
docker stop $(docker ps -q)

# Restore from clean backup
rsync -av /backup/clean-state/ /opt/tpot/

# Restart services
systemctl start tpot
```

## 🔍 Security Auditing

### Regular Security Scans
```bash
#!/bin/bash
# /usr/local/bin/security-audit.sh

# System vulnerability scan
lynis audit system

# Network port scan
nmap -sS -O localhost

# Docker security scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy image $(docker images --format "{{.Repository}}:{{.Tag}}")

# Generate report
echo "Security audit completed at $(date)" > /var/log/security-audit.log
```

### Compliance Checks
```bash
# CIS Benchmark compliance
apt install cis-cat-lite
/opt/cis-cat-lite/cis-cat-lite.sh -b /opt/cis-cat-lite/benchmarks/
```

## 📋 Security Checklist

### Daily Tasks
- [ ] Review security logs
- [ ] Check system resource usage
- [ ] Verify backup integrity
- [ ] Monitor network traffic

### Weekly Tasks
- [ ] Update system packages
- [ ] Review firewall rules
- [ ] Analyze attack patterns
- [ ] Test incident response procedures

### Monthly Tasks
- [ ] Security vulnerability assessment
- [ ] Certificate renewal check
- [ ] Access control review
- [ ] Disaster recovery testing

## 🛠️ Security Tools

### Essential Security Tools
```bash
# Install security toolkit
apt install -y \
    nmap \
    wireshark \
    tcpdump \
    netstat-nat \
    iptraf-ng \
    htop \
    iotop \
    lsof \
    strace
```

### Monitoring Tools
```bash
# Install monitoring stack
docker run -d --name prometheus prom/prometheus
docker run -d --name grafana grafana/grafana
docker run -d --name alertmanager prom/alertmanager
```

## 📚 Additional Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [OWASP Security Guidelines](https://owasp.org/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Linux Security Hardening](https://www.cisecurity.org/cis-benchmarks/)