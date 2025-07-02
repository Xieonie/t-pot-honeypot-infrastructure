#!/bin/bash

# T-Pot Infrastructure: System Update Script
# This script updates all components of the T-Pot infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/update-systems.log"

# Infrastructure endpoints
TPOT_IP="10.0.100.10"
OPNSENSE_IP="192.168.1.1"
PROXMOX_IP="192.168.1.10"

# Update settings
REBOOT_REQUIRED_FILE="/var/run/reboot-required"
UPDATE_TIMEOUT=3600  # 1 hour timeout for updates
BACKUP_BEFORE_UPDATE=true
SEND_NOTIFICATIONS=true

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

# Create backup before updates
create_backup() {
    if [[ "$BACKUP_BEFORE_UPDATE" == "true" ]]; then
        info "Creating backup before updates..."
        
        if [[ -f "$PROJECT_ROOT/scripts/maintenance/backup-configs.sh" ]]; then
            bash "$PROJECT_ROOT/scripts/maintenance/backup-configs.sh"
            success "Backup completed"
        else
            warn "Backup script not found, skipping backup"
        fi
    fi
}

# Update Proxmox VE host
update_proxmox() {
    info "Updating Proxmox VE host..."
    
    # Update package lists
    apt update
    
    # Check for available updates
    local updates_available=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
    info "Available updates: $updates_available"
    
    if [[ $updates_available -gt 0 ]]; then
        # Upgrade packages
        timeout $UPDATE_TIMEOUT apt upgrade -y
        
        # Update Proxmox VE packages
        timeout $UPDATE_TIMEOUT apt dist-upgrade -y
        
        # Clean up
        apt autoremove -y
        apt autoclean
        
        success "Proxmox VE host updated successfully"
        
        # Check if reboot is required
        if [[ -f "$REBOOT_REQUIRED_FILE" ]]; then
            warn "Reboot required for Proxmox VE host"
            echo "proxmox" >> /tmp/reboot-required-hosts.txt
        fi
    else
        success "Proxmox VE host is already up to date"
    fi
}

# Update T-Pot VM
update_tpot() {
    info "Updating T-Pot VM..."
    
    # Check if T-Pot is reachable
    if ! ping -c 3 "$TPOT_IP" > /dev/null 2>&1; then
        error "T-Pot VM is not reachable"
        return 1
    fi
    
    # Update T-Pot system
    ssh tpot@"$TPOT_IP" << 'EOF'
set -euo pipefail

echo "Updating T-Pot system packages..."
sudo apt update
sudo apt upgrade -y

echo "Updating T-Pot honeypot platform..."
cd /opt/tpot
sudo git fetch origin
sudo git pull origin main

echo "Updating Docker images..."
sudo docker-compose pull

echo "Restarting T-Pot services..."
sudo systemctl restart tpot

echo "Cleaning up old Docker images..."
sudo docker image prune -f

echo "T-Pot update completed"
EOF

    if [[ $? -eq 0 ]]; then
        success "T-Pot VM updated successfully"
        
        # Check if reboot is required
        if ssh tpot@"$TPOT_IP" "test -f /var/run/reboot-required" 2>/dev/null; then
            warn "Reboot required for T-Pot VM"
            echo "tpot" >> /tmp/reboot-required-hosts.txt
        fi
    else
        error "Failed to update T-Pot VM"
        return 1
    fi
}

# Update OPNsense firewall
update_opnsense() {
    info "Updating OPNsense firewall..."
    
    # Check if OPNsense is reachable
    if ! ping -c 3 "$OPNSENSE_IP" > /dev/null 2>&1; then
        error "OPNsense firewall is not reachable"
        return 1
    fi
    
    # Note: OPNsense updates typically require web interface or API access
    # This is a placeholder for manual update instructions
    
    cat << EOF
OPNsense Update Instructions:
============================
1. Access OPNsense web interface: https://$OPNSENSE_IP
2. Go to System > Firmware > Updates
3. Click "Check for updates"
4. If updates are available, click "Update"
5. Wait for update to complete and system to reboot

Alternatively, use the console:
1. Access OPNsense console
2. Select option 12) Update from console
3. Follow the prompts

API Update (if configured):
curl -k -u "api_key:api_secret" -X POST "https://$OPNSENSE_IP/api/core/firmware/update"
EOF

    warn "OPNsense requires manual update via web interface or console"
    echo "opnsense" >> /tmp/manual-update-required.txt
}

# Update Docker containers
update_docker_containers() {
    info "Updating Docker containers on T-Pot..."
    
    ssh tpot@"$TPOT_IP" << 'EOF'
set -euo pipefail

echo "Stopping T-Pot services..."
sudo systemctl stop tpot

echo "Pulling latest Docker images..."
cd /opt/tpot
sudo docker-compose pull

echo "Removing old containers..."
sudo docker-compose down --remove-orphans

echo "Starting updated containers..."
sudo docker-compose up -d

echo "Cleaning up unused images..."
sudo docker image prune -f

echo "Cleaning up unused volumes..."
sudo docker volume prune -f

echo "Docker containers updated successfully"
EOF

    if [[ $? -eq 0 ]]; then
        success "Docker containers updated successfully"
    else
        error "Failed to update Docker containers"
        return 1
    fi
}

# Update security signatures and rules
update_security_signatures() {
    info "Updating security signatures and rules..."
    
    ssh tpot@"$TPOT_IP" << 'EOF'
set -euo pipefail

echo "Updating Suricata rules..."
if command -v suricata-update &> /dev/null; then
    sudo suricata-update
    sudo systemctl reload suricata
else
    echo "Suricata-update not found, skipping rule updates"
fi

echo "Updating ClamAV signatures..."
if command -v freshclam &> /dev/null; then
    sudo freshclam
else
    echo "ClamAV not found, skipping signature updates"
fi

echo "Updating fail2ban filters..."
if systemctl is-active fail2ban &> /dev/null; then
    sudo systemctl reload fail2ban
fi

echo "Security signatures updated"
EOF

    success "Security signatures and rules updated"
}

# Update threat intelligence feeds
update_threat_intelligence() {
    info "Updating threat intelligence feeds..."
    
    ssh tpot@"$TPOT_IP" << 'EOF'
set -euo pipefail

# Update malicious IP lists
echo "Updating malicious IP lists..."
wget -q -O /tmp/feodo_ips.json "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
if [[ -f /tmp/feodo_ips.json ]]; then
    sudo mv /tmp/feodo_ips.json /opt/tpot/data/threat-intel/
fi

# Update malware hashes
echo "Updating malware hash database..."
wget -q -O /tmp/malware_hashes.txt "https://bazaar.abuse.ch/export/txt/sha256/recent/"
if [[ -f /tmp/malware_hashes.txt ]]; then
    sudo mv /tmp/malware_hashes.txt /opt/tpot/data/threat-intel/
fi

# Update domain blocklists
echo "Updating domain blocklists..."
wget -q -O /tmp/malicious_domains.txt "https://urlhaus.abuse.ch/downloads/text/"
if [[ -f /tmp/malicious_domains.txt ]]; then
    sudo mv /tmp/malicious_domains.txt /opt/tpot/data/threat-intel/
fi

echo "Threat intelligence feeds updated"
EOF

    success "Threat intelligence feeds updated"
}

# Verify system health after updates
verify_system_health() {
    info "Verifying system health after updates..."
    
    # Check Proxmox VE services
    local pve_services=("pvedaemon" "pveproxy" "pvestatd" "pve-cluster")
    for service in "${pve_services[@]}"; do
        if systemctl is-active "$service" > /dev/null 2>&1; then
            success "✅ $service is running"
        else
            error "❌ $service is not running"
        fi
    done
    
    # Check T-Pot services
    if ssh tpot@"$TPOT_IP" "systemctl is-active tpot" > /dev/null 2>&1; then
        success "✅ T-Pot service is running"
    else
        error "❌ T-Pot service is not running"
    fi
    
    # Check Docker containers
    local container_count=$(ssh tpot@"$TPOT_IP" "docker ps -q | wc -l" 2>/dev/null || echo "0")
    if [[ $container_count -gt 0 ]]; then
        success "✅ $container_count Docker containers are running"
    else
        warn "⚠️  No Docker containers are running"
    fi
    
    # Check honeypot services
    local honeypot_ports=("22" "23" "80" "443")
    for port in "${honeypot_ports[@]}"; do
        if timeout 5 nc -z "$TPOT_IP" "$port" 2>/dev/null; then
            success "✅ Port $port is accessible"
        else
            warn "⚠️  Port $port is not accessible"
        fi
    done
}

# Handle system reboots
handle_reboots() {
    if [[ -f /tmp/reboot-required-hosts.txt ]]; then
        info "The following systems require a reboot:"
        cat /tmp/reboot-required-hosts.txt
        
        read -p "Do you want to reboot systems now? (y/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            while read -r host; do
                case "$host" in
                    "proxmox")
                        warn "Rebooting Proxmox VE host in 60 seconds..."
                        shutdown -r +1 "System reboot for updates"
                        ;;
                    "tpot")
                        warn "Rebooting T-Pot VM..."
                        ssh tpot@"$TPOT_IP" "sudo reboot"
                        ;;
                    "opnsense")
                        warn "Please reboot OPNsense manually via web interface"
                        ;;
                esac
            done < /tmp/reboot-required-hosts.txt
        else
            warn "Systems require reboot but will not be rebooted automatically"
        fi
        
        rm -f /tmp/reboot-required-hosts.txt
    fi
}

# Send update notifications
send_notifications() {
    if [[ "$SEND_NOTIFICATIONS" == "true" ]]; then
        info "Sending update notifications..."
        
        local subject="T-Pot Infrastructure Update Report"
        local report_file="/tmp/update-report-$(date +%Y%m%d-%H%M%S).txt"
        
        # Generate update report
        cat > "$report_file" << EOF
T-Pot Infrastructure Update Report
==================================
Date: $(date)
Update Duration: $((SECONDS / 60)) minutes

Components Updated:
✓ Proxmox VE Host
✓ T-Pot VM
✓ Docker Containers
✓ Security Signatures
✓ Threat Intelligence Feeds

Manual Updates Required:
$(cat /tmp/manual-update-required.txt 2>/dev/null || echo "None")

System Health Check:
$(tail -20 "$LOG_FILE" | grep -E "(✅|❌|⚠️)" || echo "See log file for details")

Reboot Required:
$(cat /tmp/reboot-required-hosts.txt 2>/dev/null || echo "None")

Log File: $LOG_FILE
EOF

        # Send email notification
        if command -v mail &> /dev/null; then
            mail -s "$subject" root < "$report_file" 2>/dev/null || warn "Failed to send email notification"
        fi
        
        # Log to syslog
        logger -t "tpot-update" "Infrastructure update completed"
        
        success "Update notifications sent"
    fi
}

# Cleanup temporary files
cleanup() {
    info "Cleaning up temporary files..."
    rm -f /tmp/reboot-required-hosts.txt
    rm -f /tmp/manual-update-required.txt
    rm -f /tmp/update-report-*.txt
}

# Main update function
main() {
    local start_time=$SECONDS
    
    info "Starting T-Pot infrastructure update process"
    
    check_root
    create_backup
    
    # Update all components
    update_proxmox
    update_tpot
    update_opnsense
    update_docker_containers
    update_security_signatures
    update_threat_intelligence
    
    # Verify and finalize
    verify_system_health
    handle_reboots
    send_notifications
    cleanup
    
    local duration=$((SECONDS - start_time))
    success "T-Pot infrastructure update completed in $((duration / 60)) minutes"
    
    info "Update summary:"
    info "- Check log file: $LOG_FILE"
    info "- Verify system functionality"
    info "- Review any manual update requirements"
    info "- Schedule next update cycle"
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"