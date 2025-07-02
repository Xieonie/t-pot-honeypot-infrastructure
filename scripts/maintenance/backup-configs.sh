#!/bin/bash

# T-Pot Infrastructure: Configuration Backup Script
# This script creates backups of all critical configuration files

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BACKUP_DIR="/backup/tpot-configs"
LOG_FILE="/var/log/backup-configs.log"

# Infrastructure endpoints
TPOT_IP="10.0.100.10"
OPNSENSE_IP="192.168.1.1"
PROXMOX_IP="192.168.1.10"

# Backup settings
BACKUP_RETENTION_DAYS=30
COMPRESS_BACKUPS=true
REMOTE_BACKUP_ENABLED=false
REMOTE_BACKUP_HOST=""
REMOTE_BACKUP_PATH=""

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

# Create backup directory structure
create_backup_structure() {
    info "Creating backup directory structure..."
    
    local timestamp=$(date '+%Y%m%d-%H%M%S')
    local backup_path="$BACKUP_DIR/$timestamp"
    
    mkdir -p "$backup_path"/{tpot,opnsense,proxmox,project}
    
    echo "$backup_path"
}

# Backup T-Pot configurations
backup_tpot_configs() {
    local backup_path="$1"
    info "Backing up T-Pot configurations..."
    
    # T-Pot configuration files
    local tpot_configs=(
        "/opt/tpot/etc"
        "/opt/tpot/docker-compose.yml"
        "/data/tpot/config"
        "/etc/systemd/system/tpot.service"
        "/etc/cron.d/tpot"
    )
    
    for config in "${tpot_configs[@]}"; do
        if ssh tpot@"$TPOT_IP" "test -e $config" 2>/dev/null; then
            info "Backing up $config..."
            scp -r tpot@"$TPOT_IP":"$config" "$backup_path/tpot/" 2>/dev/null || warn "Failed to backup $config"
        else
            warn "Configuration not found: $config"
        fi
    done
    
    # System configurations
    local system_configs=(
        "/etc/network/interfaces"
        "/etc/ufw/user.rules"
        "/etc/fail2ban/jail.local"
        "/etc/logrotate.d/tpot"
        "/etc/rsyslog.d/tpot.conf"
    )
    
    for config in "${system_configs[@]}"; do
        if ssh tpot@"$TPOT_IP" "test -f $config" 2>/dev/null; then
            info "Backing up system config: $config..."
            scp tpot@"$TPOT_IP":"$config" "$backup_path/tpot/" 2>/dev/null || warn "Failed to backup $config"
        fi
    done
    
    # Docker configurations
    ssh tpot@"$TPOT_IP" "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'" > "$backup_path/tpot/docker-containers.txt" 2>/dev/null || warn "Failed to export docker container list"
    ssh tpot@"$TPOT_IP" "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}'" > "$backup_path/tpot/docker-images.txt" 2>/dev/null || warn "Failed to export docker images list"
    
    success "T-Pot configuration backup completed"
}

# Backup OPNsense configurations
backup_opnsense_configs() {
    local backup_path="$1"
    info "Backing up OPNsense configurations..."
    
    # Create OPNsense backup via API (if configured)
    if command -v curl &> /dev/null; then
        # Note: This requires API access to be configured
        # curl -k -u "api_key:api_secret" "https://$OPNSENSE_IP/api/core/backup/download/this" -o "$backup_path/opnsense/config-backup.xml" 2>/dev/null || warn "Failed to download OPNsense config via API"
        warn "OPNsense API backup not configured - manual backup required"
    fi
    
    # Copy local configuration templates
    if [[ -d "$PROJECT_ROOT/config/opnsense" ]]; then
        cp -r "$PROJECT_ROOT/config/opnsense"/* "$backup_path/opnsense/" 2>/dev/null || warn "Failed to copy OPNsense templates"
        success "OPNsense configuration templates backed up"
    fi
    
    # Create configuration documentation
    cat > "$backup_path/opnsense/backup-info.txt" << EOF
OPNsense Configuration Backup
=============================
Date: $(date)
OPNsense IP: $OPNSENSE_IP

Manual Backup Steps:
1. Access OPNsense web interface: https://$OPNSENSE_IP
2. Go to System > Configuration > Backups
3. Download configuration backup
4. Save as: config-backup-$(date +%Y%m%d).xml

Configuration Files Included:
- firewall-rules.xml (template)
- nat-rules.xml (template)
- interfaces.conf (template)

Note: For complete backup, download actual configuration from OPNsense web interface
EOF
    
    success "OPNsense configuration backup completed"
}

# Backup Proxmox configurations
backup_proxmox_configs() {
    local backup_path="$1"
    info "Backing up Proxmox configurations..."
    
    # Proxmox configuration files
    local proxmox_configs=(
        "/etc/network/interfaces"
        "/etc/pve/storage.cfg"
        "/etc/pve/datacenter.cfg"
        "/etc/pve/corosync.conf"
        "/etc/pve/user.cfg"
        "/etc/pve/domains.cfg"
    )
    
    for config in "${proxmox_configs[@]}"; do
        if [[ -f "$config" ]]; then
            info "Backing up Proxmox config: $config..."
            cp "$config" "$backup_path/proxmox/" 2>/dev/null || warn "Failed to backup $config"
        fi
    done
    
    # VM configurations
    if [[ -d "/etc/pve/qemu-server" ]]; then
        cp -r /etc/pve/qemu-server "$backup_path/proxmox/" 2>/dev/null || warn "Failed to backup VM configurations"
    fi
    
    # Container configurations
    if [[ -d "/etc/pve/lxc" ]]; then
        cp -r /etc/pve/lxc "$backup_path/proxmox/" 2>/dev/null || warn "Failed to backup container configurations"
    fi
    
    # Export VM/CT list
    qm list > "$backup_path/proxmox/vm-list.txt" 2>/dev/null || warn "Failed to export VM list"
    pct list > "$backup_path/proxmox/container-list.txt" 2>/dev/null || warn "Failed to export container list"
    
    # Storage information
    pvesm status > "$backup_path/proxmox/storage-status.txt" 2>/dev/null || warn "Failed to export storage status"
    
    # Copy local configuration templates
    if [[ -d "$PROJECT_ROOT/config/proxmox" ]]; then
        cp -r "$PROJECT_ROOT/config/proxmox"/* "$backup_path/proxmox/" 2>/dev/null || warn "Failed to copy Proxmox templates"
    fi
    
    success "Proxmox configuration backup completed"
}

# Backup project configurations
backup_project_configs() {
    local backup_path="$1"
    info "Backing up project configurations..."
    
    # Copy entire project configuration
    if [[ -d "$PROJECT_ROOT/config" ]]; then
        cp -r "$PROJECT_ROOT/config" "$backup_path/project/" 2>/dev/null || warn "Failed to copy project config"
    fi
    
    # Copy scripts
    if [[ -d "$PROJECT_ROOT/scripts" ]]; then
        cp -r "$PROJECT_ROOT/scripts" "$backup_path/project/" 2>/dev/null || warn "Failed to copy project scripts"
    fi
    
    # Copy documentation
    if [[ -d "$PROJECT_ROOT/docs" ]]; then
        cp -r "$PROJECT_ROOT/docs" "$backup_path/project/" 2>/dev/null || warn "Failed to copy project docs"
    fi
    
    # Copy monitoring configurations
    if [[ -d "$PROJECT_ROOT/monitoring" ]]; then
        cp -r "$PROJECT_ROOT/monitoring" "$backup_path/project/" 2>/dev/null || warn "Failed to copy monitoring configs"
    fi
    
    # Copy templates
    if [[ -d "$PROJECT_ROOT/templates" ]]; then
        cp -r "$PROJECT_ROOT/templates" "$backup_path/project/" 2>/dev/null || warn "Failed to copy templates"
    fi
    
    # Create project information file
    cat > "$backup_path/project/project-info.txt" << EOF
T-Pot Infrastructure Project Backup
===================================
Date: $(date)
Project Root: $PROJECT_ROOT
Backup Path: $backup_path

Git Information:
$(cd "$PROJECT_ROOT" && git log --oneline -5 2>/dev/null || echo "Not a git repository")

Directory Structure:
$(find "$PROJECT_ROOT" -type d -name ".git" -prune -o -type d -print | head -20)

File Count by Type:
Shell scripts: $(find "$PROJECT_ROOT" -name "*.sh" | wc -l)
Configuration files: $(find "$PROJECT_ROOT" -name "*.conf" -o -name "*.cfg" -o -name "*.yml" -o -name "*.yaml" | wc -l)
Documentation: $(find "$PROJECT_ROOT" -name "*.md" | wc -l)
EOF
    
    success "Project configuration backup completed"
}

# Compress backup if enabled
compress_backup() {
    local backup_path="$1"
    
    if [[ "$COMPRESS_BACKUPS" == "true" ]]; then
        info "Compressing backup..."
        
        local backup_dir=$(dirname "$backup_path")
        local backup_name=$(basename "$backup_path")
        local compressed_file="$backup_dir/$backup_name.tar.gz"
        
        tar -czf "$compressed_file" -C "$backup_dir" "$backup_name"
        
        if [[ $? -eq 0 ]]; then
            rm -rf "$backup_path"
            success "Backup compressed: $compressed_file"
            echo "$compressed_file"
        else
            error "Failed to compress backup"
            echo "$backup_path"
        fi
    else
        echo "$backup_path"
    fi
}

# Upload to remote backup location
upload_remote_backup() {
    local backup_file="$1"
    
    if [[ "$REMOTE_BACKUP_ENABLED" == "true" && -n "$REMOTE_BACKUP_HOST" ]]; then
        info "Uploading backup to remote location..."
        
        rsync -avz "$backup_file" "$REMOTE_BACKUP_HOST:$REMOTE_BACKUP_PATH/" 2>/dev/null
        
        if [[ $? -eq 0 ]]; then
            success "Backup uploaded to remote location"
        else
            error "Failed to upload backup to remote location"
        fi
    fi
}

# Clean old backups
cleanup_old_backups() {
    info "Cleaning up old backups..."
    
    # Remove backups older than retention period
    find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$BACKUP_RETENTION_DAYS -delete 2>/dev/null || warn "Failed to clean some old compressed backups"
    find "$BACKUP_DIR" -type d -mtime +$BACKUP_RETENTION_DAYS -exec rm -rf {} + 2>/dev/null || warn "Failed to clean some old backup directories"
    
    # Count remaining backups
    local backup_count=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name "*.tar.gz" | wc -l)
    local dir_count=$(find "$BACKUP_DIR" -maxdepth 1 -type d ! -path "$BACKUP_DIR" | wc -l)
    
    success "Cleanup completed. Remaining backups: $backup_count compressed, $dir_count directories"
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"
    info "Verifying backup integrity..."
    
    if [[ "$backup_file" == *.tar.gz ]]; then
        if tar -tzf "$backup_file" > /dev/null 2>&1; then
            success "Backup archive is valid"
        else
            error "Backup archive is corrupted"
            return 1
        fi
    else
        if [[ -d "$backup_file" ]]; then
            success "Backup directory is accessible"
        else
            error "Backup directory is not accessible"
            return 1
        fi
    fi
    
    return 0
}

# Generate backup report
generate_backup_report() {
    local backup_file="$1"
    local report_file="/tmp/backup-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
T-Pot Infrastructure Configuration Backup Report
===============================================
Date: $(date)
Backup Location: $backup_file
Backup Size: $(du -sh "$backup_file" 2>/dev/null | cut -f1 || echo "Unknown")

Components Backed Up:
✓ T-Pot configurations
✓ OPNsense configurations (templates)
✓ Proxmox configurations
✓ Project configurations

Backup Settings:
- Retention: $BACKUP_RETENTION_DAYS days
- Compression: $COMPRESS_BACKUPS
- Remote backup: $REMOTE_BACKUP_ENABLED

Verification:
$(verify_backup "$backup_file" && echo "✓ Backup integrity verified" || echo "✗ Backup integrity check failed")

Restoration Instructions:
1. Extract backup: tar -xzf $(basename "$backup_file")
2. Review configurations before applying
3. Apply configurations manually to each system
4. Test functionality after restoration

Next Backup: $(date -d "+1 day" '+%Y-%m-%d %H:%M:%S')

Log File: $LOG_FILE
EOF

    success "Backup report generated: $report_file"
}

# Send notification
send_notification() {
    local backup_file="$1"
    local status="$2"
    
    if command -v mail &> /dev/null; then
        local subject="T-Pot Configuration Backup - $status"
        local message="Configuration backup completed: $backup_file"
        
        echo "$message" | mail -s "$subject" root 2>/dev/null || warn "Failed to send email notification"
    fi
    
    # Log to syslog
    logger -t "tpot-backup" "Configuration backup $status: $backup_file"
}

# Main backup function
main() {
    info "Starting T-Pot infrastructure configuration backup"
    
    # Check prerequisites
    if ! command -v ssh &> /dev/null; then
        error "SSH client not found"
        exit 1
    fi
    
    if ! command -v scp &> /dev/null; then
        error "SCP client not found"
        exit 1
    fi
    
    # Create backup structure
    local backup_path
    backup_path=$(create_backup_structure)
    
    # Perform backups
    backup_tpot_configs "$backup_path"
    backup_opnsense_configs "$backup_path"
    backup_proxmox_configs "$backup_path"
    backup_project_configs "$backup_path"
    
    # Compress backup
    local final_backup
    final_backup=$(compress_backup "$backup_path")
    
    # Verify backup
    if verify_backup "$final_backup"; then
        success "Backup verification passed"
        
        # Upload to remote location
        upload_remote_backup "$final_backup"
        
        # Generate report
        generate_backup_report "$final_backup"
        
        # Send notification
        send_notification "$final_backup" "SUCCESS"
        
        # Cleanup old backups
        cleanup_old_backups
        
        success "Configuration backup completed successfully: $final_backup"
    else
        error "Backup verification failed"
        send_notification "$final_backup" "FAILED"
        exit 1
    fi
}

# Run main function
main "$@"