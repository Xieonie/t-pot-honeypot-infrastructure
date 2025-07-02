#!/bin/bash

# T-Pot Infrastructure: Security Audit Script
# This script performs comprehensive security audits on all infrastructure components

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/security-audit.log"

# Infrastructure endpoints
TPOT_IP="10.0.100.10"
OPNSENSE_IP="192.168.1.1"
PROXMOX_IP="192.168.1.10"

# Audit settings
AUDIT_DEPTH="comprehensive"  # Options: basic, standard, comprehensive
GENERATE_REPORT=true
SEND_ALERTS=true
REMEDIATION_MODE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Security finding counters
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0
INFO_FINDINGS=0

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
    ((INFO_FINDINGS++))
}

low() {
    log "LOW" "${GREEN}$*${NC}"
    ((LOW_FINDINGS++))
}

medium() {
    log "MEDIUM" "${YELLOW}$*${NC}"
    ((MEDIUM_FINDINGS++))
}

high() {
    log "HIGH" "${PURPLE}$*${NC}"
    ((HIGH_FINDINGS++))
}

critical() {
    log "CRITICAL" "${RED}$*${NC}"
    ((CRITICAL_FINDINGS++))
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        critical "This script must be run as root for complete audit"
        exit 1
    fi
}

# Install audit tools if needed
install_audit_tools() {
    info "Installing security audit tools..."
    
    local tools=("nmap" "lynis" "chkrootkit" "rkhunter" "aide" "fail2ban" "ufw")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        info "Installing missing tools: ${missing_tools[*]}"
        apt update
        apt install -y "${missing_tools[@]}"
    fi
    
    info "Audit tools ready"
}

# Audit network security
audit_network_security() {
    info "Auditing network security..."
    
    # Port scan of infrastructure
    info "Performing port scans..."
    
    # Scan T-Pot honeypot
    local tpot_open_ports=$(nmap -sS -O "$TPOT_IP" 2>/dev/null | grep "^[0-9]" | grep "open" | wc -l)
    if [[ $tpot_open_ports -gt 15 ]]; then
        medium "T-Pot has $tpot_open_ports open ports (expected for honeypot)"
    else
        low "T-Pot port configuration appears normal ($tpot_open_ports open ports)"
    fi
    
    # Scan OPNsense firewall
    local opnsense_open_ports=$(nmap -sS "$OPNSENSE_IP" 2>/dev/null | grep "^[0-9]" | grep "open" | wc -l)
    if [[ $opnsense_open_ports -gt 3 ]]; then
        high "OPNsense has $opnsense_open_ports open ports (should be minimal)"
    else
        low "OPNsense port configuration is secure ($opnsense_open_ports open ports)"
    fi
    
    # Scan Proxmox host
    local proxmox_open_ports=$(nmap -sS "$PROXMOX_IP" 2>/dev/null | grep "^[0-9]" | grep "open" | wc -l)
    if [[ $proxmox_open_ports -gt 5 ]]; then
        medium "Proxmox has $proxmox_open_ports open ports (review if all are necessary)"
    else
        low "Proxmox port configuration appears secure ($proxmox_open_ports open ports)"
    fi
    
    # Check for common vulnerable services
    info "Checking for vulnerable services..."
    
    local vulnerable_services=("telnet:23" "ftp:21" "rsh:514" "rlogin:513")
    for service in "${vulnerable_services[@]}"; do
        local service_name=$(echo "$service" | cut -d: -f1)
        local port=$(echo "$service" | cut -d: -f2)
        
        if nmap -p "$port" "$PROXMOX_IP" 2>/dev/null | grep -q "open"; then
            high "Vulnerable service $service_name detected on Proxmox host"
        fi
    done
    
    # Check network segmentation
    info "Testing network segmentation..."
    
    # Test if honeypot can reach management network
    if ssh -o ConnectTimeout=5 tpot@"$TPOT_IP" "ping -c 1 $PROXMOX_IP" &>/dev/null; then
        critical "Network segmentation failure: Honeypot can reach management network"
    else
        low "Network segmentation is working correctly"
    fi
}

# Audit system hardening
audit_system_hardening() {
    info "Auditing system hardening..."
    
    # Check SSH configuration
    info "Auditing SSH configuration..."
    
    local ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        # Check for root login
        if grep -q "^PermitRootLogin yes" "$ssh_config"; then
            high "SSH root login is enabled"
        else
            low "SSH root login is properly disabled"
        fi
        
        # Check for password authentication
        if grep -q "^PasswordAuthentication yes" "$ssh_config"; then
            medium "SSH password authentication is enabled (consider key-only auth)"
        else
            low "SSH password authentication is disabled"
        fi
        
        # Check SSH protocol version
        if grep -q "^Protocol 1" "$ssh_config"; then
            critical "SSH protocol version 1 is enabled (use version 2 only)"
        else
            low "SSH protocol configuration is secure"
        fi
        
        # Check for empty passwords
        if grep -q "^PermitEmptyPasswords yes" "$ssh_config"; then
            critical "SSH allows empty passwords"
        else
            low "SSH empty passwords are disabled"
        fi
    else
        medium "SSH configuration file not found"
    fi
    
    # Check firewall status
    info "Auditing firewall configuration..."
    
    if command -v ufw &> /dev/null; then
        local ufw_status=$(ufw status | grep "Status:" | awk '{print $2}')
        if [[ "$ufw_status" == "active" ]]; then
            low "UFW firewall is active"
        else
            high "UFW firewall is not active"
        fi
    else
        medium "UFW firewall is not installed"
    fi
    
    # Check for fail2ban
    if systemctl is-active fail2ban &> /dev/null; then
        low "Fail2ban is active and protecting against brute force attacks"
    else
        medium "Fail2ban is not active (recommended for SSH protection)"
    fi
    
    # Check file permissions
    info "Auditing critical file permissions..."
    
    local critical_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow")
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            local perms=$(stat -c "%a" "$file")
            case "$file" in
                "/etc/passwd")
                    if [[ "$perms" != "644" ]]; then
                        medium "$file has incorrect permissions ($perms, should be 644)"
                    fi
                    ;;
                "/etc/shadow"|"/etc/gshadow")
                    if [[ "$perms" != "640" ]] && [[ "$perms" != "600" ]]; then
                        high "$file has incorrect permissions ($perms, should be 640 or 600)"
                    fi
                    ;;
                "/etc/group")
                    if [[ "$perms" != "644" ]]; then
                        medium "$file has incorrect permissions ($perms, should be 644)"
                    fi
                    ;;
            esac
        fi
    done
    
    # Check for SUID/SGID files
    info "Checking for suspicious SUID/SGID files..."
    
    local suid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [[ $suid_files -gt 50 ]]; then
        medium "Large number of SUID/SGID files found ($suid_files) - review manually"
    else
        low "SUID/SGID file count is reasonable ($suid_files)"
    fi
    
    # Check for world-writable files
    local world_writable=$(find / -type f -perm -002 2>/dev/null | grep -v "/proc\|/sys\|/dev" | wc -l)
    if [[ $world_writable -gt 0 ]]; then
        medium "$world_writable world-writable files found (potential security risk)"
    else
        low "No suspicious world-writable files found"
    fi
}

# Audit T-Pot specific security
audit_tpot_security() {
    info "Auditing T-Pot specific security..."
    
    if ! ping -c 3 "$TPOT_IP" > /dev/null 2>&1; then
        critical "T-Pot VM is not reachable for security audit"
        return 1
    fi
    
    # Check T-Pot service status
    if ssh -o ConnectTimeout=10 tpot@"$TPOT_IP" "systemctl is-active tpot" > /dev/null 2>&1; then
        low "T-Pot service is running"
    else
        high "T-Pot service is not running"
    fi
    
    # Check Docker security
    info "Auditing Docker security on T-Pot..."
    
    # Check if Docker daemon is running as root
    if ssh tpot@"$TPOT_IP" "ps aux | grep -v grep | grep 'dockerd.*root'" > /dev/null 2>&1; then
        medium "Docker daemon is running as root (consider rootless mode)"
    fi
    
    # Check for privileged containers
    local privileged_containers=$(ssh tpot@"$TPOT_IP" "docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -c privileged" 2>/dev/null || echo "0")
    if [[ $privileged_containers -gt 0 ]]; then
        high "$privileged_containers privileged Docker containers found"
    else
        low "No privileged Docker containers found"
    fi
    
    # Check container resource limits
    local unlimited_containers=$(ssh tpot@"$TPOT_IP" "docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' | grep -c 'N/A'" 2>/dev/null || echo "0")
    if [[ $unlimited_containers -gt 0 ]]; then
        medium "$unlimited_containers containers without resource limits"
    else
        low "All containers have resource limits configured"
    fi
    
    # Check for exposed Docker socket
    if ssh tpot@"$TPOT_IP" "netstat -ln | grep ':2375\|:2376'" > /dev/null 2>&1; then
        critical "Docker socket is exposed to network (major security risk)"
    else
        low "Docker socket is not exposed to network"
    fi
    
    # Check honeypot data permissions
    local data_perms=$(ssh tpot@"$TPOT_IP" "stat -c '%a' /data 2>/dev/null" || echo "000")
    if [[ "$data_perms" == "777" ]]; then
        medium "T-Pot data directory has overly permissive permissions"
    else
        low "T-Pot data directory permissions are appropriate"
    fi
    
    # Check for default passwords
    info "Checking for default passwords..."
    
    # This is a basic check - in practice, you'd check against known default credentials
    if ssh tpot@"$TPOT_IP" "grep -q 'admin:admin\|root:root\|admin:password' /etc/passwd /etc/shadow" 2>/dev/null; then
        critical "Default credentials detected"
    else
        low "No obvious default credentials found"
    fi
}

# Audit log security
audit_log_security() {
    info "Auditing log security and integrity..."
    
    # Check log file permissions
    local log_dirs=("/var/log" "/data/tpot/logs")
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            local world_readable_logs=$(find "$log_dir" -type f -perm -004 2>/dev/null | wc -l)
            if [[ $world_readable_logs -gt 0 ]]; then
                medium "$world_readable_logs world-readable log files in $log_dir"
            else
                low "Log file permissions in $log_dir are secure"
            fi
        fi
    done
    
    # Check for log rotation
    if [[ -f "/etc/logrotate.conf" ]]; then
        low "Log rotation is configured"
    else
        medium "Log rotation is not configured"
    fi
    
    # Check log retention
    local old_logs=$(find /var/log -name "*.log" -mtime +30 2>/dev/null | wc -l)
    if [[ $old_logs -gt 100 ]]; then
        medium "Many old log files found ($old_logs) - consider cleanup"
    else
        low "Log retention appears reasonable"
    fi
    
    # Check for centralized logging
    if ssh tpot@"$TPOT_IP" "grep -q 'remote.*syslog' /etc/rsyslog.conf" 2>/dev/null; then
        low "Centralized logging is configured"
    else
        medium "Centralized logging is not configured"
    fi
    
    # Check log integrity (if AIDE is configured)
    if command -v aide &> /dev/null; then
        if [[ -f "/var/lib/aide/aide.db" ]]; then
            low "File integrity monitoring (AIDE) is configured"
        else
            medium "AIDE is installed but not initialized"
        fi
    else
        medium "File integrity monitoring (AIDE) is not installed"
    fi
}

# Audit certificate security
audit_certificate_security() {
    info "Auditing certificate security..."
    
    # Check SSL certificates
    local services=("$TPOT_IP:64297:T-Pot" "$OPNSENSE_IP:443:OPNsense" "$PROXMOX_IP:8006:Proxmox")
    
    for service in "${services[@]}"; do
        local host=$(echo "$service" | cut -d: -f1)
        local port=$(echo "$service" | cut -d: -f2)
        local name=$(echo "$service" | cut -d: -f3)
        
        # Check certificate expiration
        local cert_info=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
        
        if [[ -n "$cert_info" ]]; then
            local expiry_date=$(echo "$cert_info" | grep notAfter | cut -d= -f2)
            local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
            local current_timestamp=$(date +%s)
            local days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
            
            if [[ $days_until_expiry -lt 7 ]]; then
                critical "$name SSL certificate expires in $days_until_expiry days"
            elif [[ $days_until_expiry -lt 30 ]]; then
                high "$name SSL certificate expires in $days_until_expiry days"
            elif [[ $days_until_expiry -lt 90 ]]; then
                medium "$name SSL certificate expires in $days_until_expiry days"
            else
                low "$name SSL certificate is valid for $days_until_expiry days"
            fi
            
            # Check for self-signed certificates
            local cert_issuer=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
            local cert_subject=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
            
            if [[ "$cert_issuer" == "$cert_subject" ]]; then
                medium "$name is using a self-signed certificate"
            else
                low "$name is using a properly signed certificate"
            fi
        else
            medium "Could not retrieve certificate information for $name"
        fi
    done
}

# Audit user accounts and privileges
audit_user_accounts() {
    info "Auditing user accounts and privileges..."
    
    # Check for users with UID 0 (root privileges)
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v "^root$" | wc -l)
    if [[ $root_users -gt 0 ]]; then
        critical "$root_users non-root users with UID 0 found"
    else
        low "No unauthorized root-level accounts found"
    fi
    
    # Check for users without passwords
    local no_password_users=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [[ $no_password_users -gt 0 ]]; then
        high "$no_password_users users without passwords found"
    else
        low "All users have passwords set"
    fi
    
    # Check for inactive users
    local inactive_users=$(lastlog | awk '$2 == "**Never" {print $1}' | grep -v "^Username" | wc -l)
    if [[ $inactive_users -gt 5 ]]; then
        medium "$inactive_users users have never logged in (consider cleanup)"
    else
        low "User account activity appears normal"
    fi
    
    # Check sudo configuration
    if [[ -f "/etc/sudoers" ]]; then
        # Check for NOPASSWD entries
        local nopasswd_entries=$(grep -c "NOPASSWD" /etc/sudoers 2>/dev/null || echo "0")
        if [[ $nopasswd_entries -gt 0 ]]; then
            medium "$nopasswd_entries NOPASSWD sudo entries found (review necessity)"
        else
            low "Sudo configuration requires passwords"
        fi
    fi
}

# Run system vulnerability scans
run_vulnerability_scans() {
    info "Running vulnerability scans..."
    
    # Run Lynis security audit
    if command -v lynis &> /dev/null; then
        info "Running Lynis security audit..."
        lynis audit system --quiet --no-colors > /tmp/lynis-audit.log 2>&1
        
        local lynis_warnings=$(grep -c "Warning" /tmp/lynis-audit.log || echo "0")
        local lynis_suggestions=$(grep -c "Suggestion" /tmp/lynis-audit.log || echo "0")
        
        if [[ $lynis_warnings -gt 10 ]]; then
            medium "Lynis found $lynis_warnings warnings (review /tmp/lynis-audit.log)"
        else
            low "Lynis audit completed with $lynis_warnings warnings"
        fi
        
        info "Lynis found $lynis_suggestions suggestions for improvement"
    fi
    
    # Run chkrootkit
    if command -v chkrootkit &> /dev/null; then
        info "Running chkrootkit scan..."
        chkrootkit > /tmp/chkrootkit.log 2>&1
        
        if grep -q "INFECTED" /tmp/chkrootkit.log; then
            critical "chkrootkit detected potential rootkit infections"
        else
            low "chkrootkit scan completed - no infections detected"
        fi
    fi
    
    # Run rkhunter
    if command -v rkhunter &> /dev/null; then
        info "Running rkhunter scan..."
        rkhunter --check --skip-keypress --report-warnings-only > /tmp/rkhunter.log 2>&1
        
        local rkhunter_warnings=$(grep -c "Warning" /tmp/rkhunter.log || echo "0")
        if [[ $rkhunter_warnings -gt 0 ]]; then
            medium "rkhunter found $rkhunter_warnings warnings (review /tmp/rkhunter.log)"
        else
            low "rkhunter scan completed - no warnings"
        fi
    fi
}

# Check for security updates
check_security_updates() {
    info "Checking for security updates..."
    
    # Update package lists
    apt update > /dev/null 2>&1
    
    # Check for security updates
    local security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
    if [[ $security_updates -gt 0 ]]; then
        high "$security_updates security updates available"
    else
        low "No security updates available"
    fi
    
    # Check for kernel updates
    local current_kernel=$(uname -r)
    local available_kernel=$(apt list --upgradable 2>/dev/null | grep "linux-image" | head -1 | cut -d' ' -f1 || echo "")
    
    if [[ -n "$available_kernel" ]]; then
        medium "Kernel update available: $available_kernel (current: $current_kernel)"
    else
        low "Kernel is up to date: $current_kernel"
    fi
}

# Generate security audit report
generate_security_report() {
    if [[ "$GENERATE_REPORT" == "true" ]]; then
        local report_file="/tmp/security-audit-report-$(date +%Y%m%d-%H%M%S).html"
        
        cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>T-Pot Infrastructure Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .critical-finding { border-left-color: #d32f2f; }
        .high-finding { border-left-color: #f57c00; }
        .medium-finding { border-left-color: #fbc02d; }
        .low-finding { border-left-color: #388e3c; }
    </style>
</head>
<body>
    <h1>T-Pot Infrastructure Security Audit Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Audit Date:</strong> $(date)</p>
        <p><strong>Audit Scope:</strong> $AUDIT_DEPTH</p>
        <p><strong>Total Findings:</strong> $((CRITICAL_FINDINGS + HIGH_FINDINGS + MEDIUM_FINDINGS + LOW_FINDINGS + INFO_FINDINGS))</p>
        
        <h3>Finding Distribution:</h3>
        <ul>
            <li class="critical">Critical: $CRITICAL_FINDINGS</li>
            <li class="high">High: $HIGH_FINDINGS</li>
            <li class="medium">Medium: $MEDIUM_FINDINGS</li>
            <li class="low">Low: $LOW_FINDINGS</li>
            <li class="info">Informational: $INFO_FINDINGS</li>
        </ul>
        
        <h3>Risk Assessment:</h3>
        <p>$(if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
            echo "🔴 <strong>HIGH RISK</strong> - Critical vulnerabilities require immediate attention"
        elif [[ $HIGH_FINDINGS -gt 5 ]]; then
            echo "🟠 <strong>MEDIUM RISK</strong> - Multiple high-priority issues need resolution"
        elif [[ $MEDIUM_FINDINGS -gt 10 ]]; then
            echo "🟡 <strong>LOW RISK</strong> - Several medium-priority improvements recommended"
        else
            echo "🟢 <strong>LOW RISK</strong> - Security posture is generally good"
        fi)</p>
    </div>
    
    <h2>Detailed Findings</h2>
    <div id="findings">
$(tail -200 "$LOG_FILE" | grep -E "\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]" | while read -r line; do
    local level=$(echo "$line" | grep -o '\[.*\]' | tr -d '[]')
    local message=$(echo "$line" | sed 's/.*\] //')
    local css_class=$(echo "$level" | tr '[:upper:]' '[:lower:]')
    echo "        <div class=\"finding ${css_class}-finding\">"
    echo "            <span class=\"$css_class\">[$level]</span> $message"
    echo "        </div>"
done)</div>
    
    <h2>Recommendations</h2>
    <ol>
$(if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
    echo "        <li><strong>URGENT:</strong> Address all critical findings immediately</li>"
fi)
$(if [[ $HIGH_FINDINGS -gt 0 ]]; then
    echo "        <li>Resolve high-priority security issues within 24-48 hours</li>"
fi)
$(if [[ $MEDIUM_FINDINGS -gt 0 ]]; then
    echo "        <li>Plan remediation for medium-priority issues within 1-2 weeks</li>"
fi)
        <li>Implement regular security audits (weekly/monthly)</li>
        <li>Keep all systems updated with latest security patches</li>
        <li>Review and update security policies regularly</li>
        <li>Conduct penetration testing quarterly</li>
        <li>Implement security awareness training</li>
    </ol>
    
    <h2>Next Steps</h2>
    <ul>
        <li>Review all findings and prioritize remediation efforts</li>
        <li>Create tickets/tasks for each finding that requires action</li>
        <li>Schedule follow-up audit to verify remediation</li>
        <li>Update security documentation and procedures</li>
        <li>Consider implementing additional security controls</li>
    </ul>
    
    <hr>
    <p><small>Generated by T-Pot Security Audit Script on $(date)<br>
    Log file: $LOG_FILE</small></p>
</body>
</html>
EOF

        info "Security audit report generated: $report_file"
        
        # Send email notification if configured
        if [[ "$SEND_ALERTS" == "true" ]] && command -v mail &> /dev/null; then
            local subject="T-Pot Security Audit Report - $(date +%Y-%m-%d)"
            if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
                subject="URGENT: $subject - $CRITICAL_FINDINGS Critical Issues"
            fi
            
            mail -s "$subject" root < "$report_file" 2>/dev/null || info "Failed to send email notification"
        fi
    fi
}

# Main security audit function
main() {
    local start_time=$SECONDS
    
    info "Starting comprehensive T-Pot infrastructure security audit"
    info "Audit depth: $AUDIT_DEPTH"
    
    check_root
    install_audit_tools
    
    # Run audit modules based on depth
    audit_network_security
    audit_system_hardening
    audit_tpot_security
    audit_log_security
    audit_certificate_security
    audit_user_accounts
    check_security_updates
    
    if [[ "$AUDIT_DEPTH" == "comprehensive" ]]; then
        run_vulnerability_scans
    fi
    
    # Generate report and summary
    generate_security_report
    
    local duration=$((SECONDS - start_time))
    info "Security audit completed in $((duration / 60)) minutes"
    
    # Final summary
    info "Security Audit Summary:"
    critical "Critical findings: $CRITICAL_FINDINGS"
    high "High findings: $HIGH_FINDINGS"
    medium "Medium findings: $MEDIUM_FINDINGS"
    low "Low findings: $LOW_FINDINGS"
    info "Informational: $INFO_FINDINGS"
    
    # Exit with appropriate code
    if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
        critical "CRITICAL security issues detected - immediate action required"
        exit 1
    elif [[ $HIGH_FINDINGS -gt 5 ]]; then
        high "Multiple high-priority security issues detected"
        exit 2
    else
        info "Security audit completed successfully"
        exit 0
    fi
}

# Run main function
main "$@"