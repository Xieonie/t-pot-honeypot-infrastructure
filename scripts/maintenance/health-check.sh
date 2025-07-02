#!/bin/bash

# T-Pot Infrastructure: Health Check Script
# This script performs comprehensive health checks on all infrastructure components

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/health-check.log"

# Infrastructure endpoints
TPOT_IP="10.0.100.10"
OPNSENSE_IP="192.168.1.1"
PROXMOX_IP="192.168.1.10"

# Health check thresholds
CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
DISK_THRESHOLD=90
LOAD_THRESHOLD=2.0
NETWORK_TIMEOUT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Health status counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNING_CHECKS=0
FAILED_CHECKS=0

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
    ((WARNING_CHECKS++))
}

error() {
    log "ERROR" "${RED}$*${NC}"
    ((FAILED_CHECKS++))
}

success() {
    log "SUCCESS" "${GREEN}$*${NC}"
    ((PASSED_CHECKS++))
}

check() {
    ((TOTAL_CHECKS++))
}

# Check network connectivity
check_connectivity() {
    info "Checking network connectivity..."
    
    local hosts=("$TPOT_IP:T-Pot" "$OPNSENSE_IP:OPNsense" "$PROXMOX_IP:Proxmox" "8.8.8.8:Internet")
    
    for host_info in "${hosts[@]}"; do
        local host=$(echo "$host_info" | cut -d: -f1)
        local name=$(echo "$host_info" | cut -d: -f2)
        
        check
        if ping -c 3 -W 5 "$host" > /dev/null 2>&1; then
            success "✅ $name ($host) is reachable"
        else
            error "❌ $name ($host) is not reachable"
        fi
    done
}

# Check Proxmox VE health
check_proxmox_health() {
    info "Checking Proxmox VE health..."
    
    # Check Proxmox services
    local pve_services=("pvedaemon" "pveproxy" "pvestatd" "pve-cluster" "corosync")
    for service in "${pve_services[@]}"; do
        check
        if systemctl is-active "$service" > /dev/null 2>&1; then
            success "✅ Proxmox service $service is running"
        else
            error "❌ Proxmox service $service is not running"
        fi
    done
    
    # Check cluster status
    check
    if command -v pvecm &> /dev/null; then
        local cluster_status=$(pvecm status 2>/dev/null | grep -c "Quorate.*Yes" || echo "0")
        if [[ $cluster_status -gt 0 ]]; then
            success "✅ Proxmox cluster is quorate"
        else
            warn "⚠️  Proxmox cluster status unclear or single node"
        fi
    else
        warn "⚠️  Proxmox cluster tools not available"
    fi
    
    # Check storage status
    check
    if command -v pvesm &> /dev/null; then
        local storage_issues=$(pvesm status 2>/dev/null | grep -c "inactive\|unknown" || echo "0")
        if [[ $storage_issues -eq 0 ]]; then
            success "✅ All Proxmox storage is active"
        else
            error "❌ $storage_issues Proxmox storage issues detected"
        fi
    fi
    
    # Check VM status
    check
    local vm_count=$(qm list 2>/dev/null | grep -c "running" || echo "0")
    if [[ $vm_count -gt 0 ]]; then
        success "✅ $vm_count VMs are running"
    else
        warn "⚠️  No VMs are running"
    fi
}

# Check system resources
check_system_resources() {
    info "Checking system resources..."
    
    # Check CPU usage
    check
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d',' -f1)
    if (( $(echo "$cpu_usage < $CPU_THRESHOLD" | bc -l) )); then
        success "✅ CPU usage is acceptable (${cpu_usage}%)"
    elif (( $(echo "$cpu_usage < 95" | bc -l) )); then
        warn "⚠️  CPU usage is high (${cpu_usage}%)"
    else
        error "❌ CPU usage is critical (${cpu_usage}%)"
    fi
    
    # Check memory usage
    check
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    if (( $(echo "$mem_usage < $MEMORY_THRESHOLD" | bc -l) )); then
        success "✅ Memory usage is acceptable (${mem_usage}%)"
    elif (( $(echo "$mem_usage < 95" | bc -l) )); then
        warn "⚠️  Memory usage is high (${mem_usage}%)"
    else
        error "❌ Memory usage is critical (${mem_usage}%)"
    fi
    
    # Check disk usage
    check
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    if [[ $disk_usage -lt $DISK_THRESHOLD ]]; then
        success "✅ Disk usage is acceptable (${disk_usage}%)"
    elif [[ $disk_usage -lt 95 ]]; then
        warn "⚠️  Disk usage is high (${disk_usage}%)"
    else
        error "❌ Disk usage is critical (${disk_usage}%)"
    fi
    
    # Check load average
    check
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    if (( $(echo "$load_avg < $LOAD_THRESHOLD" | bc -l) )); then
        success "✅ Load average is acceptable ($load_avg)"
    elif (( $(echo "$load_avg < 5" | bc -l) )); then
        warn "⚠️  Load average is high ($load_avg)"
    else
        error "❌ Load average is critical ($load_avg)"
    fi
    
    # Check swap usage
    check
    local swap_usage=$(free | grep Swap | awk '{if($2>0) printf "%.1f", $3/$2 * 100.0; else print "0"}')
    if (( $(echo "$swap_usage < 50" | bc -l) )); then
        success "✅ Swap usage is acceptable (${swap_usage}%)"
    else
        warn "⚠️  Swap usage is high (${swap_usage}%)"
    fi
}

# Check T-Pot health
check_tpot_health() {
    info "Checking T-Pot health..."
    
    if ! ping -c 3 "$TPOT_IP" > /dev/null 2>&1; then
        error "❌ T-Pot VM is not reachable"
        return 1
    fi
    
    # Check T-Pot service
    check
    if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "systemctl is-active tpot" > /dev/null 2>&1; then
        success "✅ T-Pot service is running"
    else
        error "❌ T-Pot service is not running"
    fi
    
    # Check Docker containers
    check
    local container_count=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "docker ps -q | wc -l" 2>/dev/null || echo "0")
    if [[ $container_count -gt 10 ]]; then
        success "✅ $container_count Docker containers are running"
    elif [[ $container_count -gt 0 ]]; then
        warn "⚠️  Only $container_count Docker containers are running"
    else
        error "❌ No Docker containers are running"
    fi
    
    # Check honeypot services
    local honeypot_services=("22:SSH" "23:Telnet" "80:HTTP" "443:HTTPS" "2222:SSH-Alt" "8080:HTTP-Alt")
    for service in "${honeypot_services[@]}"; do
        local port=$(echo "$service" | cut -d: -f1)
        local name=$(echo "$service" | cut -d: -f2)
        
        check
        if timeout 5 nc -z "$TPOT_IP" "$port" 2>/dev/null; then
            success "✅ $name service (port $port) is accessible"
        else
            warn "⚠️  $name service (port $port) is not accessible"
        fi
    done
    
    # Check T-Pot web interface
    check
    if curl -k -s --connect-timeout $NETWORK_TIMEOUT "https://$TPOT_IP:64297" > /dev/null; then
        success "✅ T-Pot web interface is accessible"
    else
        error "❌ T-Pot web interface is not accessible"
    fi
    
    # Check T-Pot system resources
    check
    local tpot_cpu=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1" 2>/dev/null || echo "0")
    if (( $(echo "$tpot_cpu < $CPU_THRESHOLD" | bc -l) )); then
        success "✅ T-Pot CPU usage is acceptable (${tpot_cpu}%)"
    else
        warn "⚠️  T-Pot CPU usage is high (${tpot_cpu}%)"
    fi
    
    check
    local tpot_mem=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "free | grep Mem | awk '{printf \"%.1f\", \$3/\$2 * 100.0}'" 2>/dev/null || echo "0")
    if (( $(echo "$tpot_mem < $MEMORY_THRESHOLD" | bc -l) )); then
        success "✅ T-Pot memory usage is acceptable (${tpot_mem}%)"
    else
        warn "⚠️  T-Pot memory usage is high (${tpot_mem}%)"
    fi
}

# Check OPNsense health
check_opnsense_health() {
    info "Checking OPNsense health..."
    
    if ! ping -c 3 "$OPNSENSE_IP" > /dev/null 2>&1; then
        error "❌ OPNsense firewall is not reachable"
        return 1
    fi
    
    # Check web interface
    check
    if curl -k -s --connect-timeout $NETWORK_TIMEOUT "https://$OPNSENSE_IP" > /dev/null; then
        success "✅ OPNsense web interface is accessible"
    else
        error "❌ OPNsense web interface is not accessible"
    fi
    
    # Check if firewall is filtering traffic (basic test)
    check
    if timeout 5 nc -z "$OPNSENSE_IP" 22 2>/dev/null; then
        warn "⚠️  SSH port is open on OPNsense (may be intentional)"
    else
        success "✅ OPNsense firewall is filtering traffic"
    fi
    
    # Note: More detailed OPNsense checks would require API access or SNMP
    warn "⚠️  Detailed OPNsense health checks require API configuration"
}

# Check monitoring systems
check_monitoring_systems() {
    info "Checking monitoring systems..."
    
    # Check Elasticsearch
    check
    if curl -s --connect-timeout $NETWORK_TIMEOUT "http://$TPOT_IP:9200/_cluster/health" > /dev/null 2>&1; then
        local es_status=$(curl -s "http://$TPOT_IP:9200/_cluster/health" | jq -r '.status' 2>/dev/null || echo "unknown")
        if [[ "$es_status" == "green" ]]; then
            success "✅ Elasticsearch is healthy (green)"
        elif [[ "$es_status" == "yellow" ]]; then
            warn "⚠️  Elasticsearch status is yellow"
        else
            error "❌ Elasticsearch status is red or unknown"
        fi
    else
        error "❌ Elasticsearch is not accessible"
    fi
    
    # Check Kibana
    check
    if curl -s --connect-timeout $NETWORK_TIMEOUT "http://$TPOT_IP:5601/api/status" > /dev/null 2>&1; then
        success "✅ Kibana is accessible"
    else
        error "❌ Kibana is not accessible"
    fi
    
    # Check Prometheus (if configured)
    check
    if curl -s --connect-timeout $NETWORK_TIMEOUT "http://$TPOT_IP:9090/api/v1/query?query=up" > /dev/null 2>&1; then
        success "✅ Prometheus is accessible"
    else
        warn "⚠️  Prometheus is not accessible (may not be configured)"
    fi
    
    # Check Grafana (if configured)
    check
    if curl -s --connect-timeout $NETWORK_TIMEOUT "http://$TPOT_IP:3000/api/health" > /dev/null 2>&1; then
        success "✅ Grafana is accessible"
    else
        warn "⚠️  Grafana is not accessible (may not be configured)"
    fi
}

# Check security status
check_security_status() {
    info "Checking security status..."
    
    # Check firewall status on T-Pot
    check
    if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "ufw status | grep -q 'Status: active'" 2>/dev/null; then
        success "✅ UFW firewall is active on T-Pot"
    else
        error "❌ UFW firewall is not active on T-Pot"
    fi
    
    # Check fail2ban status
    check
    if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "systemctl is-active fail2ban" 2>/dev/null | grep -q "active"; then
        success "✅ Fail2ban is active on T-Pot"
    else
        warn "⚠️  Fail2ban is not active on T-Pot"
    fi
    
    # Check for recent security events
    check
    local security_events=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "grep -c 'SECURITY' /var/log/auth.log 2>/dev/null || echo 0")
    if [[ $security_events -eq 0 ]]; then
        success "✅ No recent security events in auth.log"
    else
        warn "⚠️  $security_events security events found in auth.log"
    fi
    
    # Check SSL certificates
    check
    local cert_days=$(echo | openssl s_client -connect "$TPOT_IP:64297" -servername "$TPOT_IP" 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2 | xargs -I {} date -d "{}" +%s)
    local current_time=$(date +%s)
    local days_until_expiry=$(( (cert_days - current_time) / 86400 ))
    
    if [[ $days_until_expiry -gt 30 ]]; then
        success "✅ SSL certificate is valid for $days_until_expiry days"
    elif [[ $days_until_expiry -gt 7 ]]; then
        warn "⚠️  SSL certificate expires in $days_until_expiry days"
    else
        error "❌ SSL certificate expires in $days_until_expiry days"
    fi
}

# Check log collection and retention
check_log_management() {
    info "Checking log management..."
    
    # Check log directories
    local log_dirs=("/data/cowrie/log" "/data/dionaea/log" "/data/suricata/log" "/var/log/tpot")
    for log_dir in "${log_dirs[@]}"; do
        check
        if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "test -d $log_dir" 2>/dev/null; then
            local file_count=$(ssh tpot@"$TPOT_IP" "find $log_dir -name '*.log' -o -name '*.json' | wc -l" 2>/dev/null || echo "0")
            if [[ $file_count -gt 0 ]]; then
                success "✅ Log directory $log_dir contains $file_count files"
            else
                warn "⚠️  Log directory $log_dir is empty"
            fi
        else
            error "❌ Log directory $log_dir does not exist"
        fi
    done
    
    # Check recent log activity
    check
    local recent_logs=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "find /data -name '*.log' -mmin -60 | wc -l" 2>/dev/null || echo "0")
    if [[ $recent_logs -gt 0 ]]; then
        success "✅ $recent_logs log files updated in the last hour"
    else
        warn "⚠️  No recent log activity detected"
    fi
    
    # Check disk space for logs
    check
    local log_disk_usage=$(ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "df /data | tail -1 | awk '{print \$5}' | cut -d'%' -f1" 2>/dev/null || echo "100")
    if [[ $log_disk_usage -lt 80 ]]; then
        success "✅ Log disk usage is acceptable (${log_disk_usage}%)"
    elif [[ $log_disk_usage -lt 90 ]]; then
        warn "⚠️  Log disk usage is high (${log_disk_usage}%)"
    else
        error "❌ Log disk usage is critical (${log_disk_usage}%)"
    fi
}

# Check backup status
check_backup_status() {
    info "Checking backup status..."
    
    # Check if backup directory exists
    check
    if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "test -d /backup" 2>/dev/null; then
        local backup_count=$(ssh tpot@"$TPOT_IP" "ls -1 /backup/*.tar.gz 2>/dev/null | wc -l" || echo "0")
        if [[ $backup_count -gt 0 ]]; then
            success "✅ $backup_count backup files found"
            
            # Check backup age
            local latest_backup=$(ssh tpot@"$TPOT_IP" "ls -t /backup/*.tar.gz 2>/dev/null | head -1" || echo "")
            if [[ -n "$latest_backup" ]]; then
                local backup_age=$(ssh tpot@"$TPOT_IP" "find $latest_backup -mtime -1" 2>/dev/null || echo "")
                if [[ -n "$backup_age" ]]; then
                    success "✅ Recent backup found (less than 24 hours old)"
                else
                    warn "⚠️  Latest backup is older than 24 hours"
                fi
            fi
        else
            warn "⚠️  No backup files found"
        fi
    else
        warn "⚠️  Backup directory not found"
    fi
    
    # Check backup schedule
    check
    if ssh -o ConnectTimeout=$NETWORK_TIMEOUT tpot@"$TPOT_IP" "crontab -l | grep -q backup" 2>/dev/null; then
        success "✅ Backup schedule is configured"
    else
        warn "⚠️  Backup schedule is not configured"
    fi
}

# Generate health report
generate_health_report() {
    local report_file="/tmp/health-check-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
T-Pot Infrastructure Health Check Report
========================================
Date: $(date)
Duration: $((SECONDS / 60)) minutes

Summary:
- Total checks: $TOTAL_CHECKS
- Passed: $PASSED_CHECKS ($(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))%)
- Warnings: $WARNING_CHECKS ($(( WARNING_CHECKS * 100 / TOTAL_CHECKS ))%)
- Failures: $FAILED_CHECKS ($(( FAILED_CHECKS * 100 / TOTAL_CHECKS ))%)

Overall Health Status:
$(if [[ $FAILED_CHECKS -eq 0 && $WARNING_CHECKS -eq 0 ]]; then
    echo "🟢 EXCELLENT - All systems are healthy"
elif [[ $FAILED_CHECKS -eq 0 ]]; then
    echo "🟡 GOOD - Minor issues detected"
elif [[ $FAILED_CHECKS -lt 5 ]]; then
    echo "🟠 FAIR - Some issues need attention"
else
    echo "🔴 POOR - Critical issues detected"
fi)

Detailed Results:
$(tail -100 "$LOG_FILE" | grep -E "(✅|⚠️|❌)" || echo "No detailed results available")

Recommendations:
$(if [[ $FAILED_CHECKS -gt 0 ]]; then
    echo "- Address critical failures immediately"
fi)
$(if [[ $WARNING_CHECKS -gt 0 ]]; then
    echo "- Investigate warnings and resolve if necessary"
fi)
- Schedule regular health checks
- Monitor system resources continuously
- Keep all systems updated
- Test backup and recovery procedures

Next Health Check: $(date -d "+1 day" '+%Y-%m-%d %H:%M:%S')

Log File: $LOG_FILE
EOF

    success "Health check report generated: $report_file"
    
    # Send notification if there are critical issues
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        if command -v mail &> /dev/null; then
            mail -s "CRITICAL: T-Pot Infrastructure Health Issues" root < "$report_file" 2>/dev/null || warn "Failed to send email notification"
        fi
        logger -t "tpot-health" "CRITICAL: $FAILED_CHECKS health check failures detected"
    fi
}

# Main health check function
main() {
    info "Starting T-Pot infrastructure health check"
    
    # Run all health checks
    check_connectivity
    check_proxmox_health
    check_system_resources
    check_tpot_health
    check_opnsense_health
    check_monitoring_systems
    check_security_status
    check_log_management
    check_backup_status
    
    # Generate report
    generate_health_report
    
    # Final summary
    info "Health check completed:"
    success "$PASSED_CHECKS checks passed"
    if [[ $WARNING_CHECKS -gt 0 ]]; then
        warn "$WARNING_CHECKS warnings"
    fi
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        error "$FAILED_CHECKS failures"
    fi
    
    # Exit with appropriate code
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        error "Health check completed with failures"
        exit 1
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        warn "Health check completed with warnings"
        exit 2
    else
        success "All health checks passed"
        exit 0
    fi
}

# Run main function
main "$@"