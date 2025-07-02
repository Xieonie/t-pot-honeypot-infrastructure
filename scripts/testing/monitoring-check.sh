#!/bin/bash

# T-Pot Infrastructure: Monitoring Check Script
# This script validates the monitoring and alerting systems for T-Pot infrastructure

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/monitoring-check.log"

# Infrastructure endpoints
TPOT_IP="10.0.100.10"
OPNSENSE_IP="192.168.1.1"
PROXMOX_IP="192.168.1.10"

# Monitoring endpoints
PROMETHEUS_PORT="9090"
GRAFANA_PORT="3000"
KIBANA_PORT="5601"
ELASTICSEARCH_PORT="9200"
TPOT_WEB_PORT="64297"

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

# Test network connectivity
test_connectivity() {
    info "Testing network connectivity..."
    
    local hosts=("$TPOT_IP" "$OPNSENSE_IP" "$PROXMOX_IP")
    local failed=0
    
    for host in "${hosts[@]}"; do
        if ping -c 3 -W 5 "$host" > /dev/null 2>&1; then
            success "✅ $host is reachable"
        else
            error "❌ $host is not reachable"
            ((failed++))
        fi
    done
    
    if [[ $failed -eq 0 ]]; then
        success "All hosts are reachable"
        return 0
    else
        error "$failed hosts are not reachable"
        return 1
    fi
}

# Test T-Pot services
test_tpot_services() {
    info "Testing T-Pot services..."
    
    # Test T-Pot web interface
    if curl -k -s --connect-timeout 10 "https://$TPOT_IP:$TPOT_WEB_PORT" > /dev/null; then
        success "✅ T-Pot web interface is accessible"
    else
        error "❌ T-Pot web interface is not accessible"
    fi
    
    # Test honeypot services
    local services=(
        "22:SSH"
        "23:Telnet"
        "80:HTTP"
        "443:HTTPS"
        "2222:SSH-Alt"
        "8080:HTTP-Alt"
    )
    
    for service in "${services[@]}"; do
        local port=$(echo "$service" | cut -d: -f1)
        local name=$(echo "$service" | cut -d: -f2)
        
        if timeout 5 nc -z "$TPOT_IP" "$port" 2>/dev/null; then
            success "✅ $name service (port $port) is listening"
        else
            warn "⚠️  $name service (port $port) is not accessible"
        fi
    done
}

# Test monitoring stack
test_monitoring_stack() {
    info "Testing monitoring stack..."
    
    # Test Elasticsearch
    if curl -s --connect-timeout 10 "http://$TPOT_IP:$ELASTICSEARCH_PORT/_cluster/health" > /dev/null; then
        local health=$(curl -s "http://$TPOT_IP:$ELASTICSEARCH_PORT/_cluster/health" | jq -r '.status' 2>/dev/null || echo "unknown")
        if [[ "$health" == "green" || "$health" == "yellow" ]]; then
            success "✅ Elasticsearch is healthy (status: $health)"
        else
            warn "⚠️  Elasticsearch status: $health"
        fi
    else
        error "❌ Elasticsearch is not accessible"
    fi
    
    # Test Kibana
    if curl -s --connect-timeout 10 "http://$TPOT_IP:$KIBANA_PORT/api/status" > /dev/null; then
        success "✅ Kibana is accessible"
    else
        error "❌ Kibana is not accessible"
    fi
    
    # Test Prometheus (if running)
    if curl -s --connect-timeout 10 "http://$TPOT_IP:$PROMETHEUS_PORT/api/v1/query?query=up" > /dev/null; then
        success "✅ Prometheus is accessible"
    else
        warn "⚠️  Prometheus is not accessible (may not be configured)"
    fi
    
    # Test Grafana (if running)
    if curl -s --connect-timeout 10 "http://$TPOT_IP:$GRAFANA_PORT/api/health" > /dev/null; then
        success "✅ Grafana is accessible"
    else
        warn "⚠️  Grafana is not accessible (may not be configured)"
    fi
}

# Test log collection
test_log_collection() {
    info "Testing log collection..."
    
    # Check if logs are being generated
    local log_dirs=(
        "/data/cowrie/log"
        "/data/dionaea/log"
        "/data/suricata/log"
        "/var/log/tpot"
    )
    
    for log_dir in "${log_dirs[@]}"; do
        if ssh -o ConnectTimeout=10 tpot@"$TPOT_IP" "test -d $log_dir" 2>/dev/null; then
            local file_count=$(ssh tpot@"$TPOT_IP" "find $log_dir -name '*.log' -o -name '*.json' | wc -l" 2>/dev/null || echo "0")
            if [[ $file_count -gt 0 ]]; then
                success "✅ Log directory $log_dir contains $file_count files"
            else
                warn "⚠️  Log directory $log_dir is empty"
            fi
        else
            warn "⚠️  Log directory $log_dir does not exist or is not accessible"
        fi
    done
    
    # Test recent log activity
    local recent_logs=$(ssh tpot@"$TPOT_IP" "find /data -name '*.log' -mmin -60 | wc -l" 2>/dev/null || echo "0")
    if [[ $recent_logs -gt 0 ]]; then
        success "✅ $recent_logs log files have been updated in the last hour"
    else
        warn "⚠️  No recent log activity detected"
    fi
}

# Test alerting system
test_alerting() {
    info "Testing alerting system..."
    
    # Test email configuration (if configured)
    if ssh tpot@"$TPOT_IP" "command -v mail" 2>/dev/null; then
        success "✅ Mail system is available"
        
        # Send test alert
        ssh tpot@"$TPOT_IP" "echo 'Test alert from T-Pot monitoring check' | mail -s 'T-Pot Test Alert' root" 2>/dev/null || warn "⚠️  Failed to send test email"
    else
        warn "⚠️  Mail system is not configured"
    fi
    
    # Test syslog forwarding (if configured)
    if ssh tpot@"$TPOT_IP" "netstat -an | grep :514" 2>/dev/null; then
        success "✅ Syslog forwarding is configured"
    else
        warn "⚠️  Syslog forwarding is not configured"
    fi
    
    # Test webhook endpoints (if configured)
    local webhook_config="/opt/tpot/etc/alerting/webhooks.conf"
    if ssh tpot@"$TPOT_IP" "test -f $webhook_config" 2>/dev/null; then
        success "✅ Webhook configuration found"
    else
        warn "⚠️  Webhook configuration not found"
    fi
}

# Test data retention
test_data_retention() {
    info "Testing data retention policies..."
    
    # Check disk usage
    local disk_usage=$(ssh tpot@"$TPOT_IP" "df /data --output=pcent | tail -n1 | tr -d ' %'" 2>/dev/null || echo "100")
    if [[ $disk_usage -lt 80 ]]; then
        success "✅ Disk usage is acceptable ($disk_usage%)"
    elif [[ $disk_usage -lt 90 ]]; then
        warn "⚠️  Disk usage is high ($disk_usage%)"
    else
        error "❌ Disk usage is critical ($disk_usage%)"
    fi
    
    # Check log rotation
    if ssh tpot@"$TPOT_IP" "test -f /etc/logrotate.d/tpot" 2>/dev/null; then
        success "✅ Log rotation is configured"
    else
        warn "⚠️  Log rotation is not configured"
    fi
    
    # Check old file cleanup
    local old_files=$(ssh tpot@"$TPOT_IP" "find /data -name '*.log' -mtime +30 | wc -l" 2>/dev/null || echo "0")
    if [[ $old_files -eq 0 ]]; then
        success "✅ No old log files found (good retention policy)"
    else
        warn "⚠️  $old_files log files are older than 30 days"
    fi
}

# Test performance metrics
test_performance() {
    info "Testing system performance..."
    
    # Check CPU usage
    local cpu_usage=$(ssh tpot@"$TPOT_IP" "top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1" 2>/dev/null || echo "0")
    if (( $(echo "$cpu_usage < 80" | bc -l) )); then
        success "✅ CPU usage is acceptable (${cpu_usage}%)"
    else
        warn "⚠️  CPU usage is high (${cpu_usage}%)"
    fi
    
    # Check memory usage
    local mem_usage=$(ssh tpot@"$TPOT_IP" "free | grep Mem | awk '{printf \"%.1f\", \$3/\$2 * 100.0}'" 2>/dev/null || echo "0")
    if (( $(echo "$mem_usage < 80" | bc -l) )); then
        success "✅ Memory usage is acceptable (${mem_usage}%)"
    else
        warn "⚠️  Memory usage is high (${mem_usage}%)"
    fi
    
    # Check load average
    local load_avg=$(ssh tpot@"$TPOT_IP" "uptime | awk -F'load average:' '{print \$2}' | awk '{print \$1}' | tr -d ','" 2>/dev/null || echo "0")
    if (( $(echo "$load_avg < 2" | bc -l) )); then
        success "✅ Load average is acceptable ($load_avg)"
    else
        warn "⚠️  Load average is high ($load_avg)"
    fi
}

# Test security monitoring
test_security_monitoring() {
    info "Testing security monitoring..."
    
    # Check if IDS is running
    if ssh tpot@"$TPOT_IP" "pgrep suricata" 2>/dev/null; then
        success "✅ Suricata IDS is running"
    else
        warn "⚠️  Suricata IDS is not running"
    fi
    
    # Check firewall status
    if ssh tpot@"$TPOT_IP" "ufw status | grep -q 'Status: active'" 2>/dev/null; then
        success "✅ UFW firewall is active"
    else
        warn "⚠️  UFW firewall is not active"
    fi
    
    # Check fail2ban status (if installed)
    if ssh tpot@"$TPOT_IP" "systemctl is-active fail2ban" 2>/dev/null | grep -q "active"; then
        success "✅ Fail2ban is active"
    else
        warn "⚠️  Fail2ban is not active or not installed"
    fi
    
    # Check for recent security events
    local security_events=$(ssh tpot@"$TPOT_IP" "grep -c 'SECURITY' /var/log/auth.log" 2>/dev/null || echo "0")
    if [[ $security_events -eq 0 ]]; then
        success "✅ No recent security events in auth.log"
    else
        warn "⚠️  $security_events security events found in auth.log"
    fi
}

# Test backup system
test_backup_system() {
    info "Testing backup system..."
    
    # Check if backup script exists
    if ssh tpot@"$TPOT_IP" "test -f /opt/tpot/bin/backup.sh" 2>/dev/null; then
        success "✅ Backup script exists"
    else
        warn "⚠️  Backup script not found"
    fi
    
    # Check backup directory
    if ssh tpot@"$TPOT_IP" "test -d /backup" 2>/dev/null; then
        local backup_count=$(ssh tpot@"$TPOT_IP" "ls -1 /backup/*.tar.gz 2>/dev/null | wc -l" || echo "0")
        if [[ $backup_count -gt 0 ]]; then
            success "✅ $backup_count backup files found"
        else
            warn "⚠️  No backup files found"
        fi
    else
        warn "⚠️  Backup directory not found"
    fi
    
    # Check backup schedule
    if ssh tpot@"$TPOT_IP" "crontab -l | grep -q backup" 2>/dev/null; then
        success "✅ Backup schedule is configured"
    else
        warn "⚠️  Backup schedule is not configured"
    fi
}

# Generate monitoring report
generate_monitoring_report() {
    local report_file="/tmp/monitoring-check-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
T-Pot Monitoring Check Report
=============================
Date: $(date)
Checked by: $(whoami)
Log file: $LOG_FILE

Infrastructure Status:
- T-Pot IP: $TPOT_IP
- OPNsense IP: $OPNSENSE_IP
- Proxmox IP: $PROXMOX_IP

Test Results Summary:
$(grep -c "✅" "$LOG_FILE" 2>/dev/null || echo "0") tests passed
$(grep -c "⚠️" "$LOG_FILE" 2>/dev/null || echo "0") warnings
$(grep -c "❌" "$LOG_FILE" 2>/dev/null || echo "0") failures

Detailed Results:
$(tail -n 100 "$LOG_FILE" | grep -E "(✅|⚠️|❌)" || echo "No detailed results available")

Recommendations:
- Review any warnings or failures above
- Check system resources if performance issues detected
- Verify backup and retention policies
- Ensure all monitoring services are properly configured
- Test alerting mechanisms regularly

Next Steps:
1. Address any critical failures (❌)
2. Investigate warnings (⚠️) and resolve if necessary
3. Schedule regular monitoring checks
4. Update monitoring configuration as needed
5. Document any changes or improvements

EOF

    success "Monitoring report generated: $report_file"
}

# Main monitoring check function
main() {
    info "Starting T-Pot monitoring system check"
    
    # Run all tests
    test_connectivity
    test_tpot_services
    test_monitoring_stack
    test_log_collection
    test_alerting
    test_data_retention
    test_performance
    test_security_monitoring
    test_backup_system
    
    # Generate report
    generate_monitoring_report
    
    # Summary
    local passed=$(grep -c "✅" "$LOG_FILE" 2>/dev/null || echo "0")
    local warnings=$(grep -c "⚠️" "$LOG_FILE" 2>/dev/null || echo "0")
    local failures=$(grep -c "❌" "$LOG_FILE" 2>/dev/null || echo "0")
    
    info "Monitoring check completed:"
    success "$passed tests passed"
    if [[ $warnings -gt 0 ]]; then
        warn "$warnings warnings"
    fi
    if [[ $failures -gt 0 ]]; then
        error "$failures failures"
    fi
    
    if [[ $failures -eq 0 ]]; then
        success "T-Pot monitoring system is functioning properly"
        return 0
    else
        error "T-Pot monitoring system has issues that need attention"
        return 1
    fi
}

# Run main function
main "$@"