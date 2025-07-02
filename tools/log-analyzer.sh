#!/bin/bash

# T-Pot Infrastructure: Log Analyzer Tool
# This script analyzes logs from T-Pot honeypot infrastructure for security insights

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/log-analyzer.log"

# T-Pot log directories
TPOT_IP="10.0.100.10"
COWRIE_LOGS="/data/cowrie/log"
DIONAEA_LOGS="/data/dionaea/log"
SURICATA_LOGS="/data/suricata/log"
ELASTICPOT_LOGS="/data/elasticpot/log"
SYSTEM_LOGS="/var/log"

# Analysis settings
ANALYSIS_PERIOD="24h"
OUTPUT_DIR="/tmp/log-analysis-$(date +%Y%m%d-%H%M%S)"
GENERATE_REPORT=true
SEND_ALERTS=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

critical() {
    log "CRITICAL" "${RED}$*${NC}"
}

# Create output directory
create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    info "Analysis output directory: $OUTPUT_DIR"
}

# Analyze Cowrie SSH honeypot logs
analyze_cowrie_logs() {
    info "Analyzing Cowrie SSH honeypot logs..."
    
    local cowrie_analysis="$OUTPUT_DIR/cowrie_analysis.txt"
    
    # Check if T-Pot is accessible
    if ! ping -c 1 "$TPOT_IP" > /dev/null 2>&1; then
        error "T-Pot VM is not accessible"
        return 1
    fi
    
    # Get recent Cowrie logs
    ssh tpot@"$TPOT_IP" "find $COWRIE_LOGS -name '*.json*' -mtime -1" > /tmp/cowrie_files.txt 2>/dev/null || {
        warn "Could not access Cowrie logs"
        return 1
    }
    
    if [[ ! -s /tmp/cowrie_files.txt ]]; then
        warn "No recent Cowrie log files found"
        return 1
    fi
    
    cat > "$cowrie_analysis" << EOF
Cowrie SSH Honeypot Analysis Report
==================================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Analyze login attempts
    info "Analyzing SSH login attempts..."
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.login.failed\") | \"\(.src_ip) \(.username) \(.password)\"' | \
        sort | uniq -c | sort -nr | head -20
    " >> "$cowrie_analysis" 2>/dev/null || echo "No failed login data available" >> "$cowrie_analysis"
    
    echo -e "\nTop Failed Login Attempts:" >> "$cowrie_analysis"
    echo "Count | Source IP | Username | Password" >> "$cowrie_analysis"
    echo "------|-----------|----------|----------" >> "$cowrie_analysis"
    
    # Analyze successful logins
    echo -e "\nSuccessful Login Attempts:" >> "$cowrie_analysis"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.login.success\") | \"\(.src_ip) \(.username) \(.password)\"' | \
        sort | uniq -c | sort -nr | head -10
    " >> "$cowrie_analysis" 2>/dev/null || echo "No successful login data available" >> "$cowrie_analysis"
    
    # Analyze commands executed
    echo -e "\nTop Commands Executed:" >> "$cowrie_analysis"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.command.input\") | .input' | \
        sort | uniq -c | sort -nr | head -20
    " >> "$cowrie_analysis" 2>/dev/null || echo "No command execution data available" >> "$cowrie_analysis"
    
    # Analyze file downloads
    echo -e "\nFile Downloads:" >> "$cowrie_analysis"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.session.file_download\") | \"\(.src_ip) \(.url) \(.shasum)\"' | \
        sort | uniq
    " >> "$cowrie_analysis" 2>/dev/null || echo "No file download data available" >> "$cowrie_analysis"
    
    # Analyze attack sources by country
    echo -e "\nAttack Sources by Country:" >> "$cowrie_analysis"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.src_ip) | .src_ip' | \
        sort | uniq | \
        while read ip; do
            country=\$(geoiplookup \$ip 2>/dev/null | cut -d: -f2 | cut -d, -f1 | xargs || echo 'Unknown')
            echo \"\$country\"
        done | \
        sort | uniq -c | sort -nr | head -10
    " >> "$cowrie_analysis" 2>/dev/null || echo "No geolocation data available" >> "$cowrie_analysis"
    
    success "Cowrie analysis completed: $cowrie_analysis"
}

# Analyze Dionaea malware honeypot logs
analyze_dionaea_logs() {
    info "Analyzing Dionaea malware honeypot logs..."
    
    local dionaea_analysis="$OUTPUT_DIR/dionaea_analysis.txt"
    
    cat > "$dionaea_analysis" << EOF
Dionaea Malware Honeypot Analysis Report
=======================================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Analyze connections
    echo "Connection Analysis:" >> "$dionaea_analysis"
    ssh tpot@"$TPOT_IP" "
        find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"dionaea.connection.tcp.accept\") | \"\(.src_ip) \(.dst_port)\"' | \
        sort | uniq -c | sort -nr | head -20
    " >> "$dionaea_analysis" 2>/dev/null || echo "No connection data available" >> "$dionaea_analysis"
    
    # Analyze malware downloads
    echo -e "\nMalware Downloads:" >> "$dionaea_analysis"
    ssh tpot@"$TPOT_IP" "
        find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"dionaea.download.complete\") | \"\(.src_ip) \(.url) \(.md5hash)\"' | \
        sort | uniq
    " >> "$dionaea_analysis" 2>/dev/null || echo "No malware download data available" >> "$dionaea_analysis"
    
    # Analyze shellcode
    echo -e "\nShellcode Detection:" >> "$dionaea_analysis"
    ssh tpot@"$TPOT_IP" "
        find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"dionaea.shellcode.profile\") | \"\(.src_ip) \(.shellcode)\"' | \
        sort | uniq -c | sort -nr | head -10
    " >> "$dionaea_analysis" 2>/dev/null || echo "No shellcode data available" >> "$dionaea_analysis"
    
    success "Dionaea analysis completed: $dionaea_analysis"
}

# Analyze Suricata IDS logs
analyze_suricata_logs() {
    info "Analyzing Suricata IDS logs..."
    
    local suricata_analysis="$OUTPUT_DIR/suricata_analysis.txt"
    
    cat > "$suricata_analysis" << EOF
Suricata IDS Analysis Report
===========================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Analyze alerts
    echo "IDS Alerts:" >> "$suricata_analysis"
    ssh tpot@"$TPOT_IP" "
        find $SURICATA_LOGS -name 'eve.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.event_type == \"alert\") | \"\(.alert.signature) (\(.src_ip) -> \(.dest_ip))\"' | \
        sort | uniq -c | sort -nr | head -20
    " >> "$suricata_analysis" 2>/dev/null || echo "No alert data available" >> "$suricata_analysis"
    
    # Analyze by severity
    echo -e "\nAlerts by Severity:" >> "$suricata_analysis"
    ssh tpot@"$TPOT_IP" "
        find $SURICATA_LOGS -name 'eve.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.event_type == \"alert\") | .alert.severity' | \
        sort | uniq -c | sort -nr
    " >> "$suricata_analysis" 2>/dev/null || echo "No severity data available" >> "$suricata_analysis"
    
    # Analyze by category
    echo -e "\nAlerts by Category:" >> "$suricata_analysis"
    ssh tpot@"$TPOT_IP" "
        find $SURICATA_LOGS -name 'eve.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.event_type == \"alert\") | .alert.category' | \
        sort | uniq -c | sort -nr
    " >> "$suricata_analysis" 2>/dev/null || echo "No category data available" >> "$suricata_analysis"
    
    success "Suricata analysis completed: $suricata_analysis"
}

# Analyze system logs
analyze_system_logs() {
    info "Analyzing system logs..."
    
    local system_analysis="$OUTPUT_DIR/system_analysis.txt"
    
    cat > "$system_analysis" << EOF
System Logs Analysis Report
===========================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Analyze authentication logs
    echo "Authentication Events:" >> "$system_analysis"
    ssh tpot@"$TPOT_IP" "
        grep 'sshd.*Failed password' /var/log/auth.log | \
        awk '{print \$(NF-3), \$(NF-1)}' | \
        sort | uniq -c | sort -nr | head -20
    " >> "$system_analysis" 2>/dev/null || echo "No auth log data available" >> "$system_analysis"
    
    # Analyze successful logins
    echo -e "\nSuccessful SSH Logins:" >> "$system_analysis"
    ssh tpot@"$TPOT_IP" "
        grep 'sshd.*Accepted password' /var/log/auth.log | \
        awk '{print \$(NF-3), \$(NF-1)}' | \
        sort | uniq -c | sort -nr | head -10
    " >> "$system_analysis" 2>/dev/null || echo "No successful login data available" >> "$system_analysis"
    
    # Analyze system errors
    echo -e "\nSystem Errors:" >> "$system_analysis"
    ssh tpot@"$TPOT_IP" "
        grep -i error /var/log/syslog | tail -20
    " >> "$system_analysis" 2>/dev/null || echo "No system error data available" >> "$system_analysis"
    
    success "System analysis completed: $system_analysis"
}

# Generate threat intelligence
generate_threat_intelligence() {
    info "Generating threat intelligence..."
    
    local threat_intel="$OUTPUT_DIR/threat_intelligence.txt"
    
    cat > "$threat_intel" << EOF
Threat Intelligence Report
=========================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Extract unique attacking IPs
    echo "Unique Attacking IP Addresses:" >> "$threat_intel"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.src_ip) | .src_ip' | \
        sort | uniq | head -50
    " >> "$threat_intel" 2>/dev/null || echo "No IP data available" >> "$threat_intel"
    
    # Extract malware hashes
    echo -e "\nMalware Hashes (MD5):" >> "$threat_intel"
    ssh tpot@"$TPOT_IP" "
        find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.md5hash) | .md5hash' | \
        sort | uniq
    " >> "$threat_intel" 2>/dev/null || echo "No malware hash data available" >> "$threat_intel"
    
    # Extract URLs
    echo -e "\nMalicious URLs:" >> "$threat_intel"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.url) | .url' | \
        sort | uniq
    " >> "$threat_intel" 2>/dev/null || echo "No URL data available" >> "$threat_intel"
    
    # Extract attack patterns
    echo -e "\nAttack Patterns:" >> "$threat_intel"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.command.input\") | .input' | \
        grep -E '(wget|curl|nc|netcat|/bin/sh|python|perl)' | \
        sort | uniq -c | sort -nr | head -10
    " >> "$threat_intel" 2>/dev/null || echo "No attack pattern data available" >> "$threat_intel"
    
    success "Threat intelligence generated: $threat_intel"
}

# Detect anomalies
detect_anomalies() {
    info "Detecting anomalies..."
    
    local anomalies="$OUTPUT_DIR/anomalies.txt"
    
    cat > "$anomalies" << EOF
Anomaly Detection Report
=======================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Detect unusual connection volumes
    echo "Unusual Connection Volumes:" >> "$anomalies"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.src_ip) | .src_ip' | \
        sort | uniq -c | \
        awk '\$1 > 100 {print \"High volume from \" \$2 \": \" \$1 \" connections\"}'
    " >> "$anomalies" 2>/dev/null || echo "No volume anomaly data available" >> "$anomalies"
    
    # Detect unusual time patterns
    echo -e "\nUnusual Time Patterns:" >> "$anomalies"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r '.timestamp' | \
        cut -dT -f2 | cut -d: -f1 | \
        sort | uniq -c | \
        awk '\$1 > 50 {print \"High activity in hour \" \$2 \": \" \$1 \" events\"}'
    " >> "$anomalies" 2>/dev/null || echo "No time pattern data available" >> "$anomalies"
    
    # Detect new attack vectors
    echo -e "\nPotential New Attack Vectors:" >> "$anomalies"
    ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.command.input\") | .input' | \
        grep -v -E '^(ls|cd|pwd|whoami|id|uname|cat|echo|exit|clear)' | \
        sort | uniq -c | \
        awk '\$1 == 1 {print \"Unique command: \" \$0}' | head -20
    " >> "$anomalies" 2>/dev/null || echo "No new attack vector data available" >> "$anomalies"
    
    success "Anomaly detection completed: $anomalies"
}

# Generate summary statistics
generate_statistics() {
    info "Generating statistics..."
    
    local stats="$OUTPUT_DIR/statistics.txt"
    
    cat > "$stats" << EOF
T-Pot Infrastructure Statistics
==============================
Analysis Period: Last $ANALYSIS_PERIOD
Generated: $(date)

EOF
    
    # Connection statistics
    echo "Connection Statistics:" >> "$stats"
    local total_connections=$(ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.src_ip) | .src_ip' | wc -l
    " 2>/dev/null || echo "0")
    
    local unique_ips=$(ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.src_ip) | .src_ip' | sort | uniq | wc -l
    " 2>/dev/null || echo "0")
    
    echo "Total Connections: $total_connections" >> "$stats"
    echo "Unique Source IPs: $unique_ips" >> "$stats"
    
    # Malware statistics
    local malware_samples=$(ssh tpot@"$TPOT_IP" "
        find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"dionaea.download.complete\") | .md5hash' | sort | uniq | wc -l
    " 2>/dev/null || echo "0")
    
    echo "Malware Samples Collected: $malware_samples" >> "$stats"
    
    # Command statistics
    local commands_executed=$(ssh tpot@"$TPOT_IP" "
        find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.eventid == \"cowrie.command.input\") | .input' | wc -l
    " 2>/dev/null || echo "0")
    
    echo "Commands Executed: $commands_executed" >> "$stats"
    
    # Alert statistics
    local ids_alerts=$(ssh tpot@"$TPOT_IP" "
        find $SURICATA_LOGS -name 'eve.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
        jq -r 'select(.event_type == \"alert\")' | wc -l
    " 2>/dev/null || echo "0")
    
    echo "IDS Alerts: $ids_alerts" >> "$stats"
    
    success "Statistics generated: $stats"
}

# Generate comprehensive report
generate_comprehensive_report() {
    info "Generating comprehensive report..."
    
    local report="$OUTPUT_DIR/comprehensive_report.html"
    
    cat > "$report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>T-Pot Log Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin: 20px 0; }
        .critical { color: #d32f2f; font-weight: bold; }
        .warning { color: #f57c00; }
        .info { color: #1976d2; }
        .success { color: #388e3c; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>T-Pot Infrastructure Log Analysis Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Analysis Period:</strong> Last $ANALYSIS_PERIOD</p>
        <p><strong>Output Directory:</strong> $OUTPUT_DIR</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive analysis of security events captured by the T-Pot honeypot infrastructure.</p>
    </div>
    
    <div class="section">
        <h2>Statistics Overview</h2>
        <pre>$(cat "$OUTPUT_DIR/statistics.txt" 2>/dev/null || echo "Statistics not available")</pre>
    </div>
    
    <div class="section">
        <h2>Threat Intelligence</h2>
        <pre>$(head -50 "$OUTPUT_DIR/threat_intelligence.txt" 2>/dev/null || echo "Threat intelligence not available")</pre>
    </div>
    
    <div class="section">
        <h2>Anomalies Detected</h2>
        <pre>$(cat "$OUTPUT_DIR/anomalies.txt" 2>/dev/null || echo "Anomaly data not available")</pre>
    </div>
    
    <div class="section">
        <h2>Detailed Analysis Files</h2>
        <ul>
            <li><a href="cowrie_analysis.txt">Cowrie SSH Honeypot Analysis</a></li>
            <li><a href="dionaea_analysis.txt">Dionaea Malware Honeypot Analysis</a></li>
            <li><a href="suricata_analysis.txt">Suricata IDS Analysis</a></li>
            <li><a href="system_analysis.txt">System Logs Analysis</a></li>
            <li><a href="threat_intelligence.txt">Threat Intelligence</a></li>
            <li><a href="anomalies.txt">Anomaly Detection</a></li>
            <li><a href="statistics.txt">Statistics Summary</a></li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Review and block high-volume attacking IP addresses</li>
            <li>Analyze new malware samples for threat intelligence</li>
            <li>Update firewall rules based on attack patterns</li>
            <li>Monitor for unusual time-based attack patterns</li>
            <li>Correlate findings with external threat intelligence feeds</li>
        </ul>
    </div>
    
    <hr>
    <p><small>Generated by T-Pot Log Analyzer - $(date)</small></p>
</body>
</html>
EOF

    success "Comprehensive report generated: $report"
}

# Send alerts if enabled
send_alerts() {
    if [[ "$SEND_ALERTS" == "true" ]]; then
        info "Sending alerts..."
        
        # Check for critical findings
        local critical_findings=0
        
        # Check for high-volume attacks
        local high_volume=$(ssh tpot@"$TPOT_IP" "
            find $COWRIE_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
            jq -r 'select(.src_ip) | .src_ip' | \
            sort | uniq -c | \
            awk '\$1 > 500 {print \$2}' | wc -l
        " 2>/dev/null || echo "0")
        
        if [[ $high_volume -gt 0 ]]; then
            ((critical_findings++))
            critical "High-volume attack detected from $high_volume IP addresses"
        fi
        
        # Check for malware
        local malware_count=$(ssh tpot@"$TPOT_IP" "
            find $DIONAEA_LOGS -name '*.json*' -mtime -1 -exec zcat -f {} \; 2>/dev/null | \
            jq -r 'select(.eventid == \"dionaea.download.complete\")' | wc -l
        " 2>/dev/null || echo "0")
        
        if [[ $malware_count -gt 0 ]]; then
            ((critical_findings++))
            critical "Malware samples detected: $malware_count"
        fi
        
        # Send notification if critical findings
        if [[ $critical_findings -gt 0 ]]; then
            if command -v mail &> /dev/null; then
                echo "Critical security events detected in T-Pot infrastructure. Check analysis report: $OUTPUT_DIR" | \
                    mail -s "CRITICAL: T-Pot Security Alert" root
            fi
            
            logger -t "tpot-analyzer" "CRITICAL: $critical_findings critical security events detected"
        fi
    fi
}

# Main analysis function
main() {
    info "Starting T-Pot log analysis"
    
    create_output_dir
    
    # Run all analysis modules
    analyze_cowrie_logs
    analyze_dionaea_logs
    analyze_suricata_logs
    analyze_system_logs
    generate_threat_intelligence
    detect_anomalies
    generate_statistics
    
    if [[ "$GENERATE_REPORT" == "true" ]]; then
        generate_comprehensive_report
    fi
    
    send_alerts
    
    success "Log analysis completed successfully!"
    info "Results available in: $OUTPUT_DIR"
    
    # Print summary
    echo
    echo "=== ANALYSIS SUMMARY ==="
    echo "Output Directory: $OUTPUT_DIR"
    echo "Files Generated:"
    ls -la "$OUTPUT_DIR"
    echo
    echo "Key Findings:"
    echo "- Check comprehensive_report.html for overview"
    echo "- Review threat_intelligence.txt for IOCs"
    echo "- Examine anomalies.txt for unusual patterns"
    echo "========================="
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--period)
            ANALYSIS_PERIOD="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-report)
            GENERATE_REPORT=false
            shift
            ;;
        --send-alerts)
            SEND_ALERTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -p, --period PERIOD    Analysis period (default: 24h)"
            echo "  -o, --output DIR       Output directory"
            echo "  --no-report           Skip HTML report generation"
            echo "  --send-alerts         Send alerts for critical findings"
            echo "  -h, --help            Show this help"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"