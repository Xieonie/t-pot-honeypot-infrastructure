#!/bin/bash

# T-Pot Honeypot Connectivity Test Script
# Tests network connectivity and service availability
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
TEST_RESULTS="/tmp/connectivity-test-$(date +%Y%m%d-%H%M%S).log"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo -e "${RED}[ERROR]${NC} Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$TEST_RESULTS"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$TEST_RESULTS"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$TEST_RESULTS"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$TEST_RESULTS"
}

test_network_isolation() {
    log_info "Testing network isolation..."
    
    # Test 1: T-Pot should not be directly reachable from management network
    if timeout 3 ping -c 1 "$TPOT_IP" &> /dev/null; then
        log_error "T-Pot is directly reachable from management network - SECURITY RISK!"
        return 1
    else
        log_success "T-Pot is properly isolated from management network"
    fi
    
    # Test 2: OPNsense LAN interface should not be directly reachable
    if timeout 3 ping -c 1 "$OPNSENSE_LAN_IP" &> /dev/null; then
        log_error "OPNsense LAN interface is directly reachable - SECURITY RISK!"
        return 1
    else
        log_success "OPNsense LAN interface is properly isolated"
    fi
    
    return 0
}

test_opnsense_connectivity() {
    log_info "Testing OPNsense connectivity..."
    
    # Get OPNsense WAN IP
    local wan_ip
    if [[ "$OPNSENSE_WAN_TYPE" == "dhcp" ]]; then
        # Try to determine WAN IP from common ranges
        for ip in $(seq 192.168.1.200 192.168.1.210); do
            if timeout 3 ping -c 1 "$ip" &> /dev/null; then
                wan_ip="$ip"
                break
            fi
        done
    else
        wan_ip="$OPNSENSE_WAN_IP"
    fi
    
    if [[ -n "${wan_ip:-}" ]]; then
        log_success "OPNsense WAN interface reachable at $wan_ip"
        
        # Test web interface
        if curl -k -s --connect-timeout 5 "https://$wan_ip:${HTTPS_PORT:-443}" &> /dev/null; then
            log_success "OPNsense web interface accessible"
        else
            log_warning "OPNsense web interface not accessible (may be firewalled)"
        fi
    else
        log_error "Cannot determine OPNsense WAN IP address"
        return 1
    fi
    
    return 0
}

test_port_forwarding() {
    log_info "Testing port forwarding..."
    
    # Get public IP for testing
    local public_ip
    public_ip=$(curl -s --connect-timeout 5 ifconfig.me || echo "")
    
    if [[ -z "$public_ip" ]]; then
        log_warning "Cannot determine public IP, skipping external tests"
        return 0
    fi
    
    log_info "Testing from public IP: $public_ip"
    
    # Test common honeypot ports
    local ports=("22" "80" "443")
    local failed_ports=()
    
    for port in "${ports[@]}"; do
        if timeout 5 nc -zv "$public_ip" "$port" &> /dev/null; then
            log_success "Port $port is accessible from internet"
        else
            log_error "Port $port is not accessible from internet"
            failed_ports+=("$port")
        fi
    done
    
    if [[ ${#failed_ports[@]} -eq 0 ]]; then
        return 0
    else
        log_error "Failed ports: ${failed_ports[*]}"
        return 1
    fi
}

test_tpot_services() {
    log_info "Testing T-Pot services..."
    
    # Test if we can reach T-Pot through OPNsense
    local opnsense_wan_ip
    opnsense_wan_ip=$(ip route | grep "$WAN_BRIDGE" | grep -oE '192\.168\.1\.[0-9]+' | head -1)
    
    if [[ -z "$opnsense_wan_ip" ]]; then
        log_warning "Cannot determine OPNsense WAN IP for T-Pot testing"
        return 0
    fi
    
    # Test SSH honeypot
    if timeout 5 nc -zv "$opnsense_wan_ip" 22 &> /dev/null; then
        log_success "SSH honeypot accessible through OPNsense"
    else
        log_error "SSH honeypot not accessible"
    fi
    
    # Test HTTP honeypot
    if timeout 5 nc -zv "$opnsense_wan_ip" 80 &> /dev/null; then
        log_success "HTTP honeypot accessible through OPNsense"
    else
        log_error "HTTP honeypot not accessible"
    fi
    
    # Test HTTPS honeypot
    if timeout 5 nc -zv "$opnsense_wan_ip" 443 &> /dev/null; then
        log_success "HTTPS honeypot accessible through OPNsense"
    else
        log_error "HTTPS honeypot not accessible"
    fi
    
    return 0
}

test_vm_status() {
    log_info "Testing VM status..."
    
    # Check OPNsense VM
    if qm status "$OPNSENSE_VM_ID" | grep -q "running"; then
        log_success "OPNsense VM is running"
    else
        log_error "OPNsense VM is not running"
    fi
    
    # Check T-Pot VM
    if qm status "$TPOT_VM_ID" | grep -q "running"; then
        log_success "T-Pot VM is running"
    else
        log_error "T-Pot VM is not running"
    fi
    
    return 0
}

test_bridge_configuration() {
    log_info "Testing bridge configuration..."
    
    # Check if bridges exist
    if ip link show "$WAN_BRIDGE" &> /dev/null; then
        log_success "WAN bridge ($WAN_BRIDGE) exists"
    else
        log_error "WAN bridge ($WAN_BRIDGE) does not exist"
    fi
    
    if ip link show "$LAN_BRIDGE" &> /dev/null; then
        log_success "LAN bridge ($LAN_BRIDGE) exists"
    else
        log_error "LAN bridge ($LAN_BRIDGE) does not exist"
    fi
    
    # Check bridge isolation
    local lan_bridge_ports
    lan_bridge_ports=$(ls /sys/class/net/"$LAN_BRIDGE"/brif/ 2>/dev/null | wc -l)
    
    if [[ "$lan_bridge_ports" -eq 0 ]]; then
        log_success "LAN bridge has no physical ports (properly isolated)"
    else
        log_warning "LAN bridge has physical ports - check isolation"
    fi
    
    return 0
}

test_dns_resolution() {
    log_info "Testing DNS resolution..."
    
    # Test from management host
    if nslookup google.com &> /dev/null; then
        log_success "DNS resolution working from management host"
    else
        log_error "DNS resolution failed from management host"
    fi
    
    return 0
}

generate_test_report() {
    local total_tests=7
    local passed_tests=0
    
    log_info "Generating test report..."
    
    echo "======================================" >> "$TEST_RESULTS"
    echo "T-POT CONNECTIVITY TEST REPORT" >> "$TEST_RESULTS"
    echo "======================================" >> "$TEST_RESULTS"
    echo "Date: $(date)" >> "$TEST_RESULTS"
    echo "Configuration: $CONFIG_FILE" >> "$TEST_RESULTS"
    echo "" >> "$TEST_RESULTS"
    
    # Count passed tests
    passed_tests=$(grep -c "\[PASS\]" "$TEST_RESULTS" || echo "0")
    
    echo "Test Results: $passed_tests/$total_tests passed" >> "$TEST_RESULTS"
    echo "" >> "$TEST_RESULTS"
    
    if [[ "$passed_tests" -eq "$total_tests" ]]; then
        echo "Overall Status: ALL TESTS PASSED ✅" >> "$TEST_RESULTS"
        log_success "All connectivity tests passed!"
    else
        echo "Overall Status: SOME TESTS FAILED ❌" >> "$TEST_RESULTS"
        log_error "Some connectivity tests failed. Check the log for details."
    fi
    
    echo "" >> "$TEST_RESULTS"
    echo "Full test log: $TEST_RESULTS" >> "$TEST_RESULTS"
    
    # Display summary
    echo
    echo "======================================="
    echo "TEST SUMMARY"
    echo "======================================="
    echo "Passed: $passed_tests/$total_tests"
    echo "Log file: $TEST_RESULTS"
    echo
    
    if [[ "$passed_tests" -lt "$total_tests" ]]; then
        echo "❌ Some tests failed. Please review the issues above."
        return 1
    else
        echo "✅ All tests passed! Your T-Pot infrastructure is properly configured."
        return 0
    fi
}

main() {
    echo "========================================"
    echo "T-Pot Honeypot Connectivity Test"
    echo "========================================"
    echo
    
    # Initialize test log
    echo "T-Pot Connectivity Test - $(date)" > "$TEST_RESULTS"
    echo "========================================" >> "$TEST_RESULTS"
    
    # Run tests
    test_vm_status
    test_bridge_configuration
    test_network_isolation
    test_dns_resolution
    test_opnsense_connectivity
    test_port_forwarding
    test_tpot_services
    
    # Generate report
    generate_test_report
}

# Run main function
main "$@"