# Testing and Validation Guide 🧪

This guide provides comprehensive testing procedures to validate the T-Pot honeypot infrastructure functionality, security, and performance.

## 📋 Overview

Testing is crucial to ensure that the honeypot infrastructure operates correctly, attracts attackers effectively, and maintains security isolation.

## 🔧 Pre-Deployment Testing

### Infrastructure Validation
```bash
#!/bin/bash
# Basic infrastructure connectivity test

echo "=== Infrastructure Connectivity Test ==="

# Test Proxmox VE connectivity
echo "Testing Proxmox VE..."
curl -k https://192.168.1.10:8006/api2/json/version
if [ $? -eq 0 ]; then
    echo "✅ Proxmox VE accessible"
else
    echo "❌ Proxmox VE not accessible"
fi

# Test OPNsense connectivity
echo "Testing OPNsense..."
ping -c 3 192.168.1.1
if [ $? -eq 0 ]; then
    echo "✅ OPNsense reachable"
else
    echo "❌ OPNsense not reachable"
fi

# Test T-Pot VM connectivity
echo "Testing T-Pot VM..."
ping -c 3 10.0.100.10
if [ $? -eq 0 ]; then
    echo "✅ T-Pot VM reachable"
else
    echo "❌ T-Pot VM not reachable"
fi
```

### Network Segmentation Test
```bash
#!/bin/bash
# Network isolation validation

echo "=== Network Segmentation Test ==="

# Test honeypot to management network isolation
echo "Testing honeypot isolation..."
ssh tpot@10.0.100.10 "ping -c 3 192.168.1.10"
if [ $? -ne 0 ]; then
    echo "✅ Honeypot properly isolated from management network"
else
    echo "❌ Honeypot can reach management network - SECURITY RISK!"
fi

# Test management to honeypot access
echo "Testing management access to honeypot..."
ping -c 3 10.0.100.10
if [ $? -eq 0 ]; then
    echo "✅ Management can reach honeypot for monitoring"
else
    echo "❌ Management cannot reach honeypot"
fi
```

## 🍯 Honeypot Service Testing

### Service Availability Test
```bash
#!/bin/bash
# Test all honeypot services

echo "=== Honeypot Service Availability Test ==="

HONEYPOT_IP="10.0.100.10"
SERVICES=(
    "22:SSH"
    "23:Telnet"
    "80:HTTP"
    "443:HTTPS"
    "2222:SSH-Alt"
    "8080:HTTP-Alt"
    "161:SNMP"
    "1900:UPnP"
)

for service in "${SERVICES[@]}"; do
    port=$(echo $service | cut -d: -f1)
    name=$(echo $service | cut -d: -f2)
    
    echo "Testing $name on port $port..."
    timeout 5 nc -z $HONEYPOT_IP $port
    if [ $? -eq 0 ]; then
        echo "✅ $name service is running"
    else
        echo "❌ $name service is not accessible"
    fi
done
```

### Honeypot Response Test
```bash
#!/bin/bash
# Test honeypot responses to common attacks

echo "=== Honeypot Response Test ==="

HONEYPOT_IP="10.0.100.10"

# Test SSH honeypot
echo "Testing SSH honeypot..."
expect << EOF
spawn ssh root@$HONEYPOT_IP
expect "password:"
send "admin\r"
expect eof
EOF

# Test HTTP honeypot
echo "Testing HTTP honeypot..."
curl -s -o /dev/null -w "%{http_code}" http://$HONEYPOT_IP/
if [ $? -eq 0 ]; then
    echo "✅ HTTP honeypot responding"
else
    echo "❌ HTTP honeypot not responding"
fi

# Test Telnet honeypot
echo "Testing Telnet honeypot..."
expect << EOF
spawn telnet $HONEYPOT_IP
expect "login:"
send "admin\r"
expect "Password:"
send "password\r"
expect eof
EOF
```

## 🔍 Security Testing

### Penetration Testing
```bash
#!/bin/bash
# Basic penetration testing against honeypots

echo "=== Penetration Testing ==="

HONEYPOT_IP="10.0.100.10"

# Port scanning
echo "Performing port scan..."
nmap -sS -O -A $HONEYPOT_IP > /tmp/nmap_results.txt
echo "✅ Port scan completed - results in /tmp/nmap_results.txt"

# Vulnerability scanning
echo "Performing vulnerability scan..."
nmap --script vuln $HONEYPOT_IP > /tmp/vuln_scan.txt
echo "✅ Vulnerability scan completed - results in /tmp/vuln_scan.txt"

# Web application testing
echo "Testing web applications..."
nikto -h http://$HONEYPOT_IP > /tmp/nikto_results.txt
echo "✅ Web application scan completed - results in /tmp/nikto_results.txt"
```

### Firewall Rule Testing
```bash
#!/bin/bash
# Test firewall rules and network isolation

echo "=== Firewall Rule Testing ==="

# Test blocked connections
echo "Testing blocked connections..."
timeout 5 nc -z 10.0.100.10 3389  # RDP should be blocked
if [ $? -ne 0 ]; then
    echo "✅ Unauthorized ports properly blocked"
else
    echo "❌ Unauthorized ports accessible - check firewall rules"
fi

# Test allowed connections
echo "Testing allowed connections..."
timeout 5 nc -z 10.0.100.10 22    # SSH should be allowed
if [ $? -eq 0 ]; then
    echo "✅ Authorized ports accessible"
else
    echo "❌ Authorized ports blocked - check firewall rules"
fi

# Test rate limiting
echo "Testing rate limiting..."
for i in {1..100}; do
    nc -z 10.0.100.10 22 &
done
wait
echo "✅ Rate limiting test completed - check logs for effectiveness"
```

## 📊 Performance Testing

### Load Testing
```bash
#!/bin/bash
# Performance and load testing

echo "=== Performance Testing ==="

HONEYPOT_IP="10.0.100.10"

# HTTP load test
echo "Performing HTTP load test..."
ab -n 1000 -c 10 http://$HONEYPOT_IP/ > /tmp/http_load_test.txt
echo "✅ HTTP load test completed - results in /tmp/http_load_test.txt"

# SSH connection test
echo "Testing SSH connection handling..."
for i in {1..50}; do
    timeout 10 ssh -o ConnectTimeout=5 test@$HONEYPOT_IP "exit" &
done
wait
echo "✅ SSH connection test completed"

# Resource usage monitoring
echo "Monitoring resource usage..."
ssh tpot@$HONEYPOT_IP "top -b -n 1 | head -20" > /tmp/resource_usage.txt
echo "✅ Resource usage captured - results in /tmp/resource_usage.txt"
```

### Stress Testing
```bash
#!/bin/bash
# Stress testing honeypot infrastructure

echo "=== Stress Testing ==="

# Network stress test
echo "Performing network stress test..."
hping3 -S -p 80 -i u1000 $HONEYPOT_IP &
HPING_PID=$!
sleep 60
kill $HPING_PID
echo "✅ Network stress test completed"

# Connection flood test
echo "Performing connection flood test..."
for i in {1..200}; do
    nc $HONEYPOT_IP 80 &
done
sleep 30
killall nc
echo "✅ Connection flood test completed"
```

## 🔄 Automated Testing

### Continuous Testing Script
```bash
#!/bin/bash
# Automated continuous testing

echo "=== Continuous Testing ==="

LOG_FILE="/var/log/honeypot-testing.log"

while true; do
    echo "$(date): Starting automated test cycle" >> $LOG_FILE
    
    # Basic connectivity test
    ping -c 1 10.0.100.10 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$(date): ✅ Honeypot connectivity OK" >> $LOG_FILE
    else
        echo "$(date): ❌ Honeypot connectivity FAILED" >> $LOG_FILE
        # Send alert
        echo "Honeypot connectivity failed at $(date)" | \
            mail -s "Honeypot Alert" admin@company.com
    fi
    
    # Service availability test
    nc -z 10.0.100.10 22 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$(date): ✅ SSH service OK" >> $LOG_FILE
    else
        echo "$(date): ❌ SSH service FAILED" >> $LOG_FILE
    fi
    
    # Wait 5 minutes before next test
    sleep 300
done
```

### Test Automation with Docker
```bash
#!/bin/bash
# Docker-based test automation

echo "=== Docker Test Automation ==="

# Build test container
cat > Dockerfile.test << EOF
FROM alpine:latest
RUN apk add --no-cache curl netcat-openbsd nmap
COPY test-scripts/ /tests/
WORKDIR /tests
CMD ["./run-all-tests.sh"]
EOF

# Run automated tests
docker build -t honeypot-tests -f Dockerfile.test .
docker run --rm --network host honeypot-tests
```

## 📈 Monitoring and Alerting Tests

### Log Generation Test
```bash
#!/bin/bash
# Test log generation and collection

echo "=== Log Generation Test ==="

# Generate test attacks
echo "Generating test attack logs..."
ssh-keyscan 10.0.100.10 > /dev/null 2>&1
curl -s http://10.0.100.10/admin > /dev/null 2>&1
nc 10.0.100.10 23 < /dev/null > /dev/null 2>&1

# Check log collection
echo "Checking log collection..."
ssh tpot@10.0.100.10 "tail -10 /data/cowrie/log/cowrie.json"
if [ $? -eq 0 ]; then
    echo "✅ Logs being generated and collected"
else
    echo "❌ Log collection issues detected"
fi
```

### Alert Testing
```bash
#!/bin/bash
# Test alerting mechanisms

echo "=== Alert Testing ==="

# Trigger high-volume attack alert
echo "Triggering high-volume attack alert..."
for i in {1..100}; do
    nc 10.0.100.10 22 < /dev/null > /dev/null 2>&1 &
done
wait

# Check if alert was generated
sleep 60
grep "High volume attack detected" /var/log/honeypot-alerts.log
if [ $? -eq 0 ]; then
    echo "✅ High-volume attack alert triggered"
else
    echo "❌ High-volume attack alert not triggered"
fi
```

## 🎯 Attack Simulation

### Realistic Attack Scenarios
```bash
#!/bin/bash
# Simulate realistic attack scenarios

echo "=== Attack Simulation ==="

HONEYPOT_IP="10.0.100.10"

# Brute force attack simulation
echo "Simulating SSH brute force attack..."
for password in admin password 123456 root; do
    sshpass -p $password ssh -o ConnectTimeout=5 admin@$HONEYPOT_IP "exit" 2>/dev/null
done

# Web vulnerability scanning simulation
echo "Simulating web vulnerability scan..."
curl -s http://$HONEYPOT_IP/admin > /dev/null
curl -s http://$HONEYPOT_IP/wp-admin > /dev/null
curl -s "http://$HONEYPOT_IP/index.php?id=1' OR '1'='1" > /dev/null

# Malware download simulation
echo "Simulating malware download attempt..."
wget -q http://$HONEYPOT_IP/malware.exe -O /dev/null 2>/dev/null
```

## 📋 Test Reporting

### Automated Test Report Generation
```bash
#!/bin/bash
# Generate comprehensive test report

echo "=== Test Report Generation ==="

REPORT_FILE="/tmp/honeypot-test-report-$(date +%Y%m%d-%H%M%S).html"

cat > $REPORT_FILE << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Infrastructure Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .pass { color: green; }
        .fail { color: red; }
        .section { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Honeypot Infrastructure Test Report</h1>
    <p>Generated: $(date)</p>
    
    <div class="section">
        <h2>Infrastructure Tests</h2>
        <!-- Test results will be populated here -->
    </div>
    
    <div class="section">
        <h2>Security Tests</h2>
        <!-- Security test results -->
    </div>
    
    <div class="section">
        <h2>Performance Tests</h2>
        <!-- Performance test results -->
    </div>
</body>
</html>
EOF

echo "✅ Test report generated: $REPORT_FILE"
```

## 🔧 Troubleshooting Tests

### Common Issue Detection
```bash
#!/bin/bash
# Detect and diagnose common issues

echo "=== Troubleshooting Tests ==="

# Check disk space
df -h | grep -E "(9[0-9]%|100%)"
if [ $? -eq 0 ]; then
    echo "❌ Disk space critically low"
else
    echo "✅ Disk space OK"
fi

# Check memory usage
free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'

# Check network connectivity
ping -c 3 8.8.8.8 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Internet connectivity OK"
else
    echo "❌ Internet connectivity issues"
fi

# Check service status
systemctl is-active docker > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Docker service running"
else
    echo "❌ Docker service not running"
fi
```

## 📚 Additional Resources

- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [Docker Security Testing](https://docs.docker.com/engine/security/security/)
- [Network Security Testing Tools](https://tools.kali.org/)