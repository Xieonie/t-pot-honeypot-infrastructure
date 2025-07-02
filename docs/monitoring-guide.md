# Monitoring and Analysis Guide 🔍

This guide covers comprehensive monitoring, analysis, and threat intelligence collection for the T-Pot honeypot infrastructure.

## 📋 Overview

Effective monitoring is essential for extracting valuable threat intelligence from honeypot activities while ensuring the infrastructure remains secure and operational.

## 📊 Monitoring Architecture

### Monitoring Stack Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Processing    │    │  Visualization  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • T-Pot Logs    │───▶│ • Logstash      │───▶│ • Grafana       │
│ • Network Flows │    │ • Elasticsearch │    │ • Kibana        │
│ • System Metrics│    │ • Prometheus    │    │ • Custom Dash   │
│ • Firewall Logs │    │ • AlertManager  │    │ • Reports       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Monitoring Setup

### Prometheus Configuration
```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert-rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['192.168.1.10:9100']  # Proxmox host
      - targets: ['10.0.100.10:9100']   # T-Pot VM

  - job_name: 'tpot-metrics'
    static_configs:
      - targets: ['10.0.100.10:64297']  # T-Pot metrics

  - job_name: 'opnsense'
    static_configs:
      - targets: ['192.168.1.1:9100']   # OPNsense metrics
```

### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "id": null,
    "title": "T-Pot Honeypot Overview",
    "tags": ["honeypot", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Attack Volume",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(honeypot_connections_total[5m])",
            "legendFormat": "Connections/sec"
          }
        ]
      },
      {
        "id": 2,
        "title": "Top Attack Sources",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum by (src_ip) (honeypot_connections_total))",
            "format": "table"
          }
        ]
      }
    ]
  }
}
```

## 📈 Key Metrics and KPIs

### Attack Metrics
```bash
# Connection attempts per minute
rate(honeypot_connections_total[1m])

# Unique source IPs per hour
count by (src_ip) (increase(honeypot_connections_total[1h]))

# Attack success rate
(honeypot_successful_logins / honeypot_login_attempts) * 100

# Payload diversity
count(distinct(honeypot_payloads))
```

### System Health Metrics
```bash
# CPU usage
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory usage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Disk usage
100 - ((node_filesystem_avail_bytes * 100) / node_filesystem_size_bytes)

# Network throughput
rate(node_network_receive_bytes_total[5m])
```

### Security Metrics
```bash
# Failed authentication attempts
rate(honeypot_auth_failures_total[5m])

# Malware samples collected
increase(honeypot_malware_samples_total[1h])

# Command execution attempts
rate(honeypot_commands_total[5m])

# Data exfiltration attempts
rate(honeypot_data_exfil_bytes_total[5m])
```

## 🚨 Alerting Rules

### Critical Alerts
```yaml
# /etc/prometheus/alert-rules.yml
groups:
  - name: honeypot.rules
    rules:
      - alert: HighVolumeAttack
        expr: rate(honeypot_connections_total[5m]) > 100
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High volume attack detected"
          description: "Attack rate is {{ $value }} connections/sec"

      - alert: SystemCompromise
        expr: honeypot_successful_logins > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Potential system compromise"
          description: "Successful login detected on honeypot"

      - alert: MalwareDetected
        expr: increase(honeypot_malware_samples_total[5m]) > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "Malware sample detected"
          description: "New malware sample collected"

      - alert: DataExfiltration
        expr: rate(honeypot_data_exfil_bytes_total[5m]) > 1000000
        for: 1m
        labels:
          severity: high
        annotations:
          summary: "Data exfiltration detected"
          description: "High data transfer rate: {{ $value }} bytes/sec"
```

### System Health Alerts
```yaml
  - name: system.rules
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is {{ $value }}%"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}%"

      - alert: DiskSpaceLow
        expr: 100 - ((node_filesystem_avail_bytes * 100) / node_filesystem_size_bytes) > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space"
          description: "Disk usage is {{ $value }}%"
```

## 📊 Log Analysis

### ELK Stack Configuration
```yaml
# docker-compose.yml for ELK stack
version: '3.7'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    ports:
      - "5044:5044"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf

  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200

volumes:
  elasticsearch_data:
```

### Logstash Configuration
```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  if [fields][log_type] == "honeypot" {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    geoip {
      source => "src_ip"
      target => "geoip"
    }
    
    mutate {
      add_field => { "attack_type" => "unknown" }
    }
    
    if [username] {
      mutate {
        update => { "attack_type" => "credential_attack" }
      }
    }
    
    if [command] {
      mutate {
        update => { "attack_type" => "command_execution" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "honeypot-logs-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
```

## 🔍 Threat Intelligence

### IOC Extraction
```bash
#!/bin/bash
# Extract Indicators of Compromise (IOCs)

LOG_DIR="/data/tpot/logs"
IOC_DIR="/data/threat-intel"

# Extract IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" $LOG_DIR/*.log | \
    sort | uniq -c | sort -nr > $IOC_DIR/malicious_ips.txt

# Extract domains
grep -oE "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" $LOG_DIR/*.log | \
    sort | uniq -c | sort -nr > $IOC_DIR/malicious_domains.txt

# Extract file hashes
grep -oE "[a-fA-F0-9]{32}" $LOG_DIR/*.log | \
    sort | uniq > $IOC_DIR/file_hashes_md5.txt

grep -oE "[a-fA-F0-9]{64}" $LOG_DIR/*.log | \
    sort | uniq > $IOC_DIR/file_hashes_sha256.txt

# Extract URLs
grep -oE "https?://[^\s]+" $LOG_DIR/*.log | \
    sort | uniq -c | sort -nr > $IOC_DIR/malicious_urls.txt
```

### Threat Intelligence Feeds
```python
#!/usr/bin/env python3
# threat_intel_collector.py

import requests
import json
import time
from datetime import datetime

class ThreatIntelCollector:
    def __init__(self):
        self.feeds = {
            'abuse_ch': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'malware_bazaar': 'https://mb-api.abuse.ch/api/v1/',
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
        }
    
    def collect_malicious_ips(self):
        """Collect malicious IP addresses from threat feeds"""
        try:
            response = requests.get(self.feeds['abuse_ch'])
            data = response.json()
            
            malicious_ips = []
            for entry in data:
                malicious_ips.append({
                    'ip': entry['ip_address'],
                    'first_seen': entry['first_seen'],
                    'malware': entry['malware'],
                    'confidence': entry['confidence']
                })
            
            return malicious_ips
        except Exception as e:
            print(f"Error collecting malicious IPs: {e}")
            return []
    
    def collect_malware_hashes(self):
        """Collect malware hashes from MalwareBazaar"""
        try:
            payload = {'query': 'get_recent', 'selector': '100'}
            response = requests.post(self.feeds['malware_bazaar'], data=payload)
            data = response.json()
            
            malware_hashes = []
            for entry in data['data']:
                malware_hashes.append({
                    'sha256': entry['sha256_hash'],
                    'md5': entry['md5_hash'],
                    'first_seen': entry['first_seen'],
                    'malware_family': entry['signature']
                })
            
            return malware_hashes
        except Exception as e:
            print(f"Error collecting malware hashes: {e}")
            return []
    
    def enrich_honeypot_data(self, honeypot_logs):
        """Enrich honeypot data with threat intelligence"""
        malicious_ips = self.collect_malicious_ips()
        malware_hashes = self.collect_malware_hashes()
        
        # Create lookup dictionaries
        ip_intel = {ip['ip']: ip for ip in malicious_ips}
        hash_intel = {h['sha256']: h for h in malware_hashes}
        
        enriched_logs = []
        for log in honeypot_logs:
            enriched_log = log.copy()
            
            # Enrich IP information
            if log.get('src_ip') in ip_intel:
                enriched_log['threat_intel'] = ip_intel[log['src_ip']]
                enriched_log['is_known_malicious'] = True
            
            # Enrich file hash information
            if log.get('file_hash') in hash_intel:
                enriched_log['malware_intel'] = hash_intel[log['file_hash']]
                enriched_log['is_known_malware'] = True
            
            enriched_logs.append(enriched_log)
        
        return enriched_logs

if __name__ == "__main__":
    collector = ThreatIntelCollector()
    
    # Example usage
    malicious_ips = collector.collect_malicious_ips()
    print(f"Collected {len(malicious_ips)} malicious IPs")
    
    malware_hashes = collector.collect_malware_hashes()
    print(f"Collected {len(malware_hashes)} malware hashes")
```

## 📱 Real-time Monitoring

### Live Dashboard
```html
<!DOCTYPE html>
<html>
<head>
    <title>T-Pot Live Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric-card { 
            border: 1px solid #ddd; 
            padding: 20px; 
            margin: 10px; 
            border-radius: 5px; 
            display: inline-block;
            width: 200px;
        }
        .metric-value { font-size: 2em; font-weight: bold; }
        .metric-label { color: #666; }
        #attackMap { width: 100%; height: 400px; }
    </style>
</head>
<body>
    <h1>T-Pot Live Monitor</h1>
    
    <div class="metric-card">
        <div class="metric-value" id="totalAttacks">0</div>
        <div class="metric-label">Total Attacks Today</div>
    </div>
    
    <div class="metric-card">
        <div class="metric-value" id="uniqueIPs">0</div>
        <div class="metric-label">Unique Source IPs</div>
    </div>
    
    <div class="metric-card">
        <div class="metric-value" id="malwareSamples">0</div>
        <div class="metric-label">Malware Samples</div>
    </div>
    
    <canvas id="attackChart" width="800" height="400"></canvas>
    
    <script>
        // Real-time data updates
        function updateMetrics() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalAttacks').textContent = data.total_attacks;
                    document.getElementById('uniqueIPs').textContent = data.unique_ips;
                    document.getElementById('malwareSamples').textContent = data.malware_samples;
                });
        }
        
        // Update every 30 seconds
        setInterval(updateMetrics, 30000);
        updateMetrics();
        
        // Attack timeline chart
        const ctx = document.getElementById('attackChart').getContext('2d');
        const attackChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attacks per Minute',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Update chart data
        function updateChart() {
            fetch('/api/attack-timeline')
                .then(response => response.json())
                .then(data => {
                    attackChart.data.labels = data.labels;
                    attackChart.data.datasets[0].data = data.values;
                    attackChart.update();
                });
        }
        
        setInterval(updateChart, 60000);
        updateChart();
    </script>
</body>
</html>
```

## 📧 Notification System

### Alert Manager Configuration
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@honeypot.local'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    email_configs:
      - to: 'admin@company.com'
        subject: 'Honeypot Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
    
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#security-alerts'
        title: 'Honeypot Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
```

## 📊 Reporting

### Automated Report Generation
```python
#!/usr/bin/env python3
# report_generator.py

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import json

class HoneypotReporter:
    def __init__(self, log_file):
        self.log_file = log_file
        self.data = self.load_data()
    
    def load_data(self):
        """Load and parse honeypot logs"""
        logs = []
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(logs)
    
    def generate_daily_report(self):
        """Generate daily activity report"""
        today = datetime.now().date()
        daily_data = self.data[pd.to_datetime(self.data['timestamp']).dt.date == today]
        
        report = {
            'date': str(today),
            'total_attacks': len(daily_data),
            'unique_ips': daily_data['src_ip'].nunique(),
            'top_countries': daily_data['country'].value_counts().head(10).to_dict(),
            'attack_types': daily_data['attack_type'].value_counts().to_dict(),
            'hourly_distribution': daily_data.groupby(
                pd.to_datetime(daily_data['timestamp']).dt.hour
            ).size().to_dict()
        }
        
        return report
    
    def generate_weekly_report(self):
        """Generate weekly trend analysis"""
        week_ago = datetime.now() - timedelta(days=7)
        weekly_data = self.data[pd.to_datetime(self.data['timestamp']) >= week_ago]
        
        # Create visualizations
        plt.figure(figsize=(15, 10))
        
        # Attack volume over time
        plt.subplot(2, 2, 1)
        daily_attacks = weekly_data.groupby(
            pd.to_datetime(weekly_data['timestamp']).dt.date
        ).size()
        daily_attacks.plot(kind='line')
        plt.title('Daily Attack Volume')
        plt.xlabel('Date')
        plt.ylabel('Number of Attacks')
        
        # Top attacking countries
        plt.subplot(2, 2, 2)
        top_countries = weekly_data['country'].value_counts().head(10)
        top_countries.plot(kind='bar')
        plt.title('Top Attacking Countries')
        plt.xlabel('Country')
        plt.ylabel('Attack Count')
        
        # Attack types distribution
        plt.subplot(2, 2, 3)
        attack_types = weekly_data['attack_type'].value_counts()
        attack_types.plot(kind='pie', autopct='%1.1f%%')
        plt.title('Attack Types Distribution')
        
        # Hourly attack pattern
        plt.subplot(2, 2, 4)
        hourly_pattern = weekly_data.groupby(
            pd.to_datetime(weekly_data['timestamp']).dt.hour
        ).size()
        hourly_pattern.plot(kind='bar')
        plt.title('Hourly Attack Pattern')
        plt.xlabel('Hour of Day')
        plt.ylabel('Attack Count')
        
        plt.tight_layout()
        plt.savefig(f'/tmp/weekly_report_{datetime.now().strftime("%Y%m%d")}.png')
        plt.close()
        
        return {
            'week_ending': str(datetime.now().date()),
            'total_attacks': len(weekly_data),
            'unique_ips': weekly_data['src_ip'].nunique(),
            'avg_daily_attacks': len(weekly_data) / 7,
            'chart_file': f'/tmp/weekly_report_{datetime.now().strftime("%Y%m%d")}.png'
        }

if __name__ == "__main__":
    reporter = HoneypotReporter('/data/tpot/logs/honeypot.log')
    
    # Generate reports
    daily_report = reporter.generate_daily_report()
    weekly_report = reporter.generate_weekly_report()
    
    print("Daily Report:", json.dumps(daily_report, indent=2))
    print("Weekly Report:", json.dumps(weekly_report, indent=2))
```

## 📚 Additional Resources

- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [STIX/TAXII Threat Intelligence](https://oasis-open.github.io/cti-documentation/)