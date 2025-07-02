#!/usr/bin/env python3
"""
T-Pot Infrastructure Network Scanner
This tool performs network discovery and security scanning for the T-Pot infrastructure
"""

import argparse
import ipaddress
import json
import logging
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/network-scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class NetworkScanner:
    """Network scanner for T-Pot infrastructure"""
    
    def __init__(self, targets, output_file=None, threads=50):
        self.targets = targets
        self.output_file = output_file
        self.threads = threads
        self.results = {}
        self.start_time = datetime.now()
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1433, 1521, 2222, 3306, 3389, 5432, 5900, 8080, 8443, 9200
        ]
        
        # T-Pot specific ports
        self.tpot_ports = [
            22, 23, 80, 443, 2222, 8080,  # Honeypot services
            64297,  # T-Pot web interface
            9200, 5601, 5044,  # ELK stack
            9090, 3000, 9093  # Prometheus, Grafana, Alertmanager
        ]
    
    def ping_host(self, host):
        """Ping a host to check if it's alive"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', str(host)],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def scan_port(self, host, port, timeout=3):
        """Scan a single port on a host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((str(host), port))
                return result == 0
        except (socket.error, OSError):
            return False
    
    def get_service_banner(self, host, port, timeout=3):
        """Attempt to grab service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((str(host), port))
                
                # Send HTTP request for web services
                if port in [80, 8080, 8443]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + str(host).encode() + b"\r\n\r\n")
                elif port == 22:
                    pass  # SSH will send banner automatically
                elif port == 21:
                    pass  # FTP will send banner automatically
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]  # Limit banner length
        except (socket.error, OSError, UnicodeDecodeError):
            return None
    
    def scan_host_ports(self, host):
        """Scan all ports on a single host"""
        host_results = {
            'host': str(host),
            'alive': False,
            'open_ports': [],
            'services': {},
            'scan_time': datetime.now().isoformat()
        }
        
        # Check if host is alive
        if not self.ping_host(host):
            logger.debug(f"Host {host} is not responding to ping")
            return host_results
        
        host_results['alive'] = True
        logger.info(f"Scanning {host}...")
        
        # Determine which ports to scan
        ports_to_scan = self.common_ports.copy()
        if str(host).startswith('10.0.100.'):  # T-Pot network
            ports_to_scan.extend(self.tpot_ports)
        
        # Remove duplicates and sort
        ports_to_scan = sorted(list(set(ports_to_scan)))
        
        # Scan ports
        with ThreadPoolExecutor(max_workers=20) as executor:
            port_futures = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports_to_scan
            }
            
            for future in as_completed(port_futures):
                port = port_futures[future]
                try:
                    if future.result():
                        host_results['open_ports'].append(port)
                        
                        # Try to get service banner
                        banner = self.get_service_banner(host, port)
                        if banner:
                            host_results['services'][port] = {
                                'banner': banner,
                                'service': self.identify_service(port, banner)
                            }
                        else:
                            host_results['services'][port] = {
                                'service': self.identify_service(port)
                            }
                        
                        logger.debug(f"Port {port} open on {host}")
                except Exception as e:
                    logger.error(f"Error scanning port {port} on {host}: {e}")
        
        logger.info(f"Found {len(host_results['open_ports'])} open ports on {host}")
        return host_results
    
    def identify_service(self, port, banner=None):
        """Identify service based on port and banner"""
        # Common port mappings
        port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            2222: 'SSH (Alt)',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP (Alt)',
            8443: 'HTTPS (Alt)',
            9200: 'Elasticsearch',
            5601: 'Kibana',
            5044: 'Logstash',
            9090: 'Prometheus',
            3000: 'Grafana',
            9093: 'Alertmanager',
            64297: 'T-Pot Web Interface'
        }
        
        service = port_services.get(port, f'Unknown ({port})')
        
        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = f'SSH ({banner.split()[0] if banner.split() else "Unknown"})'
            elif 'http' in banner_lower and 'server:' in banner_lower:
                server = banner.split('Server:')[1].split('\r\n')[0].strip()
                service = f'HTTP ({server})'
            elif 'ftp' in banner_lower:
                service = f'FTP ({banner.split()[0] if banner.split() else "Unknown"})'
            elif 'elasticsearch' in banner_lower:
                service = 'Elasticsearch'
        
        return service
    
    def run_nmap_scan(self, target):
        """Run detailed nmap scan on target"""
        try:
            cmd = [
                'nmap', '-sS', '-O', '-sV', '--script=default',
                '-oX', f'/tmp/nmap_{target.replace("/", "_")}.xml',
                str(target)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Nmap scan completed for {target}")
                return result.stdout
            else:
                logger.error(f"Nmap scan failed for {target}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out for {target}")
            return None
        except FileNotFoundError:
            logger.warning("Nmap not found, skipping detailed scan")
            return None
    
    def scan_network(self):
        """Scan all targets"""
        logger.info(f"Starting network scan of {len(self.targets)} targets")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_host_ports, target): target 
                for target in self.targets
            }
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    self.results[str(target)] = result
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}")
                    self.results[str(target)] = {
                        'host': str(target),
                        'error': str(e),
                        'scan_time': datetime.now().isoformat()
                    }
    
    def generate_report(self):
        """Generate scan report"""
        end_time = datetime.now()
        scan_duration = (end_time - self.start_time).total_seconds()
        
        # Calculate statistics
        total_hosts = len(self.targets)
        alive_hosts = sum(1 for r in self.results.values() if r.get('alive', False))
        total_open_ports = sum(len(r.get('open_ports', [])) for r in self.results.values())
        
        report = {
            'scan_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': scan_duration,
                'scanner_version': '1.0',
                'targets_scanned': total_hosts,
                'alive_hosts': alive_hosts,
                'total_open_ports': total_open_ports
            },
            'summary': {
                'alive_hosts': alive_hosts,
                'dead_hosts': total_hosts - alive_hosts,
                'total_open_ports': total_open_ports,
                'avg_ports_per_host': total_open_ports / max(alive_hosts, 1)
            },
            'results': self.results
        }
        
        # Identify potential security issues
        security_issues = []
        for host, data in self.results.items():
            if not data.get('alive', False):
                continue
                
            open_ports = data.get('open_ports', [])
            
            # Check for common vulnerabilities
            if 23 in open_ports:  # Telnet
                security_issues.append({
                    'host': host,
                    'issue': 'Telnet service detected',
                    'severity': 'high',
                    'description': 'Telnet transmits data in plaintext'
                })
            
            if 21 in open_ports:  # FTP
                security_issues.append({
                    'host': host,
                    'issue': 'FTP service detected',
                    'severity': 'medium',
                    'description': 'FTP may transmit credentials in plaintext'
                })
            
            if 3389 in open_ports:  # RDP
                security_issues.append({
                    'host': host,
                    'issue': 'RDP service exposed',
                    'severity': 'medium',
                    'description': 'RDP should be protected by VPN or firewall'
                })
            
            # Check for too many open ports (potential security risk)
            if len(open_ports) > 20:
                security_issues.append({
                    'host': host,
                    'issue': 'Many open ports detected',
                    'severity': 'low',
                    'description': f'{len(open_ports)} open ports detected'
                })
        
        report['security_issues'] = security_issues
        
        return report
    
    def save_report(self, report):
        """Save report to file"""
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to {self.output_file}")
            except IOError as e:
                logger.error(f"Failed to save report: {e}")
        
        # Also save to timestamped file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        timestamped_file = f"/tmp/network_scan_{timestamp}.json"
        try:
            with open(timestamped_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report also saved to {timestamped_file}")
        except IOError as e:
            logger.error(f"Failed to save timestamped report: {e}")
    
    def print_summary(self, report):
        """Print scan summary"""
        print("\n" + "="*60)
        print("T-POT NETWORK SCAN SUMMARY")
        print("="*60)
        print(f"Scan Duration: {report['scan_info']['duration_seconds']:.2f} seconds")
        print(f"Targets Scanned: {report['scan_info']['targets_scanned']}")
        print(f"Alive Hosts: {report['summary']['alive_hosts']}")
        print(f"Dead Hosts: {report['summary']['dead_hosts']}")
        print(f"Total Open Ports: {report['summary']['total_open_ports']}")
        print(f"Avg Ports/Host: {report['summary']['avg_ports_per_host']:.1f}")
        
        print(f"\nSECURITY ISSUES FOUND: {len(report['security_issues'])}")
        for issue in report['security_issues']:
            severity_symbol = {
                'high': '🔴',
                'medium': '🟡', 
                'low': '🟢'
            }.get(issue['severity'], '⚪')
            print(f"{severity_symbol} {issue['host']}: {issue['issue']}")
        
        print(f"\nALIVE HOSTS:")
        for host, data in report['results'].items():
            if data.get('alive', False):
                ports = data.get('open_ports', [])
                print(f"  {host}: {len(ports)} open ports {ports[:10]}{'...' if len(ports) > 10 else ''}")
        
        print("="*60)

def parse_targets(target_string):
    """Parse target specification into list of IP addresses"""
    targets = []
    
    for target in target_string.split(','):
        target = target.strip()
        
        try:
            # Check if it's a network range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                targets.extend(list(network.hosts()))
            # Check if it's a range (e.g., 192.168.1.1-10)
            elif '-' in target and target.count('.') == 3:
                base_ip, range_part = target.rsplit('.', 1)
                if '-' in range_part:
                    start, end = range_part.split('-')
                    for i in range(int(start), int(end) + 1):
                        targets.append(ipaddress.ip_address(f"{base_ip}.{i}"))
                else:
                    targets.append(ipaddress.ip_address(target))
            else:
                # Single IP or hostname
                targets.append(ipaddress.ip_address(target))
        except ValueError:
            # Try to resolve hostname
            try:
                resolved_ip = socket.gethostbyname(target)
                targets.append(ipaddress.ip_address(resolved_ip))
            except socket.gaierror:
                logger.error(f"Could not resolve target: {target}")
    
    return targets

def main():
    parser = argparse.ArgumentParser(
        description='T-Pot Infrastructure Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24
  %(prog)s -t 10.0.100.1-20
  %(prog)s -t 192.168.1.1,10.0.100.10,192.168.1.0/24
  %(prog)s -t 192.168.1.0/24 -o scan_results.json -j 100
        """
    )
    
    parser.add_argument(
        '-t', '--targets',
        required=True,
        help='Target specification (IP, range, or CIDR)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '-j', '--threads',
        type=int,
        default=50,
        help='Number of threads to use (default: 50)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--nmap',
        action='store_true',
        help='Run detailed nmap scans on alive hosts'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse targets
    targets = parse_targets(args.targets)
    if not targets:
        logger.error("No valid targets specified")
        sys.exit(1)
    
    logger.info(f"Parsed {len(targets)} targets")
    
    # Create scanner and run scan
    scanner = NetworkScanner(targets, args.output, args.threads)
    scanner.scan_network()
    
    # Run nmap scans if requested
    if args.nmap:
        logger.info("Running detailed nmap scans...")
        for target in targets:
            if scanner.results.get(str(target), {}).get('alive', False):
                nmap_result = scanner.run_nmap_scan(target)
                if nmap_result:
                    scanner.results[str(target)]['nmap_output'] = nmap_result
    
    # Generate and save report
    report = scanner.generate_report()
    scanner.save_report(report)
    scanner.print_summary(report)

if __name__ == '__main__':
    main()