#!/usr/bin/env python3
"""
T-Pot Infrastructure Threat Intelligence Collector
This tool collects and processes threat intelligence from various sources
"""

import argparse
import json
import logging
import requests
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import hashlib
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/threat-intel-collector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ThreatIntelCollector:
    """Threat intelligence collector for T-Pot infrastructure"""
    
    def __init__(self, db_path: str = "/data/threat-intel/threat_intel.db"):
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'T-Pot-ThreatIntel-Collector/1.0'
        })
        
        # Threat intelligence feeds
        self.feeds = {
            'abuse_ch_feodo': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
                'type': 'json',
                'description': 'Feodo Tracker IP Blocklist',
                'update_interval': 3600
            },
            'abuse_ch_malware_bazaar': {
                'url': 'https://mb-api.abuse.ch/api/v1/',
                'type': 'api',
                'description': 'MalwareBazaar Recent Samples',
                'update_interval': 3600
            },
            'abuse_ch_urlhaus': {
                'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                'type': 'json',
                'description': 'URLhaus Recent URLs',
                'update_interval': 1800
            },
            'alienvault_otx': {
                'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
                'type': 'json',
                'description': 'AlienVault OTX Pulses',
                'update_interval': 7200,
                'requires_auth': True
            },
            'emergingthreats_compromised': {
                'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'type': 'text',
                'description': 'Emerging Threats Compromised IPs',
                'update_interval': 3600
            },
            'tor_exit_nodes': {
                'url': 'https://check.torproject.org/torbulkexitlist',
                'type': 'text',
                'description': 'Tor Exit Nodes',
                'update_interval': 3600
            }
        }
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for threat intelligence storage"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_ips (
                    ip TEXT PRIMARY KEY,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    source TEXT,
                    threat_type TEXT,
                    confidence INTEGER,
                    description TEXT,
                    country TEXT,
                    asn TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_hashes (
                    hash TEXT PRIMARY KEY,
                    hash_type TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    source TEXT,
                    malware_family TEXT,
                    file_type TEXT,
                    file_size INTEGER,
                    description TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_urls (
                    url TEXT PRIMARY KEY,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    source TEXT,
                    threat_type TEXT,
                    status TEXT,
                    tags TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS feed_updates (
                    feed_name TEXT PRIMARY KEY,
                    last_update TIMESTAMP,
                    status TEXT,
                    records_added INTEGER,
                    error_message TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_last_seen ON malicious_ips(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash_last_seen ON malware_hashes(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_last_seen ON malicious_urls(last_seen)')
            
            conn.commit()
        
        logger.info("Database initialized successfully")
    
    def collect_feodo_tracker(self) -> int:
        """Collect data from Feodo Tracker"""
        try:
            response = self.session.get(self.feeds['abuse_ch_feodo']['url'], timeout=30)
            response.raise_for_status()
            
            data = response.json()
            records_added = 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for entry in data:
                    ip = entry.get('ip_address')
                    if not ip:
                        continue
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO malicious_ips 
                        (ip, first_seen, last_seen, source, threat_type, confidence, description)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ip,
                        entry.get('first_seen'),
                        entry.get('last_seen'),
                        'abuse_ch_feodo',
                        entry.get('malware', 'botnet'),
                        entry.get('confidence', 75),
                        f"Feodo Tracker: {entry.get('malware', 'Unknown malware')}"
                    ))
                    records_added += 1
                
                conn.commit()
            
            logger.info(f"Collected {records_added} IPs from Feodo Tracker")
            return records_added
            
        except Exception as e:
            logger.error(f"Error collecting from Feodo Tracker: {e}")
            return 0
    
    def collect_malware_bazaar(self) -> int:
        """Collect data from MalwareBazaar"""
        try:
            # Get recent samples
            payload = {'query': 'get_recent', 'selector': '100'}
            response = self.session.post(
                self.feeds['abuse_ch_malware_bazaar']['url'],
                data=payload,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            records_added = 0
            
            if data.get('query_status') != 'ok':
                logger.warning(f"MalwareBazaar query failed: {data.get('query_status')}")
                return 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for entry in data.get('data', []):
                    sha256_hash = entry.get('sha256_hash')
                    md5_hash = entry.get('md5_hash')
                    
                    if sha256_hash:
                        cursor.execute('''
                            INSERT OR REPLACE INTO malware_hashes 
                            (hash, hash_type, first_seen, last_seen, source, malware_family, file_type, file_size, description)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            sha256_hash,
                            'sha256',
                            entry.get('first_seen'),
                            entry.get('last_seen'),
                            'abuse_ch_malware_bazaar',
                            entry.get('signature'),
                            entry.get('file_type'),
                            entry.get('file_size'),
                            f"MalwareBazaar: {entry.get('signature', 'Unknown')}"
                        ))
                        records_added += 1
                    
                    if md5_hash:
                        cursor.execute('''
                            INSERT OR REPLACE INTO malware_hashes 
                            (hash, hash_type, first_seen, last_seen, source, malware_family, file_type, file_size, description)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            md5_hash,
                            'md5',
                            entry.get('first_seen'),
                            entry.get('last_seen'),
                            'abuse_ch_malware_bazaar',
                            entry.get('signature'),
                            entry.get('file_type'),
                            entry.get('file_size'),
                            f"MalwareBazaar: {entry.get('signature', 'Unknown')}"
                        ))
                        records_added += 1
                
                conn.commit()
            
            logger.info(f"Collected {records_added} hashes from MalwareBazaar")
            return records_added
            
        except Exception as e:
            logger.error(f"Error collecting from MalwareBazaar: {e}")
            return 0
    
    def collect_urlhaus(self) -> int:
        """Collect data from URLhaus"""
        try:
            response = self.session.get(self.feeds['abuse_ch_urlhaus']['url'], timeout=30)
            response.raise_for_status()
            
            data = response.json()
            records_added = 0
            
            if data.get('query_status') != 'ok':
                logger.warning(f"URLhaus query failed: {data.get('query_status')}")
                return 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for entry in data.get('urls', []):
                    url = entry.get('url')
                    if not url:
                        continue
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO malicious_urls 
                        (url, first_seen, last_seen, source, threat_type, status, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        url,
                        entry.get('date_added'),
                        entry.get('last_online'),
                        'abuse_ch_urlhaus',
                        entry.get('threat'),
                        entry.get('url_status'),
                        ','.join(entry.get('tags', []))
                    ))
                    records_added += 1
                
                conn.commit()
            
            logger.info(f"Collected {records_added} URLs from URLhaus")
            return records_added
            
        except Exception as e:
            logger.error(f"Error collecting from URLhaus: {e}")
            return 0
    
    def collect_emerging_threats(self) -> int:
        """Collect data from Emerging Threats"""
        try:
            response = self.session.get(
                self.feeds['emergingthreats_compromised']['url'],
                timeout=30
            )
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            records_added = 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        ip = ipaddress.ip_address(line)
                        cursor.execute('''
                            INSERT OR REPLACE INTO malicious_ips 
                            (ip, first_seen, last_seen, source, threat_type, confidence, description)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            str(ip),
                            datetime.now().isoformat(),
                            datetime.now().isoformat(),
                            'emergingthreats_compromised',
                            'compromised',
                            80,
                            'Emerging Threats Compromised IP'
                        ))
                        records_added += 1
                    except ValueError:
                        continue
                
                conn.commit()
            
            logger.info(f"Collected {records_added} IPs from Emerging Threats")
            return records_added
            
        except Exception as e:
            logger.error(f"Error collecting from Emerging Threats: {e}")
            return 0
    
    def collect_tor_exit_nodes(self) -> int:
        """Collect Tor exit nodes"""
        try:
            response = self.session.get(self.feeds['tor_exit_nodes']['url'], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            records_added = 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        ip = ipaddress.ip_address(line)
                        cursor.execute('''
                            INSERT OR REPLACE INTO malicious_ips 
                            (ip, first_seen, last_seen, source, threat_type, confidence, description)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            str(ip),
                            datetime.now().isoformat(),
                            datetime.now().isoformat(),
                            'tor_exit_nodes',
                            'anonymizer',
                            60,
                            'Tor Exit Node'
                        ))
                        records_added += 1
                    except ValueError:
                        continue
                
                conn.commit()
            
            logger.info(f"Collected {records_added} Tor exit nodes")
            return records_added
            
        except Exception as e:
            logger.error(f"Error collecting Tor exit nodes: {e}")
            return 0
    
    def update_feed_status(self, feed_name: str, status: str, records_added: int = 0, error_message: str = None):
        """Update feed status in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO feed_updates 
                (feed_name, last_update, status, records_added, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                feed_name,
                datetime.now().isoformat(),
                status,
                records_added,
                error_message
            ))
            conn.commit()
    
    def collect_all_feeds(self):
        """Collect data from all configured feeds"""
        logger.info("Starting threat intelligence collection from all feeds")
        
        total_records = 0
        
        # Feodo Tracker
        try:
            records = self.collect_feodo_tracker()
            total_records += records
            self.update_feed_status('abuse_ch_feodo', 'success', records)
        except Exception as e:
            self.update_feed_status('abuse_ch_feodo', 'error', 0, str(e))
        
        # MalwareBazaar
        try:
            records = self.collect_malware_bazaar()
            total_records += records
            self.update_feed_status('abuse_ch_malware_bazaar', 'success', records)
        except Exception as e:
            self.update_feed_status('abuse_ch_malware_bazaar', 'error', 0, str(e))
        
        # URLhaus
        try:
            records = self.collect_urlhaus()
            total_records += records
            self.update_feed_status('abuse_ch_urlhaus', 'success', records)
        except Exception as e:
            self.update_feed_status('abuse_ch_urlhaus', 'error', 0, str(e))
        
        # Emerging Threats
        try:
            records = self.collect_emerging_threats()
            total_records += records
            self.update_feed_status('emergingthreats_compromised', 'success', records)
        except Exception as e:
            self.update_feed_status('emergingthreats_compromised', 'error', 0, str(e))
        
        # Tor Exit Nodes
        try:
            records = self.collect_tor_exit_nodes()
            total_records += records
            self.update_feed_status('tor_exit_nodes', 'success', records)
        except Exception as e:
            self.update_feed_status('tor_exit_nodes', 'error', 0, str(e))
        
        logger.info(f"Threat intelligence collection completed. Total records: {total_records}")
        return total_records
    
    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP in threat intelligence database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM malicious_ips WHERE ip = ?
            ''', (ip,))
            
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
        
        return None
    
    def lookup_hash(self, hash_value: str) -> Optional[Dict]:
        """Lookup hash in threat intelligence database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM malware_hashes WHERE hash = ?
            ''', (hash_value,))
            
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
        
        return None
    
    def lookup_url(self, url: str) -> Optional[Dict]:
        """Lookup URL in threat intelligence database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM malicious_urls WHERE url = ?
            ''', (url,))
            
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # IP statistics
            cursor.execute('SELECT COUNT(*) FROM malicious_ips')
            stats['total_ips'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM malicious_ips WHERE last_seen > ?', 
                          ((datetime.now() - timedelta(days=7)).isoformat(),))
            stats['recent_ips'] = cursor.fetchone()[0]
            
            # Hash statistics
            cursor.execute('SELECT COUNT(*) FROM malware_hashes')
            stats['total_hashes'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM malware_hashes WHERE last_seen > ?',
                          ((datetime.now() - timedelta(days=7)).isoformat(),))
            stats['recent_hashes'] = cursor.fetchone()[0]
            
            # URL statistics
            cursor.execute('SELECT COUNT(*) FROM malicious_urls')
            stats['total_urls'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM malicious_urls WHERE last_seen > ?',
                          ((datetime.now() - timedelta(days=7)).isoformat(),))
            stats['recent_urls'] = cursor.fetchone()[0]
            
            # Feed statistics
            cursor.execute('SELECT feed_name, last_update, status, records_added FROM feed_updates')
            stats['feeds'] = {}
            for row in cursor.fetchall():
                stats['feeds'][row[0]] = {
                    'last_update': row[1],
                    'status': row[2],
                    'records_added': row[3]
                }
        
        return stats
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old threat intelligence data"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Clean up old IPs
            cursor.execute('DELETE FROM malicious_ips WHERE last_seen < ?', (cutoff_date,))
            deleted_ips = cursor.rowcount
            
            # Clean up old hashes
            cursor.execute('DELETE FROM malware_hashes WHERE last_seen < ?', (cutoff_date,))
            deleted_hashes = cursor.rowcount
            
            # Clean up old URLs
            cursor.execute('DELETE FROM malicious_urls WHERE last_seen < ?', (cutoff_date,))
            deleted_urls = cursor.rowcount
            
            conn.commit()
        
        logger.info(f"Cleaned up old data: {deleted_ips} IPs, {deleted_hashes} hashes, {deleted_urls} URLs")
        return deleted_ips + deleted_hashes + deleted_urls
    
    def export_iocs(self, output_file: str, format: str = 'json'):
        """Export IOCs to file"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get all IOCs
            cursor.execute('SELECT ip, threat_type, confidence, source FROM malicious_ips')
            ips = cursor.fetchall()
            
            cursor.execute('SELECT hash, hash_type, malware_family, source FROM malware_hashes')
            hashes = cursor.fetchall()
            
            cursor.execute('SELECT url, threat_type, source FROM malicious_urls')
            urls = cursor.fetchall()
        
        if format.lower() == 'json':
            data = {
                'generated': datetime.now().isoformat(),
                'ips': [{'ip': row[0], 'threat_type': row[1], 'confidence': row[2], 'source': row[3]} for row in ips],
                'hashes': [{'hash': row[0], 'hash_type': row[1], 'malware_family': row[2], 'source': row[3]} for row in hashes],
                'urls': [{'url': row[0], 'threat_type': row[1], 'source': row[2]} for row in urls]
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        elif format.lower() == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['type', 'value', 'threat_type', 'confidence', 'source'])
                
                for row in ips:
                    writer.writerow(['ip', row[0], row[1], row[2], row[3]])
                
                for row in hashes:
                    writer.writerow(['hash', row[0], row[2], '', row[3]])
                
                for row in urls:
                    writer.writerow(['url', row[0], row[1], '', row[2]])
        
        logger.info(f"Exported IOCs to {output_file} in {format} format")

def main():
    parser = argparse.ArgumentParser(
        description='T-Pot Threat Intelligence Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--collect',
        action='store_true',
        help='Collect threat intelligence from all feeds'
    )
    
    parser.add_argument(
        '--lookup-ip',
        help='Lookup IP address in threat intelligence database'
    )
    
    parser.add_argument(
        '--lookup-hash',
        help='Lookup hash in threat intelligence database'
    )
    
    parser.add_argument(
        '--lookup-url',
        help='Lookup URL in threat intelligence database'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show threat intelligence statistics'
    )
    
    parser.add_argument(
        '--cleanup',
        type=int,
        metavar='DAYS',
        help='Clean up data older than specified days'
    )
    
    parser.add_argument(
        '--export',
        help='Export IOCs to file'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'csv'],
        default='json',
        help='Export format (default: json)'
    )
    
    parser.add_argument(
        '--db-path',
        default='/data/threat-intel/threat_intel.db',
        help='Path to threat intelligence database'
    )
    
    args = parser.parse_args()
    
    collector = ThreatIntelCollector(args.db_path)
    
    if args.collect:
        collector.collect_all_feeds()
    
    elif args.lookup_ip:
        result = collector.lookup_ip(args.lookup_ip)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"IP {args.lookup_ip} not found in threat intelligence database")
    
    elif args.lookup_hash:
        result = collector.lookup_hash(args.lookup_hash)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"Hash {args.lookup_hash} not found in threat intelligence database")
    
    elif args.lookup_url:
        result = collector.lookup_url(args.lookup_url)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"URL {args.lookup_url} not found in threat intelligence database")
    
    elif args.stats:
        stats = collector.get_statistics()
        print(json.dumps(stats, indent=2))
    
    elif args.cleanup:
        deleted = collector.cleanup_old_data(args.cleanup)
        print(f"Cleaned up {deleted} old records")
    
    elif args.export:
        collector.export_iocs(args.export, args.format)
        print(f"IOCs exported to {args.export}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()