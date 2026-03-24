"""
Configuration Module

Contains configuration for the DNS Threat Monitor system.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project root
PROJECT_ROOT = Path(__file__).parent

# Database
DATABASE = {
    'path': os.getenv('DB_PATH', str(PROJECT_ROOT / 'dns_threat_monitor.db')),
    'backup_path': os.getenv('DB_BACKUP_PATH', str(PROJECT_ROOT / 'backups'))
}

# Capture
CAPTURE = {
    'interface': os.getenv('CAPTURE_INTERFACE', 'eth0'),
    'filter': os.getenv('CAPTURE_FILTER', 'udp port 53'),
    'snaplen': int(os.getenv('CAPTURE_SNAPLEN', 65535))
}

# Detection
DETECTION = {
    'blacklist_update_interval': int(os.getenv('BLACKLIST_UPDATE_INTERVAL', 86400)),  # 24 hours
    'blacklist_sources': [
        'https://urlhaus-api.abuse.ch/v1/urls/csv/',
        'https://openphish.com/feed.txt',
        'https://rules.abuse.ch/downloads/malware_domains.csv'
    ]
}

# Dashboard
DASHBOARD = {
    'host': os.getenv('DASHBOARD_HOST', '0.0.0.0'),
    'port': int(os.getenv('DASHBOARD_PORT', 5000)),
    'debug': os.getenv('DASHBOARD_DEBUG', 'False').lower() == 'true'
}

# Alerts
ALERTS = {
    'email_enabled': os.getenv('EMAIL_ALERTS_ENABLED', 'False').lower() == 'true',
    'email_to': os.getenv('EMAIL_TO', ''),
    'email_from': os.getenv('EMAIL_FROM', ''),
    'smtp_server': os.getenv('SMTP_SERVER', ''),
    'smtp_port': int(os.getenv('SMTP_PORT', 587))
}

# Logging
LOGGING = {
    'level': os.getenv('LOG_LEVEL', 'INFO'),
    'file': os.getenv('LOG_FILE', str(PROJECT_ROOT / 'dns_threat_monitor.log')),
    'max_bytes': int(os.getenv('LOG_MAX_BYTES', 10485760)),  # 10MB
    'backup_count': int(os.getenv('LOG_BACKUP_COUNT', 5))
}

# Performance
PERFORMANCE = {
    'max_query_rate': int(os.getenv('MAX_QUERY_RATE', 1000)),
    'batch_size': int(os.getenv('BATCH_SIZE', 100)),
    'worker_threads': int(os.getenv('WORKER_THREADS', 4))
}

