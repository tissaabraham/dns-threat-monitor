"""
DNS Threat Monitor Configuration
================================

Central configuration file for the DNS Threat Monitor system.
All configurable parameters should be defined here to avoid hardcoding.
"""

import os
from pathlib import Path


class Config:
    """
    Configuration class for DNS Threat Monitor.
    Centralizes all system configuration parameters.
    """

    # ============================================================================
    # PATHS AND FILES
    # ============================================================================

    # Project root directory
    PROJECT_ROOT = Path(__file__).parent.parent

    # Database
    DATABASE_FILE = PROJECT_ROOT / 'dns_threat_monitor.db'

    # Threat intelligence
    THREATS_FILE = PROJECT_ROOT / 'threats.txt'

    # Logging
    LOG_FILE = PROJECT_ROOT / 'logs' / 'dns_monitor.log'
    LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR, CRITICAL

    # ============================================================================
    # CAPTURE CONFIGURATION
    # ============================================================================

    # Network interface for tshark capture
    CAPTURE_INTERFACE = "eth0"  # Change this to match your network interface

    # DNS log file path (for dnsmasq)
    DNSMASQ_LOG_PATH = "/var/log/dnsmasq.log"

    # ============================================================================
    # PROCESSING CONFIGURATION
    # ============================================================================

    # Number of processing threads
    PROCESSING_THREADS = 2

    # Event queue size
    QUEUE_SIZE = 1000

    # ============================================================================
    # DETECTION CONFIGURATION
    # ============================================================================

    # Rule thresholds
    HIGH_QUERY_RATE_LIMIT = 50  # queries per minute
    NXDOMAIN_LIMIT = 10         # NXDOMAIN replies per minute
    SUBDOMAIN_LIMIT = 20        # unique subdomains per 5 minutes

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {".xyz", ".tk", ".top", ".pw", ".cc", ".su", ".ml", ".site"}

    # DGA detection
    DGA_ENTROPY_THRESHOLD = 3.5
    DGA_MIN_LENGTH = 12

    # ============================================================================
    # BLACKLIST CONFIGURATION
    # ============================================================================

    # Enable remote blacklist updates
    ENABLE_REMOTE_BLACKLIST = True

    # Remote blacklist URLs
    REMOTE_BLACKLIST_URLS = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    ]

    # Blacklist refresh intervals (in hours)
    BLACKLIST_REFRESH_INTERVALS = {
        "urlhaus.abuse.ch": 24,    # Daily
        "openphish": 12            # Twice daily
    }

    # ============================================================================
    # DASHBOARD CONFIGURATION
    # ============================================================================

    # Web server settings
    DASHBOARD_HOST = "0.0.0.0"
    DASHBOARD_PORT = 5000
    DASHBOARD_DEBUG = False

    # Dashboard refresh intervals (in seconds)
    DASHBOARD_UPDATE_INTERVAL = 30

    # ============================================================================
    # PERFORMANCE CONFIGURATION
    # ============================================================================

    # Database query limits
    MAX_DNS_LOGS_LIMIT = 1000
    MAX_ALERTS_LIMIT = 100

    # Time range defaults (in hours)
    DEFAULT_TIME_RANGE_HOURS = 24

    # ============================================================================
    # SYSTEM LIMITS
    # ============================================================================

    # Resource limits
    MAX_CPU_PERCENT = 30.0
    MAX_MEMORY_MB = 500

    # Detection time limits (in seconds)
    MAX_DETECTION_TIME = 3.0

    # ============================================================================
    # DEVELOPMENT/TESTING CONFIGURATION
    # ============================================================================

    # Enable test mode (uses mock data instead of live capture)
    TEST_MODE = False

    # Test data file
    TEST_DATA_FILE = PROJECT_ROOT / 'tests' / 'test_dns_data.txt'

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    @classmethod
    def get_database_path(cls) -> str:
        """Get the full path to the database file."""
        return str(cls.DATABASE_FILE)

    @classmethod
    def get_log_path(cls) -> str:
        """Get the full path to the log file."""
        return str(cls.LOG_FILE)

    @classmethod
    def ensure_directories_exist(cls):
        """Ensure all required directories exist."""
        directories = [
            cls.PROJECT_ROOT / 'logs',
            cls.PROJECT_ROOT / 'database',
            cls.PROJECT_ROOT / 'tests',
            cls.PROJECT_ROOT / 'docs'
        ]

        for directory in directories:
            directory.mkdir(exist_ok=True)

    @classmethod
    def validate_configuration(cls):
        """Validate the configuration for common issues."""
        issues = []

        # Check if threats file exists
        if not cls.THREATS_FILE.exists():
            issues.append(f"Threats file not found: {cls.THREATS_FILE}")

        # Check database directory is writable
        db_dir = cls.DATABASE_FILE.parent
        if not db_dir.exists():
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create database directory: {e}")

        # Check log directory is writable
        log_dir = cls.LOG_FILE.parent
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create log directory: {e}")

        return issues

    @classmethod
    def print_configuration(cls):
        """Print current configuration for debugging."""
        print("=== DNS Threat Monitor Configuration ===")
        print(f"Project Root: {cls.PROJECT_ROOT}")
        print(f"Database: {cls.DATABASE_FILE}")
        print(f"Threats File: {cls.THREATS_FILE}")
        print(f"Log File: {cls.LOG_FILE}")
        print(f"Processing Threads: {cls.PROCESSING_THREADS}")
        print(f"Queue Size: {cls.QUEUE_SIZE}")
        print(f"Remote Blacklist: {cls.ENABLE_REMOTE_BLACKLIST}")
        print(f"Test Mode: {cls.TEST_MODE}")
        print("========================================")


# Initialize configuration on import
Config.ensure_directories_exist()

# Validate configuration
issues = Config.validate_configuration()
if issues:
    print("Configuration Issues Found:")
    for issue in issues:
        print(f"  - {issue}")
else:
    print("✓ Configuration validated successfully")
