"""
DNS Threat Monitor Configuration
================================

Central configuration file for the DNS Threat Monitor system.
All configurable parameters should be defined here to avoid hardcoding.

> Changes made to work with the .env file rather than having them be hardcoded.
> Booleans need to be handled and Ints need to be cast, otherwise will cause problems as evnironment variables are always strings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()  # reads .env into os.environ before any getenv() calls


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
    DATABASE_FILE = PROJECT_ROOT / os.getenv("DB_FILENAME", "dns_threat_monitor.db")

    # Threat intelligence
    THREATS_FILE = PROJECT_ROOT / os.getenv("THREATS_FILENAME", "threats.txt")

    # Logging
    LOG_FILE = PROJECT_ROOT / 'logs' / os.getenv("LOG_FILENAME", "dns_monitor.log")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO") # DEBUG, INFO, WARNING, ERROR, CRITICAL

    # ============================================================================
    # CAPTURE CONFIGURATION
    # ============================================================================

    # Network interface for tshark capture
    CAPTURE_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")  # Change this to match your network interface

    # DNS log file path (for dnsmasq)
    DNSMASQ_LOG_PATH = os.getenv("DNSMASQ_LOG_PATH", "/var/log/dnsmasq.log")

    # ============================================================================
    # DETECTION CONFIGURATION
    # ============================================================================

    # Rule thresholds
    HIGH_QUERY_RATE_LIMIT = int(os.getenv("QUERY_RATE_LIMIT", "50"))  # queries per minute
    NXDOMAIN_LIMIT = int(os.getenv("NXDOMAIN_LIMIT", "10"))        # NXDOMAIN replies per minute
    SUBDOMAIN_LIMIT = int(os.getenv("SUBDOMAIN_LIMIT", "20"))        # unique subdomains per 5 minutes

    # DGA detection
    DGA_ENTROPY_THRESHOLD = float(os.getenv("DGA_ENTROPY_THRESHOLD", "3.5"))
    DGA_MIN_LENGTH = int(os.getenv("DGA_MIN_LENGTH", "12"))

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {".xyz", ".tk", ".top", ".pw", ".cc", ".su", ".ml", ".site", ".shop"}


    # ============================================================================
    # BLACKLIST CONFIGURATION
    # ============================================================================

    # Enable remote blacklist updates
    ENABLE_REMOTE_BLACKLIST = os.getenv("ENABLE_REMOTE_BLACKLIST", "true").lower() == "true"    #Has to be converted to a boolean

    # Remote blacklist URLs
    REMOTE_BLACKLIST_URLS = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    ]

    # Blacklist refresh intervals (in hours)
    BLACKLIST_REFRESH_URLHAUS = int(os.getenv("URLHAUS_REFRESH_HOURS", "24"))
    BLACKLIST_REFRESH_OPENPHISH = int(os.getenv("OPENPHISH_REFRESH_HOURS", "12"))

    # ============================================================================
    # DASHBOARD CONFIGURATION
    # ============================================================================

    # Web server settings
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
    DASHBOARD_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

    # Dashboard refresh intervals (in seconds)
    DASHBOARD_UPDATE_INTERVAL = int(os.getenv("DASHBOARD_UPDATE_INTERVAL", "30"))

    # ============================================================================
    # EMAIL ALERTING CONFIGURATION
    # ============================================================================

    # Enable email notifications
    ENABLE_EMAIL_ALERTS = os.getenv("ENABLE_EMAIL_ALERTS", "false").lower() == "true"

    # SMTP settings
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")  # sensitive - important to be in .env
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    # Email settings
    ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "dns-monitor@example.com")
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "admin@example.com").split(",")
    ALERT_EMAIL_SUBJECT = os.getenv("ALERT_EMAIL_SUBJECT", "DNS Threat Monitor Alert")

    # Alert thresholds for email notifications
    EMAIL_ALERT_SEVERITY = os.getenv("EMAIL_ALERT_SEVERITY", "HIGH")

    # ============================================================================
    # PROCESSING & PERFORMANCE CONFIGURATION
    # ============================================================================

    # Number of processing threads
    PROCESSING_THREADS = int(os.getenv("PROCESSING_THREADS", "2"))

    # Event queue size
    QUEUE_SIZE = int(os.getenv("QUEUE_SIZE", "1000"))

    # Database query limits
    MAX_DNS_LOGS_LIMIT = int(os.getenv("MAX_DNS_LOGS_LIMIT", "1000"))
    MAX_ALERTS_LIMIT = int(os.getenv("MAX_ALERTS_LIMIT", "100"))

    # Time range defaults (in hours)
    DEFAULT_TIME_RANGE_HOURS = int(os.getenv("DEFAULT_TIME_RANGE_HOURS", "24"))

    # ============================================================================
    # SYSTEM LIMITS
    # ============================================================================

    # Resource limits
    MAX_CPU_PERCENT = float(os.getenv("MAX_CPU_PERCENT", "30.0"))
    MAX_MEMORY_MB = int(os.getenv("MAX_MEMORY_MB", "500"))

    # Detection time limits (in seconds)
    MAX_DETECTION_TIME = float(os.getenv("MAX_DETECTION_TIME", "3.0"))

    # ============================================================================
    # DEVELOPMENT/TESTING CONFIGURATION
    # ============================================================================

    # Enable test mode (uses mock data instead of live capture)
    TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

    # Test data file
    TEST_DATA_FILE = PROJECT_ROOT / 'tests' / os.getenv("TEST_DATA_FILE", "test_dns_data.txt")

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
        # I think Tissa wants these replaced with logger, and only when called.
        # Need to adjust this.
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