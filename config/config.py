"""
DNS Threat Monitor Configuration

Central configuration file for the DNS Threat Monitor system.
All adjustable parameters are defined here to avoid hardcoding values elsewhere.

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

    # Get the main project folder
    PROJECT_ROOT = Path(__file__).parent.parent

    # Where the database file is stored
    DATABASE_FILE = PROJECT_ROOT / os.getenv("DB_FILENAME", "dns_threat_monitor.db")

    # File with known malicious domains
    THREATS_FILE = PROJECT_ROOT / os.getenv("THREATS_FILENAME", "threats.txt")

    # Where logs are written
    LOG_FILE = PROJECT_ROOT / 'logs' / os.getenv("LOG_FILENAME", "dns_monitor.log")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO") # DEBUG, INFO, WARNING, ERROR, CRITICAL

    # ============================================================================
    # CAPTURE CONFIGURATION
    # ============================================================================

    # Network card to capture traffic from
    CAPTURE_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")  # Change this to match the network interface

    # DNS log file path (For technitium)
    #todo
    DNSMASQ_LOG_PATH = os.getenv("DNSMASQ_LOG_PATH", "/var/log/dnsmasq.log")

    # ============================================================================
    # DETECTION CONFIGURATION
    # ============================================================================

    # Rule thresholds
    HIGH_QUERY_RATE_LIMIT = int(os.getenv("QUERY_RATE_LIMIT", "50"))  # queries per minute
    NXDOMAIN_LIMIT = int(os.getenv("NXDOMAIN_LIMIT", "10"))        # NXDOMAIN replies per minute
    SUBDOMAIN_LIMIT = int(os.getenv("SUBDOMAIN_LIMIT", "20"))        # unique subdomains per 5 minutes

    # Settings for detecting generated domains (and their default values)
    DGA_ENTROPY_THRESHOLD = float(os.getenv("DGA_ENTROPY_THRESHOLD", "3.5"))
    DGA_MIN_LENGTH = int(os.getenv("DGA_MIN_LENGTH", "12"))

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {".xyz", ".tk", ".top", ".pw", ".cc", ".su", ".ml", ".site", ".shop"}


    # ============================================================================
    # BLACKLIST CONFIGURATION
    # ============================================================================

    # Whether to update blacklist from internet
    ENABLE_REMOTE_BLACKLIST = os.getenv("ENABLE_REMOTE_BLACKLIST", "true").lower() == "true"    #Has to be converted to a boolean

    # Remote blacklist URLs
    REMOTE_BLACKLIST_URLS = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    ]

    # How often to refresh each source
    BLACKLIST_REFRESH_URLHAUS = int(os.getenv("URLHAUS_REFRESH_HOURS", "24"))
    BLACKLIST_REFRESH_OPENPHISH = int(os.getenv("OPENPHISH_REFRESH_HOURS", "12"))

    # ============================================================================
    # DASHBOARD CONFIGURATION
    # ============================================================================

    # Web server settings
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
    DASHBOARD_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

    # How often dashboard updates
    DASHBOARD_UPDATE_INTERVAL = int(os.getenv("DASHBOARD_UPDATE_INTERVAL", "30"))

    # ============================================================================
    # PERFORMANCE CONFIGURATION
    # ============================================================================

    # Number of processing threads
    PROCESSING_THREADS = int(os.getenv("PROCESSING_THREADS", "2"))

    # Event queue size
    QUEUE_SIZE = int(os.getenv("QUEUE_SIZE", "1000"))

    # Database query limits
    MAX_DNS_LOGS_LIMIT = int(os.getenv("MAX_DNS_LOGS_LIMIT", "1000"))
    MAX_ALERTS_LIMIT = int(os.getenv("MAX_ALERTS_LIMIT", "100"))

    # Default time range for queries
    DEFAULT_TIME_RANGE_HOURS = int(os.getenv("DEFAULT_TIME_RANGE_HOURS", "24"))

    # ============================================================================
    # SYSTEM LIMITS
    # ============================================================================

    # System resource limits
    MAX_CPU_PERCENT = float(os.getenv("MAX_CPU_PERCENT", "30.0"))
    MAX_MEMORY_MB = int(os.getenv("MAX_MEMORY_MB", "500"))

    # Max time to detect threats
    MAX_DETECTION_TIME = float(os.getenv("MAX_DETECTION_TIME", "3.0"))

    # ============================================================================
    # DEVELOPMENT/TESTING CONFIGURATION
    # ============================================================================

    # Use fake data for testing
    TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

    # File with test data
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
    print("Configuration validated successfully")
