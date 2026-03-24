"""
Database Schema

Defines SQLite database schema for storing:
- DNS logs
- Alerts
- Detection outcomes
- Alert lifecycle states
"""

SCHEMA_SQL = """
-- DNS Logs Table
CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    response_code INTEGER,
    response_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_domain (domain)
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dns_log_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,  -- not_significant, low, medium, high
    threat_score INTEGER NOT NULL,
    rules_triggered TEXT,  -- JSON list of triggered rules
    status TEXT DEFAULT 'new',  -- new, acknowledged, resolved, archived
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dns_log_id) REFERENCES dns_logs(id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

-- Blacklist Table
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,  -- URLhaus, Malware Domains List, OpenPhish
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain)
);

-- Statistics Table
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_queries INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0,
    high_severity_alerts INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp)
);

-- Configuration Table
CREATE TABLE IF NOT EXISTS configuration (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

