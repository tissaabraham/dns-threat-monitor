import sqlite3
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List
import json
# Import data model classes (Alert, DnsEvent, ThreatCacheEntry) from dataModels.py
# These classes define the structure for DNS events, alerts, and threat cache entries
from .dataModels import Alert, DnsEvent, ThreatCacheEntry

# ============================================================================
# DATABASE MANAGER - Core DATABASE OPERATIONS
# ============================================================================

class DatabaseManager:
    """
    Manages all interactions with the SQLite database.
    Handles initialization, CRUD operations, and queries for the dashboard.
    """

    # Database file path - stored in the project root
    DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dns_threat_monitor.db')

    def __init__(self):
        """Initialize database connection and create tables if they don't exist."""
        self.connection = None
        self.initialize_database()

    def initialize_database(self):
        """
        6.2 Database Initialisation
        
        When the application starts, check if the database exists.
        If not, automatically create the required tables.
        This ensures the system is self-initialising and easy to deploy.
        """
        try:
            # Connect to the database (creates it if it doesn't exist)
            self.connection = sqlite3.connect(self.DB_FILE, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Return rows as dictionaries
            cursor = self.connection.cursor()

            # Create dns_logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    is_response INTEGER NOT NULL,
                    response_code INTEGER,
                    resolved_ips TEXT,
                    threat_score INTEGER DEFAULT 0
                )
            ''')

            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dns_log_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_score INTEGER NOT NULL,
                    rules_triggered TEXT NOT NULL,
                    status TEXT DEFAULT 'new',
                    FOREIGN KEY (dns_log_id) REFERENCES dns_logs(id)
                )
            ''')

            # Create alert_history table - tracks all status changes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL,
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    notes TEXT,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id)
                )
            ''')

            # Create threat_cache table - stores known malicious domains
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    source TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
            ''')

            # New normalized table for resolved IPs (one row per resolved IP)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_log_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dns_log_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    FOREIGN KEY (dns_log_id) REFERENCES dns_logs(id)
                )
            ''')

            # Threat feeds table to track external sources (optional normalization)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT,
                    last_checked TEXT
                )
            ''')

            # Rules table and junction table to record which rules triggered an alert
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_rules (
                    alert_id INTEGER NOT NULL,
                    rule_id INTEGER NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id),
                    FOREIGN KEY (rule_id) REFERENCES rules(id),
                    PRIMARY KEY (alert_id, rule_id)
                )
            ''')

            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_cache_domain ON threat_cache(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_log_ips_dns_log_id ON dns_log_ips(dns_log_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_name ON rules(name)')

            self.connection.commit()
            print(f"✓ Database initialized successfully at {self.DB_FILE}")

        except sqlite3.Error as e:
            print(f"✗ Database initialization error: {e}")
            raise

    # ========================================================================
    # DNS LOGS OPERATIONS (Section 6.3.2)
    # ========================================================================

    def store_dns_log(self, event: DnsEvent, threat_score: int = 0) -> int:
        """
        6.3.2 Storing DNS Logs
        
        All DNS queries are stored in the dns_logs table.
        Each entry includes: Timestamp, Source IP, Domain, Query type, Response status.
        This ensures full visibility and supports historical analysis.
        
        Args:
            event: DnsEvent object containing DNS query/response data
            threat_score: Initial threat score assigned by detection engine
            
        Returns:
            ID of the inserted record
        """
        try:
            cursor = self.connection.cursor()
            resolved_ips_json = json.dumps(event.resolved_ips)
            
            cursor.execute('''
                INSERT INTO dns_logs 
                (timestamp, source_ip, domain, query_type, is_response, response_code, resolved_ips, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp.isoformat(),
                event.source_ip,
                event.domain,
                event.query_type,
                int(event.is_response),
                event.response_code,
                resolved_ips_json,
                threat_score
            ))
            
            dns_log_id = cursor.lastrowid

            # If resolved IPs are present, insert normalized rows into dns_log_ips
            try:
                resolved_ips = event.resolved_ips or []
                if isinstance(resolved_ips, str):
                    # Defensive: if a single string was provided
                    resolved_ips = [resolved_ips]

                for ip in resolved_ips:
                    cursor.execute('''
                        INSERT INTO dns_log_ips (dns_log_id, ip_address) VALUES (?, ?)
                    ''', (dns_log_id, ip))
            except sqlite3.Error:
                # Non-fatal: continue even if dns_log_ips insert fails
                pass

            self.connection.commit()
            return dns_log_id

        except sqlite3.Error as e:
            print(f"✗ Error storing DNS log: {e}")
            raise

    def get_recent_dns_logs(self, hours: int = 24, limit: int = 100) -> List[dict]:
        """
        Retrieve recent DNS logs for dashboard display.
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of records to return
            
        Returns:
            List of DNS log records
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM dns_logs 
                WHERE datetime(timestamp) > datetime('now', '-' || ? || ' hours')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (hours, limit))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"✗ Error retrieving DNS logs: {e}")
            raise

    # ========================================================================
    # ALERT OPERATIONS (Section 6.3.3 & 6.3.4)
    # ========================================================================

    def store_alert(self, alert: Alert, dns_log_id: int) -> int:
        """
        6.3.3 Alert Generation
        
        When a DNS event is classified as a potential threat:
        - Create an alert for medium, high, or severe threats
        - Store in the alerts table with all relevant fields
        
        Args:
            alert: Alert object containing threat information
            dns_log_id: Reference to the DNS log that triggered the alert
            
        Returns:
            ID of the inserted alert
        """
        try:
            cursor = self.connection.cursor()
            rules_json = json.dumps(alert.rules_triggered)
            
            cursor.execute('''
                INSERT INTO alerts 
                (dns_log_id, timestamp, source_ip, domain, severity, threat_score, rules_triggered, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                dns_log_id,
                alert.timestamp.isoformat(),
                alert.source_ip,
                alert.domain,
                alert.severity,
                alert.score,
                rules_json,
                alert.status
            ))
            
            self.connection.commit()
            alert_id = cursor.lastrowid
            
            # Record the initial status in alert history
            self._record_status_change(alert_id, None, alert.status, "Alert created")
            
            return alert_id
            
        except sqlite3.Error as e:
            print(f"✗ Error storing alert: {e}")
            raise

    def update_alert_status(self, alert_id: int, new_status: str, notes: str = None) -> bool:
        """
        6.3.4 Alert History Tracking
        
        Update alert status and record the change in alert_history.
        Allows tracking alert lifecycle and maintaining audit history.
        
        Args:
            alert_id: ID of the alert to update
            new_status: New status (new, acknowledged, resolved, archived)
            notes: Optional notes about the status change
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.connection.cursor()
            
            # Get current status
            cursor.execute('SELECT status FROM alerts WHERE id = ?', (alert_id,))
            result = cursor.fetchone()
            
            if not result:
                print(f"✗ Alert with ID {alert_id} not found")
                return False
            
            old_status = result[0]
            
            # Update alert status
            cursor.execute('''
                UPDATE alerts SET status = ? WHERE id = ?
            ''', (new_status, alert_id))
            
            # Record the status change in history
            self._record_status_change(alert_id, old_status, new_status, notes)
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"✗ Error updating alert status: {e}")
            raise

    def _record_status_change(self, alert_id: int, old_status: Optional[str], new_status: str, notes: str = None):
        """
        Internal helper: Record a status change in the alert_history table.
        
        Args:
            alert_id: ID of the alert
            old_status: Previous status (None if initial creation)
            new_status: New status
            notes: Optional notes about the change
        """
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO alert_history 
            (alert_id, old_status, new_status, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_id, old_status or '', new_status, datetime.now(timezone.utc).isoformat(), notes))

    def get_active_alerts(self, limit: int = 50) -> List[dict]:
        """
        Retrieve active alerts (not yet resolved or archived).
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of active alert records
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE status NOT IN ('resolved', 'archived')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"✗ Error retrieving active alerts: {e}")
            raise

    def get_alert_history(self, alert_id: int) -> List[dict]:
        """
        Retrieve the complete history of an alert's status changes.
        
        Args:
            alert_id: ID of the alert
            
        Returns:
            List of status change records
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM alert_history 
                WHERE alert_id = ?
                ORDER BY timestamp ASC
            ''', (alert_id,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"✗ Error retrieving alert history: {e}")
            raise

    # ========================================================================
    # THREAT CACHE OPERATIONS (Section 6.3.5)
    # ========================================================================

    def store_threat_cache_entry(self, threat: ThreatCacheEntry) -> int:
        """
        6.3.5 Threat Intelligence Cache
        
        Store known malicious domains retrieved from external sources.
        Caching improves performance by avoiding repeated external lookups.
        Sources: OpenPhish, Spamhaus, Abuse.ch
        
        Args:
            threat: ThreatCacheEntry object containing threat information
            
        Returns:
            ID of the inserted record, or existing ID if domain already cached
        """
        try:
            cursor = self.connection.cursor()
            
            # Try to update if domain already exists
            cursor.execute('''
                UPDATE threat_cache 
                SET source = ?, threat_type = ?, last_updated = ?
                WHERE domain = ?
            ''', (threat.source, threat.threat_type, threat.last_updated.isoformat(), threat.domain))
            
            if cursor.rowcount == 0:
                # Domain doesn't exist, insert new record
                cursor.execute('''
                    INSERT INTO threat_cache 
                    (domain, source, threat_type, last_updated)
                    VALUES (?, ?, ?, ?)
                ''', (threat.domain, threat.source, threat.threat_type, threat.last_updated.isoformat()))
            
            self.connection.commit()
            return cursor.lastrowid
            
        except sqlite3.Error as e:
            print(f"✗ Error storing threat cache entry: {e}")
            raise

    def is_domain_malicious(self, domain: str) -> bool:
        """
        Quick lookup to check if a domain is in the threat cache.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is in threat cache, False otherwise
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT id FROM threat_cache WHERE domain = ?', (domain,))
            return cursor.fetchone() is not None
            
        except sqlite3.Error as e:
            print(f"✗ Error checking threat cache: {e}")
            raise

    def get_threat_cache_size(self) -> int:
        """Get the number of entries in the threat cache."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT COUNT(*) FROM threat_cache')
            return cursor.fetchone()[0]
            
        except sqlite3.Error as e:
            print(f"✗ Error getting threat cache size: {e}")
            raise

    # ========================================================================
    # DASHBOARD INTEGRATION (Section 6.5)
    # ========================================================================

    def get_dashboard_summary(self) -> dict:
        """
        6.5 Database Access and Dashboard Integration
        
        Provide dashboard with recent activity summary including:
        - Recent DNS activity
        - Active alerts
        - Threat severity distribution
        - Historical trends
        
        Returns:
            Dictionary with dashboard summary data
        """
        try:
            cursor = self.connection.cursor()
            
            # Get count of recent DNS queries (last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) FROM dns_logs 
                WHERE datetime(timestamp) > datetime('now', '-24 hours')
            ''')
            recent_queries = cursor.fetchone()[0]
            
            # Get count of active alerts
            cursor.execute('''
                SELECT COUNT(*) FROM alerts 
                WHERE status = 'new'
            ''')
            new_alerts = cursor.fetchone()[0]
            
            # Get severity distribution
            cursor.execute('''
                SELECT severity, COUNT(*) as count FROM alerts 
                WHERE datetime(timestamp) > datetime('now', '-24 hours')
                GROUP BY severity
            ''')
            severity_dist = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Get threat cache size
            cache_size = self.get_threat_cache_size()
            
            return {
                'recent_queries_24h': recent_queries,
                'new_alerts': new_alerts,
                'severity_distribution': severity_dist,
                'threat_cache_size': cache_size
            }
            
        except sqlite3.Error as e:
            print(f"✗ Error retrieving dashboard summary: {e}")
            raise

    def search_dns_logs(self, domain: str = None, source_ip: str = None, 
                        threat_level: int = None, hours: int = 24) -> List[dict]:
        """
        6.5 Database Access and Dashboard Integration
        
        Allow dashboard users to search and filter data by:
        - Domain name
        - IP address
        - Threat level
        - Time range
        
        Args:
            domain: Filter by domain (substring match)
            source_ip: Filter by source IP
            threat_level: Filter by minimum threat score
            hours: Time range to search (hours back from now)
            
        Returns:
            List of matching DNS log records
        """
        try:
            cursor = self.connection.cursor()
            query = '''
                SELECT * FROM dns_logs 
                WHERE datetime(timestamp) > datetime('now', '-' || ? || ' hours')
            '''
            params: List = [hours]
            
            if domain:
                query += ' AND domain LIKE ?'
                params.append(f'%{domain}%')
            
            if source_ip:
                query += ' AND source_ip = ?'
                params.append(source_ip)
            
            if threat_level is not None:
                query += ' AND threat_score >= ?'
                params.append(threat_level)
            
            query += ' ORDER BY timestamp DESC'
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"✗ Error searching DNS logs: {e}")
            raise

    def search_alerts(self, domain: str = None, source_ip: str = None, 
                      severity: str = None, status: str = None, hours: int = 24) -> List[dict]:
        """
        Search alerts with multiple filter options for dashboard.
        
        Args:
            domain: Filter by domain (substring match)
            source_ip: Filter by source IP
            severity: Filter by severity level
            status: Filter by alert status
            hours: Time range to search
            
        Returns:
            List of matching alert records
        """
        try:
            cursor = self.connection.cursor()
            query = '''
                SELECT * FROM alerts 
                WHERE datetime(timestamp) > datetime('now', '-' || ? || ' hours')
            '''
            params: List = [hours]
            
            if domain:
                query += ' AND domain LIKE ?'
                params.append(f'%{domain}%')
            
            if source_ip:
                query += ' AND source_ip = ?'
                params.append(source_ip)
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            
            if status:
                query += ' AND status = ?'
                params.append(status)
            
            query += ' ORDER BY timestamp DESC'
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"✗ Error searching alerts: {e}")
            raise

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            print("✓ Database connection closed")


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example usage of the database manager
    db = DatabaseManager()
    
    # Example 1: Store a DNS log
    event = DnsEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        domain="example.com",
        query_type="A",
        is_response=False,
        response_code=0,
        resolved_ips=["93.184.216.34"]
    )
    dns_log_id = db.store_dns_log(event, threat_score=0)
    print(f"✓ Stored DNS log with ID: {dns_log_id}")
    
    # Example 2: Store an alert
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        domain="malicious.xyz",
        severity="High",
        score=85,
        rules_triggered=["high_query_rate", "known_malicious_domain"]
    )
    alert_id = db.store_alert(alert, dns_log_id)
    print(f"✓ Stored alert with ID: {alert_id}")
    
    # Example 3: Update alert status
    db.update_alert_status(alert_id, "acknowledged", "Investigating suspicious domain")
    print(f"✓ Updated alert status to acknowledged")
    
    # Example 4: Store a threat cache entry
    threat = ThreatCacheEntry(
        domain="malicious.xyz",
        source="OpenPhish",
        threat_type="phishing",
        last_updated=datetime.now(timezone.utc)
    )
    db.store_threat_cache_entry(threat)
    print(f"✓ Cached malicious domain")
    
    # Example 5: Get dashboard summary
    summary = db.get_dashboard_summary()
    print(f"✓ Dashboard Summary: {summary}")
    
    db.close()
