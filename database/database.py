import sqlite3
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List
import json
from werkzeug.security import generate_password_hash, check_password_hash
from .dataModels import Alert, DnsEvent, ThreatCacheEntry


class DatabaseManager:
    """
    Manages all interactions with the SQLite database.
    Handles initialization, CRUD operations, and queries for the dashboard.
    """

    DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dns_threat_monitor.db')

    def __init__(self):
        """Initialize database connection and create tables if they don't exist."""
        self.connection = None
        self._lock = threading.Lock()
        self.initialize_database()

    def initialize_database(self):
        """Creates all tables and indexes if they don't already exist."""
        try:
            # Wait up to 30 seconds for a lock instead of failing right away.
            self.connection = sqlite3.connect(self.DB_FILE, check_same_thread=False, timeout=30)
            self.connection.row_factory = sqlite3.Row
            # WAL mode lets the monitor write while the dashboard reads.
            self.connection.execute('PRAGMA journal_mode=WAL')
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

            # Dashboard user accounts table for login and profile data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    full_name TEXT,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT
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
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')

            self.connection.commit()
            print(f"Database initialized successfully at {self.DB_FILE}")

        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            raise

    def store_dns_log(self, event: DnsEvent, threat_score: int = 0) -> int:
        """Store a DNS event in dns_logs. Returns the new row ID."""
        with self._lock:
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
                print(f"Error storing DNS log: {e}")
                raise

    def get_recent_dns_logs(self, hours: int = 24, limit: int = 100) -> List[dict]:
        """Fetch the most recent DNS log entries within the given time window."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM dns_logs 
                WHERE datetime(timestamp) > datetime('now', '-' || ? || ' hours')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (hours, limit))
            
            rows = [dict(row) for row in cursor.fetchall()]
            # Might help Stephen when he's debugging rules - quick way to see if something scored
            for row in rows:
                row['status'] = 'Threat' if row.get('threat_score', 0) > 0 else 'Clean'
            return rows
            
        except sqlite3.Error as e:
            print(f"Error retrieving DNS logs: {e}")
            raise

    def store_alert(self, alert: Alert, dns_log_id: int) -> int:
        """Save an alert linked to dns_log_id. Returns the alert ID.
        The Alert object comes from Stephen's Detector class."""
        with self._lock:
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
                print(f"Error storing alert: {e}")
                raise

    def update_alert_status(self, alert_id: int, new_status: str, notes: str = None) -> bool:
        """Update an alert's status and log the change to alert_history."""
        with self._lock:
            try:
                cursor = self.connection.cursor()
                
                cursor.execute('SELECT status FROM alerts WHERE id = ?', (alert_id,))
                result = cursor.fetchone()
                
                if not result:
                    print(f"Alert with ID {alert_id} not found")
                    return False
                
                old_status = result[0]
                
                cursor.execute('''
                    UPDATE alerts SET status = ? WHERE id = ?
                ''', (new_status, alert_id))

                self._record_status_change(alert_id, old_status, new_status, notes)
                
                self.connection.commit()
                return True
                
            except sqlite3.Error as e:
                print(f"Error updating alert status: {e}")
                raise

    def _record_status_change(self, alert_id: int, old_status: Optional[str], new_status: str, notes: str = None):
        """Write a row to alert_history recording the status transition."""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO alert_history 
            (alert_id, old_status, new_status, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_id, old_status or '', new_status, datetime.now(timezone.utc).isoformat(), notes))

    def _process_alert_row(self, row: dict) -> dict:
        """
        Parses rules_triggered from a JSON string. Sets rule_name, score, and rules_triggered list on the row.
        """
        try:
            rules = json.loads(row.get('rules_triggered', '[]') or '[]')
        except (json.JSONDecodeError, TypeError):
            rules = []
        row['rules_triggered'] = rules
        row['rule_name'] = ', '.join(rules) if rules else '-'
        row['score'] = row.get('threat_score')
        return row

    def get_active_alerts(self, limit: int = 50) -> List[dict]:
        """Returns alerts that are still new or acknowledged (not resolved/archived)."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE status NOT IN ('resolved', 'archived')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            return [self._process_alert_row(dict(row)) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"Error retrieving active alerts: {e}")
            raise

    def get_alert_history(self, alert_id: int) -> List[dict]:
        """Returns all status-change entries for a given alert, oldest first."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM alert_history 
                WHERE alert_id = ?
                ORDER BY timestamp ASC
            ''', (alert_id,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"Error retrieving alert history: {e}")
            raise

    def store_threat_cache_entry(self, threat: ThreatCacheEntry) -> int:
        """Save a known bad domain so we can quickly check against it later."""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                UPDATE threat_cache 
                SET source = ?, threat_type = ?, last_updated = ?
                WHERE domain = ?
            ''', (threat.source, threat.threat_type, threat.last_updated.isoformat(), threat.domain))
            
            if cursor.rowcount == 0:
                cursor.execute('''
                    INSERT INTO threat_cache 
                    (domain, source, threat_type, last_updated)
                    VALUES (?, ?, ?, ?)
                ''', (threat.domain, threat.source, threat.threat_type, threat.last_updated.isoformat()))
            
            self.connection.commit()
            return cursor.lastrowid
            
        except sqlite3.Error as e:
            print(f"Error storing threat cache entry: {e}")
            raise

    def is_domain_malicious(self, domain: str) -> bool:
        """Returns True if the domain is in the local threat cache."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT id FROM threat_cache WHERE domain = ?', (domain,))
            return cursor.fetchone() is not None
            
        except sqlite3.Error as e:
            print(f"Error checking threat cache: {e}")
            raise

    def get_threat_cache_size(self) -> int:
        """Get the number of entries in the threat cache."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT COUNT(*) FROM threat_cache')
            return cursor.fetchone()[0]
            
        except sqlite3.Error as e:
            print(f"Error getting threat cache size: {e}")
            raise

    def get_dashboard_summary(self) -> dict:
        """Grabs the numbers for the dashboard - total queries, active alerts, severity breakdown etc."""
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
            print(f"Error retrieving dashboard summary: {e}")
            raise

    def search_dns_logs(self, domain: str = None, source_ip: str = None,
                        threat_level: int = None, hours: int = 24) -> List[dict]:
        """Search dns_logs with optional filters for domain, IP, threat level, and time range."""
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
            print(f"Error searching DNS logs: {e}")
            raise

    def search_alerts(self, domain: str = None, source_ip: str = None,
                      severity: str = None, status: str = None, hours: int = 24) -> List[dict]:
        """Search alerts with optional filters for domain, IP, severity, status, and time range."""
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
            return [self._process_alert_row(dict(row)) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            print(f"Error searching alerts: {e}")
            raise

    def create_user(self, username: str, password: str,
                    full_name: str = None, email: str = None) -> int:
        """Create a new user with a hashed password. Returns the new user ID.
        Raises sqlite3.IntegrityError if the username already exists."""
        with self._lock:
            try:
                cursor = self.connection.cursor()
                # Store the hash, never the raw password.
                cursor.execute('''
                    INSERT INTO users (username, full_name, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    username,
                    full_name,
                    email,
                    generate_password_hash(password),
                    datetime.now(timezone.utc).isoformat()
                ))
                self.connection.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                raise
            except sqlite3.Error as e:
                print(f"Error creating user: {e}")
                raise

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Return the user row for a username, or None if not found."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            print(f"Error retrieving user: {e}")
            raise

    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Return the user row for an id, or None if not found."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            print(f"Error retrieving user: {e}")
            raise

    def verify_user(self, username: str, password: str) -> Optional[dict]:
        """Check a username and password. Returns the user row on success, else None.
        Updates last_login on success."""
        # Compare the given password against the stored hash.
        user = self.get_user_by_username(username)
        if not user or not check_password_hash(user['password_hash'], password):
            return None
        with self._lock:
            try:
                cursor = self.connection.cursor()
                # Record the time of this successful login.
                cursor.execute(
                    'UPDATE users SET last_login = ? WHERE id = ?',
                    (datetime.now(timezone.utc).isoformat(), user['id'])
                )
                self.connection.commit()
            except sqlite3.Error as e:
                print(f"Error updating last_login: {e}")
        return user

    def update_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Verify the current password and set a new one. Returns False if the
        current password is wrong or the user does not exist."""
        # Only allow the change if the current password is correct.
        user = self.get_user_by_id(user_id)
        if not user or not check_password_hash(user['password_hash'], current_password):
            return False
        with self._lock:
            try:
                cursor = self.connection.cursor()
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), user_id)
                )
                self.connection.commit()
                return True
            except sqlite3.Error as e:
                print(f"Error updating password: {e}")
                raise

    def update_profile(self, user_id: int, full_name: str = None, email: str = None) -> bool:
        """Update a user's full name and email. Returns False if the user does not exist."""
        if not self.get_user_by_id(user_id):
            return False
        with self._lock:
            try:
                cursor = self.connection.cursor()
                cursor.execute(
                    'UPDATE users SET full_name = ?, email = ? WHERE id = ?',
                    (full_name, email, user_id)
                )
                self.connection.commit()
                return True
            except sqlite3.Error as e:
                print(f"Error updating profile: {e}")
                raise

    def count_users(self) -> int:
        """Return the total number of registered users."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            print(f"Error counting users: {e}")
            raise

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            print("Database connection closed")


if __name__ == "__main__":
    db = DatabaseManager()

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
    print(f"Stored DNS log with ID: {dns_log_id}")

    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        domain="malicious.xyz",
        severity="High",
        score=85,
        rules_triggered=["high_query_rate", "known_malicious_domain"]
    )
    alert_id = db.store_alert(alert, dns_log_id)
    print(f"Stored alert with ID: {alert_id}")

    db.update_alert_status(alert_id, "acknowledged", "Investigating suspicious domain")
    print(f"Updated alert status to acknowledged")

    threat = ThreatCacheEntry(
        domain="malicious.xyz",
        source="OpenPhish",
        threat_type="phishing",
        last_updated=datetime.now(timezone.utc)
    )
    db.store_threat_cache_entry(threat)
    print(f"Cached malicious domain")

    summary = db.get_dashboard_summary()
    print(f"Dashboard Summary: {summary}")
    
    db.close()
