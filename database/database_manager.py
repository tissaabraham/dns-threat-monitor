"""
Database Manager

Manages SQLite database operations for DNS logs, alerts, and statistics.
"""

import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

from .schema import SCHEMA_SQL

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages SQLite database for storing DNS logs and alerts.
    """
    
    def __init__(self, db_path: str = "dns_threat_monitor.db"):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize database with schema."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.executescript(SCHEMA_SQL)
            self.connection.commit()
            logger.info(f"Database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
            
    def insert_dns_log(self, source_ip: str, domain: str, query_type: str, 
                      response_code: Optional[int] = None, 
                      response_ip: Optional[str] = None) -> int:
        """
        Insert DNS log record.
        
        Args:
            source_ip: Source IP address
            domain: Domain queried
            query_type: Query type (A, AAAA, MX, etc.)
            response_code: DNS response code
            response_ip: Response IP address
            
        Returns:
            ID of inserted record
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO dns_logs (source_ip, domain, query_type, response_code, response_ip)
                VALUES (?, ?, ?, ?, ?)
            """, (source_ip, domain, query_type, response_code, response_ip))
            self.connection.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting DNS log: {e}")
            return -1
            
    def insert_alert(self, dns_log_id: int, domain: str, source_ip: str,
                    threat_type: str, severity: str, threat_score: int,
                    rules_triggered: str) -> int:
        """
        Insert threat alert.
        
        Args:
            dns_log_id: ID of associated DNS log
            domain: Domain that triggered alert
            source_ip: Source IP
            threat_type: Type of threat
            severity: Severity level
            threat_score: Threat score (0-100)
            rules_triggered: JSON list of triggered rules
            
        Returns:
            ID of inserted alert
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO alerts (dns_log_id, domain, source_ip, threat_type, 
                                   severity, threat_score, rules_triggered)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (dns_log_id, domain, source_ip, threat_type, severity, threat_score, rules_triggered))
            self.connection.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            return -1
            
    def get_alerts(self, severity: Optional[str] = None, status: Optional[str] = None,
                  limit: int = 100) -> List[Dict]:
        """
        Retrieve alerts from database.
        
        Args:
            severity: Filter by severity level
            status: Filter by status
            limit: Maximum number of records
            
        Returns:
            List of alert records
        """
        try:
            cursor = self.connection.cursor()
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if status:
                query += " AND status = ?"
                params.append(status)
                
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
            
    def update_alert_status(self, alert_id: int, status: str):
        """
        Update alert status.
        
        Args:
            alert_id: ID of alert to update
            status: New status (new, acknowledged, resolved, archived)
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE alerts 
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, alert_id))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            
    def get_statistics(self) -> Dict:
        """
        Get database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        try:
            cursor = self.connection.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM dns_logs")
            total_queries = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
            high_severity_alerts = cursor.fetchone()[0]
            
            return {
                "total_queries": total_queries,
                "total_alerts": total_alerts,
                "high_severity_alerts": high_severity_alerts
            }
        except Exception as e:
            logger.error(f"Error retrieving statistics: {e}")
            return {}
            
    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

