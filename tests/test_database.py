# Tests for database CRUD, alert lifecycle, threat cache, search, and dashboard summary.

import pytest
import os
import tempfile
from datetime import datetime, timezone
from database.database import DatabaseManager
from database.dataModels import DnsEvent, Alert, ThreatCacheEntry


class TestDatabaseManager:
    """Test the database manager functionality."""

    def setup_method(self):
        """Setup for each test method - create temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()

        # Override the DB_FILE for testing
        original_db_file = DatabaseManager.DB_FILE
        DatabaseManager.DB_FILE = self.temp_db.name

        self.db = DatabaseManager()

        # Restore original DB_FILE
        DatabaseManager.DB_FILE = original_db_file

    def teardown_method(self):
        """Cleanup after each test method."""
        if self.db:
            self.db.close()

        # Clean up temporary database file
        try:
            os.unlink(self.temp_db.name)
        except:
            pass

    def test_database_initialization(self):
        """Test database initialization and table creation."""
        # Check that tables were created
        cursor = self.db.connection.cursor()

        # Check dns_logs table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dns_logs'")
        assert cursor.fetchone() is not None

        # Check alerts table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        assert cursor.fetchone() is not None

        # Check alert_history table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_history'")
        assert cursor.fetchone() is not None

        # Check threat_cache table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_cache'")
        assert cursor.fetchone() is not None

    def test_store_and_retrieve_dns_log(self):
        """Test storing and retrieving DNS logs."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="example.com",
            query_type="A",
            is_response=False,
            response_code=0,
            resolved_ips=["93.184.216.34"]
        )

        # Store the event
        log_id = self.db.store_dns_log(event, threat_score=10)

        assert log_id > 0

        # Retrieve recent logs
        logs = self.db.get_recent_dns_logs(hours=1, limit=10)

        assert len(logs) == 1
        assert logs[0]['domain'] == "example.com"
        assert logs[0]['source_ip'] == "192.168.1.100"
        assert logs[0]['threat_score'] == 10

    def test_store_and_retrieve_alert(self):
        """Test storing and retrieving alerts."""
        # First store a DNS log
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        dns_log_id = self.db.store_dns_log(event, threat_score=50)

        # Now store an alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.com",
            severity="High",
            score=150,
            rules_triggered=["blacklist_hit", "suspicious_tld"]
        )

        alert_id = self.db.store_alert(alert, dns_log_id)

        assert alert_id > 0

        # Retrieve active alerts
        alerts = self.db.get_active_alerts(limit=10)

        assert len(alerts) == 1
        assert alerts[0]['domain'] == "malicious.com"
        assert alerts[0]['severity'] == "High"
        assert alerts[0]['threat_score'] == 150

    def test_alert_status_updates(self):
        """Test alert status update functionality."""
        # Create and store alert
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="test.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        dns_log_id = self.db.store_dns_log(event, threat_score=25)

        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="test.com",
            severity="Medium",
            score=75,
            rules_triggered=["high_query_rate"]
        )

        alert_id = self.db.store_alert(alert, dns_log_id)

        # Update alert status
        success = self.db.update_alert_status(alert_id, "acknowledged", "Investigating issue")

        assert success == True

        # Verify status was updated
        alerts = self.db.get_active_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]['status'] == "acknowledged"

    def test_alert_history_tracking(self):
        """Test alert history tracking."""
        # Create and store alert
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="history-test.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        dns_log_id = self.db.store_dns_log(event, threat_score=30)

        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="history-test.com",
            severity="Medium",
            score=80,
            rules_triggered=["test_rule"]
        )

        alert_id = self.db.store_alert(alert, dns_log_id)

        # Update status multiple times
        self.db.update_alert_status(alert_id, "acknowledged", "First update")
        self.db.update_alert_status(alert_id, "resolved", "Issue resolved")

        # Check history
        history = self.db.get_alert_history(alert_id)

        assert len(history) == 3  # Initial creation + 2 updates
        assert history[0]['new_status'] == "new"  # Initial status
        assert history[1]['new_status'] == "acknowledged"
        assert history[2]['new_status'] == "resolved"

    def test_get_all_alerts(self):
        """Test retrieving all alerts with optional status filter."""
        # Create two alerts
        event1 = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="all-alerts-1.com",
            query_type="A",
            is_response=False,
            response_code=0
        )
        dns_log_id1 = self.db.store_dns_log(event1, threat_score=20)
        alert1 = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="all-alerts-1.com",
            severity="Low",
            score=40,
            rules_triggered=["test_rule"]
        )
        alert_id1 = self.db.store_alert(alert1, dns_log_id1)
        self.db.update_alert_status(alert_id1, "resolved", "Resolved alert")

        event2 = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.101",
            domain="all-alerts-2.com",
            query_type="A",
            is_response=False,
            response_code=0
        )
        dns_log_id2 = self.db.store_dns_log(event2, threat_score=20)
        alert2 = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.101",
            domain="all-alerts-2.com",
            severity="Low",
            score=40,
            rules_triggered=["test_rule"]
        )
        self.db.store_alert(alert2, dns_log_id2)

        # get_all_alerts returns every alert, including resolved ones.
        all_alerts = self.db.get_all_alerts()
        assert len(all_alerts) >= 2
        domains = {a['domain'] for a in all_alerts}
        assert "all-alerts-1.com" in domains
        assert "all-alerts-2.com" in domains

        # Filtering by status returns only matching alerts.
        resolved_alerts = self.db.get_all_alerts(status="resolved")
        assert all(a['status'] == "resolved" for a in resolved_alerts)
        assert any(a['domain'] == "all-alerts-1.com" for a in resolved_alerts)

        new_alerts = self.db.get_all_alerts(status="new")
        assert all(a['status'] == "new" for a in new_alerts)
        assert any(a['domain'] == "all-alerts-2.com" for a in new_alerts)

    def test_threat_cache_operations(self):
        """Test threat cache operations."""
        threat = ThreatCacheEntry(
            domain="malicious-site.com",
            source="TestSource",
            threat_type="phishing",
            last_updated=datetime.now(timezone.utc)
        )

        # Store threat
        threat_id = self.db.store_threat_cache_entry(threat)

        assert threat_id > 0

        # Check if domain is marked as malicious
        is_malicious = self.db.is_domain_malicious("malicious-site.com")

        assert is_malicious == True

        # Check cache size
        cache_size = self.db.get_threat_cache_size()

        assert cache_size == 1

    def test_threat_cache_update(self):
        """Test threat cache update (upsert) functionality."""
        threat1 = ThreatCacheEntry(
            domain="test-domain.com",
            source="Source1",
            threat_type="malware",
            last_updated=datetime.now(timezone.utc)
        )

        # Store initial threat
        self.db.store_threat_cache_entry(threat1)

        # Update with new information
        threat2 = ThreatCacheEntry(
            domain="test-domain.com",
            source="Source2",
            threat_type="phishing",
            last_updated=datetime.now(timezone.utc)
        )

        self.db.store_threat_cache_entry(threat2)

        # Should still be only 1 entry (updated, not inserted)
        cache_size = self.db.get_threat_cache_size()
        assert cache_size == 1

    def test_dashboard_summary(self):
        """Test dashboard summary generation."""
        # Add some test data
        events = [
            DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain="example.com",
                query_type="A",
                is_response=False,
                response_code=0
            ),
            DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.101",
                domain="test.com",
                query_type="A",
                is_response=False,
                response_code=0
            )
        ]

        for event in events:
            self.db.store_dns_log(event, threat_score=0)

        # Create an alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.com",
            severity="High",
            score=120,
            rules_triggered=["test"]
        )

        dns_log_id = self.db.store_dns_log(events[0], 120)
        self.db.store_alert(alert, dns_log_id)

        # Get dashboard summary
        summary = self.db.get_dashboard_summary()

        assert 'recent_queries_24h' in summary
        assert 'new_alerts' in summary
        assert 'severity_distribution' in summary
        assert 'threat_cache_size' in summary

        assert summary['recent_queries_24h'] >= 2
        assert summary['new_alerts'] >= 0

    def test_search_functionality(self):
        """Test DNS log and alert search functionality."""
        # Add test data
        events = [
            DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain="google.com",
                query_type="A",
                is_response=False,
                response_code=0
            ),
            DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.101",
                domain="github.com",
                query_type="A",
                is_response=False,
                response_code=0
            )
        ]

        for event in events:
            self.db.store_dns_log(event, threat_score=0)

        # Test DNS log search by domain
        results = self.db.search_dns_logs(domain="google")

        assert len(results) == 1
        assert results[0]['domain'] == "google.com"

        # Test DNS log search by IP
        results = self.db.search_dns_logs(source_ip="192.168.1.101")

        assert len(results) == 1
        assert results[0]['source_ip'] == "192.168.1.101"

        # Test DNS log search by threat level
        high_threat_event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.102",
            domain="suspicious.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        self.db.store_dns_log(high_threat_event, threat_score=80)

        results = self.db.search_dns_logs(threat_level=50)

        assert len(results) == 1
        assert results[0]['threat_score'] == 80

    def test_database_error_handling(self):
        """Test database error handling."""
        # Try to update non-existent alert
        success = self.db.update_alert_status(99999, "resolved")

        assert success == False

        # Try to get history for non-existent alert
        history = self.db.get_alert_history(99999)

        assert len(history) == 0


class TestDatabaseIntegration:
    """Integration tests for database operations."""

    def setup_method(self):
        """Setup for integration tests."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()

        original_db_file = DatabaseManager.DB_FILE
        DatabaseManager.DB_FILE = self.temp_db.name

        self.db = DatabaseManager()
        DatabaseManager.DB_FILE = original_db_file

    def teardown_method(self):
        """Cleanup after integration tests."""
        if self.db:
            self.db.close()
        try:
            os.unlink(self.temp_db.name)
        except:
            pass

    def test_full_workflow(self):
        """Test complete database workflow."""
        # 1. Store DNS event
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="workflow-test.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        dns_log_id = self.db.store_dns_log(event, threat_score=25)

        # 2. Store alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="workflow-test.com",
            severity="Medium",
            score=75,
            rules_triggered=["workflow_test"]
        )

        alert_id = self.db.store_alert(alert, dns_log_id)

        # 3. Update alert status
        self.db.update_alert_status(alert_id, "acknowledged")

        # 4. Verify all data is stored correctly
        logs = self.db.get_recent_dns_logs(hours=1)
        alerts = self.db.get_active_alerts()
        history = self.db.get_alert_history(alert_id)

        assert len(logs) == 1
        assert len(alerts) == 1
        assert len(history) == 2  # Initial + update

        assert logs[0]['domain'] == "workflow-test.com"
        assert alerts[0]['status'] == "acknowledged"
        assert history[1]['new_status'] == "acknowledged"
