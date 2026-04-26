"""
DNS Threat Monitor - Test Suite
===============================

Unit tests for the DNS Threat Monitor system components.
Run with: python -m pytest tests/
"""

import pytest
import sys
import os
from datetime import datetime, timezone

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.dataModels import DnsEvent, Alert, ThreatCacheEntry
from parser.input_parser import parse_dnsmasq_line, parse_tshark_line, normalise_domain
from detection.rules import RuleEngine
from database.database import DatabaseManager


class TestDataModels:
    """Test data model classes."""

    def test_dns_event_creation(self):
        """Test DnsEvent object creation."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="example.com",
            query_type="A",
            is_response=False,
            response_code=0,
            resolved_ips=["93.184.216.34"]
        )

        assert event.domain == "example.com"
        assert event.source_ip == "192.168.1.100"
        assert event.query_type == "A"
        assert event.is_response == False
        assert event.resolved_ips == ["93.184.216.34"]

    def test_alert_creation(self):
        """Test Alert object creation."""
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.com",
            severity="High",
            score=85,
            rules_triggered=["blacklist_hit", "suspicious_tld"]
        )

        assert alert.domain == "malicious.com"
        assert alert.severity == "High"
        assert alert.score == 85
        assert "blacklist_hit" in alert.rules_triggered


class TestInputParser:
    """Test input parsing functions."""

    def test_parse_dnsmasq_query(self):
        """Test parsing dnsmasq query log line."""
        line = "Apr 26 14:30:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.source_ip == "192.168.1.100"
        assert event.query_type == "A"
        assert event.is_response == False

    def test_parse_dnsmasq_reply(self):
        """Test parsing dnsmasq reply log line."""
        line = "Apr 26 14:30:16 dnsmasq[1234]: reply example.com is 93.184.216.34"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.is_response == True
        assert event.resolved_ips == ["93.184.216.34"]

    def test_normalise_domain(self):
        """Test domain normalization."""
        assert normalise_domain("EXAMPLE.COM.") == "example.com"
        assert normalise_domain("sub.EXAMPLE.COM") == "sub.example.com"


class TestRuleEngine:
    """Test rule engine functionality."""

    def test_suspicious_tld_detection(self):
        """Test suspicious TLD detection."""
        rule_engine = RuleEngine()

        # Create event with suspicious TLD
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        triggered = rule_engine.check(event)
        assert "suspicious_tld" in triggered

    def test_normal_domain(self):
        """Test normal domain doesn't trigger rules."""
        rule_engine = RuleEngine()

        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="google.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        triggered = rule_engine.check(event)
        # Should not trigger suspicious_tld for .com
        assert "suspicious_tld" not in triggered


class TestDatabaseManager:
    """Test database operations."""

    def test_database_initialization(self):
        """Test database manager initialization."""
        # Use in-memory database for testing
        db = DatabaseManager()
        assert db.connection is not None

        # Clean up
        db.close()

    def test_store_and_retrieve_dns_log(self):
        """Test storing and retrieving DNS logs."""
        db = DatabaseManager()

        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="test.com",
            query_type="A",
            is_response=False,
            response_code=0,
            resolved_ips=[]
        )

        # Store event
        log_id = db.store_dns_log(event, threat_score=10)
        assert log_id > 0

        # Retrieve recent logs
        logs = db.get_recent_dns_logs(hours=1, limit=10)
        assert len(logs) > 0

        # Find our test log
        test_log = next((log for log in logs if log['domain'] == 'test.com'), None)
        assert test_log is not None
        assert test_log['threat_score'] == 10

        db.close()


# Integration test
class TestSystemIntegration:
    """Test system component integration."""

    def test_full_pipeline(self):
        """Test the complete processing pipeline."""
        # This would test the full system integration
        # For now, just test component interactions

        # Create components
        db = DatabaseManager()
        rule_engine = RuleEngine()

        # Create test event
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="suspicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        # Test rule engine
        rules_triggered = rule_engine.check(event)
        assert "suspicious_tld" in rules_triggered

        # Store in database
        log_id = db.store_dns_log(event, threat_score=20)
        assert log_id > 0

        db.close()


if __name__ == "__main__":
    # Run basic tests
    print("Running DNS Threat Monitor tests...")

    # Test data models
    test_models = TestDataModels()
    test_models.test_dns_event_creation()
    test_models.test_alert_creation()
    print("✓ Data model tests passed")

    # Test parser
    test_parser = TestInputParser()
    test_parser.test_parse_dnsmasq_query()
    test_parser.test_normalise_domain()
    print("✓ Parser tests passed")

    # Test rules
    test_rules = TestRuleEngine()
    test_rules.test_suspicious_tld_detection()
    test_rules.test_normal_domain()
    print("✓ Rule engine tests passed")

    print("All basic tests passed! ✅")
