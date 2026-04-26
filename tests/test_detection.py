"""
DNS Threat Monitor - Detection Tests
===================================

Unit tests for the threat detection components.
"""

import pytest
from datetime import datetime, timezone
from database.dataModels import DnsEvent
from detection.rules import RuleEngine
from detection.threat_detector import Detector
from parser.blacklist import Blacklist


class TestRuleEngine:
    """Test the rule engine functionality."""

    def setup_method(self):
        """Setup for each test method."""
        self.rule_engine = RuleEngine()

    def test_suspicious_tld_detection(self):
        """Test detection of suspicious TLDs."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        triggered = self.rule_engine.check(event)

        assert "suspicious_tld" in triggered

    def test_multiple_suspicious_tlds(self):
        """Test detection of various suspicious TLDs."""
        suspicious_domains = [
            "bad.xyz", "evil.tk", "mal.top", "spam.pw",
            "phish.cc", "trojan.su", "virus.ml", "worm.site"
        ]

        for domain in suspicious_domains:
            event = DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain=domain,
                query_type="A",
                is_response=False,
                response_code=0
            )

            triggered = self.rule_engine.check(event)
            assert "suspicious_tld" in triggered, f"Failed to detect {domain}"

    def test_normal_tld_not_flagged(self):
        """Test that normal TLDs are not flagged."""
        normal_domains = ["google.com", "github.io", "example.org", "test.net"]

        for domain in normal_domains:
            event = DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain=domain,
                query_type="A",
                is_response=False,
                response_code=0
            )

            triggered = self.rule_engine.check(event)
            assert "suspicious_tld" not in triggered, f"Incorrectly flagged {domain}"

    def test_high_query_rate_detection(self):
        """Test high query rate detection."""
        # Create multiple events from same IP within short time
        base_time = datetime.now(timezone.utc)
        ip = "192.168.1.100"

        # Create 60 queries (above the 50/minute threshold)
        for i in range(60):
            event = DnsEvent(
                timestamp=base_time,
                source_ip=ip,
                domain=f"test{i}.com",
                query_type="A",
                is_response=False,
                response_code=0
            )

            # The rule engine tracks rates internally
            triggered = self.rule_engine.check(event)

            # Should trigger on the 51st query or later
            if i >= 50:
                assert "high_query_rate" in triggered, f"Failed to detect high rate at query {i+1}"

    def test_nxdomain_flood_detection(self):
        """Test NXDOMAIN flood detection."""
        base_time = datetime.now(timezone.utc)
        ip = "192.168.1.100"

        # Create 15 NXDOMAIN responses (above the 10/minute threshold)
        for i in range(15):
            event = DnsEvent(
                timestamp=base_time,
                source_ip=ip,
                domain=f"nonexistent{i}.com",
                query_type="A",
                is_response=True,
                response_code=3  # NXDOMAIN
            )

            triggered = self.rule_engine.check(event)

            # Should trigger on the 11th NXDOMAIN or later
            if i >= 10:
                assert "nxdomain_flood" in triggered, f"Failed to detect NXDOMAIN flood at response {i+1}"

    def test_subdomain_abuse_detection(self):
        """Test subdomain abuse detection."""
        base_time = datetime.now(timezone.utc)
        ip = "192.168.1.100"
        root_domain = "evil.com"

        # Create 25 unique subdomains (above the 20 threshold)
        for i in range(25):
            event = DnsEvent(
                timestamp=base_time,
                source_ip=ip,
                domain=f"data{i}.{root_domain}",
                query_type="A",
                is_response=False,
                response_code=0
            )

            triggered = self.rule_engine.check(event)

            # Should trigger when we have 21+ unique subdomains
            if i >= 20:
                assert "subdomain_abuse" in triggered, f"Failed to detect subdomain abuse at subdomain {i+1}"

    def test_dga_pattern_detection(self):
        """Test Domain Generation Algorithm pattern detection."""
        # Test obviously random-looking domains
        dga_domains = [
            "kjhaskjdhkajshdkajhsd.com",
            "asdfghjklqwertyuiop.com",
            "randomstring123456.com"
        ]

        for domain in dga_domains:
            event = DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain=domain,
                query_type="A",
                is_response=False,
                response_code=0
            )

            triggered = self.rule_engine.check(event)

            # Should detect high entropy domains
            if len(domain.split('.')[0]) > 12:
                assert "dga_pattern" in triggered, f"Failed to detect DGA pattern in {domain}"

    def test_normal_domains_not_flagged(self):
        """Test that normal domains don't trigger false positives."""
        normal_events = [
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
                source_ip="192.168.1.100",
                domain="github.com",
                query_type="A",
                is_response=True,
                response_code=0,
                resolved_ips=["140.82.121.4"]
            )
        ]

        for event in normal_events:
            triggered = self.rule_engine.check(event)

            # Normal events should not trigger any rules
            assert len(triggered) == 0, f"False positive for normal event: {event.domain}"

    def test_multiple_rules_triggered(self):
        """Test that multiple rules can trigger on the same event."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="suspicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        # First, establish a high query rate by sending many requests
        for i in range(60):
            high_rate_event = DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain=f"test{i}.com",
                query_type="A",
                is_response=False,
                response_code=0
            )
            self.rule_engine.check(high_rate_event)

        # Now check the suspicious domain - should trigger multiple rules
        triggered = self.rule_engine.check(event)

        assert "suspicious_tld" in triggered
        assert "high_query_rate" in triggered
        assert len(triggered) >= 2


class TestThreatDetector:
    """Test the threat detector integration."""

    def setup_method(self):
        """Setup for each test method."""
        self.blacklist = Blacklist()
        self.rule_engine = RuleEngine()
        self.detector = Detector(self.blacklist, self.rule_engine)

    def test_blacklist_only_detection(self):
        """Test detection based on blacklist only."""
        # Add a domain to blacklist
        self.blacklist.domains.add("malicious.com")

        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="malicious.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        alert = self.detector.analyse(event)

        assert alert is not None
        assert alert.domain == "malicious.com"
        assert alert.severity == "High"  # Blacklist hits get high severity
        assert alert.score >= 100  # Blacklist base score

    def test_rules_only_detection(self):
        """Test detection based on rules only."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="suspicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        alert = self.detector.analyse(event)

        assert alert is not None
        assert alert.domain == "suspicious.xyz"
        assert alert.severity in ["Low", "Medium", "High"]
        assert "suspicious_tld" in alert.rules_triggered

    def test_combined_blacklist_and_rules(self):
        """Test detection with both blacklist and rules triggered."""
        # Add domain to blacklist
        self.blacklist.domains.add("suspicious.xyz")

        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="suspicious.xyz",
            query_type="A",
            is_response=False,
            response_code=0
        )

        alert = self.detector.analyse(event)

        assert alert is not None
        assert alert.score >= 100  # Blacklist base score
        assert "suspicious_tld" in alert.rules_triggered

    def test_no_threat_detection(self):
        """Test that clean events don't generate alerts."""
        event = DnsEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            domain="google.com",
            query_type="A",
            is_response=False,
            response_code=0
        )

        alert = self.detector.analyse(event)

        assert alert is None

    def test_severity_calculation(self):
        """Test that severity levels are calculated correctly."""
        test_cases = [
            (10, "Low"),
            (60, "Medium"),
            (120, "High")
        ]

        for score, expected_severity in test_cases:
            alert = self.detector._get_severity(score)
            assert alert == expected_severity, f"Score {score} should be {expected_severity}, got {alert}"

    def test_score_calculation(self):
        """Test threat score calculation."""
        # Test blacklist scoring
        blacklist_hit = True
        rules = []
        score = self.detector._calculate_score(blacklist_hit, rules)
        assert score >= 100

        # Test rule scoring
        blacklist_hit = False
        rules = ["suspicious_tld", "high_query_rate"]
        score = self.detector._calculate_score(blacklist_hit, rules)
        expected_score = 20 + 30  # suspicious_tld + high_query_rate scores
        assert score == expected_score


class TestDetectionIntegration:
    """Integration tests for detection components."""

    def test_full_detection_pipeline(self):
        """Test the complete detection pipeline."""
        # Setup components
        blacklist = Blacklist()
        rule_engine = RuleEngine()
        detector = Detector(blacklist, rule_engine)

        # Add test domain to blacklist
        blacklist.domains.add("blacklisted.com")

        # Test various scenarios
        test_events = [
            {
                "domain": "blacklisted.com",
                "expected_alert": True,
                "expected_severity": "High"
            },
            {
                "domain": "suspicious.xyz",
                "expected_alert": True,
                "expected_severity": "Low"
            },
            {
                "domain": "google.com",
                "expected_alert": False,
                "expected_severity": None
            }
        ]

        for test_case in test_events:
            event = DnsEvent(
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                domain=test_case["domain"],
                query_type="A",
                is_response=False,
                response_code=0
            )

            alert = detector.analyse(event)

            if test_case["expected_alert"]:
                assert alert is not None, f"Expected alert for {test_case['domain']}"
                assert alert.severity == test_case["expected_severity"], \
                    f"Expected severity {test_case['expected_severity']} for {test_case['domain']}, got {alert.severity}"
            else:
                assert alert is None, f"Unexpected alert for {test_case['domain']}"
