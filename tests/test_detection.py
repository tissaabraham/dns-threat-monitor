"""
Unit Tests for Detection Engine

Tests for blacklist-based and rule-based detection.
"""

import pytest
from detection.detection_engine import DetectionEngine, SeverityLevel, ThreatAlert


class TestDetectionEngine:
    """Tests for the DetectionEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create detection engine instance."""
        return DetectionEngine()
    
    def test_severity_level_from_score(self):
        """Test severity level calculation from threat score."""
        assert SeverityLevel.from_score(0) == SeverityLevel.NOT_SIGNIFICANT
        assert SeverityLevel.from_score(15) == SeverityLevel.LOW
        assert SeverityLevel.from_score(30) == SeverityLevel.MEDIUM
        assert SeverityLevel.from_score(85) == SeverityLevel.HIGH
    
    def test_suspicious_tld_detection(self, engine):
        """Test detection of suspicious top-level domains."""
        # Test suspicious TLDs
        assert engine._check_suspicious_tld('example.xyz')
        assert engine._check_suspicious_tld('test.top')
        assert engine._check_suspicious_tld('domain.tk')
        
        # Test normal TLDs
        assert not engine._check_suspicious_tld('example.com')
        assert not engine._check_suspicious_tld('test.org')
    
    def test_threat_alert_creation(self, sample_alert):
        """Test creation of threat alerts."""
        alert = ThreatAlert(
            domain=sample_alert['domain'],
            source_ip=sample_alert['source_ip'],
            threat_type=sample_alert['threat_type'],
            severity=SeverityLevel.HIGH,
            score=sample_alert['threat_score'],
            rules_triggered=sample_alert['rules_triggered']
        )
        
        alert_dict = alert.to_dict()
        assert alert_dict['domain'] == 'malicious-domain.xyz'
        assert alert_dict['severity'] == 'HIGH'
        assert alert_dict['score'] == 95


class TestBlacklistDetection:
    """Tests for blacklist-based detection."""
    
    def test_blacklist_loading(self, tmp_path):
        """Test loading blacklist from file."""
        # Create temporary blacklist file
        blacklist_file = tmp_path / "blacklist.txt"
        blacklist_file.write_text("malicious.com\n evil.org\n badsite.net\n")
        
        engine = DetectionEngine(str(blacklist_file))
        assert len(engine.blacklist) == 3
    
    def test_blacklist_check(self):
        """Test checking domain against blacklist."""
        engine = DetectionEngine()
        engine.blacklist.add('malicious.com')
        engine.blacklist.add('evil.org')
        
        assert engine.check_blacklist('malicious.com')
        assert engine.check_blacklist('evil.org')
        assert not engine.check_blacklist('safe.com')


class TestRuleBasedDetection:
    """Tests for rule-based behavior detection."""
    
    def test_detection_generates_alerts(self):
        """Test that detection generates appropriate alerts."""
        engine = DetectionEngine()
        engine.blacklist.add('malicious.xyz')
        
        alert = engine.detect_threats('malicious.xyz', '192.168.1.100')
        assert alert is not None
        assert alert.domain == 'malicious.xyz'
        assert alert.severity == SeverityLevel.HIGH

