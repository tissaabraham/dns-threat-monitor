"""
Test Configuration and Fixtures

Testing framework configuration for the DNS Threat Monitor.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sample_dns_log():
    """Sample DNS log data for testing."""
    return {
        'timestamp': '2026-03-24 10:30:00',
        'source_ip': '192.168.1.100',
        'domain': 'example.com',
        'query_type': 'A'
    }


@pytest.fixture
def sample_malicious_domain():
    """Sample malicious domain for testing."""
    return 'malicious-domain.xyz'


@pytest.fixture
def sample_alert():
    """Sample alert for testing."""
    return {
        'domain': 'malicious-domain.xyz',
        'source_ip': '192.168.1.100',
        'threat_type': 'malicious_domain',
        'severity': 'high',
        'threat_score': 95,
        'rules_triggered': ['blacklist_match', 'suspicious_tld']
    }

