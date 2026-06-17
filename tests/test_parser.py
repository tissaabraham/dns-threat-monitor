# Tests for dnsmasq and tshark parsers, domain normalisation, and cross-format consistency.

import pytest
from datetime import datetime, timezone
from database.dataModels import DnsEvent
from parser.input_parser import (
    parse_dnsmasq_line, parse_tshark_line, parse_line,
    normalise_domain, get_root_domain
)


class TestDnsmasqParser:
    """Test dnsmasq log line parsing."""

    def test_parse_dnsmasq_query_a_record(self):
        """Test parsing A record query."""
        line = "Apr 26 14:30:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.source_ip == "192.168.1.100"
        assert event.query_type == "A"
        assert event.is_response == False
        assert event.response_code == 0

    def test_parse_dnsmasq_reply_a_record(self):
        """Test parsing A record reply."""
        line = "Apr 26 14:30:16 dnsmasq[1234]: reply example.com is 93.184.216.34"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.is_response == True
        assert event.response_code == 0
        assert "93.184.216.34" in event.resolved_ips

    def test_parse_dnsmasq_nxdomain(self):
        """Test parsing NXDOMAIN response."""
        line = "Apr 26 14:30:17 dnsmasq[1234]: reply nonexistent.domain from 192.168.1.100"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.domain == "nonexistent.domain"
        assert event.is_response == True
        assert event.response_code == 3  # NXDOMAIN
        assert event.resolved_ips == []

    def test_parse_invalid_dnsmasq_line(self):
        """Test parsing invalid dnsmasq line."""
        line = "Invalid log line without proper format"

        event = parse_dnsmasq_line(line)

        assert event is None


class TestTsharkParser:
    """Test tshark capture parsing."""

    def test_parse_tshark_a_query(self):
        """Test parsing tshark A record query."""
        line = "Apr 26, 2026 14:30:15.123456000 UTC|192.168.1.100|8.8.8.8|example.com|A|0|0|"

        event = parse_tshark_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.source_ip == "192.168.1.100"
        assert event.query_type == "A"
        assert event.is_response == False

    def test_parse_tshark_a_response(self):
        """Test parsing tshark A record response."""
        line = "Apr 26, 2026 14:30:16.123456000 UTC|8.8.8.8|192.168.1.100|example.com|A|1|0|93.184.216.34"

        event = parse_tshark_line(line)

        assert event is not None
        assert event.domain == "example.com"
        assert event.is_response == True
        assert "93.184.216.34" in event.resolved_ips

    def test_parse_tshark_aaaa_query(self):
        """Test parsing AAAA record query."""
        line = "Apr 26, 2026 14:30:17.123456000 UTC|192.168.1.100|8.8.8.8|example.com|AAAA|0|0|"

        event = parse_tshark_line(line)

        assert event is not None
        assert event.query_type == "AAAA"

    def test_parse_invalid_tshark_line(self):
        """Test parsing invalid tshark line."""
        line = "Invalid tshark line"

        event = parse_tshark_line(line)

        assert event is None


class TestUnifiedParser:
    """Test the unified parse_line function."""

    def test_parse_dnsmasq_source(self):
        """Test unified parser with dnsmasq source."""
        line = "Apr 26 14:30:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100"

        event = parse_line("dnsmasq", line)

        assert event is not None
        assert event.domain == "example.com"

    def test_parse_tshark_source(self):
        """Test unified parser with tshark source."""
        line = "Apr 26, 2026 14:30:15.123456000 UTC|192.168.1.100|8.8.8.8|example.com|A|0|0|"

        event = parse_line("tshark", line)

        assert event is not None
        assert event.domain == "example.com"

    def test_parse_unknown_source(self):
        """Test unified parser with unknown source."""
        line = "Some log line"

        event = parse_line("unknown", line)

        assert event is None


class TestDomainUtilities:
    """Test domain normalization utilities."""

    def test_normalise_domain_basic(self):
        """Test basic domain normalization."""
        assert normalise_domain("EXAMPLE.COM") == "example.com"
        assert normalise_domain("Example.Com") == "example.com"

    def test_normalise_domain_with_trailing_dot(self):
        """Test domain normalization with trailing dot."""
        assert normalise_domain("example.com.") == "example.com"
        assert normalise_domain("sub.example.com.") == "sub.example.com"

    def test_normalise_domain_uppercase(self):
        """Test domain normalization with uppercase."""
        assert normalise_domain("MALICIOUS.XYZ") == "malicious.xyz"

    def test_get_root_domain_simple(self):
        """Test getting root domain from simple domain."""
        assert get_root_domain("example.com") == "example.com"

    def test_get_root_domain_with_subdomain(self):
        """Test getting root domain from domain with subdomain."""
        assert get_root_domain("sub.example.com") == "example.com"
        assert get_root_domain("api.sub.example.com") == "example.com"

    def test_get_root_domain_edge_cases(self):
        """Test root domain extraction edge cases."""
        assert get_root_domain("localhost") == "localhost"
        assert get_root_domain("a.b.c") == "b.c"


class TestParserIntegration:
    """Integration tests for parser components."""

    def test_parser_timestamp_parsing(self):
        """Test that timestamps are parsed correctly."""
        line = "Apr 26 14:30:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100"

        event = parse_dnsmasq_line(line)

        assert event is not None
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 4
        assert event.timestamp.day == 26

    def test_parser_data_consistency(self):
        """Test that parsed data is consistent across formats."""
        # Both parsers should produce similar DnsEvent structures
        dnsmasq_line = "Apr 26 14:30:15 dnsmasq[1234]: query[A] example.com from 192.168.1.100"
        tshark_line = "Apr 26, 2026 14:30:15.123456000 UTC|192.168.1.100|8.8.8.8|example.com|A|0|0|"

        dnsmasq_event = parse_dnsmasq_line(dnsmasq_line)
        tshark_event = parse_tshark_line(tshark_line)

        assert dnsmasq_event.domain == tshark_event.domain
        assert dnsmasq_event.query_type == tshark_event.query_type
        assert dnsmasq_event.is_response == tshark_event.is_response
