"""
DNS Log Parser Module

Parses captured DNS traffic and extracts important details:
- Timestamp of query
- Source IP address
- Domain name
- Query type (A, AAAA, MX, etc.)
"""

import logging
from datetime import datetime
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)


class DNSRecord:
    """Represents a parsed DNS record."""
    
    def __init__(self, timestamp: datetime, source_ip: str, domain: str, query_type: str):
        """
        Initialize DNS record.
        
        Args:
            timestamp: When the query was made
            source_ip: IP address of the device making the query
            domain: Domain name being queried
            query_type: Type of DNS query (A, AAAA, MX, etc.)
        """
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.domain = domain
        self.query_type = query_type
        
    def to_dict(self) -> dict:
        """Convert DNS record to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "domain": self.domain,
            "query_type": self.query_type
        }


class DNSParser:
    """
    Parses DNS logs and extracts relevant information.
    
    Processes raw DNS traffic captured by tcpdump/tshark and extracts:
    - Timestamp
    - Source IP address
    - Domain name
    - Query type
    """
    
    def __init__(self):
        """Initialize DNS parser."""
        self.records_parsed = 0
        
    def parse_packet(self, packet_data: str) -> Optional[DNSRecord]:
        """
        Parse a single DNS packet and extract relevant fields.
        
        Args:
            packet_data: Raw packet data from capture
            
        Returns:
            DNSRecord if parsing successful, None otherwise
        """
        try:
            # Parse packet data to extract DNS fields
            # This will interface with tshark output
            pass
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
            
    def parse_batch(self, packets: List[str]) -> List[DNSRecord]:
        """
        Parse multiple DNS packets.
        
        Args:
            packets: List of raw packet data
            
        Returns:
            List of parsed DNSRecord objects
        """
        records = []
        for packet in packets:
            record = self.parse_packet(packet)
            if record:
                records.append(record)
                self.records_parsed += 1
        return records
        
    def get_statistics(self) -> dict:
        """
        Get parsing statistics.
        
        Returns:
            Dictionary with parsing statistics
        """
        return {
            "records_parsed": self.records_parsed
        }

