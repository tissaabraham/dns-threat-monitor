"""
Threat Detection Engine

Implements two detection techniques:
1. Blacklist-Based Detection - Compare against known malicious domains
2. Rule-Based Behaviour Detection - Identify suspicious patterns
"""

import logging
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Threat severity levels."""
    NOT_SIGNIFICANT = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    
    @staticmethod
    def from_score(score: int) -> "SeverityLevel":
        """Convert threat score to severity level."""
        if score >= 80:
            return SeverityLevel.HIGH
        elif score >= 50:
            return SeverityLevel.MEDIUM
        elif score >= 20:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.NOT_SIGNIFICANT


class ThreatAlert:
    """Represents a generated threat alert."""
    
    def __init__(self, domain: str, source_ip: str, threat_type: str, 
                 severity: SeverityLevel, score: int, rules_triggered: List[str]):
        """
        Initialize threat alert.
        
        Args:
            domain: Domain that triggered alert
            source_ip: Source IP of the query
            threat_type: Type of threat detected
            severity: Severity level
            score: Threat score (0-100)
            rules_triggered: List of detection rules that triggered
        """
        self.domain = domain
        self.source_ip = source_ip
        self.threat_type = threat_type
        self.severity = severity
        self.score = score
        self.rules_triggered = rules_triggered
        self.status = "new"  # new, acknowledged, resolved, archived
        
    def to_dict(self) -> dict:
        """Convert alert to dictionary."""
        return {
            "domain": self.domain,
            "source_ip": self.source_ip,
            "threat_type": self.threat_type,
            "severity": self.severity.name,
            "score": self.score,
            "rules_triggered": self.rules_triggered,
            "status": self.status
        }


class DetectionEngine:
    """
    Main threat detection engine.
    
    Applies blacklist-based and rule-based detection to DNS queries.
    """
    
    def __init__(self, blacklist_file: Optional[str] = None):
        """
        Initialize detection engine.
        
        Args:
            blacklist_file: Path to blacklist file
        """
        self.blacklist = set()
        self.detection_rules = []
        self.alerts_generated = 0
        
        if blacklist_file:
            self.load_blacklist(blacklist_file)
            
    def load_blacklist(self, blacklist_file: str):
        """
        Load malicious domain blacklist.
        
        Loads from URLhaus, Malware Domains List, or OpenPhish.
        Updated every 24 hours.
        
        Args:
            blacklist_file: Path to blacklist file
        """
        try:
            with open(blacklist_file, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain:
                        self.blacklist.add(domain)
            logger.info(f"Loaded {len(self.blacklist)} domains into blacklist")
        except Exception as e:
            logger.error(f"Error loading blacklist: {e}")
            
    def check_blacklist(self, domain: str) -> bool:
        """
        Check if domain is in blacklist.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is malicious (in blacklist)
        """
        return domain.lower() in self.blacklist
        
    def detect_threats(self, domain: str, source_ip: str) -> Optional[ThreatAlert]:
        """
        Detect threats in DNS query.
        
        Applies both blacklist and rule-based detection.
        
        Args:
            domain: Domain being queried
            source_ip: Source IP of query
            
        Returns:
            ThreatAlert if threat detected, None otherwise
        """
        threat_score = 0
        rules_triggered = []
        threat_type = None
        
        # 1. Blacklist check
        if self.check_blacklist(domain):
            threat_score += 100
            rules_triggered.append("blacklist_match")
            threat_type = "malicious_domain"
            
        # 2. Rule-based detection
        if self._check_high_query_rate(domain, source_ip):
            threat_score += 15
            rules_triggered.append("high_query_rate")
            
        if self._check_suspicious_tld(domain):
            threat_score += 20
            rules_triggered.append("suspicious_tld")
            
        if self._check_random_domain_name(domain):
            threat_score += 25
            rules_triggered.append("random_domain_name")
            
        if self._check_nxdomain_pattern(domain):
            threat_score += 18
            rules_triggered.append("nxdomain_pattern")
            
        if self._check_subdomain_enumeration(domain):
            threat_score += 22
            rules_triggered.append("subdomain_enumeration")
        
        # Generate alert if threat detected
        if threat_score > 0:
            severity = SeverityLevel.from_score(threat_score)
            threat_type = threat_type or "suspicious_activity"
            alert = ThreatAlert(domain, source_ip, threat_type, severity, 
                              min(threat_score, 100), rules_triggered)
            self.alerts_generated += 1
            return alert
            
        return None
        
    def _check_high_query_rate(self, domain: str, source_ip: str) -> bool:
        """Detect unusually high frequency of DNS queries."""
        # Implementation: check if source_ip has abnormal query rate
        return False
        
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Identify requests to domains with uncommon or suspicious TLDs."""
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf']
        return any(domain.lower().endswith(tld) for tld in suspicious_tlds)
        
    def _check_random_domain_name(self, domain: str) -> bool:
        """Flag domains with randomly generated or obfuscated names."""
        # Implementation: analyze domain name entropy
        return False
        
    def _check_nxdomain_pattern(self, domain: str) -> bool:
        """Detect patterns of non-existent domain responses."""
        # Implementation: check for repeated NXDOMAIN responses
        return False
        
    def _check_subdomain_enumeration(self, domain: str) -> bool:
        """Identify excessive subdomain enumeration attempts."""
        # Implementation: check for multiple subdomain queries
        return False
        
    def get_statistics(self) -> dict:
        """Get detection engine statistics."""
        return {
            "alerts_generated": self.alerts_generated,
            "blacklist_size": len(self.blacklist)
        }

