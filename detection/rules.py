"""
Detection Rules Configuration

Defines rules for rule-based behavior detection:
- High query/response rate
- Suspicious TLD
- Random looking domain names
- Lots of NXDOMAIN responses
- High number of subdomain queries
"""

# Suspicious Top-Level Domains
SUSPICIOUS_TLDS = [
    '.xyz',
    '.top', 
    '.tk',
    '.ml',
    '.ga',
    '.cf',
    '.gq',
    '.download',
    '.review',
    '.science'
]

# Rules configuration
DETECTION_RULES = {
    'high_query_rate': {
        'description': 'Detects unusually high frequency of DNS queries from a single source',
        'threshold': 100,  # queries per minute
        'weight': 15
    },
    'suspicious_tld': {
        'description': 'Identifies requests to domains with uncommon or suspicious TLDs',
        'suspicious_tlds': SUSPICIOUS_TLDS,
        'weight': 20
    },
    'random_domain_name': {
        'description': 'Flags domains that appear to have randomly generated or obfuscated names',
        'entropy_threshold': 3.5,
        'weight': 25
    },
    'nxdomain_pattern': {
        'description': 'Detects patterns of non-existent domain responses',
        'threshold': 10,  # NXDOMAIN responses
        'weight': 18
    },
    'subdomain_enumeration': {
        'description': 'Identifies excessive subdomain enumeration attempts',
        'threshold': 20,  # subdomain queries
        'weight': 22
    }
}

# Threat Score Thresholds
THREAT_SCORE_THRESHOLDS = {
    'not_significant': 0,
    'low': 20,
    'medium': 50,
    'high': 80
}

