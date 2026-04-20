# Detection Engine Module

## Purpose

The **Detection Engine** module applies threat detection logic to identify malicious and suspicious DNS activity. This is the core analysis layer of the system architecture.

## Responsibilities

- Apply blacklist-based detection against known malicious domains
- Implement rule-based behaviour detection
- Calculate threat scores based on detection rules
- Classify events into severity levels
- Generate alerts for detected threats
- Maintain and update malicious domain lists

## Detection Methods

### 1. Blacklist-Based Detection
- Compare incoming DNS queries against known malicious domain lists
- Match against cached blacklist data
- Update malicious domain cache every 24 hours

### 2. Rule-Based Behaviour Detection
Apply detection rules to identify suspicious patterns:
- **High query/response rate** - Detects unusually high frequency of DNS queries
- **Suspicious TLD** - Identifies uncommon or suspicious top-level domains
- **Random looking domain names** - Flags domains with randomly generated or obfuscated names
- **Lots of NXDOMAIN responses** - Detects patterns indicating scanning or brute-force activity
- **High number of subdomain queries** - Identifies excessive subdomain enumeration attempts

## Threat Scoring

Events are scored and classified into severity levels:
1. **Not-significant** - No or minimal threat indicators
2. **Low Severity** - Minor suspicious activity
3. **Medium Severity** - Notable suspicious activity
4. **High Severity** - Strong malicious indicators

## Data Sources

- URLhaus - Frequently updated malicious URLs (CSV/JSON format with API)
- Malware Domains List - Known malicious domains
- OpenPhish - Phishing intelligence service with API access

## Key Components

- Blacklist management and caching system
- Detection rule implementations
- Threat scoring and severity classification engine
- Alert generation logic
- Malicious domain list update scheduler

## Technology Stack

- Python
- API clients for threat intelligence sources
- SQLite for caching blacklists

## Input/Output

- **Input**: Structured DNS records from the Parser module
- **Output**: Alert events and threat intelligence forwarded to the Database and Dashboard modules

