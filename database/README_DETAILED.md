# Database Module - Detailed Explanation

## Overview

The **Database** module manages all persistent data storage for the threat monitoring system. This is the data persistence layer of the system architecture.

---

## Classes Explanation

### 1. **Alert Class**
**Purpose**: Represents a security alert triggered by the Detection Engine

**What it contains**:
- `timestamp` - When the alert was created
- `source_ip` - IP address of the device that triggered the alert
- `domain` - The suspicious/malicious website/domain
- `severity` - How dangerous (Low, Medium, or High)
- `score` - Threat score (0-100, higher = more dangerous)
- `rules_triggered` - List of detection rules that caught this threat
- `status` - Current stage of alert lifecycle (new → acknowledged → resolved → archived)
- `id` - Database ID (auto-generated when stored)

**When used**: 
- When the Detection Engine finds something suspicious
- When storing threat information in the database

**Example**:
```python
alert = Alert(
    timestamp=datetime.now(timezone.utc),
    source_ip="192.168.1.100",
    domain="malicious.xyz",
    severity="High",
    score=85,
    rules_triggered=["high_query_rate", "known_malicious_domain"],
    status="new"
)
```

---

### 2. **DnsEvent Class**
**Purpose**: Represents a single DNS query or response from network traffic

**What it contains**:
- `timestamp` - When this DNS activity occurred
- `source_ip` - Which device on the network made the request
- `domain` - Website/domain being searched for
- `query_type` - Type of DNS query:
  - `A` - IPv4 address lookup
  - `AAAA` - IPv6 address lookup
  - `MX` - Mail server lookup
  - `CNAME` - Alias/redirect lookup
  - `PTR` - Reverse lookup (IP to name)
  - `NS` - Nameserver lookup
  - `TXT` - Text record lookup
- `is_response` - Boolean: Is this a response (True) or a query (False)?
- `response_code` - DNS status code (0 = success, others = errors)
- `resolved_ips` - List of IP addresses returned in the response
- `id` - Database ID (auto-generated when stored)

**When used**: 
- Every time the Capture Module captures DNS traffic
- When the Parser extracts DNS information
- When storing DNS records in the database

**Example**:
```python
event = DnsEvent(
    timestamp=datetime.now(timezone.utc),
    source_ip="192.168.1.100",
    domain="example.com",
    query_type="A",
    is_response=True,
    response_code=0,
    resolved_ips=["93.184.216.34"]
)
```

---

### 3. **ThreatCacheEntry Class**
**Purpose**: Represents a cached malicious domain for fast threat lookups

**What it contains**:
- `domain` - The malicious website/domain name
- `source` - Where we got this threat information:
  - `OpenPhish` - Phishing intelligence
  - `Spamhaus` - Spam and malware lists
  - `Abuse.ch` - Botnet and malware tracking
  - `URLhaus` - Malicious URL database
  - `Malware Domains List` - Known malware domains
- `threat_type` - What kind of threat:
  - `phishing` - Phishing websites
  - `malware` - Malware distribution sites
  - `botnet` - Botnet command & control servers
  - `spam` - Spam sources
  - `ransomware` - Ransomware sites
- `last_updated` - When this entry was last refreshed from the source
- `id` - Database ID (auto-generated when stored)

**When used**: 
- When caching threat intelligence data
- When checking if a domain is known to be malicious
- When updating the threat database every 24 hours

**Example**:
```python
threat = ThreatCacheEntry(
    domain="phishing-bank.com",
    source="OpenPhish",
    threat_type="phishing",
    last_updated=datetime.now(timezone.utc)
)
```

---

### 4. **DatabaseManager Class**
**Purpose**: The main controller - handles ALL database operations

**How it works**:
1. **Initialization** - Automatically creates database file and all tables on first run
2. **Stores Data** - Saves DNS events, alerts, and threat information
3. **Searches Data** - Finds specific records based on multiple filter options
4. **Updates Data** - Changes alert status and records investigation history
5. **Retrieves Data** - Gets information for the dashboard display

**Key Features**:
- ✅ Auto-creates database if it doesn't exist
- ✅ Creates 4 tables automatically
- ✅ Creates 5 performance indexes for fast searches
- ✅ Handles all database operations safely

**Main Methods**:

| Method | Purpose | Returns |
|--------|---------|---------|
| `store_dns_log(event, threat_score)` | Save a DNS query/response | Database ID |
| `get_recent_dns_logs(hours, limit)` | Get recent DNS activity | List of logs |
| `search_dns_logs(domain, ip, level, hours)` | Find DNS logs with filters | List of logs |
| `store_alert(alert, dns_log_id)` | Create a security alert | Alert ID |
| `update_alert_status(alert_id, status, notes)` | Change alert status | True/False |
| `get_active_alerts(limit)` | Get unresolved alerts | List of alerts |
| `get_alert_history(alert_id)` | Get investigation history | List of history |
| `store_threat_cache_entry(threat)` | Cache malicious domain | Entry ID |
| `is_domain_malicious(domain)` | Check if domain is bad | True/False |
| `get_threat_cache_size()` | Count cached domains | Number |
| `get_dashboard_summary()` | Get statistics | Dictionary |
| `search_alerts(domain, ip, severity, status)` | Find alerts with filters | List of alerts |
| `close()` | Close database connection | None |

---

## Database Tables Explanation

### Table 1: **dns_logs**
**Purpose**: Complete record of every DNS query and response

**What it stores**: Every DNS activity captured from the network

**Columns**:
| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER | Unique identifier (auto-generated) |
| `timestamp` | TEXT | When the DNS activity occurred |
| `source_ip` | TEXT | Device that made the DNS request |
| `domain` | TEXT | Website/domain being searched for |
| `query_type` | TEXT | Type of query (A, AAAA, MX, CNAME, PTR, NS, TXT) |
| `is_response` | INTEGER | 1 = response, 0 = query |
| `response_code` | INTEGER | DNS status code (0=success) |
| `resolved_ips` | TEXT | IP addresses returned (JSON format) |
| `threat_score` | INTEGER | Threat level (0-100) |

**Example row**:
```
id: 1
timestamp: 2026-04-02 10:15:30
source_ip: 192.168.1.100
domain: google.com
query_type: A
is_response: 1
response_code: 0
resolved_ips: ["142.250.80.46"]
threat_score: 0
```

**Why it matters**: 
- Complete visibility of network DNS activity
- Historical record for investigation
- Supports trend analysis
- Links to alerts for correlation

**Indexed by**: `timestamp`, `domain` (for fast searches)

---

### Table 2: **alerts**
**Purpose**: Records all detected security threats

**What it stores**: Every security alert generated by the Detection Engine

**Columns**:
| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER | Unique alert identifier |
| `dns_log_id` | INTEGER | Link to the DNS log that triggered this alert |
| `timestamp` | TEXT | When the alert was created |
| `source_ip` | TEXT | Device that triggered the alert |
| `domain` | TEXT | Suspicious domain |
| `severity` | TEXT | Alert level (Low, Medium, High) |
| `threat_score` | INTEGER | Calculated threat score (0-100) |
| `rules_triggered` | TEXT | Detection rules that fired (JSON format) |
| `status` | TEXT | Alert status (new, acknowledged, resolved, archived) |

**Example row**:
```
id: 1
dns_log_id: 5
timestamp: 2026-04-02 10:20:15
source_ip: 192.168.1.100
domain: malicious.xyz
severity: High
threat_score: 87
rules_triggered: ["known_malicious_domain", "high_query_rate"]
status: new
```

**Why it matters**: 
- Tracks all detected threats
- Shows severity for prioritization
- Records which rules detected the threat
- Tracks investigation status

**Status Flow**:
```
new → acknowledged → resolved
         ↓
      archived
```

**Indexed by**: `timestamp`, `status` (for fast searches)

---

### Table 3: **alert_history**
**Purpose**: Tracks every action taken during alert investigation

**What it stores**: Complete audit trail of alert status changes

**Columns**:
| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER | Unique history entry ID |
| `alert_id` | INTEGER | Which alert this is about |
| `old_status` | TEXT | Previous status before change |
| `new_status` | TEXT | Status after change |
| `timestamp` | TEXT | When the change occurred |
| `notes` | TEXT | What was done / why |

**Example rows showing an investigation**:
```
Entry 1:
alert_id: 1, old_status: "", new_status: "new"
timestamp: 2026-04-02 10:20:15
notes: Alert created

Entry 2:
alert_id: 1, old_status: "new", new_status: "acknowledged"
timestamp: 2026-04-02 10:25:00
notes: Security team started investigating

Entry 3:
alert_id: 1, old_status: "acknowledged", new_status: "resolved"
timestamp: 2026-04-02 11:00:00
notes: False positive - domain was whitelisted
```

**Why it matters**: 
- Complete investigation history
- Shows who did what and when
- Audit trail for compliance
- Can replay entire investigation

---

### Table 4: **threat_cache**
**Purpose**: Fast lookup of known malicious domains

**What it stores**: Malicious domains from external threat intelligence sources

**Columns**:
| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER | Unique identifier |
| `domain` | TEXT | Malicious domain (UNIQUE - no duplicates) |
| `source` | TEXT | Where threat info came from |
| `threat_type` | TEXT | Type of threat |
| `last_updated` | TEXT | When entry was last updated |

**Example rows**:
```
Entry 1:
domain: phishing-bank.com
source: OpenPhish
threat_type: phishing
last_updated: 2026-04-02 09:00:00

Entry 2:
domain: malware-download.net
source: Spamhaus
threat_type: malware
last_updated: 2026-04-02 08:30:00

Entry 3:
domain: botnet-c2.org
source: Abuse.ch
threat_type: botnet
last_updated: 2026-04-02 10:15:00
```

**Why it matters**: 
- Fast threat checking (no external API calls)
- Improves system performance
- 24-hour refresh keeps data current
- Multiple threat sources for accuracy

**Indexed by**: `domain` (for lightning-fast lookups)

---

## How They Work Together - Complete Flow

### Scenario: Network Device Accesses Malicious Website

**Step 1: Capture Module Catches DNS Activity**
```
Network Device → DNS Query to malicious-site.com
Capture Module captures this traffic
```

**Step 2: Parser Extracts Information**
```python
DnsEvent created:
- timestamp: 2026-04-02 10:15:00
- source_ip: 192.168.1.50
- domain: malicious-site.com
- query_type: A
- is_response: True
```

**Step 3: DatabaseManager Stores DNS Log**
```python
dns_log_id = db.store_dns_log(event, threat_score=0)
# Saved to dns_logs table, ID = 42
```

**Step 4: Detection Engine Analyzes**
```
Checks threat_cache table:
- Is malicious-site.com known bad? YES!
Checks detection rules:
- High threat score? YES (85/100)
- Known malicious domain? YES
Decision: CREATE ALERT
```

**Step 5: Alert Created and Stored**
```python
alert = Alert(
    timestamp=2026-04-02 10:20:00,
    source_ip="192.168.1.50",
    domain="malicious-site.com",
    severity="High",
    score=85,
    rules_triggered=["known_malicious_domain", "high_threat_score"]
)
alert_id = db.store_alert(alert, dns_log_id=42)
# Alert stored, ID = 1
# alert_history entry added: "Alert created"
```

**Step 6: Dashboard Shows Alert**
```
Security Team sees:
- New High severity alert
- Domain: malicious-site.com
- Device: 192.168.1.50
- Created: 2026-04-02 10:20:00
```

**Step 7: Investigation Begins**
```python
# Team acknowledges alert
db.update_alert_status(
    alert_id=1,
    new_status="acknowledged",
    notes="Blocking device, checking for compromise"
)
# alert_history entry added: old=new, new=acknowledged
```

**Step 8: Investigation Complete**
```python
# Team resolves alert
db.update_alert_status(
    alert_id=1,
    new_status="resolved",
    notes="Device cleaned, malware removed, domain blocked in firewall"
)
# alert_history entry added: old=acknowledged, new=resolved
```

**Step 9: Complete History Available**
```
db.get_alert_history(alert_id=1) returns:
1. Alert created - 10:20:00
2. Acknowledged - 10:25:00
3. Resolved - 10:45:00

Full investigation timeline available!
```

---

## Search Examples

### Search DNS Logs
```python
# Find all suspicious activity from a device in last 24 hours
results = db.search_dns_logs(
    source_ip="192.168.1.100",
    threat_level=30,
    hours=24
)

# Search for phishing-related domains
results = db.search_dns_logs(
    domain="phishing",
    hours=168  # Last 7 days
)

# Find high-threat activity
results = db.search_dns_logs(
    threat_level=70,
    hours=24
)
```

### Search Alerts
```python
# Get all new high-severity alerts
results = db.search_alerts(
    severity="High",
    status="new",
    hours=24
)

# Find alerts being investigated
results = db.search_alerts(
    status="acknowledged",
    hours=168
)

# Search by device
results = db.search_alerts(
    source_ip="192.168.1.100",
    hours=24
)
```

---

## Dashboard Integration

The dashboard can display:

```python
# Get overview statistics
summary = db.get_dashboard_summary()
# Returns:
# {
#     'recent_queries_24h': 1250,
#     'new_alerts': 5,
#     'severity_distribution': {'Low': 2, 'Medium': 2, 'High': 1},
#     'threat_cache_size': 15000
# }

# Show recent activity
recent = db.get_recent_dns_logs(hours=24, limit=100)

# Show active investigations
active = db.get_active_alerts(limit=50)

# Get investigation details
history = db.get_alert_history(alert_id=1)
```

---

## Quick Reference

| Need | Method |
|------|--------|
| Store DNS query | `store_dns_log(event)` |
| Create alert | `store_alert(alert, dns_log_id)` |
| Update alert status | `update_alert_status(alert_id, status)` |
| Find DNS activity | `search_dns_logs(...)` |
| Find alerts | `search_alerts(...)` |
| Check if domain is bad | `is_domain_malicious(domain)` |
| Cache malicious domain | `store_threat_cache_entry(threat)` |
| Get dashboard data | `get_dashboard_summary()` |
| Get investigation history | `get_alert_history(alert_id)` |

---

## Summary

The database module provides:
- ✅ Complete DNS activity logging
- ✅ Security alert tracking
- ✅ Investigation audit trail
- ✅ Malicious domain caching
- ✅ Fast searching and filtering
- ✅ Dashboard integration
- ✅ Automatic initialization
- ✅ Production-ready reliability

