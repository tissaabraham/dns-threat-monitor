# Database Module

## Purpose
The **Database** module manages all persistent data storage for the threat monitoring system. In our implementation it acts as the data persistence layer of the architecture and backs the dashboard, reporting, and testing work.

## Responsibilities
- Store parsed DNS logs and metadata
- Maintain alert event records
- Track alert lifecycle states
- Store threat intelligence and malicious domain lists
- Provide data retrieval and querying capabilities
- Manage database schema and relationships
- Archive historical data
- Support reporting and analysis queries

## Data Models
The module defines data models for:
- DNS log records (timestamp, source IP, destination IP, domain, query type, response)
- Alert events (timestamp, threat type, source IP, domain, severity, status)
- Threat intelligence (malicious domains, TLDs, patterns)
- Alert status tracking (new, acknowledged, resolved, archived)

## Technology Stack
- SQLite Database
- Python ORM or database abstraction layer
- SQL query interface

## Key Components
- Database schema definitions
- Data models (dataModels.py)
- Query interfaces
- Data insertion and retrieval logic
- Archive and retention policies

## Input/Output
- **Input**: Parsed DNS records from Parser and alerts from Detection Engine
- **Output**: Structured data queries for Dashboard and reporting

## Files
- dataModels.py - Core data model definitions for DNS logs, alerts, and threat intelligence

---

## PART 1: THE 4 CLASSES (In-Memory Data Objects)

Classes are Python objects that hold data in memory before being stored in the database.

---

### CLASS 1: Alert

**File Location**: `database/database.py` (lines 14-29)

**Purpose**: Represents a security alert triggered when the Detection Engine finds a threat

**Complete Field Breakdown**:

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `timestamp` | datetime | Exact moment alert was created | 2026-04-02 10:20:15 |
| `source_ip` | string | IP address of device that triggered alert | 192.168.1.100 |
| `domain` | string | Malicious/suspicious domain detected | malicious.xyz |
| `severity` | string | Threat level classification | High |
| `score` | integer | Calculated threat score (0-100) | 87 |
| `rules_triggered` | list | Detection rules that fired | ["malicious_domain", "high_rate"] |
| `status` | string | Investigation stage (default: "new") | new/acknowledged/resolved/archived |
| `id` | integer | Database record ID (auto-generated) | None (until stored) |

**Status Progression**:
```
new (just detected)
    ↓ (Team acknowledges)
acknowledged (actively investigating)
    ↓ (Threat handled)
resolved (investigation complete)
    ↓ (or directly to)
archived (for reference)
```

**Severity Levels**:
- `Low` - Minor suspicious activity
- `Medium` - Notable suspicious activity
- `High` - Strong malicious indicators

**Creation Point**: Detection Engine when threat is found

**Storage Point**: DatabaseManager.store_alert(alert, dns_log_id)

**Code Example**:
```python
from database.database import Alert
from datetime import datetime, timezone

# Create an alert when threat is detected
alert = Alert(
    timestamp=datetime.now(timezone.utc),
    source_ip="192.168.1.50",
    domain="phishing-bank.com",
    severity="High",
    score=92,
    rules_triggered=["known_malicious_domain", "high_threat_score"],
    status="new"
)

# Later, store it in database
alert_id = db.store_alert(alert, dns_log_id=42)
print(f"Alert stored with ID: {alert_id}")  # ID: 5
```

---

### CLASS 2: DnsEvent

**File Location**: `database/database.py` (lines 32-45)

**Purpose**: Represents a single DNS query or response captured from network traffic

**Complete Field Breakdown**:

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `timestamp` | datetime | When DNS activity occurred | 2026-04-02 10:15:30 |
| `source_ip` | string | Device that made the query | 192.168.1.100 |
| `domain` | string | Domain being searched for | example.com |
| `query_type` | string | Type of DNS query (see types below) | A |
| `is_response` | boolean | True=response, False=query | True |
| `response_code` | integer | DNS status (0=success, others=error) | 0 |
| `resolved_ips` | list | IP addresses returned | ["93.184.216.34"] |
| `id` | integer | Database record ID (auto-generated) | None (until stored) |

**Query Types**:
| Type | Meaning | Used For |
|------|---------|----------|
| `A` | IPv4 Address Record | Website IPv4 lookup |
| `AAAA` | IPv6 Address Record | Website IPv6 lookup |
| `MX` | Mail Exchange | Email server discovery |
| `CNAME` | Canonical Name | Domain alias/redirect |
| `PTR` | Pointer Record | Reverse DNS lookup (IP → domain) |
| `NS` | Nameserver | Nameserver lookup |
| `TXT` | Text Record | Verification records, SPF, DKIM |

**Response Codes**:
- `0` - Success (NOERROR)
- `1` - Format error (FORMERR)
- `2` - Server failure (SERVFAIL)
- `3` - Non-existent domain (NXDOMAIN)
- `5` - Query refused (REFUSED)

**Creation Point**: Parser when extracting DNS information

**Storage Point**: DatabaseManager.store_dns_log(event, threat_score)

**Code Example**:
```python
from database.database import DnsEvent
from datetime import datetime, timezone

# Create DNS event from captured traffic
event = DnsEvent(
    timestamp=datetime.now(timezone.utc),
    source_ip="192.168.1.100",
    domain="google.com",
    query_type="A",
    is_response=True,
    response_code=0,
    resolved_ips=["142.250.80.46"]
)

# Store in database
dns_log_id = db.store_dns_log(event, threat_score=0)
print(f"DNS log stored with ID: {dns_log_id}")  # ID: 42
```

---

### CLASS 3: ThreatCacheEntry

**File Location**: `database/database.py` (lines 48-56)

**Purpose**: Represents a cached malicious domain from external threat intelligence sources

**Complete Field Breakdown**:

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `domain` | string | Malicious domain name | phishing-bank.com |
| `source` | string | Where threat info came from | OpenPhish |
| `threat_type` | string | Category of threat | phishing |
| `last_updated` | datetime | When entry was last refreshed | 2026-04-02 09:00:00 |
| `id` | integer | Database record ID (auto-generated) | None (until stored) |

**Threat Sources** (Updated Every 24 Hours):
- `OpenPhish` - Phishing intelligence and detection
- `Spamhaus` - Spam and malware distribution lists
- `Abuse.ch` - Botnet command & control tracking
- `URLhaus` - Malicious URL database
- `Malware Domains List` - Known malware domains

**Threat Types**:
| Type | Description | Example |
|------|-------------|---------|
| `phishing` | Phishing/credential theft | fake-amazon.com |
| `malware` | Malware distribution | malware-download.net |
| `botnet` | Botnet C&C servers | botnet-command.xyz |
| `spam` | Spam sources | spam-sender.com |
| `ransomware` | Ransomware sites | ransomware-pay.org |

**Creation Point**: External threat intelligence services (OpenPhish, Spamhaus, etc.)

**Storage Point**: DatabaseManager.store_threat_cache_entry(threat)

**Update Frequency**: Every 24 hours

**Purpose**: Enables fast threat checking without external API calls on every query

**Code Example**:
```python
from database.database import ThreatCacheEntry
from datetime import datetime, timezone

# Create threat cache entry from external source
threat = ThreatCacheEntry(
    domain="phishing-bank.com",
    source="OpenPhish",
    threat_type="phishing",
    last_updated=datetime.now(timezone.utc)
)

# Cache in database
entry_id = db.store_threat_cache_entry(threat)
print(f"Threat cached with ID: {entry_id}")  # ID: 1

# Later, quick threat check
if db.is_domain_malicious("phishing-bank.com"):
    print("Domain is known to be malicious!")
```

---

### CLASS 4: DatabaseManager

**File Location**: `database/database.py` (lines 59-673)

**Purpose**: Main controller that manages all database operations

**Initialization**:
```python
from database.database import DatabaseManager

# Initialize (auto-creates database and all tables)
db = DatabaseManager()
```

**Auto-Initialization Features**:
- Creates database file: `dns_threat_monitor.db`
- Creates 4 tables automatically
- Creates 5 performance indexes
- Handles all connections safely

**Core Methods**:

#### DNS Log Operations:
```python
# Store DNS event
dns_log_id = db.store_dns_log(event, threat_score=0)
# Returns: Database ID of stored record

# Get recent DNS logs
logs = db.get_recent_dns_logs(hours=24, limit=100)
# Returns: List of DNS log records from last 24 hours

# Search DNS logs with filters
results = db.search_dns_logs(
    domain="example",      # substring match
    source_ip="192.168.1.100",  # exact match
    threat_level=50,       # minimum threat score
    hours=24              # time range
)
# Returns: Filtered list of DNS logs
```

#### Alert Operations:
```python
# Create and store alert
alert_id = db.store_alert(alert, dns_log_id=42)
# Returns: Database ID of alert

# Update alert status (auto-creates history entry)
success = db.update_alert_status(
    alert_id=5,
    new_status="acknowledged",
    notes="Starting investigation"
)
# Returns: True if successful, False if alert not found

# Get all unresolved alerts
active = db.get_active_alerts(limit=50)
# Returns: List of alerts not yet resolved/archived

# Get investigation history
history = db.get_alert_history(alert_id=5)
# Returns: List of all status changes for this alert
```

#### Threat Cache Operations:
```python
# Cache malicious domain
entry_id = db.store_threat_cache_entry(threat)
# Returns: Database ID of cache entry

# Quick threat check
is_bad = db.is_domain_malicious("malicious.xyz")
# Returns: True if domain in cache, False otherwise

# Get cache statistics
size = db.get_threat_cache_size()
# Returns: Total number of cached domains
```

#### Dashboard Support:
```python
# Get dashboard overview statistics
summary = db.get_dashboard_summary()
# Returns: {
#     'recent_queries_24h': 1250,
#     'new_alerts': 5,
#     'severity_distribution': {'Low': 2, 'Medium': 2, 'High': 1},
#     'threat_cache_size': 15000
# }

# Advanced alert search
alerts = db.search_alerts(
    domain="phishing",
    source_ip="192.168.1.100",
    severity="High",
    status="new",
    hours=24
)
# Returns: Filtered list of alerts
```

#### Connection Management:
```python
# Close database connection
db.close()
# Returns: None
```

---

## PART 2: THE 4 TABLES (Database Storage)

Tables are permanent storage in SQLite database where objects are saved.

---

### TABLE 1: dns_logs

**File Location**: `database/database.py` (lines 96-110)

**Purpose**: Stores every DNS query and response captured from the network

**When Records Are Added**:
- Every time Parser extracts DNS information
- For every DNS query/response from network traffic

**Complete Column Breakdown**:

| Column | Type | Purpose | Example |
|--------|------|---------|---------|
| `id` | INTEGER | Unique record identifier (auto-increment) | 42 |
| `timestamp` | TEXT | ISO format datetime of DNS activity | 2026-04-02 10:15:30 |
| `source_ip` | TEXT | IP address of device making query | 192.168.1.100 |
| `domain` | TEXT | Domain name being queried | google.com |
| `query_type` | TEXT | Type of DNS query (A, AAAA, MX, etc.) | A |
| `is_response` | INTEGER | 1 if response, 0 if query | 1 |
| `response_code` | INTEGER | DNS response status code | 0 |
| `resolved_ips` | TEXT | JSON array of returned IPs | ["142.250.80.46"] |
| `threat_score` | INTEGER | Threat level (0-100) | 25 |

**Example Record**:
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

---

id: 2
timestamp: 2026-04-02 10:20:15
source_ip: 192.168.1.50
domain: phishing-bank.com
query_type: A
is_response: 1
response_code: 0
resolved_ips: ["1.2.3.4"]
threat_score: 92
```

**How Data Flows In**:
```
Network Traffic
    ↓
Capture Module detects DNS query
    ↓
Parser extracts information
    ↓
DnsEvent object created
    ↓
DatabaseManager.store_dns_log(event)
    ↓
Record inserted into dns_logs table
```

**Why It Matters**:
- Complete visibility of network DNS activity
- Historical record for investigation
- Supports trend analysis
- Links to alerts for correlation
- Enables forensic analysis

**Indexes** (for fast searching):
- `idx_dns_logs_timestamp` - Search by time
- `idx_dns_logs_domain` - Search by domain name

**Typical Queries**:
```python
# Get all DNS queries in last 24 hours
logs = db.search_dns_logs(hours=24)

# Find all queries for a specific domain
logs = db.search_dns_logs(domain="phishing")

# Find all queries from a specific device
logs = db.search_dns_logs(source_ip="192.168.1.100", hours=168)

# Find all high-threat DNS activity
logs = db.search_dns_logs(threat_level=70, hours=24)
```

---

### TABLE 2: alerts

**File Location**: `database/database.py` (lines 112-131)

**Purpose**: Stores every security alert/threat detected by the Detection Engine

**When Records Are Added**:
- When Detection Engine finds a threat
- For every security alert created

**Complete Column Breakdown**:

| Column | Type | Purpose | Example |
|--------|------|---------|---------|
| `id` | INTEGER | Unique alert identifier (auto-increment) | 5 |
| `dns_log_id` | INTEGER | Foreign key to dns_logs table | 2 |
| `timestamp` | TEXT | ISO format datetime alert created | 2026-04-02 10:20:15 |
| `source_ip` | TEXT | IP address of device that triggered alert | 192.168.1.50 |
| `domain` | TEXT | Suspicious/malicious domain | phishing-bank.com |
| `severity` | TEXT | Alert level (Low, Medium, High) | High |
| `threat_score` | INTEGER | Calculated threat score (0-100) | 87 |
| `rules_triggered` | TEXT | JSON array of detection rules | ["known_malicious", "high_rate"] |
| `status` | TEXT | Alert status (new by default) | new |

**Example Records**:
```
Record 1 (New Alert):
id: 5
dns_log_id: 2
timestamp: 2026-04-02 10:20:15
source_ip: 192.168.1.50
domain: phishing-bank.com
severity: High
threat_score: 87
rules_triggered: ["known_malicious_domain", "high_query_rate"]
status: new

Record 2 (Acknowledged Alert):
id: 6
dns_log_id: 3
timestamp: 2026-04-02 10:25:00
source_ip: 192.168.1.75
domain: malware-download.net
severity: High
threat_score: 95
rules_triggered: ["malware_distribution", "suspicious_tld"]
status: acknowledged

Record 3 (Resolved Alert):
id: 7
dns_log_id: 1
timestamp: 2026-04-02 10:30:00
source_ip: 192.168.1.100
domain: suspicious-domain.xyz
severity: Medium
threat_score: 65
rules_triggered: ["random_domain_name"]
status: resolved
```

**Status Flow Diagram**:
```
┌─────────────────────────────────────────────────┐
│ ALERT STATUS LIFECYCLE                          │
├─────────────────────────────────────────────────┤
│                                                 │
│  new (just detected)                            │
│   ↓ (Team reviews)                              │
│  acknowledged (investigating)                   │
│   ├─ (Threat handled)                           │
│   │  ↓                                          │
│   │  resolved (investigation complete)          │
│   │   ↓                                         │
│   │  archived (stored for reference)            │
│   │                                            │
│   └─ (OR) Can go directly to:                   │
│      archived (without resolving)               │
│                                                 │
└─────────────────────────────────────────────────┘
```

**How Data Flows In**:
```
Detection Engine finds threat
    ↓
Alert object created
    ↓
DatabaseManager.store_alert(alert, dns_log_id)
    ↓
Record inserted into alerts table
    ↓
Entry added to alert_history (status: "new")
```

**Why It Matters**:
- Tracks all detected threats
- Shows severity for prioritization
- Records which rules detected threat
- Tracks investigation status
- Enables alert management workflow

**Indexes** (for fast searching):
- `idx_alerts_timestamp` - Search by time
- `idx_alerts_status` - Search by alert status

**Typical Queries**:
```python
# Get all new (unacknowledged) high-severity alerts
alerts = db.search_alerts(severity="High", status="new")

# Get alerts being investigated
alerts = db.search_alerts(status="acknowledged", hours=24)

# Get alerts from specific device
alerts = db.search_alerts(source_ip="192.168.1.50", hours=168)

# Get all high-severity alerts created today
alerts = db.search_alerts(severity="High", hours=24)

# Find alerts related to phishing
alerts = db.search_alerts(domain="phishing", hours=24)
```

---

### TABLE 3: alert_history

**File Location**: `database/database.py` (lines 133-149)

**Purpose**: Tracks every action taken during alert investigation (audit trail)

**When Records Are Added**:
- When alert is first created (auto entry: old_status = "", new_status = "new")
- Every time alert status changes
- With optional notes about what happened

**Complete Column Breakdown**:

| Column | Type | Purpose | Example |
|--------|------|---------|---------|
| `id` | INTEGER | Unique history entry ID (auto-increment) | 15 |
| `alert_id` | INTEGER | Foreign key to alerts table | 5 |
| `old_status` | TEXT | Previous status before change | new |
| `new_status` | TEXT | Status after change | acknowledged |
| `timestamp` | TEXT | ISO format datetime of change | 2026-04-02 10:25:00 |
| `notes` | TEXT | Reason for change or action taken | "Isolating device from network" |

**Example Investigation Timeline**:
```
ENTRY 1 (Alert Created - Auto):
id: 10
alert_id: 5
old_status: (empty)
new_status: new
timestamp: 2026-04-02 10:20:15
notes: Alert created

ENTRY 2 (Team Acknowledges):
id: 11
alert_id: 5
old_status: new
new_status: acknowledged
timestamp: 2026-04-02 10:25:00
notes: Security team started investigating - isolating device

ENTRY 3 (Team Updates):
id: 12
alert_id: 5
old_status: acknowledged
new_status: acknowledged
timestamp: 2026-04-02 10:35:00
notes: Confirmed malware infection - initiating cleanup

ENTRY 4 (Investigation Complete):
id: 13
alert_id: 5
old_status: acknowledged
new_status: resolved
timestamp: 2026-04-02 11:00:00
notes: Malware removed, device cleaned, domain blocked in firewall
```

**How Data Flows In**:
```
Alert created
    ↓
alert_history entry added (status: "new")
    ↓
Team reviews alert
    ↓
update_alert_status() called
    ↓
alerts table status updated
    ↓
alert_history entry added (old → new status)
    ↓
Team completes investigation
    ↓
update_alert_status() called again
    ↓
alerts table status updated
    ↓
alert_history entry added
```

**Why It Matters**:
- Complete investigation timeline
- Shows what action was taken when
- Audit trail for compliance
- Can replay entire investigation
- Documents decision-making process

**Typical Queries**:
```python
# Get complete investigation history for specific alert
history = db.get_alert_history(alert_id=5)
# Shows: Alert created → Acknowledged → Resolved with timestamps

# Can reconstruct investigation:
for entry in history:
    print(f"{entry['timestamp']}: {entry['old_status']} → {entry['new_status']}")
    print(f"  Note: {entry['notes']}")
```

---

### TABLE 4: threat_cache

**File Location**: `database/database.py` (lines 151-163)

**Purpose**: Fast lookup of known malicious domains (caches external threat intelligence)

**When Records Are Added**:
- Every 24 hours from threat intelligence sources
- When new malicious domains are discovered

**Complete Column Breakdown**:

| Column | Type | Purpose | Example |
|--------|------|---------|---------|
| `id` | INTEGER | Unique identifier (auto-increment) | 1 |
| `domain` | TEXT | Malicious domain name (UNIQUE constraint) | phishing-bank.com |
| `source` | TEXT | Where threat info came from | OpenPhish |
| `threat_type` | TEXT | Category of threat | phishing |
| `last_updated` | TEXT | ISO format datetime of last refresh | 2026-04-02 09:00:00 |

**Example Cached Domains**:
```
Entry 1:
id: 1
domain: phishing-bank.com
source: OpenPhish
threat_type: phishing
last_updated: 2026-04-02 09:00:00

Entry 2:
id: 2
domain: malware-download.net
source: Spamhaus
threat_type: malware
last_updated: 2026-04-02 08:30:00

Entry 3:
id: 3
domain: botnet-c2.org
source: Abuse.ch
threat_type: botnet
last_updated: 2026-04-02 10:15:00

Entry 4:
id: 4
domain: ransomware-pay.xyz
source: URLhaus
threat_type: ransomware
last_updated: 2026-04-02 07:45:00

Entry 5:
id: 5
domain: spam-sender.com
source: Malware Domains List
threat_type: spam
last_updated: 2026-04-02 06:20:00
```

**External Threat Sources** (Updated Every 24 Hours):
| Source | Focus | Update Frequency |
|--------|-------|------------------|
| OpenPhish | Phishing detection | Daily |
| Spamhaus | Spam/malware | Daily |
| Abuse.ch | Botnet tracking | Daily |
| URLhaus | Malicious URLs | Daily |
| Malware Domains List | Known malware | Daily |

**How Data Flows In**:
```
External Threat Sources (24-hour update)
    ├─ OpenPhish API
    ├─ Spamhaus API
    ├─ Abuse.ch API
    ├─ URLhaus API
    └─ Malware Domains List API
         ↓
Retrieve new malicious domains
         ↓
ThreatCacheEntry objects created
         ↓
DatabaseManager.store_threat_cache_entry()
         ↓
Records inserted/updated in threat_cache table
```

**Why It Matters**:
- Enables instant threat checking
- No need for external API calls on every query
- Improves system performance significantly
- Multiple sources ensure accuracy
- 24-hour refresh keeps data current

**Indexes** (for fast searching):
- `idx_threat_cache_domain` - SUPER FAST domain lookups!

**Typical Usage**:
```python
# Quick threat check (instant, no external API call)
if db.is_domain_malicious("phishing-bank.com"):
    print("Domain is known to be malicious!")
    # Take action immediately

# Get cache statistics
cache_size = db.get_threat_cache_size()
print(f"Cached domains: {cache_size}")  # e.g., 15000+
```

---

## PART 3: HOW CLASSES & TABLES WORK TOGETHER

### Complete Integration Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ COMPLETE DATA FLOW: FROM NETWORK TO DATABASE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. NETWORK TRAFFIC                                             │
│     └─ DNS query captured by Capture Module                     │
│                                                                 │
│  2. PARSER CREATES DnsEvent CLASS                               │
│     └─ Extracts DNS information from captured traffic           │
│     └─ Creates DnsEvent object in memory                        │
│                                                                 │
│  3. DatabaseManager.store_dns_log()                             │
│     └─ Stores DnsEvent in dns_logs TABLE                        │
│     └─ Returns dns_log_id = 42                                 │
│                                                                 │
│  4. DETECTION ENGINE ANALYZES                                   │
│     ├─ Checks threat_cache TABLE (is domain malicious?)         │
│     ├─ Runs detection rules                                     │
│     ├─ Calculates threat_score                                  │
│     └─ Decision: THREAT FOUND?                                  │
│                                                                 │
│  5. IF THREAT FOUND:                                            │
│     ├─ Creates Alert CLASS object                               │
│     ├─ DatabaseManager.store_alert()                            │
│     ├─ Alert stored in alerts TABLE (id=5)                      │
│     └─ Entry added to alert_history TABLE (status: "new")       │
│                                                                 │
│  6. DASHBOARD DISPLAYS ALERT                                    │
│     └─ Security team sees threat notification                   │
│                                                                 │
│  7. SECURITY TEAM INVESTIGATES                                  │
│     ├─ DatabaseManager.update_alert_status()                    │
│     ├─ alerts TABLE status updated                              │
│     └─ Entry added to alert_history TABLE with notes            │
│                                                                 │
│  8. INVESTIGATION COMPLETES                                     │
│     ├─ Status changed to "resolved"                             │
│     ├─ alert_history shows complete timeline                    │
│     └─ Available for audit and compliance                       │
│                                                                 │
│  9. THREAT INTELLIGENCE REFRESH (24-hour)                       │
│     ├─ External sources queried                                 │
│     ├─ ThreatCacheEntry objects created                         │
│     ├─ threat_cache TABLE updated                               │
│     └─ Ready for next day's detection                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Real-World Example Timeline

**10:15:00** - Device queries malicious domain
- Network traffic captured
- DnsEvent created with domain=phishing-bank.com
- Stored in dns_logs table (ID=42)

**10:15:05** - Detection Engine analyzes
- Queries threat_cache table
- Found: phishing-bank.com IS malicious
- Calculates threat_score = 92/100
- Rules triggered: 2

**10:15:10** - Alert created and stored
- Alert object created with severity="High"
- Stored in alerts table (ID=5, status="new")
- Entry added to alert_history (Alert created)

**10:15:15** - Dashboard shows alert
- Security team sees: HIGH severity alert
- Domain: phishing-bank.com
- Device: 192.168.1.50

**10:20:00** - Team acknowledges
- update_alert_status(5, "acknowledged")
- alerts table updated (status: new → acknowledged)
- alert_history entry added with notes

**10:45:00** - Investigation complete
- update_alert_status(5, "resolved")
- alerts table updated (status: acknowledged → resolved)
- alert_history entry added with final notes

**11:00:00** - Full history available
- get_alert_history(5) returns all entries
- Complete timeline visible:
  - 10:15:10 Alert created
  - 10:20:00 Acknowledged
  - 10:45:00 Resolved

---

## PART 4: KEY RELATIONSHIPS & CONSTRAINTS

### Foreign Key Relationships

```
alerts TABLE
    ↓
    dns_log_id (INTEGER)
    └─ Points to → dns_logs TABLE (id)

alert_history TABLE
    ↓
    alert_id (INTEGER)
    └─ Points to → alerts TABLE (id)
```

### Unique Constraints

```
threat_cache TABLE
    ↓
    domain column is UNIQUE
    └─ No duplicate domains can be stored
    └─ Ensures clean cache
```

### Data Integrity

- Foreign keys prevent orphaned records
- Unique constraints prevent duplicates
- Auto-increment IDs ensure uniqueness
- Transactions ensure atomic operations

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

## SUMMARY TABLE

| Component | Type | Purpose | Key Feature |
|-----------|------|---------|------------|
| **Alert** | Class | Security threat info | Status lifecycle tracking |
| **DnsEvent** | Class | DNS query/response | Complete DNS metadata |
| **ThreatCacheEntry** | Class | Cached malicious domain | Fast threat lookup |
| **DatabaseManager** | Class | Database controller | Auto-initialization |
| **dns_logs** | Table | All DNS queries | Complete visibility |
| **alerts** | Table | Detected threats | Status tracking |
| **alert_history** | Table | Investigation timeline | Audit trail |
| **threat_cache** | Table | Known malicious domains | Performance optimization |

---

## Summary

The database module provides:
- Complete DNS activity logging
- Security alert tracking
- Investigation audit trail
- Malicious domain caching
- Fast searching and filtering
- Dashboard integration
- Automatic initialization
- Production-ready reliability

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
