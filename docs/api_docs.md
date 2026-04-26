# DNS Threat Monitor - API Documentation

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Capture       │ -> │   Parser        │ -> │   Detection     │
│   (dnsmasq +    │    │   (input_parser │    │   (rules +      │
│    tshark)      │    │    + blacklist) │    │    detector)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         v                       v                       v
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Database      │    │   Dashboard     │    │   Alerting      │
│   (storage +    │    │   (web UI)      │    │   (email)        │
│    queries)     │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Core Components

### 1. Data Models (`database/dataModels.py`)

#### DnsEvent
Represents a DNS query or response event.

```python
@dataclass
class DnsEvent:
    timestamp: datetime
    source_ip: str
    domain: str
    query_type: str  # "A", "AAAA", "MX", etc.
    is_response: bool
    response_code: int
    resolved_ips: list = field(default_factory=list)
    id: Optional[int] = None
```

#### Alert
Represents a detected threat or suspicious activity.

```python
@dataclass
class Alert:
    timestamp: datetime
    source_ip: str
    domain: str
    severity: str  # "Low", "Medium", "High"
    score: int
    rules_triggered: list
    status: str = "new"
    id: Optional[int] = None
```

#### ThreatCacheEntry
Represents cached malicious domain information.

```python
@dataclass
class ThreatCacheEntry:
    domain: str
    source: str  # "OpenPhish", "Spamhaus", etc.
    threat_type: str  # "phishing", "malware", etc.
    last_updated: datetime
    id: Optional[int] = None
```

### 2. Database Manager (`database/database.py`)

#### Key Methods

```python
class DatabaseManager:
    def store_dns_log(self, event: DnsEvent, threat_score: int = 0) -> int
    def store_alert(self, alert: Alert, dns_log_id: int) -> int
    def get_recent_dns_logs(self, hours: int = 24, limit: int = 100) -> List[dict]
    def get_dashboard_summary(self) -> dict
    def search_dns_logs(self, domain: str = None, source_ip: str = None,
                       threat_level: int = None, hours: int = 24) -> List[dict]
```

### 3. Input Parser (`parser/input_parser.py`)

#### Key Functions

```python
def parse_dnsmasq_line(line: str) -> DnsEvent | None
def parse_tshark_line(line: str) -> DnsEvent | None
def parse_line(source: str, line: str) -> DnsEvent | None
def normalise_domain(domain: str) -> str
```

### 4. Blacklist Manager (`parser/blacklist.py`)

#### Key Methods

```python
class Blacklist:
    def load_from_file(self, filepath: str)
    def load_from_url(self, url: str)
    def start_auto_refresh(self, url: str, interval_hours: int = 24)
    def is_malicious(self, domain: str) -> bool
```

### 5. Rule Engine (`detection/rules.py`)

#### Detection Rules

1. **High Query Rate**: Flags IPs making >50 queries/minute
2. **Suspicious TLD**: Detects domains with unusual TLDs (.xyz, .tk, etc.)
3. **NXDOMAIN Flood**: Flags excessive non-existent domain responses
4. **Subdomain Abuse**: Detects excessive subdomain enumeration
5. **DGA Pattern**: Identifies algorithmically generated domains

#### Key Methods

```python
class RuleEngine:
    def check(self, event: DnsEvent) -> list  # Returns triggered rule names
```

### 6. Threat Detector (`detection/threat_detector.py`)

#### Key Methods

```python
class Detector:
    def analyse(self, event: DnsEvent) -> Alert | None
```

### 7. Main Orchestrator (`core/dns_monitor.py`)

#### Key Methods

```python
class DNSThreatMonitor:
    def start(self)  # Start monitoring
    def stop(self)   # Stop monitoring
```

## Configuration (`config/config.py`)

All system configuration is centralized in the `Config` class:

- Database paths and settings
- Capture interface configuration
- Detection thresholds and rules
- Blacklist refresh intervals
- Performance limits
- Email alerting settings

## Data Flow

1. **Capture**: DNS traffic collected from dnsmasq logs and tshark
2. **Parse**: Raw log lines converted to `DnsEvent` objects
3. **Detect**: Events analyzed against rules and blacklist
4. **Store**: Events and alerts saved to SQLite database
5. **Alert**: High-severity threats trigger notifications

## API Usage Examples

### Basic System Startup
```python
from core.dns_monitor import DNSThreatMonitor

monitor = DNSThreatMonitor()
monitor.start()  # Runs until interrupted
```

### Manual Event Processing
```python
from parser.input_parser import parse_line
from detection.threat_detector import Detector
from parser.blacklist import Blacklist
from detection.rules import RuleEngine

# Parse DNS log line
event = parse_line("dnsmasq", log_line)

# Analyze for threats
blacklist = Blacklist()
rules = RuleEngine()
detector = Detector(blacklist, rules)
alert = detector.analyse(event)
```

### Database Queries
```python
from database.database import DatabaseManager

db = DatabaseManager()

# Get recent activity
logs = db.get_recent_dns_logs(hours=24, limit=100)

# Get dashboard summary
summary = db.get_dashboard_summary()
print(f"Recent queries: {summary['recent_queries_24h']}")
print(f"New alerts: {summary['new_alerts']}")
```

## Error Handling

All components include comprehensive error handling:
- Database operations wrapped in try/catch blocks
- Network requests include timeouts and retries
- Invalid data gracefully skipped with logging
- System shutdown signals handled properly

## Performance Characteristics

- **Detection Time**: <3 seconds per event
- **CPU Usage**: <30% during normal operation
- **Memory Usage**: <500MB
- **Concurrent Processing**: Multi-threaded event processing
