# Quick Reference Guide - DNS Threat Monitor

**Project:** CT5180 Capstone - Group E (NUIG)  
**Team:** Stephen Small, Tissa Abraham, Robert O'Brien

## Quick Start

### 1. Setup
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure
```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Run Locally
```bash
python main.py
```

### 4. Run with Docker
```bash
cd docker
docker-compose up -d
```

### 5. Access Dashboard
- **URL:** http://localhost:5000
- **Port:** 5000 (configurable)

---

## System Architecture

```
┌─────────────────────────────────────────────────┐
│         DNS Traffic (Port 53)                   │
└────────────────┬────────────────────────────────┘
                 │
        ┌────────▼─────────┐
        │  DNSMASQ/Tshark  │ ◄─── Capture Layer
        └────────┬─────────┘
                 │
        ┌────────▼─────────┐
        │   DNS Parser     │ ◄─── Parse Layer
        └────────┬─────────┘
                 │
   ┌─────────────┼─────────────┐
   │             │             │
┌──▼──┐  ┌──────▼──────┐  ┌───▼───┐
│Black│  │  Rule-Based │  │Threat │ ◄─── Detection
│list │  │ Behaviour   │  │Score  │
└──┬──┘  └──────┬──────┘  └───┬───┘
   │            │             │
   └────────────┼─────────────┘
                │
        ┌───────▼────────┐
        │  SQLite DB     │ ◄─── Storage Layer
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │   Flask Web    │ ◄─── Presentation
        │   Dashboard    │
        └────────────────┘
```

---

## Key Modules

### capture/dns_capture.py
```python
from capture.dns_capture import DNSCapture

capture = DNSCapture(interface="eth0")
capture.start_capture()
```

### parser/dns_parser.py
```python
from parser.dns_parser import DNSParser

parser = DNSParser()
record = parser.parse_packet(packet_data)
```

### detection/detection_engine.py
```python
from detection.detection_engine import DetectionEngine

detector = DetectionEngine("blacklist.txt")
alert = detector.detect_threats("example.com", "192.168.1.100")
```

### database/database_manager.py
```python
from database.database_manager import DatabaseManager

db = DatabaseManager()
log_id = db.insert_dns_log("192.168.1.100", "example.com", "A")
alerts = db.get_alerts(severity="high")
```

### dashboard/app.py
```python
from dashboard.app import create_app

app = create_app()
app.run(host='0.0.0.0', port=5000)
```

---

## Detection Rules

| Rule | Trigger | Weight |
|------|---------|--------|
| High Query Rate | >100 queries/min | +15 |
| Suspicious TLD | .xyz, .top, .tk, etc. | +20 |
| Random Domain | High entropy name | +25 |
| NXDOMAIN Pattern | >10 NXDOMAIN responses | +18 |
| Subdomain Enumeration | >20 subdomain queries | +22 |
| Blacklist Match | Domain in malicious list | +100 |

---

## Threat Severity Levels

| Level | Score | Description |
|-------|-------|-------------|
| Not-significant | 0-19 | No threat |
| Low | 20-49 | Minor activity, monitor |
| Medium | 50-79 | Notable activity, investigate |
| High | 80-100 | Strong threat, immediate action |

---

## API Endpoints

### Get Alerts
```
GET /api/alerts?severity=high&status=new&limit=100
```

### Get DNS Logs
```
GET /api/logs?limit=100
```

### Update Alert Status
```
PATCH /api/alerts/{id}
Body: {"status": "acknowledged"}
```

### Get Statistics
```
GET /api/statistics
```

### Search
```
GET /api/search?q=example.com&type=domain
```

---

## Configuration Files

### .env (Environment Variables)
- `DB_PATH`: Database file location
- `CAPTURE_INTERFACE`: Network interface
- `DASHBOARD_PORT`: Web dashboard port
- `BLACKLIST_UPDATE_INTERVAL`: Blacklist update frequency

### config.py
- Database settings
- Capture configuration
- Detection parameters
- Dashboard options
- Email notification settings
- Logging configuration
- Performance tuning

### docker/dnsmasq.conf
- DNS server configuration
- Upstream servers
- Cache settings
- Logging options

---

## File Structure

```
capture/          → Traffic capture layer
parser/           → DNS log parsing
detection/        → Threat detection engine
database/         → Data storage
dashboard/        → Web interface
docker/           → Container deployment
tests/            → Unit tests
main.py           → Entry point
config.py         → Configuration
requirements.txt  → Dependencies
```

---

## Database Schema

### dns_logs table
- id, timestamp, source_ip, domain, query_type, response_code, response_ip

### alerts table
- id, dns_log_id, domain, source_ip, threat_type, severity, threat_score, rules_triggered, status

### blacklist table
- id, domain, source, added_at, last_updated

### statistics table
- id, total_queries, total_alerts, high_severity_alerts, timestamp

---

## Troubleshooting

### Cannot capture DNS traffic
- Check root/sudo access required
- Verify port 53 is not blocked
- Confirm correct interface in config

### Dashboard not responding
- Check port 5000 is available
- Verify DASHBOARD_PORT in .env
- Check firewall rules

### Database errors
- Ensure database directory exists and is writable
- Delete .db file to reset schema
- Check file permissions

---

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test
pytest tests/test_detection.py::TestDetectionEngine

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Monitoring

### Check System Status
- Access http://localhost:5000
- View statistics dashboard
- Monitor recent alerts

### View Logs
```bash
tail -f dns_threat_monitor.log
```

### Check Database
```bash
sqlite3 dns_threat_monitor.db
> SELECT COUNT(*) FROM alerts WHERE severity='high';
```

---

## Performance Targets

- Detection latency: < 3 seconds
- CPU usage: < 30%
- Memory: < 500MB
- False positives: < 10%

---

## Support & Contact

**Team Members:**
- Stephen Small
- Tissa Abraham
- Robert O'Brien

**Institution:** National University of Ireland, Galway  
**Project:** CT5180 Capstone Project

---

## Additional Resources

- `README.md` - Full project documentation
- `GETTING_STARTED.md` - Detailed setup guide
- `PROJECT_STRUCTURE.md` - File hierarchy
- `FILES_CREATED_SUMMARY.md` - Complete file listing
- `CONTRIBUTING.md` - Development guidelines (if present)

---

**Last Updated:** March 24, 2026

