# DNS Threat Monitor - Documentation Index

**Project:** CT5180 Capstone Group Project - Group E  
**Team:** Stephen Small, Tissa Abraham, Robert O'Brien  
**Institution:** National University of Ireland, Galway (NUIG)

---

## 📚 Documentation Guide

This file helps you navigate all documentation and resources for the DNS Threat Monitor project.

---

## 🎯 Start Here

### For New Team Members
1. **[README.md](README.md)** - Read the project overview
2. **[GETTING_STARTED.md](GETTING_STARTED.md)** - Follow setup instructions
3. **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Common commands

### For Project Structure
1. **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - File hierarchy
2. **[FILE_MANIFEST.md](FILE_MANIFEST.md)** - Complete file listing
3. **[FILES_CREATED_SUMMARY.md](FILES_CREATED_SUMMARY.md)** - Detailed descriptions

### For Development
1. Review module files in each directory
2. Check docstrings and type hints
3. Run tests: `pytest tests/`

---

## 📖 Documentation Files

### Main Documentation

| File | Purpose | Audience |
|------|---------|----------|
| **[README.md](README.md)** | Complete project documentation | Everyone |
| **[GETTING_STARTED.md](GETTING_STARTED.md)** | Setup and installation guide | New users |
| **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** | Quick command reference | Developers |
| **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** | File hierarchy and organization | Developers |
| **[FILES_CREATED_SUMMARY.md](FILES_CREATED_SUMMARY.md)** | Detailed file descriptions | Developers |
| **[FILE_MANIFEST.md](FILE_MANIFEST.md)** | Complete file listing | Developers |
| **[DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)** | This file | Everyone |

---

## 🗂️ Project Modules

### capture/ - DNS Traffic Capture
- **Description:** Captures DNS traffic from network
- **Key Files:** `dns_capture.py`
- **Entry Point:** `DNSCapture` class
- **Technology:** tshark, tcpdump, DNSMASQ

### parser/ - DNS Log Parsing
- **Description:** Parses DNS logs and extracts metadata
- **Key Files:** `dns_parser.py`
- **Entry Point:** `DNSParser` class
- **Extracts:** timestamp, source IP, domain, query type

### detection/ - Threat Detection
- **Description:** Detects threats using blacklist and rules
- **Key Files:** 
  - `detection_engine.py` - Main detection logic
  - `rules.py` - Rule configuration
  - `blacklist_manager.py` - Blacklist management
- **Entry Point:** `DetectionEngine` class
- **Features:** 5 detection rules, threat scoring, severity levels

### database/ - Data Storage
- **Description:** Manages SQLite database
- **Key Files:**
  - `schema.py` - Database schema
  - `database_manager.py` - CRUD operations
- **Entry Point:** `DatabaseManager` class
- **Tables:** dns_logs, alerts, blacklist, statistics

### dashboard/ - Web Interface
- **Description:** Flask web application for monitoring
- **Key Files:**
  - `app.py` - Flask application
  - `templates/index.html` - HTML template
  - `static/css/style.css` - Styling
  - `static/js/dashboard.js` - Interactions
- **Entry Point:** Flask app
- **Features:** Statistics, alerts, search, filtering

### docker/ - Container Deployment
- **Description:** Docker containerization
- **Key Files:**
  - `Dockerfile` - Container image
  - `docker-compose.yml` - Orchestration
  - `dnsmasq.conf` - DNS config
- **Usage:** `docker-compose up -d`

### tests/ - Testing
- **Description:** Unit tests
- **Key Files:** `test_detection.py`
- **Frameworks:** pytest
- **Run:** `pytest tests/`

---

## ⚙️ Configuration Files

### config.py
- Main configuration module
- Database settings
- Capture interface configuration
- Detection parameters
- Dashboard options
- Email alert settings
- Logging configuration
- Performance tuning

### .env.example
- Environment variable template
- Copy to `.env` and customize
- Contains all configuration parameters

### conftest.py
- Pytest configuration
- Test fixtures
- Sample test data

---

## 🚀 Quick Start

### Installation
```bash
pip install -r requirements.txt
cp .env.example .env
```

### Local Execution
```bash
python main.py
```

### Docker Deployment
```bash
cd docker
docker-compose up -d
```

### Access Dashboard
```
http://localhost:5000
```

### Run Tests
```bash
pytest tests/
```

---

## 📊 System Architecture

### 5-Layer Design

```
┌─────────────────┐
│   Dashboard     │ ← Presentation Layer
└─────────────────┘
        ↑
┌─────────────────┐
│    Database     │ ← Data Storage Layer
└─────────────────┘
        ↑
┌─────────────────┐
│   Detection     │ ← Detection Engine Layer
└─────────────────┘
        ↑
┌─────────────────┐
│     Parser      │ ← Parsing Layer
└─────────────────┘
        ↑
┌─────────────────┐
│    Capture      │ ← Traffic Capture Layer
└─────────────────┘
```

---

## 🔍 Key Features

### Detection
- Blacklist-based detection (URLhaus, OpenPhish, Malware Lists)
- Rule-based detection (5 detection rules)
- Threat scoring (0-100)
- Severity levels (Not-significant, Low, Medium, High)

### Database
- SQLite storage
- DNS logs
- Alert tracking
- Blacklist caching
- Statistics

### Web Interface
- Statistics dashboard
- Alert management
- DNS log search/filter
- Real-time refresh
- REST API

### Deployment
- Docker containerization
- Docker Compose
- Security hardening
- Health checks

---

## 📋 Detection Rules

1. **High Query Rate** - >100 queries/minute (+15)
2. **Suspicious TLD** - .xyz, .top, .tk, etc. (+20)
3. **Random Domain Name** - High entropy (+25)
4. **NXDOMAIN Pattern** - >10 NXDOMAIN responses (+18)
5. **Subdomain Enumeration** - >20 subdomains (+22)
6. **Blacklist Match** - Domain in malicious list (+100)

---

## 🎯 Performance Targets

- Detection latency: < 3 seconds
- CPU usage: < 30%
- Memory usage: < 500MB
- False positive rate: < 10%

---

## 📞 Support & Resources

### Team Information
- **Stephen Small**
- **Tissa Abraham**
- **Robert O'Brien**

### Project Information
- **Course:** CT5180 Capstone Project
- **Institution:** NUIG
- **Year:** 2026

### Resources
- README.md - Full documentation
- GETTING_STARTED.md - Setup guide
- QUICK_REFERENCE.md - Command reference
- Project files - Implementation details

---

## 🔗 Related Files

### Source Code
- `main.py` - Main entry point
- `capture/dns_capture.py` - Traffic capture
- `parser/dns_parser.py` - Log parsing
- `detection/detection_engine.py` - Detection logic
- `database/database_manager.py` - Database operations
- `dashboard/app.py` - Web application

### Configuration
- `config.py` - Configuration module
- `.env.example` - Environment template
- `docker/dnsmasq.conf` - DNS configuration

### Tests
- `tests/test_detection.py` - Unit tests
- `conftest.py` - Test configuration

---

## 🎓 Learning Path

### 1. Understanding the Project
- [ ] Read README.md
- [ ] Review GETTING_STARTED.md
- [ ] Understand project goals

### 2. System Architecture
- [ ] Study PROJECT_STRUCTURE.md
- [ ] Review FILE_MANIFEST.md
- [ ] Understand 5-layer design

### 3. Code Review
- [ ] Review each module
- [ ] Check docstrings
- [ ] Understand class structure

### 4. Development
- [ ] Set up environment
- [ ] Run tests
- [ ] Start implementing

### 5. Deployment
- [ ] Configure .env
- [ ] Build Docker image
- [ ] Deploy system

---

## ✅ Checklist for Getting Started

- [ ] Read README.md
- [ ] Follow GETTING_STARTED.md
- [ ] Install dependencies
- [ ] Configure environment
- [ ] Run tests
- [ ] Start development or deployment

---

## 📌 Important Locations

| Item | Location |
|------|----------|
| Main Entry Point | `main.py` |
| Configuration | `config.py` or `.env` |
| Database File | `dns_threat_monitor.db` |
| Logs | `dns_threat_monitor.log` |
| Dashboard | `http://localhost:5000` |
| Docker Compose | `docker/docker-compose.yml` |

---

## 🔄 Development Workflow

### Start Development
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run Tests
```bash
pytest tests/ -v
```

### Start Application
```bash
python main.py
```

### Access Dashboard
```
http://localhost:5000
```

### Deploy with Docker
```bash
cd docker
docker-compose up -d
```

---

## 📚 Additional Resources

- Python Documentation: https://docs.python.org/3/
- Flask Documentation: https://flask.palletsprojects.com/
- SQLite Documentation: https://www.sqlite.org/docs.html
- Docker Documentation: https://docs.docker.com/
- Pytest Documentation: https://docs.pytest.org/

---

## 🎉 Ready to Start?

1. **Start with:** [GETTING_STARTED.md](GETTING_STARTED.md)
2. **Then read:** [README.md](README.md)
3. **Reference:** [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
4. **Explore:** Module files in each directory

---

**Documentation Index Created:** March 24, 2026  
**Last Updated:** March 24, 2026  
**Version:** 1.0

