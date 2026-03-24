# PROJECT FILE STRUCTURE

DNS Threat Monitor - Group E, CT5180 Capstone Project at NUIG

## Directory Structure

```
dns-threat-monitor/
├── capture/
│   ├── __init__.py
│   └── dns_capture.py              # DNS traffic capture using tshark/tcpdump
├── parser/
│   ├── __init__.py
│   └── dns_parser.py               # Parse DNS logs and extract metadata
├── detection/
│   ├── __init__.py
│   ├── detection_engine.py         # Main threat detection engine
│   ├── rules.py                    # Detection rules configuration
│   └── blacklist_manager.py        # Blacklist management and updates
├── database/
│   ├── __init__.py
│   ├── schema.py                   # SQLite database schema
│   └── database_manager.py         # Database operations
├── dashboard/
│   ├── __init__.py
│   ├── app.py                      # Flask web application
│   ├── templates/
│   │   └── index.html              # Dashboard HTML template
│   └── static/
│       ├── css/
│       │   └── style.css           # Dashboard styling
│       └── js/
│           └── dashboard.js        # Dashboard JavaScript
├── docker/
│   ├── Dockerfile                  # Docker image configuration
│   ├── docker-compose.yml          # Docker Compose orchestration
│   └── dnsmasq.conf                # DNSMASQ DNS server config
├── tests/
│   └── test_detection.py           # Detection engine tests
├── main.py                         # Main application entry point
├── config.py                       # Configuration module
├── conftest.py                     # Pytest configuration
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment configuration template
├── README.md                       # Project README
├── GETTING_STARTED.md              # Getting started guide
└── LICENSE                         # Project license
```

## Key Files Overview

### Core Application
- **main.py**: Entry point that orchestrates all system components
- **config.py**: Centralized configuration management
- **requirements.txt**: Python package dependencies

### System Layers

1. **Traffic Capture Layer** (capture/)
   - Captures DNS queries on port 53
   - Interfaces with tshark/tcpdump

2. **Parsing Layer** (parser/)
   - Extracts DNS metadata from captured traffic
   - Timestamp, source IP, domain name, query type

3. **Detection Layer** (detection/)
   - **detection_engine.py**: Implements blacklist and rule-based detection
   - **rules.py**: Configurable detection rules
   - **blacklist_manager.py**: Updates malicious domain lists from:
     - URLhaus
     - OpenPhish
     - Malware Domains List

4. **Database Layer** (database/)
   - **schema.py**: SQLite schema definition
   - **database_manager.py**: CRUD operations for logs and alerts

5. **Presentation Layer** (dashboard/)
   - Flask web dashboard for monitoring
   - Real-time alert viewing
   - DNS log search and filtering

### Docker Deployment
- **Dockerfile**: Container image definition
- **docker-compose.yml**: Multi-container orchestration
- **dnsmasq.conf**: DNS server configuration

### Testing & Documentation
- **tests/test_detection.py**: Unit tests for detection engine
- **conftest.py**: Pytest fixtures and configuration
- **GETTING_STARTED.md**: Setup and usage guide

## Configuration Files

- **.env.example**: Template for environment variables
- **config.py**: Python configuration module
- **docker/dnsmasq.conf**: DNS server configuration

## Component Responsibilities

### Capture Module
- Listens on UDP/TCP port 53
- Uses DNSMASQ to intercept DNS traffic
- Forwards packets to parser

### Parser Module
- Processes raw DNS traffic
- Extracts key fields
- Formats for detection engine

### Detection Engine
- Applies blacklist-based detection
- Implements 5 detection rules:
  * High query/response rate
  * Suspicious TLD
  * Random domain names
  * NXDOMAIN patterns
  * Subdomain enumeration
- Generates alerts with severity levels:
  * Not-significant (0-19)
  * Low (20-49)
  * Medium (50-79)
  * High (80-100)

### Database
- Stores DNS logs
- Records alerts and their status
- Maintains statistics
- Supports querying and reporting

### Dashboard
- REST API endpoints for data retrieval
- Web interface for visualization
- Alert status management
- Search and filtering

## Data Flow

1. DNS Traffic (port 53) ↓
2. DNSMASQ Interception ↓
3. Tshark/tcpdump Capture ↓
4. DNS Parser ↓
5. Detection Engine ↓
6. Database Storage ↓
7. Dashboard Presentation

## Configuration

See `.env.example` for all configurable options:
- Database path
- Capture interface
- Detection rules
- Email alerts
- Logging
- Performance settings

## Getting Started

1. Install dependencies: `pip install -r requirements.txt`
2. Configure environment: `cp .env.example .env`
3. Run locally: `python main.py`
4. Or use Docker: `docker-compose up -d`
5. Access dashboard: http://localhost:5000

See GETTING_STARTED.md for detailed instructions.

