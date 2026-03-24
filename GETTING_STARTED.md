"""
GETTING STARTED WITH DNS THREAT MONITOR

This guide will help you set up and run the DNS Threat Monitor system.

## Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose (for containerized deployment)
- Linux environment (Ubuntu 20.04+ recommended)
- Root or sudo access (for packet capture)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd dns-threat-monitor
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Linux/Mac
# or
.\\venv\\Scripts\\activate  # On Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit .env with your settings
nano .env
```

## Running the System

### Option 1: Local Execution

```bash
# Start the monitoring system
python main.py

# In another terminal, start the web dashboard
python -m dashboard.app
```

### Option 2: Docker Deployment

```bash
cd docker
docker-compose up -d
```

Access the dashboard at: http://localhost:5000

## System Components

1. **Traffic Capture Layer** (capture/)
   - Captures DNS traffic using tshark/tcpdump
   - Monitors port 53 (UDP/TCP)

2. **Parsing Layer** (parser/)
   - Extracts DNS metadata
   - Timestamp, source IP, domain, query type

3. **Detection Engine** (detection/)
   - Applies blacklist-based detection
   - Implements rule-based behavior analysis
   - Generates threat alerts

4. **Database Layer** (database/)
   - SQLite database for logs and alerts
   - Persistent storage of detection results

5. **Dashboard** (dashboard/)
   - Flask web interface
   - Visualize alerts and logs
   - Search and filter capabilities

## Configuration

### Blacklist Sources

The system updates malicious domain lists every 24 hours from:
- URLhaus: https://urlhaus-api.abuse.ch/v1/urls/csv/
- OpenPhish: https://openphish.com/feed.txt
- Malware Domains List

### Detection Rules

The system applies these detection rules:
- High query/response rate
- Suspicious TLD (.xyz, .top, .tk, etc.)
- Random looking domain names
- Lots of NXDOMAIN responses
- High number of subdomain queries

### Severity Levels

Threats are classified as:
- Not-significant (score 0-19)
- Low Severity (score 20-49)
- Medium Severity (score 50-79)
- High Severity (score 80-100)

## Testing

Run tests with pytest:

```bash
pytest tests/ -v
pytest tests/ --cov=.  # With coverage
```

## Monitoring Performance

Monitor these metrics:
- Detection results generated within 3 seconds
- CPU usage below 30%
- Memory usage below 500MB
- False positive rate below 10%

## Troubleshooting

### Cannot capture DNS traffic
- Ensure you have root/sudo access
- Check that port 53 is not blocked
- Verify network interface is correct in config

### Database errors
- Check database file permissions
- Ensure data directory exists and is writable
- Delete db file to reinitialize schema

### Dashboard not accessible
- Check DASHBOARD_HOST and DASHBOARD_PORT in config
- Ensure port 5000 is not in use
- Check firewall rules

## Support

For issues or questions, contact the development team:
- Stephen Small
- Tissa Abraham
- Robert O'Brien

Project: CT5180 Capstone Project, NUIG
"""

