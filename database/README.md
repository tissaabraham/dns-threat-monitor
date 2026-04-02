# Database Module
## Purpose
The **Database** module manages all persistent data storage for the threat monitoring system. This is the data persistence layer of the system architecture.
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
