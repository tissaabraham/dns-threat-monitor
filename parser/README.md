# Parser Module

## Purpose

The **Parser** module extracts relevant DNS metadata from captured network traffic. This is the second layer of the system architecture and handles data transformation and normalization.

## Responsibilities

- Extract relevant DNS fields from raw packet data
- Parse DNS queries and responses
- Extract and normalize metadata including:
  - Timestamp
  - Source IP address
  - Destination IP address
  - Domain name
  - Query type (A, AAAA, MX, etc.)
  - Response code
- Format and clean extracted data for storage

## Key Components

- DNS packet parsing scripts
- Data extraction and normalization routines
- Field mapping and transformation logic

## Technology Stack

- Python
- tshark / tcpdump parsing
- Data processing libraries

## Input/Output

- **Input**: Raw DNS traffic from the Capture module
- **Output**: Structured DNS records forwarded to the Detection Engine and Database module

