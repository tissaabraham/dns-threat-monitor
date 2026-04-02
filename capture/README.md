# Capture Module

## Purpose

The **Capture** module is responsible for capturing DNS traffic from the home network. This is the first layer of the system architecture and serves as the data collection point.

## Responsibilities

- Capture DNS queries and responses from network traffic
- Interface with DNSMASQ to intercept DNS traffic
- Utilize tcpdump or tshark to extract DNS packets
- Provide raw DNS packet data to the Parser module for processing

## Key Components

- DNS traffic interception scripts
- Packet capture configuration files
- Integration with DNSMASQ or alternative DNS forwarding services

## Technology Stack

- tcpdump / tshark
- DNSMASQ
- Python packet capture libraries

## Output

Captured DNS packets and traffic logs are forwarded to the **Parser** module for extraction and processing.

