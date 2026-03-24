# dns-threat-monitor
Passive Monitoring and Threat Detection in a Home Wi-Fi Network

## Repository Information

This repository is the storage and working location for **Group E's Capstone Project for CT5180 at NUIG (National University of Ireland, Galway)**.

**Team Members:**
- Stephen Small
- Tissa Abraham
- Robert O'Brien

## Project Overview

This project focuses on the design and implementation of a passive monitoring and threat detection system for a home Wi-Fi network environment. The system will monitor DNS traffic within a home network to identify potentially malicious domains and suspicious activity without actively blocking or modifying network traffic. It will only observe, analyse, and generate alerts.

**The goal of the project is to create a tool to monitor home networks and report on suspicious activity detected.** This will be done by the use of DNSMASQ to intercept and forward traffic, which will then be examined using Tshark and events created, with each packet compared against a known list of malicious sites and against several detection rules.

Unlike enterprise networks that commonly deploy Intrusion Detection Systems (IDS), home networks often lack monitoring and visibility. This project aims to demonstrate that a lightweight, cost-effective, and secure monitoring solution can be implemented using accessible hardware and open-source technologies.

## Motivation

Home networks have changed significantly in recent years. Modern households now include many internet-connected devices such as laptops, smartphones, smart TVs, gaming consoles, and IoT devices like smart lights and home assistants.

Home users rarely have equivalent protection. As a result, there is a clear security gap between enterprise and home network environments. This project directly addresses that gap by designing and implementing a lightweight, passive DNS monitoring and threat detection system that is suitable for home use. The system aims to provide visibility, alerting, and structured detection without requiring expensive hardware or complex configuration.

## Goals and Objectives

### Primary Goal
The primary goal of this project is to design and implement a lightweight passive DNS monitoring and threat detection system suitable for deployment in a home Wi-Fi network environment. The system aims to improve network visibility, identify potentially malicious domain activity, and provide structured threat reporting without interfering with normal network operations.

### Specific Objectives
The project will achieve these goals by:
- Capturing DNS queries from devices in a simulated home network
- Parsing DNS logs to extract useful information
- Extracting important details such as timestamp, source IP address, domain name, and query type
- Storing the extracted DNS information in a structured SQLite database
- Detecting malicious domains using a predefined blacklist
- Detecting suspicious behaviour using simple rules, such as repeated DNS queries or domains with unusual characteristics
- Storing generated alerts in the SQLite database
- Recording detected threats and updating their status (new, acknowledged, resolved, archived)
- Providing a web-based dashboard to view, search, and filter logs and alerts
- Sending automated email notifications for serious threats
- Running the system inside Docker for easy and consistent deployment
- Testing the system using virtual machines to simulate multiple devices
- Evaluating system performance, detection accuracy, and system limitations

## Criteria for Success

### Functional Success Criteria
- The system successfully captures DNS logs from the simulated home network environment
- DNS logs are correctly parsed and relevant fields (timestamp, source IP, domain name, query type) are extracted
- Extracted DNS data and generated alerts are correctly stored and retrievable from the SQLite database
- All known malicious test domains used during evaluation are detected
- Suspicious behaviour patterns (such as repeated or abnormal domain queries) are correctly identified
- Alerts are automatically generated when detection rules are triggered
- High-severity threats generate automated email notifications
- The web dashboard displays updated logs and alerts without significant delay and allows users to search and filter records

### Performance Criteria
- Detection results are generated within 3 seconds of receiving DNS data
- CPU usage remains below 30% during normal operation
- Memory usage remains below 500MB
- The system continues to function correctly under simulated high DNS traffic conditions

### Accuracy Criteria
- The false positive rate remains below 10% during controlled testing
- Detection rules correctly identify both malicious domains and suspicious behaviour patterns

### Deployment and Portability Criteria
- The system runs successfully inside a Docker container
- The system can be deployed on a standard Linux environment without major configuration changes
- The system can be tested using virtual machines to simulate multiple devices and IP addresses

## Security Challenges and Solutions

### The Home Network Security Gap
The rapid growth of connected household devices increases exposure to external threats. Many devices communicate automatically with remote servers, often without user awareness. In the absence of monitoring mechanisms, compromised devices may initiate malicious communications undetected. Enterprise environments mitigate such risks using dedicated traffic inspection systems. However, their complexity and resource requirements limit suitability for domestic deployment.

### DNS as a Strategic Observation Point
DNS translates domain names into IP addresses and precedes most internet communications. Monitoring DNS queries provides early visibility into external connections without requiring deep packet inspection.

DNS monitoring offers:
- Early detection of connections to known malicious domains
- Identification of abnormal access patterns
- Reduced resource consumption compared to full traffic inspection

This makes DNS an effective observation layer for lightweight security monitoring.

## Detection Methodology

The system uses two simple detection techniques:

### 1. Blacklist-Based Detection
Known malicious domains are stored in a predefined blacklist. Incoming DNS queries are compared against this list. If a match is found, the system generates an alert.

### 2. Rule-Based Behaviour Detection
The system also analyses DNS activity using a set of simple behavioural rules to identify suspicious patterns:
- Repeated DNS queries within a short time period
- Requests to domains that match known malicious patterns
- Requests to unusual or suspicious domain names

A domain may be considered suspicious if it:
- Uses uncommon top-level domains such as .xyz or .top
- Contains long random character strings
- Uses multiple subdomains or unusual naming patterns

### Detection Rules

The system applies the following detection rules to identify suspicious behaviour:

- **High query/response rate** - Detects unusually high frequency of DNS queries from a single source
- **Suspicious TLD** - Identifies requests to domains with uncommon or suspicious top-level domains
- **Random looking domain names** - Flags domains that appear to have randomly generated or obfuscated names
- **Lots of NXDOMAIN responses** - Detects patterns of non-existent domain responses, indicating scanning or brute-force activity
- **High number of subdomain queries** - Identifies excessive subdomain enumeration attempts

### Threat Scoring and Severity Levels

Each detection rule contributes to an event's threat score. Based on the accumulated score, each event is classified into one of four severity levels:

1. **Not-significant** - No or minimal threat indicators detected
2. **Low Severity** - Minor suspicious activity, requires monitoring
3. **Medium Severity** - Notable suspicious activity, investigation recommended
4. **High Severity** - Strong indicators of malicious or suspicious activity, immediate attention recommended

If one or more of these conditions are detected, the system assigns a higher threat score and generates an alert.

## Technology Stack

- **Python** - Core system implementation
- **Packet Capture Tools** - tcpdump / tshark for DNS traffic capture
- **DNS Forwarding Service** - dnsmasq or unbound
- **SQLite Database** - For storing DNS logs and alerts
- **Flask Web Framework** - Web-based dashboard for visualization
- **Email Notification Service** - For alert notifications
- **Docker** - Containerized deployment and testing
- **Virtual Machines** - Testing environment for simulating multiple devices

## System Architecture

### Overview
The system consists of five main layers:

1. **Traffic Capture Layer** - Captures DNS traffic from the network
2. **Parsing and Processing Layer** - Extracts relevant DNS metadata
3. **Detection Engine** - Applies blacklist and rule-based detection
4. **Data Storage Layer** - Stores logs and alerts in SQLite database
5. **Presentation and Alerting Layer** - Web dashboard and email notifications

## Data Management

### Malicious Domain List Management
A list of malicious domains will be cached and updated every 24 hours from one or more of the following sources:

- **URLhaus** - Frequently updated site with malicious URLs, available in CSV or JSON format. Provides an API for querying.
- **Malware Domains List** - Comprehensive list of known malicious domains.
- **OpenPhish** - Phishing intelligence service with API access for querying and retrieving malicious domains.

### Database and Storage
Parsed DNS metadata and alert information are stored in a structured SQLite database. The database maintains logs, detection outcomes, and alert lifecycle states to support querying, reporting, and historical analysis.

## Deployment

The system is containerised using Docker to ensure portability and consistent runtime environments. Testing is conducted using virtual machines to simulate realistic network activity.

## Limitations and Future Considerations

- Encrypted DNS technologies such as DNS over HTTPS (DoH) may bypass local monitoring. For evaluation purposes, encrypted DNS will be disabled within the testing environment.
- The system represents a foundational approach to home network monitoring and can be extended with more sophisticated detection algorithms.

## Testing Strategy

The system is tested using virtual machines to simulate multiple devices and IP addresses, ensuring realistic network conditions and comprehensive coverage of detection capabilities.

## Project Outcomes

This project demonstrates that enterprise-style monitoring principles can be adapted to a simple, home-friendly architecture using open-source tools and efficient design. It provides a practical solution for home users to gain visibility into their network activity and identify potential security threats.


