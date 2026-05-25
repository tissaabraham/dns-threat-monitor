# Docker Module

## Purpose

The **Docker** module contains containerization configuration and deployment scripts. This enables consistent, portable deployment of the threat monitoring system across different environments.

## Responsibilities

- Define Docker container configuration
- Manage application containerization
- Configure service dependencies
- Set up environment variables and network settings
- Provide deployment scripts and orchestration
- Enable testing in isolated environments
- Ensure portability across Linux systems

## Key Components

- Dockerfile(s) for application containerization
- Docker Compose configuration (if using multi-container setup)
- Environment configuration files
- Network configuration
- Volume mount specifications
- Health check definitions

## Technology Stack

- Docker
- Docker Compose (optional)
- Linux container runtime

## Features

- Complete application isolation
- Consistent runtime environment
- Easy deployment and scaling
- Environment variable management
- Volume persistence for logs and databases
- Network configuration for traffic capture

## Deployment

The system is containerized to ensure:
- Easy deployment on any Linux system with Docker installed
- Consistent runtime environment across testing and production
- Simplified configuration management
- Isolated testing environments
- Quick startup and teardown

## Usage

Deploy the system by building and running Docker containers according to the Dockerfile and Docker Compose configurations provided in this directory.

## Important notes:
> Note: The docker files will need to be in the main root directory, and cannot be placed in the docker folder.
> 
> This is because they must be in the same folder which we run the "docker-compose up" command.
> >This could be changed by editing the build segment of the yml, but it's easiest to leave them here.

While we are testing this, before the full deployment and dashboard,
it is important to run the network tests through the deployed docker container.

This is done by installing DNS utilities:
> apt-get update && apt-get install -y bind9-dnsutils

Then, in another terminal within the container, we can start doing lookups:
> nslookup google.com 127.0.0.1

>nslookup fake-evil-site.xyz 127.0.0.1

These should then be captured and displayed to the user in the primary terminal.