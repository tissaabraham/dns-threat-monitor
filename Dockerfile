# Start from a lightweight Linux base image
FROM python:3.11-slim

# Install system tools — Technitium DNS Server and tshark
RUN apt-get update && apt-get install -y \
    tshark \
    curl \
    unzip \
    mono-runtime \
    && rm -rf /var/lib/apt/lists/*

# Download and install Technitium DNS Server
RUN curl -L -o technitium-dns-server.zip https://download.technitium.com/dns/TechnitiumDNS.zip && \
    unzip technitium-dns-server.zip -d /opt/technitium-dns && \
    rm technitium-dns-server.zip && \
    chmod +x /opt/technitium-dns/TechnitiumDNS.exe

# Create the log file Technitium will write to
RUN mkdir -p /var/log && touch /var/log/technitium-dns.log && chmod 666 /var/log/technitium-dns.log

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy all your project files into the container
COPY . .

# Create Technitium DNS configuration directory
RUN mkdir -p /opt/technitium-dns/config

# Copy the startup script (explained below)
COPY start.sh /start.sh
RUN chmod +x /start.sh

# This is what runs when the container starts
CMD ["/start.sh"]