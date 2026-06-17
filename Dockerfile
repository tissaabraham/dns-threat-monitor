# Start from a lightweight Linux base image
FROM python:3.11-slim

# Install system tools — dnsmasq and tshark
RUN apt-get update && apt-get install -y \
    dnsmasq \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Create the log file dnsmasq will write to
RUN mkdir -p /var/log && touch /var/log/dnsmasq.log && chmod 666 /var/log/dnsmasq.log

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy all your project files into the container
COPY . .

# Copy your dnsmasq config into the right place
COPY dnsmasq.conf /etc/dnsmasq.conf

# Copy the startup script (explained below)
COPY start.sh /start.sh
RUN chmod +x /start.sh

# This is what runs when the container starts
CMD ["/start.sh"]