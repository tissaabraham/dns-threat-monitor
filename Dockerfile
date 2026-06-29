# Start from a lightweight Linux base image
FROM python:3.11-slim

# Install system tools — tshark for packet capture
RUN apt-get update && apt-get install -y \
    tshark \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy all your project files into the container
COPY . .

# Create log directories for Technitium
RUN mkdir -p /var/log/technitium/dns && chmod 777 /var/log/technitium/dns

# Copy the startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# This is what runs when the container starts
CMD ["/start.sh"]
