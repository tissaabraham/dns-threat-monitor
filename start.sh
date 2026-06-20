#!/bin/bash

# Start dnsmasq in the background
dnsmasq --no-daemon &

# Give dnsmasq a moment to start up and create the log file
sleep 2

# Creates the db file if it doesn't already exist (Stops the compose from crashing if not there)
touch /app/dns_threat_monitor.db &

# Start the dashboard
python dashboard/app.py &

# Start the Python monitoring system
# pythonpath tells python where to find the modules, fixed errors caused by files in different folders.
# Now that main is just a pointer, we can use it as the entry point for everything.
PYTHONPATH=/app python /app/main.py
