#!/bin/bash

# Start Technitium DNS Server in the background
cd /opt/technitium-dns
mono TechnitiumDNS.exe --StartService &

# Give Technitium DNS a moment to start up
sleep 5

# Creates the db file if it doesn't already exist (Stops the compose from crashing if not there)
touch /app/dns_threat_monitor.db &

# Start the dashboard
python dashboard/app.py &

# Start the Python monitoring system
# pythonpath tells python where to find the modules, fixed errors caused by files in different folders.
# Now that main is just a pointer, we can use it as the entry point for everything.
PYTHONPATH=/app python /app/main.py
