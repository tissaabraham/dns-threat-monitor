#!/bin/bash

# Start Technitium DNS Server in the background
cd /opt/technitium-dns
mono TechnitiumDNS.exe --StartService &

# Give Technitium DNS a moment to start up
sleep 5

# Start the dashboard
python dashboard/app.py &

# Start the Python monitoring system
# pythonpath tells python where to find the modules, fixed errors caused by files in different folders.
# Now that main is just a pointer, we can use it as the entry point for everything.
PYTHONPATH=/app python /app/main.py
