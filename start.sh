#!/bin/bash

# Start dnsmasq in the background
dnsmasq --no-daemon &

# Give dnsmasq a moment to start up and create the log file
sleep 2

# Start the dashboard
python dashboard/app.py &

# Start the Python monitoring system
# pythonpath tells python where to find the modules, fixed errors caused by files in different folders.
# Now that main is just a pointer, we can use it as the entry point for everything.
PYTHONPATH=/app python /app/main.py
