#!/bin/bash
set -e

# Create necessary directories
mkdir -p /var/log/technitium/dns/queries
mkdir -p /app/data

# Export Python path
export PYTHONPATH=/app

# Start the dashboard in the background
echo "Starting DNS Threat Monitor Dashboard..."
python /app/dashboard/app.py &
DASHBOARD_PID=$!

# Give the dashboard a moment to start
sleep 2

# Start the monitoring system in the foreground
echo "Starting DNS monitoring system..."
python /app/main.py &
MONITOR_PID=$!

# Wait for both processes
wait $DASHBOARD_PID $MONITOR_PID
