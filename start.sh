#!/bin/bash
# Stop on first error
set -e

# Make sure the log and data directories exist inside the container
mkdir -p /var/log/technitium/dns/queries
mkdir -p /app/data

# Let Python find the project modules
export PYTHONPATH=/app

# Start the Flask dashboard in the background
echo "Starting DNS Threat Monitor Dashboard..."
python /app/dashboard/app.py &
DASHBOARD_PID=$!

# Give the dashboard a moment to bind its port
sleep 2

# Start the main monitoring loop in the background
echo "Starting DNS monitoring system..."
python /app/main.py &
MONITOR_PID=$!

# Keep the container alive until either process exits
wait $DASHBOARD_PID $MONITOR_PID
