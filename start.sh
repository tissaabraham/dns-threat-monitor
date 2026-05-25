#!/bin/bash

# Start dnsmasq in the background
dnsmasq --no-daemon &

# Give dnsmasq a moment to start up and create the log file
sleep 2

# Start the dashboard (Uncomment when dashboard ready)
#python dashboard.py &

# Start the Python monitoring system
python main.py
