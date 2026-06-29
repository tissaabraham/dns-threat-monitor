#!/bin/bash

# Start Technitium using its own entrypoint in the background
/usr/bin/dotnet /opt/technitium/dns/DnsServerApp.dll /etc/dns &
TECHNITIUM_PID=$!

# Wait for the web API to be reachable
echo "Waiting for Technitium API..."
for i in $(seq 1 60); do
    if wget -q -O /dev/null http://localhost:5380/api/user/login 2>/dev/null; then
        echo "Technitium API is ready"
        break
    fi
    sleep 1
done

# Log in and get a session token
TOKEN=$(wget -qO- "http://localhost:5380/api/user/login?user=admin&pass=admin" \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    echo "Enabling query logging..."
    wget -qO- \
        --post-data "logQueries=true&logFolder=/var/log/technitium/dns/queries" \
        --header "Authorization: Bearer $TOKEN" \
        "http://localhost:5380/api/settings/set" \
        && echo "Query logging enabled" || echo "Warning: could not enable query logging"
else
    echo "Warning: could not obtain Technitium API token"
fi

# Hand off to Technitium process
wait $TECHNITIUM_PID
