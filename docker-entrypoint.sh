#!/bin/bash
# Docker entrypoint for Instanton Server
# Handles certificate permissions before starting the server

set -e

# If running as root, fix certificate permissions and switch to instanton user
if [ "$(id -u)" = "0" ]; then
    # Copy certificates to a location the instanton user can read
    if [ -f "/certs/cert.pem" ] && [ -f "/certs/key.pem" ]; then
        mkdir -p /app/certs
        cp /certs/cert.pem /app/certs/cert.pem
        cp /certs/key.pem /app/certs/key.pem
        chmod 644 /app/certs/cert.pem
        chmod 600 /app/certs/key.pem
        chown -R instanton:instanton /app/certs

        # Update cert paths to point to the copied certs
        export INSTANTON_CERT_PATH="/app/certs/cert.pem"
        export INSTANTON_KEY_PATH="/app/certs/key.pem"

        echo "Certificates prepared for instanton user"
    else
        echo "Warning: Certificate files not found in /certs, running without TLS"
    fi

    # Switch to instanton user and run the command
    exec gosu instanton "$@"
else
    # Already running as non-root, just execute
    exec "$@"
fi
