#!/bin/bash
set -euo pipefail

PROXY_PORT=${PROXY_PORT:-15001}
PROXY_UID=${PROXY_UID:-1337}

echo "Setting up iptables redirect: all TCP egress -> port ${PROXY_PORT} (excluding UID ${PROXY_UID})"

# Create custom chain
iptables -t nat -N PROXY_OUTPUT

# Skip traffic from the proxy itself (avoid redirect loops)
iptables -t nat -A PROXY_OUTPUT -m owner --uid-owner ${PROXY_UID} -j RETURN

# Skip loopback
iptables -t nat -A PROXY_OUTPUT -d 127.0.0.0/8 -j RETURN

# Skip EC2 metadata endpoint (Bedrock workload identity)
iptables -t nat -A PROXY_OUTPUT -d 169.254.169.254/32 -j RETURN

# Redirect everything else to the proxy
iptables -t nat -A PROXY_OUTPUT -p tcp -j REDIRECT --to-ports ${PROXY_PORT}

# Install into OUTPUT chain
iptables -t nat -A OUTPUT -p tcp -j PROXY_OUTPUT

echo "iptables rules installed:"
iptables -t nat -L PROXY_OUTPUT -v --line-numbers
