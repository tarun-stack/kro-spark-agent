#!/bin/bash
set -euo pipefail

CERT_DIR=/certs
CERT_VALIDITY_DAYS=${CERT_VALIDITY_DAYS:-365}

echo "Generating ephemeral CA certificate (validity: ${CERT_VALIDITY_DAYS} days)..."

# Generate EC key for CA (faster than RSA for a demo)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$CERT_DIR/ca-key.pem" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" \
  -out "$CERT_DIR/ca-cert.pem" -days "$CERT_VALIDITY_DAYS" -subj "/CN=Transparent Proxy CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Create combined CA bundle for the main container
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  cat /etc/ssl/certs/ca-certificates.crt "$CERT_DIR/ca-cert.pem" > "$CERT_DIR/combined-ca.crt"
else
  cp "$CERT_DIR/ca-cert.pem" "$CERT_DIR/combined-ca.crt"
fi

# Alias for NODE_EXTRA_CA_CERTS
cp "$CERT_DIR/ca-cert.pem" "$CERT_DIR/proxy-ca.crt"

# Make CA key readable by proxy (UID 1337)
chmod 644 "$CERT_DIR/ca-key.pem"

echo "CA certificate ready at $CERT_DIR/proxy-ca.crt"
