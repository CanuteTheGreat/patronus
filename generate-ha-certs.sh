#!/bin/bash
# Patronus SD-WAN - HA stack TLS cert generator
# Purpose: docker-compose.ha.yml's haproxy service bind-mounts ./certs
#          read-only and haproxy.cfg expects a combined cert+key PEM at
#          /etc/ssl/certs/patronus.pem (`bind *:443 ssl crt ...`). This repo
#          does not ship a real cert (correctly -- don't commit private
#          keys), so generate a local self-signed one before bringing the
#          HA stack up.
#
# Usage: ./generate-ha-certs.sh
#
# Idempotent: skips generation if certs/patronus.pem already exists, so it's
# safe to call from CI / first-run setup alongside build-frontend.sh.

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$PROJECT_DIR/certs"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Patronus HA Stack - Self-Signed TLS Cert Generator      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

if ! command -v openssl &> /dev/null; then
    echo "❌ openssl not found. Install it before running this script."
    exit 1
fi

mkdir -p "$CERTS_DIR"

if [ -f "$CERTS_DIR/patronus.pem" ]; then
    echo "✅ $CERTS_DIR/patronus.pem already exists -- leaving it in place."
    echo "   Delete it first if you want to regenerate (e.g. CN changed)."
    exit 0
fi

echo "🔐 Generating self-signed cert (CN=localhost, SAN=localhost,*.patronus-ha,dashboard1,dashboard2,dashboard3)..."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/patronus.key" \
    -out "$CERTS_DIR/patronus.crt" \
    -subj "/C=US/O=Patronus/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:haproxy,DNS:dashboard1,DNS:dashboard2,DNS:dashboard3,IP:127.0.0.1" \
    2>/dev/null

# HAProxy wants cert+key concatenated in a single PEM.
cat "$CERTS_DIR/patronus.crt" "$CERTS_DIR/patronus.key" > "$CERTS_DIR/patronus.pem"
chmod 600 "$CERTS_DIR/patronus.key" "$CERTS_DIR/patronus.pem"

echo ""
echo "✅ Generated:"
echo "   $CERTS_DIR/patronus.crt  (certificate)"
echo "   $CERTS_DIR/patronus.key  (private key)"
echo "   $CERTS_DIR/patronus.pem  (combined, what haproxy.cfg actually mounts)"
echo ""
echo "⚠️  Self-signed -- browsers/curl will warn/need -k. Replace with a real"
echo "   cert (e.g. Let's Encrypt) for production use."
echo ""
echo "Next step: docker-compose -f docker-compose.ha.yml up -d"
