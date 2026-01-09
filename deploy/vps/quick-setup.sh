#!/bin/bash
# ============================================================================
# Instanton Quick Setup - Minimal commands for VPS deployment
# Run this on your VPS with: curl -sSL https://raw.githubusercontent.com/DrRuin/instanton/main/deploy/vps/quick-setup.sh | sudo bash
# ============================================================================

set -e

DOMAIN="instanton.tech"
INSTANTON_DIR="/opt/instanton"

echo "🚀 Installing Instanton relay server for ${DOMAIN}..."

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    apt update && apt install -y docker.io docker-compose
    systemctl enable docker && systemctl start docker
fi

# Setup directories
mkdir -p ${INSTANTON_DIR}/certs

# Clone repository
cd ${INSTANTON_DIR}
git clone https://github.com/DrRuin/instanton.git . 2>/dev/null || git pull

# Create env file
cat > .env << EOF
INSTANTON_DOMAIN=${DOMAIN}
INSTANTON_LOG_LEVEL=info
EOF

# Start server (initially without TLS for testing)
docker-compose up -d instanton-server

echo ""
echo "✅ Instanton server started!"
echo ""
echo "⚠️  IMPORTANT: You still need to:"
echo "1. Configure DNS in Hostinger (A record for @ and * pointing to this VPS IP)"
echo "2. Get SSL certificates with: certbot certonly --standalone -d ${DOMAIN}"
echo "3. Copy certs: cp /etc/letsencrypt/live/${DOMAIN}/* ${INSTANTON_DIR}/certs/"
echo "4. Restart: docker-compose restart instanton-server"
echo ""
echo "Once done, users can use: pip install instanton && instanton --port 8000"
