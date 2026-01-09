#!/bin/bash
# ============================================================================
# Instanton Quick Setup - Minimal commands for VPS deployment
# Run this on your VPS with: curl -sSL https://raw.githubusercontent.com/DrRuin/instanton/main/deploy/vps/quick-setup.sh | sudo bash
# ============================================================================

set -e

DOMAIN="instanton.tech"
INSTANTON_DIR="/opt/instanton"

echo "🚀 Installing Instanton relay server for ${DOMAIN}..."

# Install Docker with Compose V2 plugin (NOT legacy docker-compose)
if ! command -v docker &> /dev/null; then
    apt update
    apt install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable docker && systemctl start docker
fi

# Verify Docker Compose V2 is available
if ! docker compose version &> /dev/null; then
    echo "⚠️  Installing Docker Compose plugin..."
    apt install -y docker-compose-plugin
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

# Start server (using Docker Compose V2)
docker compose up -d instanton-server

echo ""
echo "✅ Instanton server started!"
echo ""
echo "⚠️  IMPORTANT: You still need to:"
echo "1. Configure DNS in Hostinger (A record for @ and * pointing to this VPS IP)"
echo "2. Get SSL certificates with: certbot certonly --standalone -d ${DOMAIN}"
echo "3. Copy certs: cp /etc/letsencrypt/live/${DOMAIN}/* ${INSTANTON_DIR}/certs/"
echo "4. Restart: docker compose restart instanton-server"
echo ""
echo "Once done, users can use: pip install instanton && instanton --port 8000"
