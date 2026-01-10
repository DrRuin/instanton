#!/bin/bash
# ============================================================================
# Instanton Quick Setup - Minimal commands for VPS deployment
# Run this on your VPS with: curl -sSL https://raw.githubusercontent.com/DrRuin/instanton/main/deploy/vps/quick-setup.sh | sudo bash
# ============================================================================

set -e

DOMAIN="instanton.tech"
INSTANTON_DIR="/opt/instanton"

echo "🚀 Installing Instanton relay server for ${DOMAIN}..."

# Install basic deps
apt update
apt install -y ca-certificates curl gnupg git

# Check if Docker Compose V2 is already available
if docker compose version &> /dev/null 2>&1; then
    echo "✓ Docker Compose V2 already installed"
else
    echo "Installing Docker Compose V2..."

    # Remove legacy docker-compose if present
    apt remove -y docker-compose 2>/dev/null || true

    # Check if docker.io is installed (Ubuntu package)
    if dpkg -l 2>/dev/null | grep -q docker.io; then
        echo "Detected docker.io, installing standalone Docker Compose V2..."
        # Install Docker Compose V2 as standalone binary (works with docker.io)
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        mkdir -p /usr/local/lib/docker/cli-plugins
        curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    elif ! command -v docker &> /dev/null; then
        echo "Installing Docker CE from official repository..."
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt update
        apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        # Docker installed but no compose - install standalone binary
        echo "Installing standalone Docker Compose V2..."
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        mkdir -p /usr/local/lib/docker/cli-plugins
        curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    fi
    systemctl enable docker && systemctl start docker
fi

# Verify Docker Compose V2
if ! docker compose version &> /dev/null 2>&1; then
    echo "❌ Docker Compose V2 installation failed"
    exit 1
fi
echo "✓ Docker Compose V2: $(docker compose version --short)"

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
