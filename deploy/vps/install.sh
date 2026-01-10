#!/bin/bash
# ============================================================================
# Instanton VPS Installation Script
# One-command deployment for instanton.tech relay server
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTANTON_DIR="/opt/instanton"
DOMAIN="${INSTANTON_DOMAIN:-instanton.tech}"
EMAIL="${ACME_EMAIL:-admin@instanton.tech}"

echo -e "${BLUE}"
echo "============================================================================"
echo "                    Instanton Relay Server Installer"
echo "                         For: ${DOMAIN}"
echo "============================================================================"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Usage: sudo ./install.sh"
   exit 1
fi

# Get VPS IP
VPS_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || curl -s api.ipify.org)
echo -e "${GREEN}✓ Detected VPS IP: ${VPS_IP}${NC}"

# Step 1: Install dependencies (Docker with Compose V2 plugin)
echo -e "\n${YELLOW}[1/7] Installing dependencies...${NC}"
apt update
apt install -y ca-certificates curl gnupg git certbot ufw

# Check if Docker Compose V2 is already available
if docker compose version &> /dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker Compose V2 already installed${NC}"
else
    echo -e "${YELLOW}Installing Docker with Compose V2...${NC}"

    # Remove legacy docker-compose if present
    apt remove -y docker-compose 2>/dev/null || true

    # Check if docker.io is installed (Ubuntu package)
    if dpkg -l | grep -q docker.io; then
        echo -e "${YELLOW}Detected docker.io, installing standalone Docker Compose V2...${NC}"
        # Install Docker Compose V2 as standalone binary (works with docker.io)
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        mkdir -p /usr/local/lib/docker/cli-plugins
        curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

        # Also create symlink for CLI plugin
        mkdir -p ~/.docker/cli-plugins 2>/dev/null || true
        ln -sf /usr/local/lib/docker/cli-plugins/docker-compose ~/.docker/cli-plugins/docker-compose 2>/dev/null || true
    else
        # Fresh install - use Docker official repository
        echo -e "${YELLOW}Installing Docker CE from official repository...${NC}"
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt update
        apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
fi

systemctl enable docker
systemctl start docker

# Verify installation
if docker compose version &> /dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker Compose V2 installed: $(docker compose version --short)${NC}"
else
    echo -e "${RED}✗ Docker Compose V2 installation failed${NC}"
    exit 1
fi

# Step 2: Create directory structure
echo -e "\n${YELLOW}[2/7] Setting up directories...${NC}"
mkdir -p ${INSTANTON_DIR}/certs
mkdir -p ${INSTANTON_DIR}/data
cd ${INSTANTON_DIR}

echo -e "${GREEN}✓ Directories created${NC}"

# Step 3: Clone or download Instanton
echo -e "\n${YELLOW}[3/7] Downloading Instanton...${NC}"
if [ -d "${INSTANTON_DIR}/.git" ]; then
    git pull origin main
else
    git clone https://github.com/DrRuin/instanton.git .
fi

echo -e "${GREEN}✓ Instanton downloaded${NC}"

# Step 4: Configure firewall
echo -e "\n${YELLOW}[4/7] Configuring firewall...${NC}"
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (cert renewal)
ufw allow 443/tcp  # HTTPS (public traffic)
ufw allow 4443/tcp # Control plane (tunnel clients)
ufw --force enable

echo -e "${GREEN}✓ Firewall configured${NC}"

# Step 5: Get SSL certificates
echo -e "\n${YELLOW}[5/7] Obtaining SSL certificates...${NC}"
echo -e "${YELLOW}NOTE: You need to add DNS TXT record when prompted!${NC}"
echo ""
echo "Before continuing, ensure these DNS records exist in Hostinger:"
echo "  Type: A    Name: @      Value: ${VPS_IP}"
echo "  Type: A    Name: *      Value: ${VPS_IP}"
echo "  Type: A    Name: relay  Value: ${VPS_IP}"
echo ""
read -p "Press Enter when DNS records are configured..."

# Request certificate
certbot certonly \
    --standalone \
    --preferred-challenges http \
    -d "${DOMAIN}" \
    --email "${EMAIL}" \
    --agree-tos \
    --non-interactive || {
    echo -e "${YELLOW}Standalone failed, trying manual DNS challenge for wildcard...${NC}"
    certbot certonly \
        --manual \
        --preferred-challenges dns \
        -d "${DOMAIN}" \
        -d "*.${DOMAIN}" \
        --email "${EMAIL}" \
        --agree-tos
}

# Copy certificates
cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${INSTANTON_DIR}/certs/cert.pem
cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${INSTANTON_DIR}/certs/key.pem
chmod 644 ${INSTANTON_DIR}/certs/cert.pem
chmod 600 ${INSTANTON_DIR}/certs/key.pem

echo -e "${GREEN}✓ SSL certificates obtained${NC}"

# Step 6: Create environment file
echo -e "\n${YELLOW}[6/7] Creating configuration...${NC}"
AUTH_TOKEN=$(openssl rand -hex 32)

cat > ${INSTANTON_DIR}/.env << EOF
INSTANTON_DOMAIN=${DOMAIN}
INSTANTON_LOG_LEVEL=info
INSTANTON_AUTH_TOKEN=${AUTH_TOKEN}
EOF

echo -e "${GREEN}✓ Configuration created${NC}"
echo -e "${BLUE}Auth Token: ${AUTH_TOKEN}${NC}"
echo "(Save this token for authenticated tunnels)"

# Step 7: Start Instanton
echo -e "\n${YELLOW}[7/7] Starting Instanton server...${NC}"
cd ${INSTANTON_DIR}
docker compose up -d instanton-server

# Wait for startup
sleep 5

# Check if running
if docker ps | grep -q instanton-server; then
    echo -e "${GREEN}✓ Instanton server is running!${NC}"
else
    echo -e "${RED}✗ Server failed to start. Check logs:${NC}"
    docker logs instanton-server
    exit 1
fi

# Setup systemd service
cat > /etc/systemd/system/instanton.service << EOF
[Unit]
Description=Instanton Relay Server
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=${INSTANTON_DIR}
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable instanton

# Setup certificate renewal cron
cat > /etc/cron.d/instanton-cert-renewal << EOF
0 0,12 * * * root certbot renew --quiet && cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${INSTANTON_DIR}/certs/cert.pem && cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${INSTANTON_DIR}/certs/key.pem && cd ${INSTANTON_DIR} && docker compose restart instanton-server
EOF

echo ""
echo -e "${GREEN}============================================================================${NC}"
echo -e "${GREEN}                    Installation Complete!${NC}"
echo -e "${GREEN}============================================================================${NC}"
echo ""
echo -e "Server Status:"
echo -e "  ${BLUE}Health Check:${NC} curl https://${DOMAIN}:4443/health"
echo ""
echo -e "Users can now run:"
echo -e "  ${BLUE}pip install instanton${NC}"
echo -e "  ${BLUE}instanton --port 8000${NC}"
echo ""
echo -e "They will get URLs like: ${BLUE}https://abc123.${DOMAIN}${NC}"
echo ""
echo -e "Management Commands:"
echo -e "  View logs:    ${YELLOW}docker logs -f instanton-server${NC}"
echo -e "  Restart:      ${YELLOW}docker compose restart instanton-server${NC}"
echo -e "  Status:       ${YELLOW}docker ps${NC}"
echo ""
echo -e "${GREEN}✓ All done! Your Instanton relay server is live.${NC}"
