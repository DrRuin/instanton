# Instanton VPS Setup Guide for instanton.tech

Complete guide to deploy Instanton relay server on your VPS so users can get `*.instanton.tech` URLs.

## Prerequisites

- VPS with Ubuntu 22.04+ (or similar Linux distro)
- Root/sudo access
- Domain: `instanton.tech` (from Hostinger)
- Ports 80, 443, and 4443 open

## Architecture

```
User's Machine                   Your VPS (instanton.tech)              User's localhost
     |                                    |                                    |
     |  instanton --port 8000             |                                    |
     |  ─────────────────────────>        |                                    |
     |                          [Relay Server:8443]                            |
     |                                    |                                    |
Internet Request                          |                                    |
     |                                    |                                    |
https://abc123.instanton.tech   ─────>  [HTTPS:443]  ─────────────────>  localhost:8000
```

## Step 1: DNS Configuration (Hostinger)

1. Log in to Hostinger control panel
2. Go to **Domains** → **instanton.tech** → **DNS / Nameservers**
3. Add these DNS records:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | @ | `YOUR_VPS_IP` | 3600 |
| A | * | `YOUR_VPS_IP` | 3600 |
| A | relay | `YOUR_VPS_IP` | 3600 |

The **wildcard A record (*)** is critical - it allows `*.instanton.tech` subdomains to work.

## Step 2: VPS Initial Setup

SSH into your VPS and run:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y docker.io docker-compose git certbot curl

# Enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add your user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

## Step 3: Get SSL Certificates with Let's Encrypt

```bash
# Stop any services using port 80
sudo systemctl stop nginx 2>/dev/null || true
sudo systemctl stop apache2 2>/dev/null || true

# Get wildcard certificate (requires DNS challenge)
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d "instanton.tech" \
  -d "*.instanton.tech" \
  --email your-email@example.com \
  --agree-tos

# When prompted, add TXT record to Hostinger DNS:
# Type: TXT
# Name: _acme-challenge
# Value: (the value certbot shows)
# Wait 2-5 minutes for DNS propagation, then press Enter
```

After successful certificate issuance, certificates are at:
- `/etc/letsencrypt/live/instanton.tech/fullchain.pem`
- `/etc/letsencrypt/live/instanton.tech/privkey.pem`

## Step 4: Deploy Instanton Relay Server

```bash
# Create instanton directory
sudo mkdir -p /opt/instanton
cd /opt/instanton

# Clone the repository (or copy files)
git clone https://github.com/DrRuin/instanton.git .

# Create certs directory with proper permissions
sudo mkdir -p /opt/instanton/certs
sudo cp /etc/letsencrypt/live/instanton.tech/fullchain.pem /opt/instanton/certs/cert.pem
sudo cp /etc/letsencrypt/live/instanton.tech/privkey.pem /opt/instanton/certs/key.pem
sudo chmod 644 /opt/instanton/certs/cert.pem
sudo chmod 600 /opt/instanton/certs/key.pem

# Create environment file
cat > /opt/instanton/.env << 'EOF'
INSTANTON_DOMAIN=instanton.tech
INSTANTON_LOG_LEVEL=info
INSTANTON_AUTH_TOKEN=your-secret-token-here
EOF

# Build and start the server
docker-compose up -d instanton-server
```

## Step 5: Verify Server is Running

```bash
# Check container status
docker ps

# Check logs
docker logs instanton-server

# Test health endpoint
curl http://localhost:4443/health

# Test from internet (wait for DNS propagation)
curl https://instanton.tech:4443/health
```

## Step 6: Setup Systemd Service (Auto-start on boot)

```bash
cat | sudo tee /etc/systemd/system/instanton.service << 'EOF'
[Unit]
Description=Instanton Relay Server
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/instanton
ExecStart=/usr/bin/docker-compose up
ExecStop=/usr/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable instanton
sudo systemctl start instanton
```

## Step 7: Setup Certificate Auto-Renewal

```bash
# Create renewal script
cat | sudo tee /opt/instanton/renew-certs.sh << 'EOF'
#!/bin/bash
certbot renew --quiet
cp /etc/letsencrypt/live/instanton.tech/fullchain.pem /opt/instanton/certs/cert.pem
cp /etc/letsencrypt/live/instanton.tech/privkey.pem /opt/instanton/certs/key.pem
docker-compose -f /opt/instanton/docker-compose.yml restart instanton-server
EOF

sudo chmod +x /opt/instanton/renew-certs.sh

# Add to crontab (runs twice daily)
echo "0 0,12 * * * root /opt/instanton/renew-certs.sh" | sudo tee /etc/cron.d/instanton-cert-renewal
```

## Step 8: Configure Firewall

```bash
# Using UFW (Ubuntu)
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP (for cert renewal)
sudo ufw allow 443/tcp    # HTTPS (public traffic)
sudo ufw allow 4443/tcp   # Control plane (tunnel clients)
sudo ufw enable
```

## Testing

Once everything is set up, users can use Instanton:

```bash
# On any machine
pip install instanton
instanton --port 8000

# Output:
# ⚡ Instanton v1.0.0
# ✓ Tunnel established
# Public URL: https://abc123.instanton.tech
# Forwarding: https://abc123.instanton.tech → http://localhost:8000
```

## Troubleshooting

### DNS not resolving
```bash
# Check DNS propagation
dig instanton.tech
dig test.instanton.tech
nslookup instanton.tech
```

### Certificate issues
```bash
# Test certificate
openssl s_client -connect instanton.tech:443 -servername instanton.tech
```

### Container not starting
```bash
docker logs instanton-server
docker-compose logs -f
```

### Connection refused
```bash
# Check ports are open
netstat -tlnp | grep -E '443|4443'
ss -tlnp | grep -E '443|4443'
```

## Production Recommendations

1. **Monitoring**: Add Prometheus + Grafana (use `--profile monitoring` with docker-compose)
2. **Backups**: Backup `/opt/instanton/certs` and `/opt/instanton/.env`
3. **Logs**: Use `docker-compose logs -f` or configure log rotation
4. **Security**: Use strong `INSTANTON_AUTH_TOKEN` for authenticated tunnels
5. **Rate Limiting**: Already built-in, configure in server settings
