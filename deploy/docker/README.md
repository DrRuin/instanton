# 🐳 Instanton Docker Deployment

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/Self--Hosted-Yes-success?style=for-the-badge" alt="Self-Hosted"/>
  <img src="https://img.shields.io/badge/OAuth-Supported-blueviolet?style=for-the-badge" alt="OAuth"/>
</p>

<p align="center">
  <strong>Run your own Instanton relay server in minutes.</strong>
</p>

---

## ⚡ Quick Start

### 1. Setup Certificates

**Production (Let's Encrypt + Certbot):**

```bash
# Install certbot
sudo apt install certbot

# Get certificate (DNS must point to your VPS first)
sudo certbot certonly --standalone -d tunnel.yourdomain.com

# Link certs to instanton directory
mkdir -p certs
sudo cp /etc/letsencrypt/live/tunnel.yourdomain.com/fullchain.pem certs/cert.pem
sudo cp /etc/letsencrypt/live/tunnel.yourdomain.com/privkey.pem certs/key.pem
sudo chown $USER:$USER certs/*.pem
```

**Development (self-signed):**

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"
```

### 2. Run the Server

```bash
docker run -d \
  -p 443:443 \
  -p 4443:4443 \
  -v ./certs:/certs:ro \
  -e INSTANTON_DOMAIN=tunnel.example.com \
  ghcr.io/drruin/instanton-server
```

### 3. Connect a Client

```bash
pip install instanton
instanton --port 8000 --server tunnel.example.com:4443
```

**Done.** Your self-hosted tunnel is live.

---

## 🏗️ Docker Compose

> **Note:** Use `docker compose` (V2) not `docker-compose` (V1)

### Basic Setup

```bash
# Clone the repo
git clone https://github.com/DrRuin/instanton.git
cd instanton

# Create certificates
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"

# Start the server
docker compose up -d instanton-server

# With monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d
```

### Environment Variables

Create a `.env` file:

```bash
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_LOG_LEVEL=info
INSTANTON_REQUEST_TIMEOUT=0  # 0 = no timeout (streaming)
```

---

## ⚙️ Configuration

### Server Options

| Variable | Description | Default |
|:--|:--|:--|
| `INSTANTON_DOMAIN` | Base domain for tunnels | Required |
| `INSTANTON_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |
| `INSTANTON_REQUEST_TIMEOUT` | Seconds (0 = indefinite) | `120` |

### Ports

| Port | Description |
|:--|:--|
| `443` | HTTPS (public traffic) |
| `4443` | Control plane (client connections) |
| `9090` | Prometheus metrics |

### Volumes

| Path | Description |
|:--|:--|
| `/certs` | TLS certificates (`cert.pem`, `key.pem`) |
| `/data` | Persistent data storage |

---

## 🔐 OAuth Authentication

Require users to authenticate before accessing tunnels.

### Supported Providers

| Provider | Type | Discovery |
|:--|:--|:--|
| **GitHub** | OAuth 2.0 | Manual |
| **Google** | OIDC | Auto |
| **Okta** | OIDC | Auto |
| **Auth0** | OIDC | Auto |
| **Azure AD** | OIDC | Auto |
| **Keycloak** | OIDC | Auto |

### GitHub Setup

```bash
# .env
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=github
INSTANTON_OAUTH_CLIENT_ID=Iv1.abc123...
INSTANTON_OAUTH_CLIENT_SECRET=your-secret
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

1. Go to **GitHub > Settings > Developer settings > OAuth Apps**
2. Set callback URL: `https://tunnel.mycompany.com/_instanton/oauth/callback`
3. Copy Client ID and Secret to `.env`

### Google Setup

```bash
# .env
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=google
INSTANTON_OAUTH_CLIENT_ID=123456.apps.googleusercontent.com
INSTANTON_OAUTH_CLIENT_SECRET=GOCSPX-...
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

1. Go to **Google Cloud Console > APIs & Services > Credentials**
2. Create OAuth 2.0 Client ID (Web application)
3. Add redirect URI: `https://tunnel.mycompany.com/_instanton/oauth/callback`

### Generic OIDC (Okta, Auth0, Keycloak)

```bash
# .env
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=oidc
INSTANTON_OAUTH_ISSUER_URL=https://mycompany.okta.com
INSTANTON_OAUTH_CLIENT_ID=0oa...
INSTANTON_OAUTH_CLIENT_SECRET=...
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

### Access Control

```bash
# Allow only @mycompany.com emails
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com

# Allow multiple domains
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com,partner.com

# Allow specific emails
INSTANTON_OAUTH_ALLOWED_EMAILS=contractor@gmail.com

# If both empty → all authenticated users allowed
```

### OAuth Environment Variables

| Variable | Description |
|:--|:--|
| `INSTANTON_OAUTH_PROVIDER` | `github`, `google`, `oidc` |
| `INSTANTON_OAUTH_CLIENT_ID` | OAuth Client ID |
| `INSTANTON_OAUTH_CLIENT_SECRET` | OAuth Client Secret |
| `INSTANTON_OAUTH_ISSUER_URL` | OIDC issuer (required for `oidc`) |
| `INSTANTON_OAUTH_ALLOWED_DOMAINS` | Comma-separated domains |
| `INSTANTON_OAUTH_ALLOWED_EMAILS` | Comma-separated emails |
| `INSTANTON_OAUTH_SESSION_DURATION` | Session TTL in seconds (default: 86400) |

---

## 🔒 Security Features

<table>
<tr>
<td width="50%">

### OAuth/OIDC
- PKCE (S256) code exchange
- State parameter (CSRF protection)
- Nonce validation (replay protection)
- JWT signature validation via JWKS
- Secure cookies (HttpOnly, Secure, SameSite)

</td>
<td width="50%">

### Infrastructure
- Non-root container user
- Read-only certificate mounts
- TLS 1.3 encryption
- Health check endpoints
- Graceful shutdown

</td>
</tr>
</table>

---

## 🏭 Building Images

```bash
# Client image
docker build -t instanton/instanton -f Dockerfile .

# Server image
docker build -t instanton/instanton-server -f Dockerfile.server .
```

---

## 📊 Monitoring

### Prometheus

The included `prometheus.yml` scrapes metrics from the server:

```yaml
scrape_configs:
  - job_name: 'instanton-server'
    static_configs:
      - targets: ['instanton-server:9090']
```

### Start with Monitoring

```bash
docker compose --profile monitoring up -d
```

- **Prometheus:** http://localhost:9091
- **Grafana:** http://localhost:3000 (admin/admin)

---

## 🩺 Health Checks

| Endpoint | Description |
|:--|:--|
| `GET /health` | Server health status |
| `GET /stats` | Active tunnel statistics |
| `GET /metrics` | Prometheus metrics |

---

## 📁 File Structure

```
instanton/
├── Dockerfile              # Client image
├── Dockerfile.server       # Server image
├── docker-compose.yml      # Main compose file
├── docker-entrypoint.sh    # Server entrypoint
├── certs/                  # Your certificates
│   ├── cert.pem
│   └── key.pem
└── deploy/docker/
    ├── README.md           # This file
    ├── prometheus.yml      # Prometheus config
    ├── docker-compose.oauth.yml
    └── .env.oauth.example
```

---

## 🚨 Troubleshooting

### Certificate Issues

```bash
# Check certificate permissions
docker exec instanton-server ls -la /app/certs/

# View server logs
docker compose logs -f instanton-server
```

### Connection Refused

```bash
# Verify ports are exposed
docker ps
netstat -tlnp | grep -E '443|4443'

# Test health endpoint
curl -k https://localhost:4443/health
```

### OAuth Not Working

1. Verify callback URL matches exactly
2. Check `INSTANTON_OAUTH_ALLOWED_DOMAINS` spelling
3. Ensure client secret has no trailing whitespace

---

## 🔧 Advanced Configuration

### Full docker-compose.yml

```yaml
services:
  instanton-server:
    image: ghcr.io/drruin/instanton-server:latest
    ports:
      - "443:443"
      - "4443:4443"
      - "9090:9090"
    environment:
      - INSTANTON_DOMAIN=${INSTANTON_DOMAIN}
      - INSTANTON_REQUEST_TIMEOUT=0
      - INSTANTON_OAUTH_PROVIDER=${INSTANTON_OAUTH_PROVIDER:-}
      - INSTANTON_OAUTH_CLIENT_ID=${INSTANTON_OAUTH_CLIENT_ID:-}
      - INSTANTON_OAUTH_CLIENT_SECRET=${INSTANTON_OAUTH_CLIENT_SECRET:-}
      - INSTANTON_OAUTH_ALLOWED_DOMAINS=${INSTANTON_OAUTH_ALLOWED_DOMAINS:-}
    volumes:
      - ./certs:/certs:ro
    restart: unless-stopped
```

### Certbot Auto-Renewal

```bash
# Create renewal hook to update certs
sudo nano /etc/letsencrypt/renewal-hooks/deploy/instanton.sh
```

```bash
#!/bin/bash
cp /etc/letsencrypt/live/tunnel.yourdomain.com/fullchain.pem /path/to/instanton/certs/cert.pem
cp /etc/letsencrypt/live/tunnel.yourdomain.com/privkey.pem /path/to/instanton/certs/key.pem
docker restart instanton-server
```

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/instanton.sh
```

### Production Checklist

- [ ] DNS A record pointing to VPS IP
- [ ] Certbot certificates obtained
- [ ] Auto-renewal hook configured
- [ ] OAuth configured with allowed domains
- [ ] `.env` added to `.gitignore`
- [ ] Monitoring enabled
- [ ] Firewall allows 443, 4443

---

<p align="center">
  <sub>Life's too short for port forwarding.</sub>
</p>
