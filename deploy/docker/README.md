# Instanton Docker Deployment

Quick start guide for running Instanton with Docker.

## Quick Start

### Run the Tunnel Client

```bash
# Connect to public relay
docker run --rm -it --network host instanton/instanton --port 8000

# With custom subdomain
docker run --rm -it --network host instanton/instanton --port 8000 --subdomain myapp
```

### Run the Relay Server (Self-Hosted)

```bash
docker run -d \
  -p 443:443 \
  -p 4443:4443 \
  -p 9090:9090 \
  -v ./certs:/certs:ro \
  instanton/instanton-server \
  --domain tunnel.example.com
```

## Docker Compose

> **IMPORTANT**: Use `docker compose` (V2, with space) instead of `docker-compose` (V1, with hyphen).
> The legacy docker-compose V1 has compatibility issues with newer Docker versions.

For a complete setup with monitoring, use the docker-compose.yml in the project root:

```bash
# Start relay server only
docker compose up -d instanton-server

# Start with monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Start with example app
docker compose --profile example up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INSTANTON_DOMAIN` | Domain for the relay server | `localhost` |
| `INSTANTON_LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |
| `INSTANTON_AUTH_TOKEN` | Authentication token for clients | - |
| `INSTANTON_SERVER` | Relay server address (for client) | `instanton.tech:4443` |
| `INSTANTON_REQUEST_TIMEOUT` | Request timeout in seconds (0=indefinite) | `120` |

### OAuth/OIDC Environment Variables (Self-Hosted)

| Variable | Description | Example |
|----------|-------------|---------|
| `INSTANTON_OAUTH_PROVIDER` | OAuth provider type | `github`, `google`, `oidc` |
| `INSTANTON_OAUTH_CLIENT_ID` | OAuth client ID | `Iv1.abc123...` |
| `INSTANTON_OAUTH_CLIENT_SECRET` | OAuth client secret | `secret123...` |
| `INSTANTON_OAUTH_ISSUER_URL` | OIDC issuer URL (required for `oidc` provider) | `https://accounts.google.com` |
| `INSTANTON_OAUTH_ALLOWED_DOMAINS` | Comma-separated allowed email domains | `mycompany.com,partner.com` |
| `INSTANTON_OAUTH_ALLOWED_EMAILS` | Comma-separated allowed emails | `admin@other.com` |
| `INSTANTON_OAUTH_SESSION_DURATION` | Session duration in seconds | `86400` (24 hours) |

### Volumes

| Path | Description |
|------|-------------|
| `/certs` | TLS certificates (cert.pem, key.pem) |
| `/data` | Persistent data storage |

### Ports

| Port | Description |
|------|-------------|
| 443 | HTTPS (public traffic) |
| 4443 | Control plane (tunnel clients connect here) |
| 9090 | Prometheus metrics |

## OAuth/OIDC Authentication (Self-Hosted)

Instanton supports OAuth 2.0 / OpenID Connect authentication for self-hosted deployments. This allows organizations to require users to authenticate via their identity provider before accessing tunneled services.

### Supported Providers

- **GitHub** - OAuth 2.0 (no OIDC discovery)
- **Google** - Full OIDC with discovery
- **Generic OIDC** - Any OIDC-compliant provider (Okta, Auth0, Keycloak, Azure AD, etc.)

### GitHub OAuth Setup

1. Go to GitHub > Settings > Developer settings > OAuth Apps > New OAuth App
2. Set Authorization callback URL to: `https://your-domain.com/_instanton/oauth/callback`
3. Copy the Client ID and Client Secret

```bash
# .env file
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=github
INSTANTON_OAUTH_CLIENT_ID=Iv1.abc123...
INSTANTON_OAUTH_CLIENT_SECRET=your-client-secret
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

```bash
docker compose up -d instanton-server
```

### Google OAuth Setup

1. Go to Google Cloud Console > APIs & Services > Credentials
2. Create OAuth 2.0 Client ID (Web application)
3. Add authorized redirect URI: `https://your-domain.com/_instanton/oauth/callback`
4. Copy the Client ID and Client Secret

```bash
# .env file
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=google
INSTANTON_OAUTH_CLIENT_ID=123456789.apps.googleusercontent.com
INSTANTON_OAUTH_CLIENT_SECRET=GOCSPX-...
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

### Generic OIDC Setup (Okta, Auth0, Keycloak)

```bash
# .env file for Okta
INSTANTON_DOMAIN=tunnel.mycompany.com
INSTANTON_OAUTH_PROVIDER=oidc
INSTANTON_OAUTH_ISSUER_URL=https://mycompany.okta.com
INSTANTON_OAUTH_CLIENT_ID=0oa...
INSTANTON_OAUTH_CLIENT_SECRET=...
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com
```

### Access Control

You can restrict access by email domain or specific emails:

```bash
# Allow only @mycompany.com emails
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com

# Allow multiple domains
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com,partner.com

# Allow specific emails
INSTANTON_OAUTH_ALLOWED_EMAILS=external-contractor@gmail.com

# If both are empty, all authenticated users are allowed
```

### Security Features

The OAuth implementation includes:

- **PKCE (S256)** - Proof Key for Code Exchange prevents authorization code interception
- **State Parameter** - CSRF protection with 5-minute expiration
- **Nonce Validation** - Replay attack protection for OIDC
- **JWT Signature Validation** - ID tokens validated using provider JWKS
- **Open Redirect Prevention** - Redirect URLs validated to same origin
- **Secure Cookies** - HttpOnly, Secure, SameSite=Lax
- **Email Verification** - Only verified emails accepted

## Building Images

```bash
# Build client image
docker build -t instanton/instanton -f Dockerfile .

# Build server image
docker build -t instanton/instanton-server -f Dockerfile.server .
```

## Health Checks

Both images include health checks:

- **Client**: Verifies Python import works
- **Server**: HTTP check on `/health` endpoint

## Prometheus Configuration

The `prometheus.yml` in this folder is pre-configured to scrape metrics from the Instanton server:

```yaml
scrape_configs:
  - job_name: 'instanton-server'
    static_configs:
      - targets: ['instanton-server:9090']
```

## Security Notes

- Both images run as non-root user `instanton`
- TLS certificates should be mounted read-only
- Use Docker secrets for sensitive configuration in production
- OAuth client secrets should never be committed to version control
- Use environment files (`.env`) and add them to `.gitignore`

## Example: Complete OAuth Deployment

Create a `.env` file:

```bash
# Domain configuration
INSTANTON_DOMAIN=tunnel.mycompany.com

# OAuth configuration (GitHub example)
INSTANTON_OAUTH_PROVIDER=github
INSTANTON_OAUTH_CLIENT_ID=Iv1.abc123
INSTANTON_OAUTH_CLIENT_SECRET=your-secret-here
INSTANTON_OAUTH_ALLOWED_DOMAINS=mycompany.com

# Optional: session duration (default 24 hours)
INSTANTON_OAUTH_SESSION_DURATION=86400
```

Run:

```bash
# Start with OAuth enabled
docker compose up -d instanton-server

# Check logs
docker compose logs -f instanton-server
```

Test:

1. Open `https://tunnel.mycompany.com` in browser
2. You'll be redirected to GitHub/Google/OIDC provider
3. After authentication, you'll have access to tunneled services
4. Session persists for 24 hours (configurable)
