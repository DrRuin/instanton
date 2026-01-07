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
  -p 8443:8443 \
  -p 9090:9090 \
  -v ./certs:/certs:ro \
  instanton/instanton-server \
  --domain tunnel.example.com
```

## Docker Compose

For a complete setup with monitoring, use the docker-compose.yml in the project root:

```bash
# Start relay server only
docker-compose up -d instanton-server

# Start with monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d

# Start with example app
docker-compose --profile example up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INSTANTON_DOMAIN` | Domain for the relay server | `localhost` |
| `INSTANTON_LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |
| `INSTANTON_AUTH_TOKEN` | Authentication token for clients | - |
| `INSTANTON_SERVER` | Relay server address (for client) | `instanton.dev:443` |

### Volumes

| Path | Description |
|------|-------------|
| `/certs` | TLS certificates (cert.pem, key.pem) |
| `/data` | Persistent data storage |

### Ports

| Port | Description |
|------|-------------|
| 443 | HTTPS (public traffic) |
| 8443 | Control plane (tunnel clients connect here) |
| 9090 | Prometheus metrics |

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
