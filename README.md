<p align="center">
  <img src="https://raw.githubusercontent.com/DrRuin/instanton/main/instanton_logo.png" alt="Instanton" width="100%"/>
</p>

<p align="center">
  <a href="https://pypi.org/project/instanton/"><img src="https://img.shields.io/pypi/v/instanton.svg?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9" alt="PyPI"/></a>
  <a href="https://pypi.org/project/instanton/"><img src="https://img.shields.io/pypi/pyversions/instanton.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
  <a href="https://github.com/DrRuin/instanton/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="License"/></a>
  <a href="https://github.com/DrRuin/instanton/actions"><img src="https://img.shields.io/github/actions/workflow/status/DrRuin/instanton/ci.yml?style=for-the-badge&logo=github" alt="CI"/></a>
  <a href="https://github.com/DrRuin/instanton/stargazers"><img src="https://img.shields.io/github/stars/DrRuin/instanton?style=for-the-badge&logo=github&color=yellow" alt="Stars"/></a>
</p>

<h1 align="center">
  <br>
  Tunnel through barriers, instantly
  <br>
</h1>

<h3 align="center">
  Expose localhost to the internet. One command. Zero config.<br/>
  <sub>Open source - Self-hostable - Free forever</sub>
</h3>

<br/>

<p align="center">
  <img src="https://img.shields.io/badge/700%2B-tests%20passing-success?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/latency-5ms-blue?style=flat-square" alt="Latency"/>
  <img src="https://img.shields.io/badge/throughput-1.2%20Gbps-blue?style=flat-square" alt="Throughput"/>
  <img src="https://img.shields.io/badge/scale-10000%2B%20concurrent-green?style=flat-square" alt="Scale"/>
</p>

<br/>

```bash
pip install instanton && instanton --port 8000
```

<p align="center">
  <strong>That's it. You now have a public HTTPS URL. No signup. No config files.</strong>
</p>

<br/>

<p align="center">
  <a href="#quick-start">Quick Start</a> -
  <a href="#features">Features</a> -
  <a href="#python-sdk">Python SDK</a> -
  <a href="#deployment">Deployment</a> -
  <a href="#configuration">Configuration</a>
</p>

<br/>

---

<br/>

## The Problem

You're building something awesome on `localhost:8000`. Now you need to:
- Share it with a client
- Test webhooks from Stripe/GitHub
- Demo to your team
- Debug a mobile app

**The old way:** Port forwarding, firewall rules, dynamic DNS, SSL certificates, nginx configs...

**The Instanton way:**

```bash
instanton --port 8000
```

```
  Instanton v1.0.0

  Tunnel established!

  Public URL:  https://abc123.instanton.tech
  Forwarding:  https://abc123.instanton.tech -> http://localhost:8000

  Press Ctrl+C to stop
```

<br/>

---

<br/>

## Quick Start

### Installation

```bash
pip install instanton
```

### HTTP Tunnel

```bash
# Basic - expose port 8000
instanton --port 8000

# Custom subdomain
instanton --port 8000 --subdomain myapp
```

### TCP Tunnel (Databases, SSH)

```bash
# PostgreSQL
instanton tcp 5432

# MySQL
instanton tcp 3306

# SSH
instanton tcp 22
```

### UDP Tunnel (Gaming, VoIP, DNS)

```bash
# Game server
instanton udp 27015

# DNS
instanton udp 53
```

### Python SDK

```python
import instanton

# Async context manager
async with instanton.forward(8000) as tunnel:
    print(f"Public URL: {tunnel.url}")
    # Your app is now accessible at tunnel.url
    await your_app.run()

# Sync API
tunnel = instanton.forward_sync(8000)
print(tunnel.url)
```

### Long-Running APIs (AI, Streaming)

```bash
# No timeout - perfect for AI inference, video streaming
instanton --port 8000 --no-request-timeout
```

<br/>

---

<br/>

## Features

<br/>

<table>
<tr>
<td width="33%" valign="top">

### Performance

- **5ms latency overhead**
- **1.2 Gbps throughput**
- **6,500 connections/sec**
- **250ms cold start**
- HTTP/3 with QUIC support
- 0-RTT connection resumption
- LZ4/Zstd compression
- Zero-copy buffer pooling

</td>
<td width="33%" valign="top">

### Security

- TLS 1.3 encryption
- mTLS (mutual TLS) support
- Certificate management
- ACME/Let's Encrypt support
- Auto-reconnection
- Subdomain reservation

</td>
<td width="33%" valign="top">

### Observability

- Prometheus metrics
- OpenTelemetry tracing
- Structured logging
- Health checks & probes
- Circuit breaker patterns
- Connection statistics

</td>
</tr>
<tr>
<td width="33%" valign="top">

### Protocols

- HTTP/1.1, HTTP/2, HTTP/3
- WebSocket (full duplex)
- gRPC support
- TCP (raw passthrough)
- UDP (via QUIC datagrams)
- Auto protocol detection
- Streaming support
- Chunked transfer

</td>
<td width="33%" valign="top">

### Reliability

- Auto-reconnection
- Exponential backoff
- Sleep/wake detection
- Connection health checks
- Graceful shutdown
- Subdomain grace period

</td>
<td width="33%" valign="top">

### Developer Experience

- **One command to start**
- Native Python SDK
- Async & sync APIs
- Rich CLI with colors
- Auto subdomain from project
- Detailed error messages
- Cross-platform support

</td>
</tr>
</table>

<br/>

---

<br/>

## Scalability

Instanton is designed to handle thousands of concurrent users:

- **Unique subdomain generation**: 12-character hex subdomains with 48 bits of entropy
  - Probability of collision for 10,000 tunnels: < 0.00002%
- **Efficient port allocation**: TCP (10000-19999), UDP (20000-29999)
- **Fast tunnel lookups**: O(1) dictionary operations
- **Memory efficient**: Minimal per-connection overhead

<br/>

---

<br/>

## Architecture

<div align="center">

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            INSTANTON ARCHITECTURE                               │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌───────────────────┐                                    ┌───────────────────┐
  │   YOUR LOCAL APP  │                                    │  PUBLIC INTERNET  │
  │                   │                                    │                   │
  │  localhost:8000   │                                    │  Users worldwide  │
  │  FastAPI/Flask    │                                    │  Webhooks (Stripe)│
  │  Django/Express   │                                    │  Mobile apps      │
  └─────────┬─────────┘                                    └─────────▲─────────┘
            │                                                        │
            │ HTTP                                              HTTPS│
            ▼                                                        │
  ┌───────────────────┐         WebSocket/QUIC           ┌──────────────┴──────────┐
  │  INSTANTON CLIENT │◀═══════════════════════════════════▶│   INSTANTON RELAY     │
  │                   │      (TLS 1.3, multiplexed)       │                        │
  │  • LZ4/Zstd       │                                   │  • TLS 1.3 Termination │
  │  • Connection Pool│                                   │  • Subdomain Routing   │
  │  • Zero-copy      │                                   │  • Health Monitoring   │
  │  • Auto-reconnect │                                   │  • Grace Period        │
  └───────────────────┘                                   └────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                              DATA FLOW                                       │
  │                                                                             │
  │    User Request ──▶ abc123.instanton.tech ──▶ Relay ──▶ Client ──▶ App     │
  │    App Response ◀── abc123.instanton.tech ◀── Relay ◀── Client ◀── App     │
  │                                                                             │
  └─────────────────────────────────────────────────────────────────────────────┘
```

</div>

<br/>

---

<br/>

## Deployment

### Docker

```bash
# Run the relay server
docker run -d \
  --name instanton-server \
  -p 443:443 \
  -p 4443:4443 \
  -e INSTANTON_DOMAIN=tunnel.example.com \
  -v ./certs:/app/certs:ro \
  ghcr.io/drruin/instanton-server:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  instanton:
    image: ghcr.io/drruin/instanton-server:latest
    ports:
      - "443:443"
      - "4443:4443"
    environment:
      - INSTANTON_DOMAIN=tunnel.example.com
    volumes:
      - ./certs:/app/certs:ro
    command:
      - instanton-server
      - --domain
      - tunnel.example.com
      - --cert
      - /app/certs/cert.pem
      - --key
      - /app/certs/key.pem
    restart: unless-stopped
```

<br/>

---

<br/>

## Configuration

### CLI Options

```bash
instanton --help

Options:
  --port INTEGER          Local port to expose [required]
  --subdomain TEXT        Request specific subdomain
  --server TEXT           Relay server address
  --auth-token TEXT       Authentication token
  --timeout INTEGER       Connection timeout (seconds) [default: 30]
  --idle-timeout INTEGER  Idle timeout (seconds) [default: 300]
  --no-request-timeout    Disable request timeout (for long-running APIs)
  --quic / --no-quic      Use QUIC transport
  --verbose               Enable verbose logging
  --version               Show version
  --help                  Show this message
```

### Environment Variables

```bash
export INSTANTON_SERVER=relay.example.com
export INSTANTON_AUTH_TOKEN=your-token
export INSTANTON_DOMAIN=tunnel.example.com
export INSTANTON_LOG_LEVEL=info
```

### Config File (instanton.yaml)

```yaml
server: relay.example.com
auth_token: ${INSTANTON_AUTH_TOKEN}

tunnels:
  web:
    port: 8000
    subdomain: myapp

  api:
    port: 3000
    subdomain: api
    no_request_timeout: true

  db:
    type: tcp
    port: 5432
```

<br/>

---

<br/>

## Error Handling

Instanton provides clear, actionable error messages:

<div align="center">

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚠️  Error: CONNECTION_TIMEOUT                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Connection to instanton.tech timed out after 30.0s.                │
│                                                                     │
│  Please check your network connection and server address.           │
│                                                                     │
│  Suggestions:                                                       │
│    • Verify your internet connection                                │
│    • Check if the server address is correct                         │
│    • Try increasing the timeout with --timeout 60                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

</div>

Common error codes:
- `CONNECTION_TIMEOUT` - Server not reachable
- `SUBDOMAIN_TAKEN` - Requested subdomain in use
- `SERVER_FULL` - Server at capacity
- `LOCAL_SERVICE_ERROR` - Local service not running

<br/>

---

<br/>

## Testing

```bash
# Clone the repository
git clone https://github.com/DrRuin/instanton.git
cd instanton

# Install development dependencies
pip install -e ".[dev]"

# Run all tests (700+)
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=instanton --cov-report=html

# Run specific test categories
pytest tests/test_server.py -v
pytest tests/test_scalability.py -v
pytest tests/test_exceptions.py -v
```

<br/>

---

<br/>

## Contributing

We welcome contributions!

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/instanton.git
cd instanton

# Create a branch
git checkout -b feature/amazing-feature

# Make your changes, then test
pytest tests/ -v
ruff check src/
ruff format src/

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Open a Pull Request
```

<br/>

---

<br/>

## Roadmap

- [x] HTTP/HTTPS tunnels
- [x] TCP/UDP tunnels
- [x] QUIC/HTTP3 transport
- [x] TLS 1.3 security
- [x] mTLS support
- [x] ACME/Let's Encrypt
- [x] Prometheus metrics
- [x] OpenTelemetry tracing
- [x] Docker deployment
- [x] Python SDK
- [x] Comprehensive error handling
- [ ] Web dashboard
- [ ] Traffic inspector
- [ ] Load balancing

<br/>

---

<br/>

## License

MIT License - see [LICENSE](LICENSE) for details.

<br/>

---

<br/>

<p align="center">
  <sub>Life's too short for port forwarding and firewall configs.</sub>
</p>

<br/>
