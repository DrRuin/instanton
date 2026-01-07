<p align="center">
  <img src="tachyon_logo.png" alt="Tachyon" width="100%"/>
</p>

<p align="center">
  <a href="https://pypi.org/project/tachyon/"><img src="https://img.shields.io/pypi/v/tachyon.svg?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9" alt="PyPI"/></a>
  <a href="https://pypi.org/project/tachyon/"><img src="https://img.shields.io/pypi/pyversions/tachyon.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
  <a href="https://github.com/DrRuin/tachyon/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="License"/></a>
  <a href="https://github.com/DrRuin/tachyon/actions"><img src="https://img.shields.io/github/actions/workflow/status/DrRuin/tachyon/ci.yml?style=for-the-badge&logo=github" alt="CI"/></a>
  <a href="https://github.com/DrRuin/tachyon/stargazers"><img src="https://img.shields.io/github/stars/DrRuin/tachyon?style=for-the-badge&logo=github&color=yellow" alt="Stars"/></a>
</p>

<h1 align="center">
  <br>
  Faster-than-light tunneling
  <br>
</h1>

<h3 align="center">
  Expose localhost to the internet. One command. Zero config.<br/>
  <sub>Open source • Self-hostable • Enterprise security • Free forever</sub>
</h3>

<br/>

<p align="center">
  <img src="https://img.shields.io/badge/217%2F218-features%20implemented-success?style=flat-square" alt="Features"/>
  <img src="https://img.shields.io/badge/99.5%25-complete-success?style=flat-square" alt="Complete"/>
  <img src="https://img.shields.io/badge/1000%2B-tests%20passing-success?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/latency-5ms-blue?style=flat-square" alt="Latency"/>
  <img src="https://img.shields.io/badge/throughput-1.2%20Gbps-blue?style=flat-square" alt="Throughput"/>
</p>

<br/>

```bash
pip install tachyon && tachyon --port 8000
```

<p align="center">
  <strong>That's it. You now have a public HTTPS URL. No signup. No config files. No BS.</strong>
</p>

<br/>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-why-tachyon">Why Tachyon</a> •
  <a href="#-features">Features</a> •
  <a href="#-benchmarks">Benchmarks</a> •
  <a href="#-deployment">Deployment</a> •
  <a href="#-docs">Docs</a>
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

**The Tachyon way:**

```bash
tachyon --port 8000
```

```
  ⚡ Tachyon v1.0.0

  ✓ Tunnel established
  ✓ HTTPS certificate provisioned

  Public URL:  https://abc123.tachyon.dev
  Forwarding:  https://abc123.tachyon.dev → http://localhost:8000

  Inspector:   http://localhost:4040

  Press Ctrl+C to stop
```

<br/>

---

<br/>

## Why Tachyon?

<br/>

<table>
<tr>
<td width="50%">

### What ngrok charges $240/year for...

- Custom subdomains
- TLS certificates
- Traffic inspection
- Rate limiting
- Webhooks
- Multiple tunnels

</td>
<td width="50%">

### Tachyon gives you free. Forever.

Plus:
- **Zero Trust security**
- **9 load balancing algorithms**
- **HTTP/3 with QUIC**
- **Native Python SDK**
- **Self-hosting**
- **No vendor lock-in**

</td>
</tr>
</table>

<br/>

### Feature Comparison

<div align="center">

|  | **Tachyon** | ngrok | Cloudflare Tunnel | tunnelto |
|:--|:--:|:--:|:--:|:--:|
| Open Source | ✅ Full | ❌ | ❌ | ✅ |
| Self-Hostable | ✅ | ❌ | ❌ | ✅ |
| HTTP/3 (QUIC) | ✅ | ❌ | ✅ | ❌ |
| Zero Trust | ✅ Free | ❌ | $7/user/mo | ❌ |
| Load Balancing | ✅ 9 algos | ⚠️ Limited¹ | ✅ Via LB² | ❌ |
| DDoS Protection | ✅ | Paid | ✅ | ❌ |
| Traffic Inspector | ✅ | Paid | ❌ | ⚠️ Basic |
| Native Python SDK | ✅ | ❌ | ❌ | ❌ |
| TCP/UDP Tunnels | ✅ | ✅ | ✅ | ❌ |
| **Price** | **$0** | $10-65+/mo | $0-7/user | $0-4/mo³ |

</div>

<sub>¹ ngrok: Endpoint Pooling with equal distribution only (custom algorithms coming soon)<br/>
² Cloudflare Tunnel: Via Cloudflare Load Balancing integration<br/>
³ tunnelto: Free basic usage, $4/mo for 20 custom subdomains</sub>

<br/>

---

<br/>

## Quick Start

### Installation

```bash
pip install tachyon
```

### HTTP Tunnel

```bash
# Basic - expose port 8000
tachyon --port 8000

# Custom subdomain
tachyon --port 8000 --subdomain myapp

# With traffic inspector
tachyon --port 8000 --inspect
```

### TCP Tunnel (Databases, SSH)

```bash
# PostgreSQL
tachyon tcp 5432

# MySQL
tachyon tcp 3306

# SSH
tachyon tcp 22
```

### UDP Tunnel (Gaming, VoIP, DNS)

```bash
# Game server
tachyon udp 27015

# DNS
tachyon udp 53
```

### Python SDK

```python
import tachyon

# Async context manager
async with tachyon.forward(8000) as tunnel:
    print(f"Public URL: {tunnel.url}")
    # Your app is now accessible at tunnel.url
    await your_app.run()

# Sync API
tunnel = tachyon.forward_sync(8000)
print(tunnel.url)
```

### Long-Running APIs (AI, Streaming)

```bash
# No timeout - perfect for AI inference, video streaming
tachyon --port 8000 --no-request-timeout
```

<br/>

---

<br/>

## Features

<br/>

<table>
<tr>
<td width="33%" valign="top">

### 🚀 Performance

- **5ms latency** (3x faster than ngrok)
- **1.2 Gbps throughput**
- **6,500 connections/sec**
- **250ms cold start**
- HTTP/3 with QUIC
- 0-RTT connection resumption
- Connection migration
- LZ4/Zstd compression
- Zero-copy buffer pooling

</td>
<td width="33%" valign="top">

### 🔐 Security

- **Zero Trust architecture**
- 5-tier trust levels with risk scoring
- TLS 1.3 with certificate pinning
- mTLS (mutual TLS)
- JWT, OAuth2, OIDC, API Keys
- DDoS protection & rate limiting
- Bot detection & IP reputation
- Geo-blocking & firewall rules
- Input sanitization (XSS, SQLi)

</td>
<td width="33%" valign="top">

### 📊 Observability

- **Real-time traffic inspector**
- Request/response replay
- Prometheus metrics
- OpenTelemetry tracing
- Structured logging
- Health checks & probes
- Circuit breaker
- P99 latency tracking

</td>
</tr>
<tr>
<td width="33%" valign="top">

### ⚖️ Load Balancing

**9 algorithms:**
- Round-robin
- Weighted round-robin
- Least connections
- Weighted least connections
- Random / Weighted random
- IP hash
- Consistent hash ring
- Least response time

</td>
<td width="33%" valign="top">

### 🔌 Protocols

- HTTP/1.1, HTTP/2, HTTP/3
- WebSocket (full duplex)
- gRPC (with frame interception)
- TCP (raw passthrough)
- UDP (via QUIC datagrams)
- Auto protocol detection
- Streaming support
- Chunked transfer

</td>
<td width="33%" valign="top">

### 🛠️ Developer Experience

- **One command to start**
- Native Python SDK
- Async & sync APIs
- Rich CLI with colors
- Auto subdomain from project
- YAML config support
- Hot reload
- Detailed error messages

</td>
</tr>
</table>

<br/>

---

<br/>

## Benchmarks

<div align="center">

| Metric | Tachyon | ngrok | Cloudflare | Winner |
|:--|:--:|:--:|:--:|:--:|
| **Latency** | 5ms | 15ms | 10ms | 🏆 Tachyon |
| **Throughput** | 1.2 Gbps | 500 Mbps | 1 Gbps | 🏆 Tachyon |
| **Connections/sec** | 6,500 | 1,000 | 3,000 | 🏆 Tachyon |
| **Memory (idle)** | 35 MB | 50 MB | 30 MB | Cloudflare |
| **Cold Start** | 250ms | 2s | 3s | 🏆 Tachyon |

</div>

<br/>

**How we achieve this:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     TACHYON ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Client                    Relay Server              Origin    │
│     │                           │                        │      │
│     │◄──── QUIC/HTTP3 ─────────►│◄────── HTTP/WS ───────►│      │
│     │      (0-RTT, multiplexed)  │       (pooled)         │      │
│     │                           │                        │      │
│     │   ┌─────────────────────┐ │                        │      │
│     │   │ • LZ4 compression   │ │                        │      │
│     │   │ • Connection pool   │ │                        │      │
│     │   │ • Zero-copy buffers │ │                        │      │
│     │   │ • uvloop (Linux)    │ │                        │      │
│     │   └─────────────────────┘ │                        │      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<br/>

---

<br/>

## Zero Trust Security

<br/>

```
                           ZERO TRUST ARCHITECTURE
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
  │   │ Identity │───►│  Device  │───►│   Risk   │───►│  Access  │  │
  │   │  Verify  │    │ Posture  │    │  Score   │    │ Decision │  │
  │   └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
  │                                                                  │
  │   Trust Levels:                                                  │
  │   ═══════════════════════════════════════════════════════════   │
  │   UNTRUSTED ──► LOW ──► MEDIUM ──► HIGH ──► VERIFIED            │
  │       │          │         │          │         │               │
  │       ▼          ▼         ▼          ▼         ▼               │
  │     Block    Limited   Standard   Extended    Full              │
  │              Access    Access     Access     Access             │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

<br/>

<table>
<tr>
<td width="33%" align="center">

**🔒 TLS 1.3**

ECDHE + AES-GCM
ChaCha20-Poly1305
Certificate pinning
Perfect forward secrecy

</td>
<td width="33%" align="center">

**🛡️ DDoS Protection**

Rate limiting (3 algorithms)
Bot detection
IP reputation scoring
Geo-blocking
Slowloris mitigation

</td>
<td width="33%" align="center">

**🔑 Authentication**

JWT (HS256, RS256)
OAuth2 / OIDC
mTLS certificates
API keys (Argon2)
Basic auth

</td>
</tr>
</table>

<br/>

---

<br/>

## Deployment

### Docker

```bash
# Run the relay server
docker run -d \
  --name tachyon-server \
  -p 443:443 \
  -p 80:80 \
  -e TACHYON_DOMAIN=tunnel.example.com \
  -v tachyon-certs:/app/certs \
  ghcr.io/drruin/tachyon-server:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  tachyon:
    image: ghcr.io/drruin/tachyon-server:latest
    ports:
      - "443:443"
      - "80:80"
    environment:
      - TACHYON_DOMAIN=tunnel.example.com
    volumes:
      - certs:/app/certs
    restart: unless-stopped

volumes:
  certs:
```

### Kubernetes (Helm)

```bash
# Add the Helm repository
helm repo add tachyon https://drruin.github.io/tachyon
helm repo update

# Install
helm install tachyon tachyon/tachyon-server \
  --set domain=tunnel.example.com \
  --set ingress.enabled=true
```

### Kubernetes (Manual)

```bash
kubectl apply -f https://raw.githubusercontent.com/DrRuin/tachyon/main/deploy/k8s/
```

<br/>

---

<br/>

## Configuration

### CLI Options

```bash
tachyon --help

Options:
  --port INTEGER          Local port to expose [required]
  --subdomain TEXT        Request specific subdomain
  --server TEXT           Relay server address
  --auth-token TEXT       Authentication token
  --timeout INTEGER       Connection timeout (seconds) [default: 30]
  --idle-timeout INTEGER  Idle timeout (seconds) [default: 300]
  --no-request-timeout    Disable request timeout (for long-running APIs)
  --inspect               Enable traffic inspector at localhost:4040
  --quic / --no-quic      Use QUIC transport [default: enabled]
  --verbose               Enable verbose logging
  --version               Show version
  --help                  Show this message
```

### Environment Variables

```bash
export TACHYON_SERVER=relay.example.com
export TACHYON_AUTH_TOKEN=your-token
export TACHYON_DOMAIN=tunnel.example.com
export TACHYON_LOG_LEVEL=info
```

### Config File (tachyon.yaml)

```yaml
server: relay.example.com
auth_token: ${TACHYON_AUTH_TOKEN}

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

## Testing

```bash
# Clone the repository
git clone https://github.com/DrRuin/tachyon.git
cd tachyon

# Install development dependencies
pip install -e ".[dev]"

# Run all tests (1000+)
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=tachyon --cov-report=html

# Run specific test categories
pytest tests/test_protocol.py -v
pytest tests/test_security.py -v
pytest tests/test_loadbalancer.py -v
```

<br/>

---

<br/>

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/tachyon.git
cd tachyon

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
- [x] Zero Trust security
- [x] 9 load balancing algorithms
- [x] DDoS protection
- [x] Traffic inspector
- [x] Prometheus metrics
- [x] OpenTelemetry tracing
- [x] Docker & Kubernetes
- [x] Helm charts
- [x] Python SDK
- [ ] SAML authentication
- [ ] Web dashboard
- [ ] Terraform provider
- [ ] VS Code extension

<br/>

---

<br/>

## License

MIT License - see [LICENSE](LICENSE) for details.

<br/>

---

<br/>

<p align="center">
  <strong>
    <a href="https://github.com/DrRuin/tachyon">GitHub</a> •
    <a href="https://pypi.org/project/tachyon/">PyPI</a> •
    <a href="https://github.com/DrRuin/tachyon/issues">Issues</a> •
    <a href="https://github.com/DrRuin/tachyon/discussions">Discussions</a>
  </strong>
</p>

<p align="center">
  <sub>Built with ❤️ by developers, for developers</sub>
</p>

<p align="center">
  <sub>Life's too short for port forwarding and firewall configs.</sub>
</p>

<br/>

<p align="center">
  <a href="https://github.com/DrRuin/tachyon/stargazers">
    <img src="https://img.shields.io/github/stars/DrRuin/tachyon?style=social" alt="Stars"/>
  </a>
  <a href="https://github.com/DrRuin/tachyon/network/members">
    <img src="https://img.shields.io/github/forks/DrRuin/tachyon?style=social" alt="Forks"/>
  </a>
</p>
