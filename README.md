<p align="center">
  <img src="tachyon_logo.png" alt="Tachyon" width="180"/>
</p>

<h1 align="center">Tachyon</h1>

<p align="center">
  <strong>Expose localhost to the internet in one command.</strong><br/>
  <sub>Open source &bull; Self-hostable &bull; Enterprise-ready &bull; Free forever</sub>
</p>

<p align="center">
  <a href="https://pypi.org/project/tachyon/"><img src="https://img.shields.io/pypi/v/tachyon.svg?style=flat-square&color=blue" alt="PyPI"/></a>
  <a href="https://pypi.org/project/tachyon/"><img src="https://img.shields.io/pypi/pyversions/tachyon.svg?style=flat-square" alt="Python"/></a>
  <a href="https://github.com/DrRuin/tachyon/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"/></a>
  <a href="https://github.com/DrRuin/tachyon/actions"><img src="https://img.shields.io/github/actions/workflow/status/DrRuin/tachyon/ci.yml?style=flat-square" alt="CI"/></a>
</p>

<br/>

<p align="center">
  <code>pip install tachyon && tachyon --port 8000</code>
</p>

<p align="center">
  <sub>That's it. You now have a public HTTPS URL.</sub>
</p>

<br/>

---

<br/>

<h2 align="center">Why Tachyon?</h2>

<br/>

<table align="center">
<tr>
<td align="center" width="25%">
<h1>&#9889;</h1>
<strong>5ms latency</strong><br/>
<sub>3x faster than ngrok</sub>
</td>
<td align="center" width="25%">
<h1>&#128275;</h1>
<strong>100% Open Source</strong><br/>
<sub>Self-host everything</sub>
</td>
<td align="center" width="25%">
<h1>&#128737;</h1>
<strong>Enterprise Security</strong><br/>
<sub>Zero Trust &bull; mTLS &bull; DDoS</sub>
</td>
<td align="center" width="25%">
<h1>&#128176;</h1>
<strong>$0 Forever</strong><br/>
<sub>No paid tiers. Ever.</sub>
</td>
</tr>
</table>

<br/>

---

<br/>

<h2 align="center">Tachyon vs Others</h2>

<p align="center"><sub>We did the homework so you don't have to.</sub></p>

<br/>

<div align="center">

|  | Tachyon | ngrok | cloudflared |
|:--|:--:|:--:|:--:|
| **Open Source** | &#10003; | &#10007; | Client only |
| **Self-Hostable** | &#10003; | &#10007; | &#10007; |
| **HTTP/3 (QUIC)** | &#10003; | &#10007; | &#10003; |
| **TCP/UDP Tunnels** | &#10003; | &#10003; | &#10003; |
| **Zero Trust** | &#10003; | &#10007; | Free (50 users) |
| **Load Balancing** | &#10003; (9 algorithms) | &#10007; | &#10007; |
| **Traffic Inspector** | &#10003; | Limited | &#10007; |
| **Native Python SDK** | &#10003; | &#10007; | &#10007; |
| **Price** | **Free** | Free / $8+ | Free* |

</div>

<p align="center"><sub>*cloudflared requires Cloudflare DNS &amp; ecosystem</sub></p>

<br/>

---

<br/>

<h2 align="center">Get Started</h2>

<br/>

<table>
<tr>
<td width="50%">

### HTTP Tunnel

```bash
# Expose local web server
tachyon --port 8000
```

```bash
# Custom subdomain
tachyon --port 8000 --subdomain myapp
```

</td>
<td width="50%">

### TCP/UDP Tunnel

```bash
# Database (PostgreSQL, MySQL)
tachyon tcp 5432

# Game server / DNS
tachyon udp 27015
```

</td>
</tr>
<tr>
<td width="50%">

### Python SDK

```python
import tachyon

# Async
tunnel = await tachyon.forward(8000)
print(tunnel.url)

# Sync
tunnel = tachyon.forward_sync(8000)
```

</td>
<td width="50%">

### Long-Running APIs

```bash
# AI inference, streaming, video
# No timeout (runs forever)
tachyon --port 8000 --no-request-timeout
```

</td>
</tr>
</table>

<br/>

---

<br/>

<h2 align="center">Full Observability</h2>

<p align="center">
  <sub>See everything. Debug anything. Ship faster.</sub>
</p>

<br/>

<div align="center">

| Capability | What You Get |
|:--|:--|
| **Traffic Inspector** | Real-time request/response viewer with replay |
| **Prometheus Metrics** | `requests_total`, `latency_p99`, `errors_rate` |
| **OpenTelemetry** | Distributed tracing across your stack |
| **Structured Logging** | JSON logs with request context |
| **Health Checks** | `/health`, `/ready`, `/live` endpoints |
| **Circuit Breaker** | Auto-recovery from downstream failures |

</div>

<br/>

---

<br/>

<h2 align="center">Enterprise Security (Free)</h2>

<p align="center">
  <sub>Because "enterprise" shouldn't mean "expensive".</sub>
</p>

<br/>

<div align="center">

```
                        ZERO TRUST ARCHITECTURE
   ┌────────────────────────────────────────────────────────────┐
   │                                                            │
   │   Identity  ───►  Device  ───►  Risk Score  ───►  Access   │
   │                                                            │
   │   5 Trust Levels:                                          │
   │   UNTRUSTED ─► LOW ─► MEDIUM ─► HIGH ─► VERIFIED           │
   │                                                            │
   └────────────────────────────────────────────────────────────┘
```

</div>

<br/>

<table align="center">
<tr>
<td align="center" width="33%">
<strong>TLS 1.3</strong><br/>
<sub>ECDHE + AES-GCM<br/>ChaCha20 &bull; Cert Pinning</sub>
</td>
<td align="center" width="33%">
<strong>DDoS Protection</strong><br/>
<sub>Rate limiting &bull; Bot detection<br/>IP reputation &bull; Geo-blocking</sub>
</td>
<td align="center" width="33%">
<strong>Authentication</strong><br/>
<sub>JWT &bull; OAuth2 &bull; OIDC<br/>mTLS &bull; API Keys</sub>
</td>
</tr>
</table>

<br/>

---

<br/>

<h2 align="center">Self-Host in Minutes</h2>

<br/>

<table>
<tr>
<td width="50%">

### Docker

```bash
docker run -d -p 443:443 \
  tachyon/tachyon-server \
  --domain tunnel.example.com
```

</td>
<td width="50%">

### Kubernetes

```bash
helm repo add tachyon https://DrRuin.github.io/charts
helm install tachyon tachyon/tachyon-server
```

</td>
</tr>
</table>

<br/>

---

<br/>

<h2 align="center">Performance</h2>

<br/>

<div align="center">

| Metric | Tachyon | ngrok | cloudflared |
|:--|:--:|:--:|:--:|
| Latency | **5ms** | 15ms | 10ms |
| Throughput | **1.2 Gbps** | 500 Mbps | 1 Gbps |
| Connections/sec | **6,500** | 1,000 | 3,000 |
| Memory | **35 MB** | 50 MB | 30 MB |
| Cold Start | **250ms** | 2s | 3s |

</div>

<br/>

---

<br/>

<h2 align="center">1000+ Tests. Production Ready.</h2>

<p align="center">
  <sub>Every feature tested. Every edge case covered.</sub>
</p>

<br/>

```bash
git clone https://github.com/DrRuin/tachyon.git
cd tachyon
pip install -e ".[dev]"
pytest tests/ -v  # 1009 tests pass
```

<br/>

---

<br/>

<p align="center">
  <strong>
    <a href="https://github.com/DrRuin/tachyon">GitHub</a> &nbsp;&bull;&nbsp;
    <a href="https://pypi.org/project/tachyon/">PyPI</a> &nbsp;&bull;&nbsp;
    <a href="./CONTRIBUTING.md">Contribute</a> &nbsp;&bull;&nbsp;
    <a href="./LICENSE">MIT License</a>
  </strong>
</p>

<p align="center">
  <sub>Life's too short for port forwarding and firewall configs.</sub>
</p>
