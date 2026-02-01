<p align="center">
  <img src="https://raw.githubusercontent.com/DrRuin/instanton/main/instanton_logo.png" alt="Instanton" width="100%"/>
</p>

<p align="center">
  <a href="https://pypi.org/project/instanton/"><img src="https://img.shields.io/pypi/v/instanton.svg?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9" alt="PyPI"/></a>
  <a href="https://pypi.org/project/instanton/"><img src="https://img.shields.io/pypi/pyversions/instanton.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
  <a href="https://github.com/DrRuin/instanton/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge" alt="License"/></a>
  <a href="https://github.com/DrRuin/instanton/stargazers"><img src="https://img.shields.io/github/stars/DrRuin/instanton?style=for-the-badge&logo=github&color=yellow" alt="Stars"/></a>
</p>

<h1 align="center">⚡ Tunnel through barriers, instantly</h1>

<p align="center">
  <strong>Expose localhost to the internet. One command. Zero bullshit.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/QUIC-Enabled-blueviolet?style=flat-square&logo=curl" alt="QUIC"/>
  <img src="https://img.shields.io/badge/HTTP%2F3-Ready-blue?style=flat-square" alt="HTTP/3"/>
  <img src="https://img.shields.io/badge/TLS%201.3-Secure-success?style=flat-square&logo=letsencrypt" alt="TLS"/>
  <img src="https://img.shields.io/badge/Self--Hostable-Yes-orange?style=flat-square&logo=docker" alt="Self-Host"/>
</p>

<br/>

<p align="center">

```bash
pip install instanton && instanton --port 8000
```

</p>

<br/>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-python-sdk">SDK</a> •
  <a href="#-self-host">Self-Host</a> •
  <a href="#-contributing">Contributing</a>
</p>

<br/>

---

<br/>

## 🎯 The Problem

<table>
<tr>
<td width="50%">

### ❌ The Old Way

```
✗ Port forwarding
✗ Firewall rules
✗ Dynamic DNS
✗ SSL certificates
✗ Nginx configs
✗ Hours of debugging
```

</td>
<td width="50%">

### ✅ The Instanton Way

```bash
instanton --port 8000
```

**That's it.** Public HTTPS URL. Instant.

</td>
</tr>
</table>

<br/>

---

<br/>

## 🚀 Quick Start

```bash
pip install instanton
```

```bash
instanton --port 8000
```

<p align="center">
<img width="600" src="https://img.shields.io/badge/Output-282a36?style=for-the-badge" alt=""/>
</p>

```
  ╭──────────────────────────────────────────────────────────────╮
  │                                                              │
  │   Instanton v1.0.0                                           │
  │                                                              │
  │   ✓ Tunnel established!                                      │
  │                                                              │
  │   🌐 Public URL:   https://abc123.instanton.tech             │
  │   🔗 Forwarding:   → localhost:8000                          │
  │                                                              │
  │   Press Ctrl+C to stop                                       │
  │                                                              │
  ╰──────────────────────────────────────────────────────────────╯
```

<br/>

---

<br/>

## ✨ Features

<p align="center">
  <img src="https://img.shields.io/badge/5ms-Latency-blue?style=for-the-badge" alt="Latency"/>
  <img src="https://img.shields.io/badge/1.2_Gbps-Throughput-blue?style=for-the-badge" alt="Throughput"/>
  <img src="https://img.shields.io/badge/10K+-Concurrent-green?style=for-the-badge" alt="Concurrent"/>
  <img src="https://img.shields.io/badge/0--RTT-Resumption-purple?style=for-the-badge" alt="0-RTT"/>
</p>

<br/>

<table>
<tr>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-Transport-000?style=for-the-badge" alt="Transport"/>
<br/><br/>
<code>QUIC</code><br/>
<code>HTTP/3</code><br/>
<code>WebTransport</code><br/>
<code>WebSocket</code>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-Protocols-000?style=for-the-badge" alt="Protocols"/>
<br/><br/>
<code>HTTP</code><br/>
<code>TCP</code><br/>
<code>UDP</code><br/>
<code>gRPC</code>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-Performance-000?style=for-the-badge" alt="Performance"/>
<br/><br/>
<code>BBR</code><br/>
<code>0-RTT</code><br/>
<code>Streaming</code><br/>
<code>LZ4/Zstd</code>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-Security-000?style=for-the-badge" alt="Security"/>
<br/><br/>
<code>TLS 1.3</code><br/>
<code>mTLS</code><br/>
<code>ACME</code><br/>
<code>Let's Encrypt</code>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-Reliability-000?style=for-the-badge" alt="Reliability"/>
<br/><br/>
<code>Auto-reconnect</code><br/>
<code>Migration</code><br/>
<code>Pooling</code><br/>
<code>Health checks</code>
</td>
</tr>
</table>

<br/>

---

<br/>

## 🆚 Public vs Self-Hosted

<table>
<tr>
<th width="30%"></th>
<th width="35%" align="center">☁️ Public<br/><sub>instanton.tech</sub></th>
<th width="35%" align="center">🏠 Self-Hosted<br/><sub>Your infrastructure</sub></th>
</tr>
<tr><td><strong>💰 Price</strong></td><td align="center"><code>Free</code></td><td align="center"><code>Free</code></td></tr>
<tr><td><strong>⚡ Setup</strong></td><td align="center"><code>Instant</code></td><td align="center"><code>5 min</code></td></tr>
<tr><td><strong>🔐 Auth</strong></td><td align="center">—</td><td align="center">OAuth + Basic</td></tr>
<tr><td><strong>📊 Dashboard</strong></td><td align="center">—</td><td align="center">✓ Real-time</td></tr>
<tr><td><strong>📈 Metrics</strong></td><td align="center">—</td><td align="center">✓ Prometheus</td></tr>
<tr><td><strong>🚦 Rate Limits</strong></td><td align="center">Fair use</td><td align="center">Configurable</td></tr>
<tr><td><strong>🛡️ IP Restrict</strong></td><td align="center">—</td><td align="center">✓ Allow/Deny</td></tr>
<tr><td><strong>🌐 Custom Domain</strong></td><td align="center">DNS only</td><td align="center">Full control</td></tr>
<tr><td><strong>⏱️ Timeouts</strong></td><td align="center">~2 min</td><td align="center">Unlimited</td></tr>
<tr><td><strong>🔢 Tunnel Limits</strong></td><td align="center">Fair use</td><td align="center">Per-IP config</td></tr>
<tr><td><strong>💾 Data</strong></td><td align="center">Shared</td><td align="center">Your servers</td></tr>
<tr><td><strong>🔒 TLS</strong></td><td align="center">Managed</td><td align="center">You control</td></tr>
</table>

<p align="center">
  <sub><strong>OAuth:</strong> GitHub • Google • Okta • Auth0 • Azure AD • Keycloak</sub>
</p>

<br/>

---

<br/>

## 💡 Use Cases

<table>
<tr>
<td align="center" width="20%">
<h3>🪝</h3>
<strong>Webhooks</strong><br/>
<sub>Stripe, GitHub, Twilio</sub>
</td>
<td align="center" width="20%">
<h3>🎬</h3>
<strong>Demos</strong><br/>
<sub>Share without deploying</sub>
</td>
<td align="center" width="20%">
<h3>📱</h3>
<strong>Mobile</strong><br/>
<sub>Test on real devices</sub>
</td>
<td align="center" width="20%">
<h3>🤖</h3>
<strong>AI/ML</strong><br/>
<sub>Long-running inference</sub>
</td>
<td align="center" width="20%">
<h3>🎮</h3>
<strong>Gaming</strong><br/>
<sub>UDP game servers</sub>
</td>
</tr>
</table>

<br/>

---

<br/>

## 🐍 Python SDK

```python
import instanton

async with await instanton.forward(8000) as tunnel:
    print(f"🌐 Live at: {tunnel.url}")
    await your_app.run()
```

<p align="center">
  <sub>Async-first. Context-managed. Zero config.</sub>
</p>

<br/>

---

<br/>

## 🐳 Self-Host

```bash
# Get certs with Certbot (recommended)
sudo certbot certonly --standalone -d tunnel.yourdomain.com
mkdir -p certs
sudo cp /etc/letsencrypt/live/tunnel.yourdomain.com/{fullchain.pem,privkey.pem} certs/
sudo mv certs/fullchain.pem certs/cert.pem && sudo mv certs/privkey.pem certs/key.pem

# Run the server
docker run -d -p 443:443 -p 4443:4443 -v ./certs:/certs:ro -e INSTANTON_DOMAIN=tunnel.yourdomain.com ghcr.io/drruin/instanton-server
```

<p align="center">
  <sub>Full guide: <a href="deploy/docker/README.md">deploy/docker/README.md</a></sub>
</p>

<br/>

---

<br/>

## 🔌 TCP & UDP

<table>
<tr>
<td width="33%">

```bash
# 🗄️ Database
instanton tcp 5432
```

</td>
<td width="33%">

```bash
# 🎮 Game Server
instanton udp 27015
```

</td>
<td width="33%">

```bash
# 🔐 SSH
instanton tcp 22
```

</td>
</tr>
</table>

<br/>

---

<br/>

## ⏳ Long-Running APIs

```bash
# AI inference, video streaming — no timeout
instanton --port 8000 --no-request-timeout
```

<p align="center">
  <sub>Perfect for LLM inference, video processing, and streaming endpoints.</sub>
</p>

<br/>

---

<br/>

## 🤝 Contributing

```bash
git clone https://github.com/DrRuin/instanton.git
cd instanton && pip install -e ".[dev]"
pytest tests/ -v
```

<p align="center">
  <a href="https://github.com/DrRuin/instanton/issues">Report Bug</a> •
  <a href="https://github.com/DrRuin/instanton/issues">Request Feature</a> •
  <a href="https://github.com/DrRuin/instanton/pulls">Submit PR</a>
</p>

<br/>

---

<br/>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="MIT License"/></a>
</p>

<p align="center">
  <strong>Life's too short for port forwarding.</strong>
</p>

<p align="center">
  <sub>Made with ❤️ by <a href="https://github.com/DrRuin">DrRuin</a></sub>
</p>
