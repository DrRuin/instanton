# Changelog

All notable changes to Instanton will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-06

### Added
- Initial release of Instanton
- HTTP/HTTPS tunnel support with automatic subdomain generation
- TCP tunnel support for raw TCP connections
- UDP tunnel support for UDP traffic
- WebSocket transport with automatic reconnection
- QUIC (HTTP/3) transport with connection migration
- Python SDK with async/await support
- CLI with rich terminal output
- Request inspector for debugging
- Webhook verification for GitHub, Stripe, Slack, Discord, and more
- Rate limiting with multiple algorithms
- DDoS protection with IP reputation tracking
- Load balancing with 9 different algorithms
- High availability with automatic failover
- Zero trust security model
- mTLS support
- Certificate management with auto-renewal
- Prometheus metrics export
- OpenTelemetry tracing integration
- Docker support with multi-stage builds
- Kubernetes deployment with Helm charts
- Comprehensive test suite (1009 tests)

### Security
- TLS 1.3 support
- Automatic certificate generation
- Request sanitization
- IP-based access control
- Rate limiting per IP and global

[Unreleased]: https://github.com/DrRuin/instanton/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DrRuin/instanton/releases/tag/v0.1.0
