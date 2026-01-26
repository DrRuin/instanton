"""Instanton Server - Main entry point."""

import asyncio

import click
from rich.console import Console

from instanton.core.config import ServerConfig
from instanton.server.relay import RelayServer

console = Console()

BANNER = """
██╗███╗   ██╗███████╗████████╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ██╗
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗  ██║
██║██╔██╗ ██║███████╗   ██║   ███████║██╔██╗ ██║   ██║   ██║   ██║██╔██╗ ██║
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╗██║
██║██║ ╚████║███████║   ██║   ██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚████║
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
                            RELAY SERVER
"""


@click.command()
@click.option("--domain", "-d", required=True, help="Base domain for tunnels")
@click.option("--https-bind", default="0.0.0.0:443", help="HTTPS bind address")
@click.option("--control-bind", default="0.0.0.0:4443", help="Control plane bind")
@click.option("--cert", envvar="INSTANTON_CERT_PATH", help="TLS certificate path")
@click.option("--key", envvar="INSTANTON_KEY_PATH", help="TLS private key path")
@click.option("--acme", is_flag=True, help="Enable Let's Encrypt")
@click.option("--acme-email", help="Email for Let's Encrypt")
@click.option("--max-tunnels", default=10000, help="Maximum concurrent tunnels")
@click.option(
    "--request-timeout",
    envvar="INSTANTON_REQUEST_TIMEOUT",
    type=float,
    default=120.0,
    help="Request timeout in seconds (0 for indefinite). Default: 120s",
)
@click.option(
    "--rate-limit",
    is_flag=True,
    default=False,
    help="Enable rate limiting per IP",
)
@click.option(
    "--rate-limit-rps",
    type=float,
    default=100.0,
    help="Requests per second limit (default: 100)",
)
@click.option(
    "--rate-limit-burst",
    type=int,
    default=10,
    help="Burst allowance above rate limit (default: 10)",
)
@click.option(
    "--ip-allow",
    multiple=True,
    help="Allow IP/CIDR (can repeat). Example: --ip-allow 10.0.0.0/8",
)
@click.option(
    "--ip-deny",
    multiple=True,
    help="Deny IP/CIDR (can repeat). Deny takes precedence. Example: --ip-deny 1.2.3.4",
)
@click.option(
    "--auth-user",
    envvar="INSTANTON_AUTH_USER",
    help="Username for basic authentication",
)
@click.option(
    "--auth-pass",
    envvar="INSTANTON_AUTH_PASS",
    help="Password for basic authentication",
)
@click.option(
    "--max-tunnels-per-ip",
    type=int,
    default=10,
    help="Maximum tunnels per IP address (default: 10)",
)
@click.option(
    "--tunnel-rate-limit",
    type=float,
    default=5.0,
    help="Max tunnel creations per minute per IP (default: 5)",
)
@click.option(
    "--tunnel-rate-burst",
    type=int,
    default=3,
    help="Burst allowance for tunnel creation (default: 3)",
)
@click.option(
    "--dashboard-user",
    envvar="INSTANTON_DASHBOARD_USER",
    help="Username for dashboard authentication (enables dashboard)",
)
@click.option(
    "--dashboard-password",
    envvar="INSTANTON_DASHBOARD_PASSWORD",
    help="Password for dashboard authentication (enables dashboard)",
)
@click.option(
    "--tcp-port-min",
    type=int,
    default=10000,
    envvar="INSTANTON_TCP_PORT_MIN",
    help="TCP tunnel port range start (default: 10000)",
)
@click.option(
    "--tcp-port-max",
    type=int,
    default=19999,
    envvar="INSTANTON_TCP_PORT_MAX",
    help="TCP tunnel port range end (default: 19999)",
)
@click.option(
    "--udp-port-min",
    type=int,
    default=20000,
    envvar="INSTANTON_UDP_PORT_MIN",
    help="UDP tunnel port range start (default: 20000)",
)
@click.option(
    "--udp-port-max",
    type=int,
    default=29999,
    envvar="INSTANTON_UDP_PORT_MAX",
    help="UDP tunnel port range end (default: 29999)",
)
@click.option(
    "--oauth-provider",
    type=click.Choice(["github", "google", "oidc"]),
    envvar="INSTANTON_OAUTH_PROVIDER",
    help="OAuth provider for authentication (self-hosted only)",
)
@click.option(
    "--oauth-client-id",
    envvar="INSTANTON_OAUTH_CLIENT_ID",
    help="OAuth client ID",
)
@click.option(
    "--oauth-client-secret",
    envvar="INSTANTON_OAUTH_CLIENT_SECRET",
    help="OAuth client secret",
)
@click.option(
    "--oauth-issuer-url",
    envvar="INSTANTON_OAUTH_ISSUER_URL",
    help="OIDC issuer URL for discovery (required for 'oidc' provider)",
)
@click.option(
    "--oauth-allowed-domain",
    multiple=True,
    envvar="INSTANTON_OAUTH_ALLOWED_DOMAINS",
    help="Allowed email domains (can be repeated)",
)
@click.option(
    "--oauth-allowed-email",
    multiple=True,
    envvar="INSTANTON_OAUTH_ALLOWED_EMAILS",
    help="Allowed specific emails (can be repeated)",
)
@click.option(
    "--oauth-session-duration",
    type=int,
    default=86400,
    envvar="INSTANTON_OAUTH_SESSION_DURATION",
    help="OAuth session duration in seconds (default: 86400 = 24h)",
)
def main(
    domain: str,
    https_bind: str,
    control_bind: str,
    cert: str | None,
    key: str | None,
    acme: bool,
    acme_email: str | None,
    max_tunnels: int,
    request_timeout: float,
    rate_limit: bool,
    rate_limit_rps: float,
    rate_limit_burst: int,
    ip_allow: tuple[str, ...],
    ip_deny: tuple[str, ...],
    auth_user: str | None,
    auth_pass: str | None,
    max_tunnels_per_ip: int,
    tunnel_rate_limit: float,
    tunnel_rate_burst: int,
    dashboard_user: str | None,
    dashboard_password: str | None,
    tcp_port_min: int,
    tcp_port_max: int,
    udp_port_min: int,
    udp_port_max: int,
    oauth_provider: str | None,
    oauth_client_id: str | None,
    oauth_client_secret: str | None,
    oauth_issuer_url: str | None,
    oauth_allowed_domain: tuple[str, ...],
    oauth_allowed_email: tuple[str, ...],
    oauth_session_duration: int,
):
    """Run the Instanton relay server."""
    console.print(BANNER, style="cyan")

    timeout_value = request_timeout if request_timeout > 0 else None

    ip_restrict_enabled = bool(ip_allow or ip_deny)
    auth_enabled = bool(auth_user and auth_pass)
    dashboard_enabled = bool(dashboard_user and dashboard_password)
    oauth_enabled = bool(oauth_provider and oauth_client_id and oauth_client_secret)

    config = ServerConfig(
        base_domain=domain,
        https_bind=https_bind,
        control_bind=control_bind,
        cert_path=cert,
        key_path=key,
        acme_enabled=acme,
        acme_email=acme_email,
        max_tunnels=max_tunnels,
        request_timeout=timeout_value,
        rate_limit_enabled=rate_limit,
        rate_limit_rps=rate_limit_rps,
        rate_limit_burst=rate_limit_burst,
        ip_restrict_enabled=ip_restrict_enabled,
        ip_allow=list(ip_allow),
        ip_deny=list(ip_deny),
        auth_enabled=auth_enabled,
        auth_username=auth_user,
        auth_password=auth_pass,
        max_tunnels_per_ip=max_tunnels_per_ip,
        tunnel_creation_rate_limit=tunnel_rate_limit,
        tunnel_creation_burst=tunnel_rate_burst,
        dashboard_enabled=dashboard_enabled,
        dashboard_user=dashboard_user,
        dashboard_password=dashboard_password,
        tcp_port_min=tcp_port_min,
        tcp_port_max=tcp_port_max,
        udp_port_min=udp_port_min,
        udp_port_max=udp_port_max,
        oauth_enabled=oauth_enabled,
        oauth_provider=oauth_provider or "oidc",
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_issuer_url=oauth_issuer_url,
        oauth_allowed_domains=list(oauth_allowed_domain),
        oauth_allowed_emails=list(oauth_allowed_email),
        oauth_session_duration=oauth_session_duration,
    )

    console.print(f"Starting relay server for {domain}...", style="yellow")
    console.print(f"HTTPS: {https_bind}", style="dim")
    console.print(f"Control: {control_bind}", style="dim")
    timeout_str = f"{timeout_value}s" if timeout_value else "indefinite"
    console.print(f"Request timeout: {timeout_str}", style="dim")
    console.print(f"Per-IP limits: {max_tunnels_per_ip} tunnels, {tunnel_rate_limit}/min creation rate", style="dim")
    if rate_limit:
        console.print(f"Request rate limit: {rate_limit_rps} req/s, burst: {rate_limit_burst}", style="dim")
    if ip_restrict_enabled:
        console.print(f"IP restrictions: {len(ip_allow)} allow, {len(ip_deny)} deny", style="dim")
    if auth_enabled:
        console.print(f"Basic auth: enabled (user: {auth_user})", style="dim")
    if dashboard_enabled:
        console.print(f"Dashboard: enabled at /dashboard (user: {dashboard_user})", style="green")
    else:
        console.print("Dashboard: disabled (set --dashboard-user and --dashboard-password to enable)", style="dim")
    if oauth_enabled:
        domains_str = ", ".join(oauth_allowed_domain) if oauth_allowed_domain else "all"
        console.print(f"OAuth: enabled (provider: {oauth_provider}, domains: {domains_str})", style="green")
    else:
        console.print("OAuth: disabled (set --oauth-provider, --oauth-client-id, --oauth-client-secret to enable)", style="dim")

    asyncio.run(run_server(config))


async def run_server(config: ServerConfig):
    """Run the relay server."""
    server = RelayServer(config)

    try:
        await server.start()
        console.print("Server started, press Ctrl+C to stop", style="green")

        await asyncio.Event().wait()
    except KeyboardInterrupt:
        console.print("\nShutting down...", style="yellow")
    finally:
        await server.stop()


if __name__ == "__main__":
    main()
