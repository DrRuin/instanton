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
):
    """Run the Instanton relay server."""
    console.print(BANNER, style="cyan")

    # Convert 0 to None for indefinite timeout
    timeout_value = request_timeout if request_timeout > 0 else None

    # Determine if IP restrictions are enabled (any rules provided)
    ip_restrict_enabled = bool(ip_allow or ip_deny)

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
    )

    console.print(f"Starting relay server for {domain}...", style="yellow")
    console.print(f"HTTPS: {https_bind}", style="dim")
    console.print(f"Control: {control_bind}", style="dim")
    timeout_str = f"{timeout_value}s" if timeout_value else "indefinite"
    console.print(f"Request timeout: {timeout_str}", style="dim")
    if rate_limit:
        console.print(f"Rate limit: {rate_limit_rps} req/s, burst: {rate_limit_burst}", style="dim")
    if ip_restrict_enabled:
        console.print(f"IP restrictions: {len(ip_allow)} allow, {len(ip_deny)} deny", style="dim")

    asyncio.run(run_server(config))


async def run_server(config: ServerConfig):
    """Run the relay server."""
    server = RelayServer(config)

    try:
        await server.start()
        console.print("Server started, press Ctrl+C to stop", style="green")

        # Wait forever
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        console.print("\nShutting down...", style="yellow")
    finally:
        await server.stop()


if __name__ == "__main__":
    main()
