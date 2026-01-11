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
):
    """Run the Instanton relay server."""
    console.print(BANNER, style="cyan")

    # Convert 0 to None for indefinite timeout
    timeout_value = request_timeout if request_timeout > 0 else None

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
    )

    console.print(f"Starting relay server for {domain}...", style="yellow")
    console.print(f"HTTPS: {https_bind}", style="dim")
    console.print(f"Control: {control_bind}", style="dim")
    timeout_str = f"{timeout_value}s" if timeout_value else "indefinite"
    console.print(f"Request timeout: {timeout_str}", style="dim")

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
