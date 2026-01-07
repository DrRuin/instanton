"""Instanton CLI - Command line interface."""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """
██╗███╗   ██╗███████╗████████╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ██╗
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗  ██║
██║██╔██╗ ██║███████╗   ██║   ███████║██╔██╗ ██║   ██║   ██║   ██║██╔██╗ ██║
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╗██║
██║██║ ╚████║███████║   ██║   ██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚████║
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
              Tunnel through barriers, instantly
"""


@click.group(invoke_without_command=True)
@click.option("--port", "-p", type=int, help="Local port to expose")
@click.option("--subdomain", "-s", help="Request specific subdomain")
@click.option("--server", default="instanton.dev", help="Instanton server address")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--auth-token", envvar="INSTANTON_AUTH_TOKEN", help="Authentication token")
@click.option("--inspect", "-i", is_flag=True, help="Enable request inspector")
@click.option("--quic/--no-quic", default=True, help="Use QUIC transport (default: yes)")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    help="Connection timeout in seconds (default: 30)",
)
@click.option(
    "--idle-timeout",
    type=float,
    default=300.0,
    help="Idle timeout in seconds before auto-disconnect (default: 300)",
)
@click.option(
    "--keepalive",
    "-k",
    type=float,
    default=30.0,
    help="Keepalive interval in seconds (default: 30)",
)
@click.option(
    "--no-request-timeout",
    is_flag=True,
    default=False,
    help="Disable request timeout (for long-running APIs, streaming)",
)
@click.pass_context
def main(
    ctx: click.Context,
    port: int | None,
    subdomain: str | None,
    server: str,
    verbose: bool,
    auth_token: str | None,
    inspect: bool,
    quic: bool,
    timeout: float,
    idle_timeout: float,
    keepalive: float,
    no_request_timeout: bool,
):
    """Instanton - Tunnel through barriers, instantly.

    Examples:

        instanton --port 8000

        instanton --port 3000 --subdomain myapp

        instanton --port 8080 --server custom.server.com

        instanton --port 8000 --timeout 60 --idle-timeout 600

    For long-running APIs or streaming (no forced timeout):

        instanton --port 8000 --no-request-timeout

    You can run multiple tunnels simultaneously for different ports:

        Terminal 1: instanton --port 3000 --subdomain frontend

        Terminal 2: instanton --port 5432 --subdomain database

        Terminal 3: instanton --port 8000 --subdomain api

    Use 'instanton COMMAND --help' for more info on specific commands.
    """
    if ctx.invoked_subcommand is None:
        if port is None:
            console.print(BANNER, style="cyan")
            console.print("Usage: instanton --port 8000", style="yellow")
            console.print("       instanton --port 3000 --subdomain myapp", style="yellow")
            console.print("       instanton --port 8000 --timeout 60", style="yellow")
            console.print("\nCommands:", style="bold")
            console.print("  instanton status   Show server status", style="dim")
            console.print("  instanton version  Show version information", style="dim")
            console.print("  instanton http     Start HTTP tunnel (shorthand)", style="dim")
            console.print("  instanton tcp      Start TCP tunnel", style="dim")
            return

        # Start tunnel with timeout options
        asyncio.run(
            start_tunnel(
                port,
                subdomain,
                server,
                verbose,
                auth_token,
                inspect,
                quic,
                timeout,
                idle_timeout,
                keepalive,
                no_request_timeout,
            )
        )


async def start_tunnel(
    port: int,
    subdomain: str | None,
    server: str,
    verbose: bool,
    auth_token: str | None,
    inspect: bool,
    quic: bool,
    timeout: float = 30.0,
    idle_timeout: float = 300.0,
    keepalive: float = 30.0,
    no_request_timeout: bool = False,
):
    """Start a tunnel to expose local port.

    Args:
        port: Local port to forward traffic to
        subdomain: Requested subdomain (optional)
        server: Instanton server address
        verbose: Enable verbose output
        auth_token: Authentication token
        inspect: Enable request inspector
        quic: Use QUIC transport
        timeout: Connection timeout in seconds
        idle_timeout: Idle timeout before auto-disconnect
        keepalive: Keepalive interval in seconds
        no_request_timeout: Disable request timeout (for long-running APIs/streaming)
    """
    from instanton.client.tunnel import ProxyConfig, TunnelClient
    from instanton.core.config import ClientConfig
    from instanton.sdk import _suggest_subdomain

    console.print(BANNER, style="cyan")

    # Auto-suggest subdomain if not provided
    if subdomain is None:
        suggested = _suggest_subdomain()
        if suggested:
            subdomain = suggested
            console.print(f"Auto-detected project: [cyan]{subdomain}[/cyan]", style="dim")

    console.print(f"Starting tunnel for localhost:{port}...", style="yellow")
    if verbose:
        timeout_str = "indefinite" if no_request_timeout else f"{timeout}s"
        console.print(
            f"[dim]Timeout: {timeout}s | Idle timeout: {idle_timeout}s | "
            f"Keepalive: {keepalive}s | Request timeout: {timeout_str}[/dim]"
        )

    if no_request_timeout:
        console.print(
            "[dim]Request timeout disabled - connections can stay open indefinitely[/dim]"
        )

    # Create client config with timeout settings
    client_config = ClientConfig(
        server_addr=server,
        local_port=port,
        subdomain=subdomain,
        use_quic=quic,
        connect_timeout=timeout,
        idle_timeout=idle_timeout,
        keepalive_interval=keepalive,
    )

    # Create proxy config with optional indefinite timeout
    proxy_config = ProxyConfig(
        read_timeout=None if no_request_timeout else 30.0,
        stream_timeout=None,  # Always allow indefinite streaming
    )

    client = TunnelClient(
        local_port=port,
        server_addr=server,
        subdomain=subdomain,
        use_quic=quic,
        config=client_config,
        proxy_config=proxy_config,
    )

    try:
        url = await client.connect()
        panel_content = (
            f"[green]✓ Tunnel established![/green]\n\n"
            f"[bold]Public URL:[/bold] [cyan]{url}[/cyan]\n"
            f"[bold]Forwarding to:[/bold] http://localhost:{port}\n"
            f"[bold]Subdomain:[/bold] {client.subdomain or 'auto-assigned'}"
        )
        if no_request_timeout:
            panel_content += "\n[bold]Request Timeout:[/bold] [green]indefinite[/green]"
        if verbose:
            panel_content += (
                f"\n[bold]Timeout:[/bold] {timeout}s\n"
                f"[bold]Idle timeout:[/bold] {idle_timeout}s\n"
                f"[bold]Keepalive:[/bold] {keepalive}s"
            )
        console.print(
            Panel(
                panel_content,
                title="Instanton",
                border_style="green",
            )
        )
        console.print("\nPress Ctrl+C to stop the tunnel.\n", style="dim")

        # Show inspect info if enabled
        if inspect:
            console.print("[bold]Request Inspector:[/bold] http://localhost:4040", style="cyan")

        await client.run()
    except KeyboardInterrupt:
        console.print("\nShutting down...", style="yellow")
        await client.close()


@main.command()
@click.option("--server", default="instanton.dev", help="Instanton server address")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(server: str, json_output: bool):
    """Show server status and active tunnels.

    Connects to the server and displays health and tunnel information.
    """
    import httpx

    try:
        # Try to get server status
        base_url = f"https://{server}"
        if ":" not in server:
            base_url = f"https://{server}:4443"

        with httpx.Client(verify=False, timeout=5.0) as client:
            # Get health
            try:
                health_resp = client.get(f"{base_url}/health")
                health = health_resp.json()
            except Exception:
                health = {"status": "unknown", "tunnels": 0}

            # Get stats
            try:
                stats_resp = client.get(f"{base_url}/stats")
                stats = stats_resp.json()
            except Exception:
                stats = {"total_tunnels": 0, "max_tunnels": 0, "tunnels": []}

        if json_output:
            import json

            console.print(json.dumps({"health": health, "stats": stats}, indent=2))
            return

        # Display nicely
        console.print(f"\n[bold]Server:[/bold] {server}")
        status = health.get("status", "unknown")
        console.print(f"[bold]Status:[/bold] [green]{status}[/green]")
        total = stats.get("total_tunnels", 0)
        max_t = stats.get("max_tunnels", "N/A")
        console.print(f"[bold]Active Tunnels:[/bold] {total}/{max_t}")

        tunnels = stats.get("tunnels", [])
        if tunnels:
            console.print("\n[bold]Active Tunnels:[/bold]")
            table = Table()
            table.add_column("Subdomain", style="cyan")
            table.add_column("ID", style="dim")
            table.add_column("Requests", justify="right")
            table.add_column("Bytes In", justify="right")
            table.add_column("Bytes Out", justify="right")
            table.add_column("Connected At")

            for tunnel in tunnels:
                table.add_row(
                    tunnel.get("subdomain", ""),
                    tunnel.get("id", "")[:8] + "...",
                    str(tunnel.get("request_count", 0)),
                    _format_bytes(tunnel.get("bytes_received", 0)),
                    _format_bytes(tunnel.get("bytes_sent", 0)),
                    tunnel.get("connected_at", "")[:19],
                )

            console.print(table)
        else:
            console.print("\n[dim]No active tunnels[/dim]")

    except Exception as e:
        console.print(f"[red]Error connecting to server:[/red] {e}")
        sys.exit(1)


@main.command()
def version():
    """Show version information."""
    from instanton import __version__

    console.print(BANNER, style="cyan")
    console.print(f"[bold]Version:[/bold] {__version__}")
    console.print(f"[bold]Python:[/bold] {sys.version}")


@main.command()
@click.argument("port", type=int)
@click.option("--subdomain", "-s", help="Request specific subdomain")
@click.option("--server", default="instanton.dev", help="Instanton server address")
@click.option("--auth-token", envvar="INSTANTON_AUTH_TOKEN", help="Authentication token")
def http(port: int, subdomain: str | None, server: str, auth_token: str | None):
    """Start an HTTP tunnel (shorthand command).

    Examples:

        instanton http 8000

        instanton http 3000 --subdomain myapp
    """
    asyncio.run(
        start_tunnel(
            port, subdomain, server, verbose=False, auth_token=auth_token, inspect=False, quic=True
        )
    )


@main.command()
@click.argument("port", type=int)
@click.option("--remote-port", "-r", type=int, help="Remote port to bind on server")
@click.option("--server", default="instanton.dev", help="Instanton server address")
@click.option("--quic/--no-quic", default=False, help="Use QUIC transport")
def tcp(port: int, remote_port: int | None, server: str, quic: bool):
    """Start a TCP tunnel for non-HTTP protocols.

    Examples:

        instanton tcp 22                    # SSH tunnel

        instanton tcp 5432 --remote-port 5432   # PostgreSQL

        instanton tcp 3306                  # MySQL
    """
    asyncio.run(start_tcp_tunnel_cli(port, remote_port, server, quic))


async def start_tcp_tunnel_cli(
    port: int,
    remote_port: int | None,
    server: str,
    quic: bool,
):
    """Start a TCP tunnel from CLI."""
    from instanton.client.tcp_tunnel import TcpTunnelClient, TcpTunnelConfig

    console.print(BANNER, style="cyan")
    console.print(f"Starting TCP tunnel for localhost:{port}...", style="yellow")

    config = TcpTunnelConfig(
        local_port=port,
        remote_port=remote_port,
    )

    client = TcpTunnelClient(
        config=config,
        server_addr=server,
        use_quic=quic,
    )

    try:
        url = await client.connect()
        console.print(
            Panel(
                f"[green]TCP tunnel established![/green]\n\n"
                f"[bold]Public URL:[/bold] [cyan]{url}[/cyan]\n"
                f"[bold]Forwarding to:[/bold] localhost:{port}\n"
                f"[bold]Remote Port:[/bold] {client.assigned_port or 'auto-assigned'}",
                title="Instanton TCP Tunnel",
                border_style="green",
            )
        )
        console.print("\nPress Ctrl+C to stop the tunnel.\n", style="dim")

        await client.run()
    except KeyboardInterrupt:
        console.print("\nShutting down...", style="yellow")
        await client.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        await client.close()


@main.command()
@click.argument("port", type=int)
@click.option("--remote-port", "-r", type=int, help="Remote port to bind on server")
@click.option("--server", default="instanton.dev", help="Instanton server address")
@click.option("--quic/--no-quic", default=True, help="Use QUIC transport (default: yes)")
def udp(port: int, remote_port: int | None, server: str, quic: bool):
    """Start a UDP tunnel for datagram protocols.

    Examples:

        instanton udp 53                    # DNS tunnel

        instanton udp 5060 --remote-port 5060   # SIP/VoIP

        instanton udp 27015                 # Game server
    """
    asyncio.run(start_udp_tunnel_cli(port, remote_port, server, quic))


async def start_udp_tunnel_cli(
    port: int,
    remote_port: int | None,
    server: str,
    quic: bool,
):
    """Start a UDP tunnel from CLI."""
    from instanton.client.udp_tunnel import UdpTunnelClient, UdpTunnelConfig

    console.print(BANNER, style="cyan")
    console.print(f"Starting UDP tunnel for localhost:{port}...", style="yellow")

    config = UdpTunnelConfig(
        local_port=port,
        remote_port=remote_port,
    )

    client = UdpTunnelClient(
        config=config,
        server_addr=server,
        use_quic=quic,
    )

    try:
        url = await client.connect()
        console.print(
            Panel(
                f"[green]UDP tunnel established![/green]\n\n"
                f"[bold]Public URL:[/bold] [cyan]{url}[/cyan]\n"
                f"[bold]Forwarding to:[/bold] localhost:{port}\n"
                f"[bold]Remote Port:[/bold] {client.assigned_port or 'auto-assigned'}\n"
                f"[bold]Transport:[/bold] {'QUIC' if quic else 'WebSocket'}",
                title="Instanton UDP Tunnel",
                border_style="green",
            )
        )
        console.print("\nPress Ctrl+C to stop the tunnel.\n", style="dim")

        await client.run()
    except KeyboardInterrupt:
        console.print("\nShutting down...", style="yellow")
        await client.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        await client.close()


@main.command()
@click.argument("url")
@click.option("--output", "-o", type=click.Path(), help="Output file for request data")
def replay(url: str, output: str | None):
    """Replay a captured request from the inspector.

    Examples:

        instanton replay https://myapp.instanton.dev/api/test
    """
    console.print("[yellow]Request replay feature coming soon![/yellow]")


def _format_bytes(num_bytes: int | float) -> str:
    """Format bytes into human readable string."""
    value: float = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(value) < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


if __name__ == "__main__":
    main()
