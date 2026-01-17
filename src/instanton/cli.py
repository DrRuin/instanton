"""Instanton CLI - Command line interface."""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Global flag to track shutdown state
_shutdown_requested = False

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
@click.option("--server", default="instanton.tech", help="Instanton server address")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--auth-token", envvar="INSTANTON_AUTH_TOKEN", help="Authentication token")
@click.option("--inspect", "-i", is_flag=True, help="Enable request inspector")
@click.option("--quic/--no-quic", default=False, help="Use QUIC transport")
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

        # Start tunnel with timeout options and proper signal handling
        _run_tunnel_with_signal_handling(
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


def _run_tunnel_with_signal_handling(
    port: int,
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
) -> None:
    """Run tunnel with proper signal handling for clean Ctrl+C shutdown."""
    global _shutdown_requested
    _shutdown_requested = False

    # Use selector event loop on Windows to fix WebSocket connection issues
    # The default ProactorEventLoop on Windows has issues with some SSL/WebSocket operations
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Create the main task
    main_task = loop.create_task(
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

    def signal_handler(sig: int, frame: object) -> None:
        """Handle Ctrl+C signal."""
        global _shutdown_requested
        if _shutdown_requested:
            # Second Ctrl+C - force exit
            console.print("\n[red]Force shutdown![/red]")
            sys.exit(1)
        _shutdown_requested = True
        console.print("\n[yellow]Shutting down gracefully...[/yellow]")
        # Cancel the main task to trigger cleanup
        main_task.cancel()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        pass  # Expected when Ctrl+C is pressed
    except KeyboardInterrupt:
        pass  # Fallback in case signal handler doesn't catch it
    finally:
        # Clean up pending tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        # Wait for all tasks to complete their cancellation
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


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
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Graceful shutdown - close the client properly
        await client.close()
        console.print("[green]Tunnel closed.[/green]")
    except Exception as e:
        # Import here to avoid circular imports
        from instanton.core.exceptions import InstantonError, format_error_for_user

        # Always try to close the client on error
        with contextlib.suppress(Exception):
            await client.close()

        if isinstance(e, InstantonError):
            console.print(
                Panel(
                    f"[red]{e.message}[/red]",
                    title=f"Error: {e.code}",
                    border_style="red",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]{format_error_for_user(e)}[/red]",
                    title="Connection Error",
                    border_style="red",
                )
            )
        sys.exit(1)


@main.command()
@click.option("--server", default="instanton.tech", help="Instanton server address")
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
@click.option("--server", default="instanton.tech", help="Instanton server address")
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
@click.option("--server", default="instanton.tech", help="Instanton server address")
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
@click.option("--server", default="instanton.tech", help="Instanton server address")
@click.option("--quic/--no-quic", default=False, help="Use QUIC transport")
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


def _format_bytes(num_bytes: int | float) -> str:
    """Format bytes into human readable string."""
    value: float = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(value) < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


# =============================================================================
# Domain Management Commands
# =============================================================================


@main.group()
def domain():
    """Manage custom domains for tunnels.

    Custom domains allow you to use your own domain (e.g., api.mycompany.com)
    instead of the default random.instanton.tech subdomains.

    Examples:

        instanton domain add api.mycompany.com --tunnel-id abc123

        instanton domain verify api.mycompany.com

        instanton domain list

        instanton domain status api.mycompany.com

        instanton domain remove api.mycompany.com
    """
    pass


@domain.command("add")
@click.argument("domain_name")
@click.option("--tunnel-id", "-t", required=True, help="Tunnel ID to associate with this domain")
@click.option("--storage", default="domains.json", help="Path to domain storage file")
def domain_add(domain_name: str, tunnel_id: str, storage: str):
    """Register a new custom domain.

    After registration, you'll receive DNS records to configure.
    """
    asyncio.run(_domain_add_async(domain_name, tunnel_id, storage))


async def _domain_add_async(domain_name: str, tunnel_id: str, storage: str):
    """Async implementation of domain add command."""
    from instanton.domains import DomainManager, DomainStore

    store = DomainStore(storage)
    manager = DomainManager(store)

    try:
        registration = await manager.register_domain(domain_name, tunnel_id)

        console.print(
            Panel(
                f"[green]Domain registered successfully![/green]\n\n"
                f"[bold]Domain:[/bold] {registration.domain}\n"
                f"[bold]Tunnel ID:[/bold] {registration.tunnel_id}\n"
                f"[bold]Status:[/bold] Pending verification\n\n"
                f"[yellow]Configure these DNS records:[/yellow]\n\n"
                f"1. [bold]CNAME Record[/bold]\n"
                f"   Name: {domain_name}\n"
                f"   Value: instanton.tech\n\n"
                f"2. [bold]TXT Record[/bold]\n"
                f"   Name: _instanton.{domain_name}\n"
                f"   Value: {registration.verification_token}\n\n"
                f"After configuring DNS, run:\n"
                f"  [cyan]instanton domain verify {domain_name}[/cyan]",
                title="Domain Registration",
                border_style="green",
            )
        )
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@domain.command("verify")
@click.argument("domain_name")
@click.option("--storage", default="domains.json", help="Path to domain storage file")
def domain_verify(domain_name: str, storage: str):
    """Verify DNS records for a domain."""
    asyncio.run(_domain_verify_async(domain_name, storage))


async def _domain_verify_async(domain_name: str, storage: str):
    """Async implementation of domain verify command."""
    from instanton.domains import DomainManager, DomainStore

    store = DomainStore(storage)
    manager = DomainManager(store)

    try:
        console.print(f"Verifying DNS records for [cyan]{domain_name}[/cyan]...", style="yellow")
        result = await manager.verify_domain(domain_name)

        if result.is_verified:
            console.print(
                Panel(
                    f"[green]Domain verified successfully![/green]\n\n"
                    f"[bold]Domain:[/bold] {result.domain}\n"
                    f"[bold]CNAME:[/bold] [green]Valid[/green] -> {result.cname_target}\n"
                    f"[bold]TXT:[/bold] [green]Valid[/green]\n\n"
                    f"Your domain is now active and ready to use!",
                    title="Verification Successful",
                    border_style="green",
                )
            )
        else:
            cname_status = "[green]Valid[/green]" if result.cname_valid else "[red]Invalid[/red]"
            txt_status = "[green]Valid[/green]" if result.txt_valid else "[red]Invalid[/red]"

            console.print(
                Panel(
                    f"[yellow]Verification incomplete[/yellow]\n\n"
                    f"[bold]Domain:[/bold] {result.domain}\n"
                    f"[bold]CNAME:[/bold] {cname_status}\n"
                    f"[bold]TXT:[/bold] {txt_status}\n\n"
                    f"[red]Error:[/red] {result.error or 'Unknown error'}",
                    title="Verification Status",
                    border_style="yellow",
                )
            )
            sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@domain.command("list")
@click.option("--storage", default="domains.json", help="Path to domain storage file")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def domain_list(storage: str, json_output: bool):
    """List all registered domains."""
    asyncio.run(_domain_list_async(storage, json_output))


async def _domain_list_async(storage: str, json_output: bool):
    """Async implementation of domain list command."""
    import json

    from instanton.domains import DomainStore

    store = DomainStore(storage)
    domains = await store.list_all()

    if json_output:
        data = [d.to_dict() for d in domains]
        console.print(json.dumps(data, indent=2, default=str))
        return

    if not domains:
        console.print("[dim]No domains registered[/dim]")
        return

    table = Table(title="Registered Domains")
    table.add_column("Domain", style="cyan")
    table.add_column("Tunnel ID", style="dim")
    table.add_column("Verified", justify="center")
    table.add_column("Created At")

    for domain in domains:
        verified = "[green]Yes[/green]" if domain.verified else "[yellow]No[/yellow]"
        created = domain.created_at.strftime("%Y-%m-%d %H:%M") if domain.created_at else "N/A"
        table.add_row(
            domain.domain,
            domain.tunnel_id[:12] + "..." if len(domain.tunnel_id) > 12 else domain.tunnel_id,
            verified,
            created,
        )

    console.print(table)


@domain.command("status")
@click.argument("domain_name")
@click.option("--storage", default="domains.json", help="Path to domain storage file")
def domain_status(domain_name: str, storage: str):
    """Show detailed status for a domain."""
    asyncio.run(_domain_status_async(domain_name, storage))


async def _domain_status_async(domain_name: str, storage: str):
    """Async implementation of domain status command."""
    from instanton.domains import DomainManager, DomainStatus, DomainStore

    store = DomainStore(storage)
    manager = DomainManager(store)

    info = await manager.get_domain_status(domain_name)

    if info.status == DomainStatus.NOT_FOUND:
        console.print(f"[red]Domain not found:[/red] {domain_name}")
        sys.exit(1)

    status_colors = {
        DomainStatus.PENDING_VERIFICATION: "yellow",
        DomainStatus.CNAME_ONLY: "yellow",
        DomainStatus.VERIFIED: "green",
        DomainStatus.CERTIFICATE_PENDING: "cyan",
        DomainStatus.ACTIVE: "green",
    }
    status_color = status_colors.get(info.status, "white")

    content = (
        f"[bold]Domain:[/bold] {info.domain}\n"
        f"[bold]Status:[/bold] [{status_color}]{info.status.value}[/{status_color}]\n"
        f"[bold]Tunnel ID:[/bold] {info.tunnel_id or 'N/A'}\n"
        f"[bold]Verified:[/bold] {'Yes' if info.verified else 'No'}\n"
        f"[bold]Certificate:[/bold] {'Ready' if info.certificate_ready else 'Pending'}"
    )

    if info.verified_at:
        content += f"\n[bold]Verified At:[/bold] {info.verified_at.strftime('%Y-%m-%d %H:%M')}"

    if info.dns_instructions:
        content += f"\n\n[yellow]DNS Setup Required:[/yellow]\n{info.dns_instructions}"

    console.print(
        Panel(
            content,
            title=f"Domain Status: {domain_name}",
            border_style=status_color,
        )
    )


@domain.command("remove")
@click.argument("domain_name")
@click.option("--storage", default="domains.json", help="Path to domain storage file")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def domain_remove(domain_name: str, storage: str, yes: bool):
    """Remove a registered domain."""
    if not yes:
        if not click.confirm(f"Are you sure you want to remove '{domain_name}'?"):
            console.print("[dim]Cancelled[/dim]")
            return

    asyncio.run(_domain_remove_async(domain_name, storage))


async def _domain_remove_async(domain_name: str, storage: str):
    """Async implementation of domain remove command."""
    from instanton.domains import DomainManager, DomainStore

    store = DomainStore(storage)
    manager = DomainManager(store)

    deleted = await manager.delete_domain(domain_name)

    if deleted:
        console.print(f"[green]Domain removed:[/green] {domain_name}")
    else:
        console.print(f"[red]Domain not found:[/red] {domain_name}")
        sys.exit(1)


if __name__ == "__main__":
    main()
