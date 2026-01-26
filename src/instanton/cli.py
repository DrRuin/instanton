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
@click.option(
    "--config", "-c",
    "config_file",
    type=click.Path(exists=True),
    help="Path to YAML or TOML config file",
)
@click.option("--port", "-p", type=int, help="Local port to expose")
@click.option("--subdomain", "-s", help="Request specific subdomain")
@click.option("--server", default=None, help="Instanton server address")
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
@click.option(
    "--read-timeout",
    type=float,
    default=None,
    help="Read timeout in seconds for local service responses (default: None/indefinite)",
)
@click.option(
    "--max-connections",
    type=int,
    default=100,
    help="Maximum concurrent connections to local service (default: 100)",
)
@click.option(
    "--retry-count",
    type=int,
    default=2,
    help="Number of retry attempts on connection failure (default: 2)",
)
@click.option(
    "--log-level",
    "-l",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    default="warning",
    help="Log level (default: warning, use --verbose for debug)",
)
@click.option("--proxy-user", envvar="INSTANTON_PROXY_USER", help="Proxy auth username")
@click.option("--proxy-pass", envvar="INSTANTON_PROXY_PASS", help="Proxy auth password")
@click.pass_context
def main(
    ctx: click.Context,
    config_file: str | None,
    port: int | None,
    subdomain: str | None,
    server: str | None,
    verbose: bool,
    auth_token: str | None,
    inspect: bool,
    quic: bool,
    timeout: float,
    idle_timeout: float,
    keepalive: float,
    no_request_timeout: bool,
    read_timeout: float | None,
    max_connections: int,
    retry_count: int,
    log_level: str,
    proxy_user: str | None,
    proxy_pass: str | None,
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
    file_config: dict = {}
    if config_file:
        from instanton.core.config import flatten_config, load_config_from_file
        try:
            raw_config = load_config_from_file(config_file)
            file_config = flatten_config(raw_config)
            console.print(f"Loaded config from {config_file}", style="dim")
        except Exception as e:
            console.print(f"[red]Failed to load config: {e}[/red]")
            sys.exit(1)

    if server is None:
        server = file_config.get("server", "instanton.tech")
    if port is None and "port" in file_config:
        port = int(file_config["port"])
    if subdomain is None and "subdomain" in file_config:
        subdomain = file_config["subdomain"]
    if timeout == 30.0 and "timeout" in file_config:
        timeout = float(file_config["timeout"])
    if idle_timeout == 300.0 and "idle_timeout" in file_config:
        idle_timeout = float(file_config["idle_timeout"])
    if keepalive == 30.0 and "keepalive" in file_config:
        keepalive = float(file_config["keepalive"])
    if "timeouts_connect" in file_config:
        timeout = float(file_config["timeouts_connect"])
    if "timeouts_idle" in file_config:
        idle_timeout = float(file_config["timeouts_idle"])
    if "performance_compression_level" in file_config or "performance_chunk_size" in file_config:
        import os
        if "performance_compression_level" in file_config:
            os.environ["INSTANTON_COMPRESSION_LEVEL"] = str(
                file_config["performance_compression_level"]
            )
        if "performance_chunk_size" in file_config:
            os.environ["INSTANTON_CHUNK_SIZE"] = str(file_config["performance_chunk_size"])

    ctx.ensure_object(dict)
    ctx.obj["config_file"] = config_file
    ctx.obj["file_config"] = file_config

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
            read_timeout,
            max_connections,
            retry_count,
            log_level,
            proxy_user,
            proxy_pass,
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
    read_timeout: float | None,
    max_connections: int,
    retry_count: int,
    log_level: str,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
) -> None:
    """Run tunnel with proper signal handling for clean Ctrl+C shutdown."""
    global _shutdown_requested
    _shutdown_requested = False

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

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
            read_timeout,
            max_connections,
            retry_count,
            log_level,
            proxy_user,
            proxy_pass,
        )
    )

    def signal_handler(sig: int, frame: object) -> None:
        """Handle Ctrl+C signal."""
        global _shutdown_requested
        if _shutdown_requested:
            console.print("\n[red]Force shutdown![/red]")
            sys.exit(1)
        _shutdown_requested = True
        console.print("\n[yellow]Shutting down gracefully...[/yellow]")
        main_task.cancel()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
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
    read_timeout: float | None = None,
    max_connections: int = 100,
    retry_count: int = 2,
    log_level: str = "info",
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
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
        read_timeout: Read timeout for local service responses
        max_connections: Maximum concurrent connections to local service
        retry_count: Number of retry attempts on failure
        log_level: Log level (debug, info, warning, error)
        proxy_user: Username for proxy authentication
        proxy_pass: Password for proxy authentication
    """
    import structlog

    effective_log_level = "debug" if verbose else log_level

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(__import__("logging"), effective_log_level.upper())
        ),
    )
    from instanton.client.tunnel import ProxyConfig, TunnelClient
    from instanton.core.config import ClientConfig
    from instanton.sdk import _suggest_subdomain

    console.print(BANNER, style="cyan")

    if subdomain is None:
        suggested = _suggest_subdomain()
        if suggested:
            subdomain = suggested

    console.print(f"Starting tunnel for localhost:{port}...", style="yellow")

    client_config = ClientConfig(
        server_addr=server,
        local_port=port,
        subdomain=subdomain,
        use_quic=quic,
        connect_timeout=timeout,
        idle_timeout=idle_timeout,
        keepalive_interval=keepalive,
        proxy_username=proxy_user,
        proxy_password=proxy_pass,
    )

    effective_read_timeout = None if no_request_timeout else read_timeout
    proxy_config = ProxyConfig(
        read_timeout=effective_read_timeout,
        stream_timeout=None,
        max_connections=max_connections,
        retry_count=retry_count,
    )

    client = TunnelClient(
        local_port=port,
        server_addr=server,
        subdomain=subdomain,
        use_quic=quic,
        config=client_config,
        proxy_config=proxy_config,
        proxy_username=proxy_user,
        proxy_password=proxy_pass,
    )

    try:
        url = await client.connect()
        panel_content = (
            f"[green]Tunnel established![/green]\n\n"
            f"[bold]Public URL:[/bold] [cyan]{url}[/cyan]\n"
            f"[bold]Forwarding:[/bold] localhost:{port}"
        )
        console.print(
            Panel(
                panel_content,
                title="Instanton",
                border_style="green",
            )
        )
        console.print("\nPress Ctrl+C to stop.\n", style="dim")

        if inspect:
            console.print("[bold]Request Inspector:[/bold] http://localhost:4040", style="cyan")

        await client.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        await client.close()
        console.print("[green]Tunnel closed.[/green]")
    except Exception as e:
        from instanton.core.exceptions import InstantonError, format_error_for_user

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
        base_url = f"https://{server}"
        if ":" not in server:
            base_url = f"https://{server}:4443"

        with httpx.Client(verify=False, timeout=5.0) as client:
            try:
                health_resp = client.get(f"{base_url}/health")
                health = health_resp.json()
            except Exception:
                health = {"status": "unknown", "tunnels": 0}

            try:
                stats_resp = client.get(f"{base_url}/stats")
                stats = stats_resp.json()
            except Exception:
                stats = {"total_tunnels": 0, "max_tunnels": 0, "tunnels": []}

        if json_output:
            import json

            console.print(json.dumps({"health": health, "stats": stats}, indent=2))
            return

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
@click.option("--proxy-user", envvar="INSTANTON_PROXY_USER", help="Proxy auth username")
@click.option("--proxy-pass", envvar="INSTANTON_PROXY_PASS", help="Proxy auth password")
def http(port: int, subdomain: str | None, server: str, auth_token: str | None, proxy_user: str | None, proxy_pass: str | None):
    """Start an HTTP tunnel (shorthand command).

    Examples:

        instanton http 8000

        instanton http 3000 --subdomain myapp
    """
    asyncio.run(
        start_tunnel(
            port, subdomain, server, verbose=False, auth_token=auth_token, inspect=False, quic=True,
            proxy_user=proxy_user, proxy_pass=proxy_pass,
        )
    )


@main.command()
@click.argument("port", type=int)
@click.option("--remote-port", "-r", type=int, help="Remote port to bind on server")
@click.option("--server", default="instanton.tech", help="Instanton server address")
@click.option("--quic/--no-quic", default=False, help="Use QUIC transport")
@click.option("--proxy-user", envvar="INSTANTON_PROXY_USER", help="Proxy auth username")
@click.option("--proxy-pass", envvar="INSTANTON_PROXY_PASS", help="Proxy auth password")
def tcp(port: int, remote_port: int | None, server: str, quic: bool, proxy_user: str | None, proxy_pass: str | None):
    """Start a TCP tunnel for non-HTTP protocols.

    Examples:

        instanton tcp 22                    # SSH tunnel

        instanton tcp 5432 --remote-port 5432   # PostgreSQL

        instanton tcp 3306                  # MySQL
    """
    asyncio.run(start_tcp_tunnel_cli(port, remote_port, server, quic, proxy_user, proxy_pass))


async def start_tcp_tunnel_cli(
    port: int,
    remote_port: int | None,
    server: str,
    quic: bool,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
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
        proxy_username=proxy_user,
        proxy_password=proxy_pass,
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
@click.option("--quic/--no-quic", default=True, help="Use QUIC transport (recommended for UDP)")
@click.option(
    "--keepalive",
    "-k",
    type=float,
    default=10.0,
    help="Keepalive interval in seconds (default: 10, lower for games)",
)
@click.option(
    "--idle-timeout",
    type=float,
    default=300.0,
    help="Idle timeout in seconds (default: 300)",
)
@click.option(
    "--max-datagram-size",
    type=int,
    default=1400,
    help="Maximum datagram size in bytes (default: 1400, MTU-safe)",
)
@click.option("--proxy-user", envvar="INSTANTON_PROXY_USER", help="Proxy auth username")
@click.option("--proxy-pass", envvar="INSTANTON_PROXY_PASS", help="Proxy auth password")
def udp(
    port: int,
    remote_port: int | None,
    server: str,
    quic: bool,
    keepalive: float,
    idle_timeout: float,
    max_datagram_size: int,
    proxy_user: str | None,
    proxy_pass: str | None,
):
    """Start a UDP tunnel for datagram protocols.

    Optimized for game servers, VoIP, DNS, and real-time applications.

    Examples:

        instanton udp 53                         # DNS tunnel

        instanton udp 5060 --remote-port 5060    # SIP/VoIP

        instanton udp 27015                      # Game server (Source engine)

        instanton udp 7777 --keepalive 5         # Fast keepalive for games

        instanton udp 19132 --quic               # Minecraft Bedrock (QUIC recommended)
    """
    asyncio.run(
        start_udp_tunnel_cli(
            port, remote_port, server, quic, keepalive, idle_timeout, max_datagram_size,
            proxy_user, proxy_pass,
        )
    )


async def start_udp_tunnel_cli(
    port: int,
    remote_port: int | None,
    server: str,
    quic: bool,
    keepalive: float = 10.0,
    idle_timeout: float = 300.0,
    max_datagram_size: int = 1400,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
):
    """Start a UDP tunnel from CLI."""
    from instanton.client.udp_tunnel import UdpTunnelClient, UdpTunnelConfig

    console.print(BANNER, style="cyan")
    console.print(f"Starting UDP tunnel for localhost:{port}...", style="yellow")
    console.print(
        f"[dim]Keepalive: {keepalive}s | Idle timeout: {idle_timeout}s | "
        f"Max datagram: {max_datagram_size} bytes[/dim]"
    )

    config = UdpTunnelConfig(
        local_port=port,
        remote_port=remote_port,
        max_datagram_size=max_datagram_size,
        idle_timeout=idle_timeout,
        keepalive_interval=keepalive,
    )

    client = UdpTunnelClient(
        config=config,
        server_addr=server,
        use_quic=quic,
        proxy_username=proxy_user,
        proxy_password=proxy_pass,
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


@main.group()
def config():
    """View and export configuration settings.

    All settings can be configured via environment variables with the
    INSTANTON_ prefix. Use these commands to see current values.

    Examples:

        instanton config show            # Show all config settings

        instanton config export          # Export as env vars

        instanton config validate        # Validate current config
    """
    pass


@config.command("show")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--section", "-s", help="Show only specific section (performance, timeouts, reconnect, resources)")
def config_show(json_output: bool, section: str | None):
    """Show current configuration settings.

    Displays all configurable settings with their current values.
    Values come from environment variables or defaults.
    """
    from instanton.core.config import get_config

    cfg = get_config()
    display = cfg.to_display_dict()

    if section:
        section = section.lower()
        if section not in display:
            console.print(f"[red]Unknown section:[/red] {section}")
            console.print(f"[dim]Available: {', '.join(display.keys())}[/dim]")
            sys.exit(1)
        display = {section: display[section]}

    if json_output:
        import json
        console.print(json.dumps(display, indent=2))
        return

    console.print(BANNER, style="cyan")
    console.print("[bold]Current Configuration[/bold]\n")

    for section_name, settings in display.items():
        table = Table(title=section_name.replace("_", " ").title())
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Env Variable", style="dim")

        for key, value in settings.items():
            env_var = f"INSTANTON_{key.upper()}"
            value_str = str(value) if value is not None else "[dim]None[/dim]"
            table.add_row(key, value_str, env_var)

        console.print(table)
        console.print()


@config.command("export")
@click.option("--shell", type=click.Choice(["bash", "powershell", "cmd"]), default="bash", help="Shell format")
def config_export(shell: str):
    """Export current configuration as environment variables.

    Outputs commands to set all config values as env vars.
    """
    from instanton.core.config import get_config

    cfg = get_config()
    env_dict = cfg.to_env_dict()

    console.print(f"# Instanton Configuration Export ({shell})")
    console.print("# Copy and paste or save to a file\n")

    for key, value in env_dict.items():
        if value is None:
            continue
        value_str = str(value).lower() if isinstance(value, bool) else str(value)

        if shell == "bash":
            console.print(f'export {key}="{value_str}"')
        elif shell == "powershell":
            console.print(f'$env:{key}="{value_str}"')
        elif shell == "cmd":
            console.print(f'set {key}={value_str}')


@config.command("validate")
def config_validate():
    """Validate current configuration.

    Checks that all config values are valid and within expected ranges.
    """
    from instanton.core.config import clear_config, get_config

    clear_config()

    try:
        cfg = get_config()

        errors = []
        warnings = []

        perf = cfg.performance
        if perf.chunk_size < 1024:
            warnings.append(f"chunk_size ({perf.chunk_size}) is very small, may impact performance")
        if perf.chunk_size > 10 * 1024 * 1024:
            warnings.append(f"chunk_size ({perf.chunk_size}) is very large, may cause memory issues")
        if perf.compression_level < 1 or perf.compression_level > 19:
            errors.append(f"compression_level ({perf.compression_level}) must be between 1 and 19")

        timeouts = cfg.timeouts
        if timeouts.connect_timeout < 1:
            warnings.append(f"connect_timeout ({timeouts.connect_timeout}s) is very short")
        if timeouts.ping_interval < 5:
            warnings.append(f"ping_interval ({timeouts.ping_interval}s) is very short, may cause overhead")

        resources = cfg.resources
        if resources.tcp_port_min >= resources.tcp_port_max:
            errors.append(f"tcp_port_min ({resources.tcp_port_min}) must be less than tcp_port_max ({resources.tcp_port_max})")
        if resources.udp_port_min >= resources.udp_port_max:
            errors.append(f"udp_port_min ({resources.udp_port_min}) must be less than udp_port_max ({resources.udp_port_max})")

        if errors:
            console.print("[red bold]Configuration Errors:[/red bold]")
            for error in errors:
                console.print(f"  [red]x[/red] {error}")
            console.print()

        if warnings:
            console.print("[yellow bold]Configuration Warnings:[/yellow bold]")
            for warning in warnings:
                console.print(f"  [yellow]![/yellow] {warning}")
            console.print()

        if not errors and not warnings:
            console.print("[green]OK - Configuration is valid[/green]")
        elif not errors:
            console.print("[green]OK - Configuration is valid (with warnings)[/green]")
        else:
            console.print("[red]ERROR - Configuration has errors[/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)


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
    if not yes and not click.confirm(f"Are you sure you want to remove '{domain_name}'?"):
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
