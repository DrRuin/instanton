"""Instanton Tunnel Status Card.

Provides the tunnel card component for displaying individual tunnel
connection details including status, URL, port, and connection time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shiny import ui

if TYPE_CHECKING:
    from instanton.dashboard.services.tunnels import Tunnel


def create_tunnel_card(tunnel: Tunnel) -> ui.TagChild:
    """Create an Instanton tunnel status card.

    Renders a card displaying tunnel connection details including
    subdomain, status, public URL, local port, and connection time.

    Args:
        tunnel: Tunnel object with connection details.

    Returns:
        Shiny UI card element with tunnel status.
    """
    # Status badge
    status_class = {
        "active": "badge-success",
        "disconnected": "badge-secondary",
        "reserved": "badge-warning",
    }.get(tunnel.status, "badge-secondary")

    # Type badge
    type_class = {
        "http": "badge-primary",
        "tcp": "badge-info",
        "udp": "badge-warning",
    }.get(tunnel.tunnel_type, "badge-secondary")

    # Format connected time
    connected_str = tunnel.connected_at.strftime("%Y-%m-%d %H:%M")

    return ui.card(
        ui.card_header(
            ui.tags.div(
                ui.tags.span(
                    tunnel.subdomain,
                    class_="tunnel-subdomain",
                ),
                ui.tags.span(
                    tunnel.status.upper(),
                    class_=f"badge {status_class}",
                ),
                class_="tunnel-header",
            ),
        ),
        ui.tags.div(
            # Public URL
            ui.tags.div(
                ui.tags.label("Public URL"),
                ui.tags.code(tunnel.public_url),
                class_="tunnel-field",
            ),
            # Local port
            ui.tags.div(
                ui.tags.label("Local Port"),
                ui.tags.span(str(tunnel.local_port)),
                class_="tunnel-field",
            ),
            # Type
            ui.tags.div(
                ui.tags.label("Type"),
                ui.tags.span(
                    tunnel.tunnel_type.upper(),
                    class_=f"badge {type_class}",
                ),
                class_="tunnel-field",
            ),
            # Connected since
            ui.tags.div(
                ui.tags.label("Connected"),
                ui.tags.span(connected_str),
                class_="tunnel-field",
            ),
            class_="tunnel-body",
        ),
        class_="tunnel-card",
    )
