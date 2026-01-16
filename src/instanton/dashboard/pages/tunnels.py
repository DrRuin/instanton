"""Instanton Tunnel Management.

View and control active tunnel connections in the Instanton dashboard.
Displays real-time tunnel status, connection details, and provides
controls for managing tunnel lifecycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.services.tunnels import get_tunnel_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def page_ui() -> ui.TagChild:
    """Create the Instanton tunnel management page UI.

    Renders the tunnel list with filtering options and status indicators
    for monitoring active and historical tunnel connections.

    Returns:
        Shiny UI element for tunnel management.
    """
    return ui.div(
        ui.h2("Tunnels"),
        ui.p(
            "Manage your active and recent tunnel connections.",
            class_="text-muted",
        ),
        # Filters
        ui.layout_columns(
            ui.input_select(
                "tunnel_status_filter",
                "Status",
                choices={
                    "all": "All",
                    "active": "Active",
                    "disconnected": "Disconnected",
                    "reserved": "Reserved",
                },
            ),
            ui.input_select(
                "tunnel_type_filter",
                "Type",
                choices={
                    "all": "All",
                    "http": "HTTP",
                    "tcp": "TCP",
                    "udp": "UDP",
                },
            ),
            ui.input_action_button(
                "btn_refresh_tunnels",
                "Refresh",
                class_="btn-secondary",
            ),
            col_widths=[4, 4, 4],
        ),
        ui.hr(),
        # Tunnel list
        ui.output_ui("tunnel_list"),
        class_="tunnels-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton tunnel management page server logic.

    Handles tunnel list rendering with filtering and status updates
    for the tunnel management interface.

    Args:
        input: Shiny input object with filter values.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    tunnel_service = get_tunnel_service()

    @output
    @render.ui
    async def tunnel_list() -> ui.TagChild:
        # Trigger refresh on button click
        input.btn_refresh_tunnels()

        user = current_user()
        if not user:
            return ui.p("Please log in to view tunnels.", class_="text-muted")

        tunnels = await tunnel_service.list_all(user.id)

        # Apply filters
        status_filter = input.tunnel_status_filter()
        type_filter = input.tunnel_type_filter()

        if status_filter != "all":
            tunnels = [t for t in tunnels if t.status == status_filter]

        if type_filter != "all":
            tunnels = [t for t in tunnels if t.tunnel_type == type_filter]

        if not tunnels:
            return ui.tags.div(
                ui.p("No tunnels found.", class_="text-muted"),
                class_="empty-state",
            )

        # Create table rows
        rows = []
        for tunnel in tunnels:
            status_class = {
                "active": "badge-success",
                "disconnected": "badge-secondary",
                "reserved": "badge-warning",
            }.get(tunnel.status, "badge-secondary")

            type_class = {
                "http": "badge-primary",
                "tcp": "badge-info",
                "udp": "badge-warning",
            }.get(tunnel.tunnel_type, "badge-secondary")

            connected_str = tunnel.connected_at.strftime("%Y-%m-%d %H:%M")

            rows.append(
                ui.tags.tr(
                    ui.tags.td(tunnel.subdomain),
                    ui.tags.td(
                        ui.tags.span(
                            tunnel.tunnel_type.upper(),
                            class_=f"badge {type_class}",
                        )
                    ),
                    ui.tags.td(str(tunnel.local_port)),
                    ui.tags.td(
                        ui.tags.code(tunnel.public_url, class_="small"),
                    ),
                    ui.tags.td(
                        ui.tags.span(
                            tunnel.status.upper(),
                            class_=f"badge {status_class}",
                        )
                    ),
                    ui.tags.td(connected_str),
                )
            )

        return ui.tags.table(
            ui.tags.thead(
                ui.tags.tr(
                    ui.tags.th("Subdomain"),
                    ui.tags.th("Type"),
                    ui.tags.th("Local Port"),
                    ui.tags.th("Public URL"),
                    ui.tags.th("Status"),
                    ui.tags.th("Connected"),
                ),
            ),
            ui.tags.tbody(*rows),
            class_="table table-hover",
        )
