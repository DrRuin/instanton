"""Instanton Traffic Inspector.

View, search, and replay HTTP requests flowing through Instanton tunnels.
Provides real-time traffic monitoring with request/response inspection
and the ability to replay captured requests for debugging.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.services.traffic import get_traffic_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User
    from instanton.dashboard.services.traffic import TrafficLog


def page_ui() -> ui.TagChild:
    """Create the Instanton traffic inspector page UI.

    Renders the traffic log table with filtering, search, and detail
    view capabilities for inspecting tunnel traffic.

    Returns:
        Shiny UI element for traffic inspection.
    """
    return ui.div(
        ui.h2("Traffic Inspector"),
        ui.p(
            "View and replay HTTP requests passing through your tunnels.",
            class_="text-muted",
        ),
        # Filters
        ui.layout_columns(
            ui.input_select(
                "inspector_tunnel",
                "Tunnel",
                choices={"all": "All Tunnels"},
            ),
            ui.input_select(
                "inspector_status",
                "Status",
                choices={
                    "all": "All",
                    "2xx": "2xx Success",
                    "3xx": "3xx Redirect",
                    "4xx": "4xx Client Error",
                    "5xx": "5xx Server Error",
                },
            ),
            ui.input_text(
                "inspector_search",
                "Search",
                placeholder="path, method...",
            ),
            col_widths=[4, 3, 5],
        ),
        ui.hr(),
        # Request list
        ui.output_ui("request_list"),
        # Request detail modal
        ui.output_ui("request_detail_modal"),
        class_="inspector-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton traffic inspector page server logic.

    Handles traffic log display, filtering, detail view rendering,
    and request replay functionality for the traffic inspector.

    Args:
        input: Shiny input object with filter and search values.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    traffic_service = get_traffic_service()
    selected_log = reactive.Value[TrafficLog | None](None)

    @output
    @render.ui
    async def request_list() -> ui.TagChild:
        # Auto-refresh every 2 seconds
        reactive.invalidate_later(2)

        user = current_user()
        if not user:
            return ui.p("Please log in to view traffic.", class_="text-muted")

        tunnel_id = input.inspector_tunnel()
        if tunnel_id == "all":
            tunnel_id = None

        status_filter = input.inspector_status()
        search = input.inspector_search()

        logs = await traffic_service.list_recent(
            user_id=user.id,
            tunnel_id=tunnel_id,
            status_filter=status_filter,
            search=search,
            limit=100,
        )

        if not logs:
            return ui.tags.div(
                ui.p("No traffic recorded yet.", class_="text-muted"),
                ui.p("Make requests to your tunnel URL to see them here."),
                class_="empty-state",
            )

        # Create table rows
        rows = []
        for i, log in enumerate(logs):
            status_class = _get_status_class(log.response_status)
            time_str = log.timestamp.strftime("%H:%M:%S")

            rows.append(
                ui.tags.tr(
                    ui.tags.td(time_str),
                    ui.tags.td(
                        ui.tags.span(
                            log.request_method,
                            class_=f"badge badge-{_get_method_color(log.request_method)}",
                        )
                    ),
                    ui.tags.td(
                        ui.tags.code(
                            log.request_path[:50]
                            + ("..." if len(log.request_path) > 50 else ""),
                            class_="small",
                        )
                    ),
                    ui.tags.td(
                        ui.tags.span(
                            str(log.response_status or "-"),
                            class_=f"badge {status_class}",
                        )
                    ),
                    ui.tags.td(f"{log.response_time_ms or '-'}ms"),
                    ui.tags.td(f"{log.response_size or 0}B"),
                    ui.tags.td(
                        ui.input_action_button(
                            f"view_log_{i}",
                            "View",
                            class_="btn-sm btn-outline-primary",
                        ),
                    ),
                    id=f"log_row_{i}",
                    class_="log-row",
                )
            )

        return ui.tags.table(
            ui.tags.thead(
                ui.tags.tr(
                    ui.tags.th("Time"),
                    ui.tags.th("Method"),
                    ui.tags.th("Path"),
                    ui.tags.th("Status"),
                    ui.tags.th("Duration"),
                    ui.tags.th("Size"),
                    ui.tags.th("Actions"),
                ),
            ),
            ui.tags.tbody(*rows),
            class_="table table-hover request-table",
        )

    @output
    @render.ui
    def request_detail_modal() -> ui.TagChild | None:
        log = selected_log()
        if not log:
            return None

        # Format headers
        req_headers = _format_headers(log.request_headers)
        resp_headers = _format_headers(log.response_headers)

        return ui.modal(
            # Request section
            ui.h5("Request"),
            ui.tags.div(
                ui.tags.strong(f"{log.request_method} {log.request_path}"),
                class_="request-line",
            ),
            ui.tags.pre(
                f"Headers:\n{req_headers}\n\nBody:\n{log.request_body or '(empty)'}",
                class_="code-block",
            ),
            ui.hr(),
            # Response section
            ui.h5(f"Response ({log.response_status})"),
            ui.tags.pre(
                f"Headers:\n{resp_headers}\n\nBody:\n{log.response_body or '(empty)'}",
                class_="code-block",
            ),
            ui.hr(),
            # Actions
            ui.input_action_button(
                "btn_replay",
                "Replay Request",
                class_="btn-primary",
            ),
            ui.input_action_button(
                "btn_close_modal",
                "Close",
                class_="btn-secondary",
            ),
            title=f"Request Detail - {log.response_time_ms}ms",
            easy_close=True,
        )


def _get_status_class(status: int | None) -> str:
    """Get CSS class for status code."""
    if not status:
        return "badge-secondary"
    if 200 <= status < 300:
        return "badge-success"
    if 300 <= status < 400:
        return "badge-info"
    if 400 <= status < 500:
        return "badge-warning"
    if status >= 500:
        return "badge-danger"
    return "badge-secondary"


def _get_method_color(method: str) -> str:
    """Get color for HTTP method."""
    colors = {
        "GET": "primary",
        "POST": "success",
        "PUT": "warning",
        "PATCH": "warning",
        "DELETE": "danger",
        "HEAD": "info",
        "OPTIONS": "secondary",
    }
    return colors.get(method.upper(), "secondary")


def _format_headers(headers: dict[str, str] | None) -> str:
    """Format headers for display."""
    if not headers:
        return "(none)"
    return "\n".join(f"{k}: {v}" for k, v in headers.items())
