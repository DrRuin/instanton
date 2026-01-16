"""Instanton Dashboard - Main Overview.

The primary landing page for the Instanton Cloud dashboard, displaying
real-time statistics, active tunnel status, and quick-start guides.
Automatically refreshes to show live tunnel and traffic data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.components.stats_card import create_stats_card
from instanton.dashboard.components.tunnel_card import create_tunnel_card
from instanton.dashboard.services.traffic import get_traffic_service
from instanton.dashboard.services.tunnels import get_tunnel_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def page_ui() -> ui.TagChild:
    """Create the Instanton dashboard overview page UI.

    Renders the main dashboard with statistics cards, active tunnel list,
    and quick-start command examples for new users.

    Returns:
        Shiny UI element for the dashboard overview.
    """
    return ui.div(
        ui.h2("Dashboard"),
        # Stats row
        ui.layout_columns(
            create_stats_card(
                "Active Tunnels",
                ui.output_text("stat_tunnels"),
                color="primary",
            ),
            create_stats_card(
                "Requests Today",
                ui.output_text("stat_requests"),
                color="success",
            ),
            create_stats_card(
                "Avg Response",
                ui.output_text("stat_response"),
                color="info",
            ),
            create_stats_card(
                "Error Rate",
                ui.output_text("stat_errors"),
                color="warning",
            ),
            col_widths=[3, 3, 3, 3],
        ),
        ui.hr(),
        # Active tunnels
        ui.h4("Active Tunnels"),
        ui.output_ui("tunnel_cards"),
        # Quick start
        ui.hr(),
        ui.h4("Quick Start"),
        ui.tags.div(
            ui.p("Expose a local server to the internet:"),
            ui.tags.pre("instanton --port 8000"),
            ui.p("TCP tunnel (e.g., SSH, databases):"),
            ui.tags.pre("instanton tcp 5432"),
            ui.p("UDP tunnel (e.g., DNS, gaming):"),
            ui.tags.pre("instanton udp 53"),
            class_="quick-start",
        ),
        class_="dashboard-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton dashboard page server logic.

    Handles reactive data binding for dashboard statistics including
    tunnel counts, request volumes, response times, and error rates.

    Args:
        input: Shiny input object.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    tunnel_service = get_tunnel_service()
    traffic_service = get_traffic_service()

    @output
    @render.text
    async def stat_tunnels() -> str:
        """Display count of active tunnels."""
        user = current_user()
        if not user:
            return "0"
        count = await tunnel_service.count_active(user.id)
        return str(count)

    @output
    @render.text
    async def stat_requests() -> str:
        """Display total requests processed today."""
        user = current_user()
        if not user:
            return "0"
        count = await tunnel_service.count_requests_today(user.id)
        return f"{count:,}"

    @output
    @render.text
    async def stat_response() -> str:
        """Display average response time from recent traffic logs."""
        user = current_user()
        if not user:
            return "- ms"

        logs = await traffic_service.list_recent(user_id=user.id, limit=100)
        if not logs:
            return "- ms"

        response_times = [
            log.response_time_ms for log in logs if log.response_time_ms is not None
        ]
        if not response_times:
            return "- ms"

        avg_ms = sum(response_times) / len(response_times)
        return f"{avg_ms:.0f} ms"

    @output
    @render.text
    async def stat_errors() -> str:
        """Display error rate (4xx/5xx responses) from recent traffic."""
        user = current_user()
        if not user:
            return "0%"

        logs = await traffic_service.list_recent(user_id=user.id, limit=100)
        if not logs:
            return "0%"

        total = len(logs)
        errors = sum(
            1
            for log in logs
            if log.response_status is not None and log.response_status >= 400
        )

        if total == 0:
            return "0%"

        error_rate = (errors / total) * 100
        return f"{error_rate:.1f}%"

    @output
    @render.ui
    async def tunnel_cards() -> ui.TagChild:
        user = current_user()
        if not user:
            return ui.p("Please log in to view tunnels.", class_="text-muted")

        tunnels = await tunnel_service.list_active(user.id)

        if not tunnels:
            return ui.tags.div(
                ui.p("No active tunnels.", class_="text-muted"),
                ui.tags.div(
                    ui.p("Start a tunnel with:"),
                    ui.tags.pre("instanton --port 8000"),
                    class_="empty-state-hint",
                ),
                class_="empty-state",
            )

        # Create tunnel cards
        cards = [create_tunnel_card(t) for t in tunnels]

        return ui.layout_columns(
            *cards,
            col_widths=[4] * len(cards),
        )
