"""Instanton Dashboard Statistics Card.

Provides reusable statistics card component for displaying metrics
like tunnel counts, request volumes, and performance data.
"""

from __future__ import annotations

from shiny import ui


def create_stats_card(
    title: str,
    value_output: ui.TagChild,
    icon: str | None = None,
    color: str = "primary",
) -> ui.TagChild:
    """Create an Instanton dashboard statistics card.

    Renders a styled card showing a metric title and dynamic value,
    used for dashboard overview statistics.

    Args:
        title: Card title/label (e.g., "Active Tunnels").
        value_output: Shiny output element for the dynamic value.
        icon: Optional icon name for visual enhancement.
        color: Card color theme (primary, success, warning, danger, info).

    Returns:
        Shiny UI card element with statistics display.
    """
    icon_element = None
    if icon:
        icon_element = ui.tags.span(
            icon,
            class_="stats-card-icon",
        )

    return ui.card(
        ui.tags.div(
            ui.tags.div(
                ui.tags.h6(title, class_="stats-card-title"),
                ui.tags.div(
                    value_output,
                    class_="stats-card-value",
                ),
                class_="stats-card-content",
            ),
            icon_element,
            class_=f"stats-card stats-card-{color}",
        ),
        class_="stats-card-wrapper",
    )
