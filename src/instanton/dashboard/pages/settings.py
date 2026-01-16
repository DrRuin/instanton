"""Instanton Account Settings.

Provides account management functionality including viewing account info,
usage limits, and dangerous operations like data deletion and token revocation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.services.tokens import get_token_service
from instanton.dashboard.services.traffic import get_traffic_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def page_ui() -> ui.TagChild:
    """Create the Instanton settings page UI.

    Renders account information, usage limits, and danger zone controls
    for managing destructive operations like data deletion.

    Returns:
        Shiny UI element for account settings.
    """
    return ui.div(
        ui.h2("Settings"),
        ui.p("Manage your account settings.", class_="text-muted"),
        # Account info
        ui.card(
            ui.card_header("Account Information"),
            ui.tags.div(
                ui.output_ui("account_info"),
                class_="account-info",
            ),
        ),
        ui.hr(),
        # Usage limits
        ui.card(
            ui.card_header("Usage Limits"),
            ui.tags.div(
                ui.output_ui("usage_limits"),
                class_="usage-limits",
            ),
        ),
        ui.hr(),
        # Danger zone
        ui.card(
            ui.card_header(
                ui.tags.span("Danger Zone", class_="text-danger"),
            ),
            ui.tags.div(
                ui.p(
                    "These actions are irreversible. Please be careful.",
                    class_="text-muted",
                ),
                ui.input_action_button(
                    "btn_delete_all_data",
                    "Delete All Traffic Logs",
                    class_="btn-outline-danger",
                ),
                ui.input_action_button(
                    "btn_revoke_all_tokens",
                    "Revoke All Tokens",
                    class_="btn-outline-danger",
                ),
                class_="danger-zone",
            ),
        ),
        class_="settings-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton settings page server logic.

    Handles account information display and dangerous operations
    like bulk data deletion and token revocation.

    Args:
        input: Shiny input object.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    token_service = get_token_service()
    traffic_service = get_traffic_service()

    @output
    @render.ui
    def account_info() -> ui.TagChild:
        user = current_user()
        if not user:
            return ui.p("Please log in to view account info.", class_="text-muted")

        return ui.tags.div(
            ui.tags.div(
                ui.tags.label("Email"),
                ui.tags.span(user.email),
                class_="info-row",
            ),
            ui.tags.div(
                ui.tags.label("Display Name"),
                ui.tags.span(user.display_name or "(not set)"),
                class_="info-row",
            ),
            ui.tags.div(
                ui.tags.label("Account Tier"),
                ui.tags.span(
                    user.tier.upper(),
                    class_=f"badge badge-{_get_tier_color(user.tier)}",
                ),
                class_="info-row",
            ),
            ui.tags.div(
                ui.tags.label("User ID"),
                ui.tags.code(user.id),
                class_="info-row",
            ),
        )

    @output
    @render.ui
    def usage_limits() -> ui.TagChild:
        user = current_user()
        if not user:
            return ui.p("Please log in to view limits.", class_="text-muted")

        return ui.tags.div(
            ui.tags.div(
                ui.tags.label("Max Tunnels"),
                ui.tags.span(
                    str(user.max_tunnels)
                    if user.max_tunnels < 999999
                    else "Unlimited"
                ),
                class_="info-row",
            ),
            ui.tags.div(
                ui.tags.label("Max Requests/Day"),
                ui.tags.span(
                    f"{user.max_requests_per_day:,}"
                    if user.max_requests_per_day < 999999999
                    else "Unlimited"
                ),
                class_="info-row",
            ),
        )

    @reactive.effect
    @reactive.event(input.btn_delete_all_data)
    async def _delete_all_data() -> None:
        """Delete all traffic logs for the current user."""
        user = current_user()
        if not user:
            ui.notification_show("Please log in first.", type="error")
            return

        try:
            count = await traffic_service.delete_all_logs(user.id)
            ui.notification_show(
                f"Deleted {count:,} traffic log(s).",
                type="message",
            )
        except Exception as e:
            ui.notification_show(f"Error: {e}", type="error")

    @reactive.effect
    @reactive.event(input.btn_revoke_all_tokens)
    async def _revoke_all_tokens() -> None:
        """Revoke all API tokens for the current user."""
        user = current_user()
        if not user:
            ui.notification_show("Please log in first.", type="error")
            return

        try:
            count = await token_service.revoke_all_tokens(user.id)
            ui.notification_show(
                f"Revoked {count} API token(s).",
                type="message",
            )
        except Exception as e:
            ui.notification_show(f"Error: {e}", type="error")


def _get_tier_color(tier: str) -> str:
    """Get badge color for tier."""
    colors = {
        "free": "secondary",
        "pro": "primary",
        "enterprise": "success",
        "unlimited": "warning",
    }
    return colors.get(tier.lower(), "secondary")
