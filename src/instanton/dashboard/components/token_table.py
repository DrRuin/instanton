"""Instanton API Token Table Components.

Provides reusable components for displaying and managing API tokens
in the Instanton dashboard, including the token list table and
new token creation display.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shiny import ui

if TYPE_CHECKING:
    from instanton.dashboard.services.tokens import APIToken


def create_token_table(tokens: list[APIToken]) -> ui.TagChild:
    """Create an Instanton API token list table.

    Renders a table displaying all active API tokens with their names,
    prefixes, creation dates, usage stats, and revocation controls.

    Args:
        tokens: List of APIToken objects to display.

    Returns:
        Shiny UI table element with token list.
    """
    if not tokens:
        return ui.tags.div(
            ui.tags.p(
                "No API tokens yet. Create one to get started.",
                class_="text-muted",
            ),
            class_="empty-state",
        )

    rows = []
    for token in tokens:
        # Format dates
        created_str = token.created_at.strftime("%Y-%m-%d")
        last_used_str = (
            token.last_used_at.strftime("%Y-%m-%d")
            if token.last_used_at
            else "Never"
        )

        rows.append(
            ui.tags.tr(
                ui.tags.td(token.name),
                ui.tags.td(
                    ui.tags.code(f"{token.token_prefix}..."),
                ),
                ui.tags.td(created_str),
                ui.tags.td(last_used_str),
                ui.tags.td(f"{token.total_requests:,}"),
                ui.tags.td(
                    ui.input_action_button(
                        f"revoke_{token.id}",
                        "Revoke",
                        class_="btn-sm btn-outline-danger",
                    ),
                ),
            )
        )

    return ui.tags.table(
        ui.tags.thead(
            ui.tags.tr(
                ui.tags.th("Name"),
                ui.tags.th("Token"),
                ui.tags.th("Created"),
                ui.tags.th("Last Used"),
                ui.tags.th("Requests"),
                ui.tags.th("Actions"),
            ),
        ),
        ui.tags.tbody(*rows),
        class_="table token-table",
    )


def create_new_token_display(raw_token: str) -> ui.TagChild:
    """Create display for a newly created Instanton API token.

    Renders a warning card showing the raw token value that must be
    copied immediately, as it won't be displayed again.

    Args:
        raw_token: The raw token string (tach_...) to display once.

    Returns:
        Shiny UI card element with token display and copy button.
    """
    return ui.card(
        ui.card_header(
            ui.tags.span("New Token Created", class_="text-success"),
        ),
        ui.tags.div(
            ui.tags.p(
                "Copy this token now. You won't be able to see it again!",
                class_="text-warning",
            ),
            ui.tags.div(
                ui.tags.pre(
                    raw_token,
                    class_="token-display",
                ),
                ui.input_action_button(
                    "btn_copy_token",
                    "Copy to Clipboard",
                    class_="btn-sm btn-primary",
                ),
                class_="token-display-wrapper",
            ),
            class_="new-token-body",
        ),
        class_="new-token-card",
    )
