"""Instanton API Token Management.

Create and manage API tokens for authenticating Instanton CLI connections
and programmatic API access. Tokens provide secure, revocable access
to tunnel creation and management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.components.token_table import (
    create_new_token_display,
    create_token_table,
)
from instanton.dashboard.services.tokens import get_token_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def page_ui() -> ui.TagChild:
    """Create the Instanton API token management page UI.

    Renders the token creation form and existing token list with
    usage statistics and revocation controls.

    Returns:
        Shiny UI element for token management.
    """
    return ui.div(
        ui.h2("API Tokens"),
        ui.p(
            "Use API tokens to authenticate CLI connections and API requests.",
            class_="text-muted",
        ),
        # Create token form
        ui.card(
            ui.card_header("Create New Token"),
            ui.tags.div(
                ui.layout_columns(
                    ui.input_text(
                        "token_name",
                        "Token Name",
                        placeholder="e.g., Development, Production",
                    ),
                    ui.input_action_button(
                        "btn_create_token",
                        "Create Token",
                        class_="btn-primary",
                    ),
                    col_widths=[8, 4],
                ),
                class_="create-token-form",
            ),
        ),
        # New token display (shown after creation)
        ui.output_ui("new_token_display"),
        ui.hr(),
        # Token list
        ui.h4("Your Tokens"),
        ui.output_ui("token_list"),
        class_="tokens-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton API token management page server logic.

    Handles token creation, listing, and revocation for managing
    API access credentials in the Instanton dashboard.

    Args:
        input: Shiny input object with form values.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    token_service = get_token_service()
    new_token = reactive.Value[str | None](None)
    token_refresh = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.btn_create_token)
    async def _create_token() -> None:
        user = current_user()
        if not user:
            ui.notification_show("Please log in first.", type="error")
            return

        name = input.token_name()
        if not name:
            ui.notification_show("Please enter a token name.", type="error")
            return

        raw_token, _ = await token_service.create_token(
            name=name,
            user_id=user.id,
        )

        new_token.set(raw_token)
        token_refresh.set(token_refresh() + 1)
        ui.notification_show("Token created successfully!", type="message")

    @output
    @render.ui
    def new_token_display() -> ui.TagChild | None:
        token = new_token()
        if not token:
            return None
        return create_new_token_display(token)

    @output
    @render.ui
    async def token_list() -> ui.TagChild:
        # Trigger refresh
        token_refresh()

        user = current_user()
        if not user:
            return ui.p("Please log in to manage tokens.", class_="text-muted")

        tokens = await token_service.list_tokens(user.id)
        return create_token_table(tokens)
