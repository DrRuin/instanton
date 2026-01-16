"""Instanton Cloud Dashboard - Shiny for Python.

Main application entry point that creates and configures the Shiny dashboard.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from shiny import App, reactive, ui

from instanton.dashboard.config import DashboardConfig, DashboardMode
from instanton.dashboard.pages import dashboard, inspector, login, settings, tokens, tunnels
from instanton.dashboard.services.auth import get_auth_service
from instanton.dashboard.services.supabase import init_storage

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def create_app(config: DashboardConfig | None = None) -> App:
    """Create the Shiny dashboard application.

    Args:
        config: Dashboard configuration. If None, loads from environment.

    Returns:
        Configured Shiny App instance.
    """
    if config is None:
        config = DashboardConfig()

    # Initialize storage backend
    init_storage(config)

    # Get static assets directory
    static_dir = Path(__file__).parent / "static"

    # Create the app UI
    app_ui = _create_ui(config)

    def server(input: object, output: object, session: object) -> None:
        """Main server function for the Shiny app."""
        # Reactive value for current user
        current_user: reactive.Value[User | None] = reactive.Value(None)

        # Auth service
        auth_service = get_auth_service()

        @reactive.effect
        async def _check_auth() -> None:
            """Check authentication state on load."""
            user = await auth_service.get_current_user()
            current_user.set(user)

        # Login page server (handles auth state changes)
        login.page_server(input, output, session, current_user)

        # Main page servers
        dashboard.page_server(input, output, session, current_user)
        tunnels.page_server(input, output, session, current_user)
        inspector.page_server(input, output, session, current_user)
        tokens.page_server(input, output, session, current_user)
        settings.page_server(input, output, session, current_user)

    return App(
        app_ui,
        server,
        static_assets=str(static_dir) if static_dir.exists() else None,
    )


def _create_ui(config: DashboardConfig) -> ui.TagChild:
    """Create the main application UI.

    Args:
        config: Dashboard configuration.

    Returns:
        Shiny UI element.
    """
    # Determine title based on mode
    if config.mode == DashboardMode.CLOUD:
        title_text = "Instanton Cloud"
    else:
        title_text = "Instanton Inspector"

    return ui.page_navbar(
        # Navigation tabs
        ui.nav_panel("Dashboard", dashboard.page_ui()),
        ui.nav_panel("Tunnels", tunnels.page_ui()),
        ui.nav_panel("Inspector", inspector.page_ui()),
        ui.nav_panel("API Tokens", tokens.page_ui()),
        ui.nav_panel("Settings", settings.page_ui()),
        # Login page (shown when not authenticated in cloud mode)
        ui.nav_panel(
            "Login",
            login.page_ui(),
            value="login",
        ),
        # Header title
        title=ui.tags.span(
            ui.tags.strong("Instanton"),
            f" | {title_text}",
            class_="navbar-brand-text",
        ),
        # Include custom CSS
        header=ui.tags.head(
            ui.tags.link(rel="stylesheet", href="styles.css"),
            ui.tags.meta(name="viewport", content="width=device-width, initial-scale=1"),
        ),
        # Footer
        footer=ui.tags.footer(
            ui.tags.div(
                ui.tags.span(f"Instanton Dashboard | Mode: {config.mode.value}"),
                ui.tags.span(" | "),
                ui.tags.a(
                    "Documentation",
                    href="https://instanton.tech/docs",
                    target="_blank",
                ),
                class_="footer-content",
            ),
            class_="dashboard-footer",
        ),
        id="main_navbar",
        inverse=True,
        fillable=True,
    )


# Default app instance (for uvicorn)
app = create_app()
