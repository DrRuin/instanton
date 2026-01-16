"""Instanton Dashboard Navigation Bar.

Provides the primary navigation component for the Instanton dashboard,
displaying the logo, user information, and authentication controls.
"""

from __future__ import annotations

from shiny import ui


def create_navbar(current_user: dict | None = None) -> ui.TagChild:
    """Create the Instanton dashboard navigation bar.

    Renders the top navigation with branding, user email display,
    and login/logout controls based on authentication state.

    Args:
        current_user: Current user info dict or None if not authenticated.

    Returns:
        Shiny UI navigation element.
    """
    user_section = []

    if current_user:
        user_section = [
            ui.tags.span(
                current_user.get("email", "Local User"),
                class_="navbar-user-email",
            ),
            ui.input_action_button(
                "btn_logout",
                "Logout",
                class_="btn-sm btn-outline-secondary",
            ),
        ]
    else:
        user_section = [
            ui.input_action_button(
                "btn_login",
                "Login",
                class_="btn-sm btn-primary",
            ),
        ]

    return ui.tags.nav(
        ui.tags.div(
            # Logo
            ui.tags.a(
                ui.tags.span(
                    "Instanton",
                    class_="navbar-brand-text",
                ),
                href="#",
                class_="navbar-brand",
            ),
            # User section
            ui.tags.div(
                *user_section,
                class_="navbar-user",
            ),
            class_="navbar-container",
        ),
        class_="navbar",
    )
