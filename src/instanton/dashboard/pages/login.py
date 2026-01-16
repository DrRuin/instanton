"""Instanton Cloud Authentication.

Provides login and signup functionality for the Instanton Cloud dashboard.
In cloud mode, users authenticate via Supabase Auth with anti-abuse protection.
In self-hosted mode, authentication is optional.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shiny import reactive, render, ui

from instanton.dashboard.services.auth import get_auth_service

if TYPE_CHECKING:
    from instanton.dashboard.services.auth import User


def page_ui() -> ui.TagChild:
    """Create the Instanton authentication page UI.

    Renders a tabbed interface with login and signup forms for
    authenticating users to the Instanton Cloud dashboard.

    Returns:
        Shiny UI element containing the authentication forms.
    """
    return ui.div(
        ui.tags.div(
            ui.h2("Welcome to Instanton"),
            ui.p("Sign in to manage your tunnels and view traffic.", class_="text-muted"),
            # Tab set for login/signup
            ui.navset_tab(
                ui.nav_panel(
                    "Login",
                    ui.tags.div(
                        ui.input_text(
                            "login_email",
                            "Email",
                            placeholder="you@example.com",
                        ),
                        ui.input_password(
                            "login_password",
                            "Password",
                            placeholder="Your password",
                        ),
                        ui.input_action_button(
                            "btn_login",
                            "Sign In",
                            class_="btn-primary btn-block",
                        ),
                        ui.output_ui("login_error"),
                        class_="login-form",
                    ),
                ),
                ui.nav_panel(
                    "Sign Up",
                    ui.tags.div(
                        ui.input_text(
                            "signup_email",
                            "Email",
                            placeholder="you@example.com",
                        ),
                        ui.input_password(
                            "signup_password",
                            "Password",
                            placeholder="Choose a password",
                        ),
                        ui.input_password(
                            "signup_password_confirm",
                            "Confirm Password",
                            placeholder="Confirm your password",
                        ),
                        ui.input_action_button(
                            "btn_signup",
                            "Create Account",
                            class_="btn-primary btn-block",
                        ),
                        ui.output_ui("signup_error"),
                        class_="signup-form",
                    ),
                ),
                id="auth_tabs",
            ),
            class_="auth-container",
        ),
        class_="login-page",
    )


def page_server(
    input: Any,
    output: Any,
    session: Any,
    current_user: reactive.Value[User | None],
) -> None:
    """Instanton authentication page server logic.

    Handles login and signup form submissions, validates input,
    and updates the current user state on successful authentication.

    Args:
        input: Shiny input object with form values.
        output: Shiny output object for rendering.
        session: Shiny session for user context.
        current_user: Reactive value tracking the authenticated user.
    """
    auth_service = get_auth_service()
    login_error_msg = reactive.Value("")
    signup_error_msg = reactive.Value("")

    @reactive.effect
    @reactive.event(input.btn_login)
    async def _handle_login() -> None:
        email = input.login_email()
        password = input.login_password()

        if not email or not password:
            login_error_msg.set("Please enter email and password.")
            return

        user, error = await auth_service.login(email, password)

        if error:
            login_error_msg.set(error)
        elif user:
            login_error_msg.set("")
            current_user.set(user)

    @reactive.effect
    @reactive.event(input.btn_signup)
    async def _handle_signup() -> None:
        email = input.signup_email()
        password = input.signup_password()
        password_confirm = input.signup_password_confirm()

        if not email or not password:
            signup_error_msg.set("Please enter email and password.")
            return

        if password != password_confirm:
            signup_error_msg.set("Passwords do not match.")
            return

        if len(password) < 8:
            signup_error_msg.set("Password must be at least 8 characters.")
            return

        # Get client info for anti-abuse
        # Note: In real implementation, get from request headers
        client_ip = None
        fingerprint = None

        user, error = await auth_service.signup(
            email=email,
            password=password,
            ip=client_ip,
            fingerprint=fingerprint,
        )

        if error:
            signup_error_msg.set(error)
        elif user:
            signup_error_msg.set("")
            current_user.set(user)

    @output
    @render.ui
    def login_error() -> ui.TagChild | None:
        """Render login error message if present."""
        error = login_error_msg()
        if error:
            return ui.tags.div(error, class_="alert alert-danger")
        return None

    @output
    @render.ui
    def signup_error() -> ui.TagChild | None:
        """Render signup error message if present."""
        error = signup_error_msg()
        if error:
            return ui.tags.div(error, class_="alert alert-danger")
        return None
