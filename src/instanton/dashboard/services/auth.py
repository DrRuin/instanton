"""Instanton Authentication Service.

Handles user authentication for the Instanton Cloud dashboard.
In cloud mode, uses Supabase Auth with email/password authentication
and anti-abuse protection. In self-hosted mode, provides a local user
with unlimited access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from instanton.dashboard.services.supabase import (
    get_supabase_client,
    is_cloud_mode,
    is_local_mode,
)


@dataclass
class User:
    """Represents an authenticated user."""

    id: str
    email: str
    display_name: str | None = None
    tier: str = "free"
    max_tunnels: int = 5
    max_requests_per_day: int = 10000


class AuthService:
    """Instanton Authentication Service.

    Provides user authentication for the Instanton dashboard with support
    for both cloud mode (Supabase Auth with anti-abuse) and self-hosted
    mode (local user with unlimited access).
    """

    def __init__(self) -> None:
        """Initialize auth service."""
        self._abuse_checker: Any = None

    async def signup(
        self,
        email: str,
        password: str,
        ip: str | None = None,
        fingerprint: str | None = None,
    ) -> tuple[User | None, str | None]:
        """Sign up a new user (cloud mode only).

        Args:
            email: User email.
            password: User password.
            ip: Client IP address for anti-abuse.
            fingerprint: Browser fingerprint for anti-abuse.

        Returns:
            (User, None) on success
            (None, error_message) on failure
        """
        if is_local_mode():
            return None, "Signup not available in local mode"

        # Run anti-abuse checks
        if ip and fingerprint:
            from instanton.dashboard.antiabuse import AbuseCheckResult, AntiAbuseChecker

            if self._abuse_checker is None:
                self._abuse_checker = AntiAbuseChecker()

            abuse_result = await self._abuse_checker.full_signup_check(
                email=email,
                ip=ip,
                fingerprint=fingerprint,
            )

            if abuse_result != AbuseCheckResult.ALLOWED:
                return None, f"Signup blocked: {abuse_result.value}"

        # Create user in Supabase
        client = get_supabase_client()
        try:
            response = client.auth.sign_up(
                {
                    "email": email,
                    "password": password,
                }
            )

            if response.user:
                # Create profile with anti-abuse metadata
                await self._create_profile(
                    user_id=response.user.id,
                    email=email,
                    ip=ip,
                    fingerprint=fingerprint,
                )

                return (
                    User(
                        id=response.user.id,
                        email=email,
                        display_name=None,
                    ),
                    None,
                )

            return None, "Signup failed"

        except Exception as e:
            return None, str(e)

    async def login(
        self, email: str, password: str
    ) -> tuple[User | None, str | None]:
        """Log in an existing user (cloud mode only).

        Args:
            email: User email.
            password: User password.

        Returns:
            (User, None) on success
            (None, error_message) on failure
        """
        if is_local_mode():
            return None, "Login not available in local mode"

        client = get_supabase_client()
        try:
            response = client.auth.sign_in_with_password(
                {
                    "email": email,
                    "password": password,
                }
            )

            if response.user:
                # Fetch profile for tier/limits
                profile = await self._get_profile(response.user.id)

                return (
                    User(
                        id=response.user.id,
                        email=email,
                        display_name=profile.get("display_name") if profile else None,
                        tier=profile.get("tier", "free") if profile else "free",
                        max_tunnels=profile.get("max_tunnels", 5) if profile else 5,
                    ),
                    None,
                )

            return None, "Invalid credentials"

        except Exception as e:
            return None, str(e)

    async def logout(self) -> None:
        """Log out the current user (cloud mode only)."""
        if is_cloud_mode():
            client = get_supabase_client()
            client.auth.sign_out()

    async def get_current_user(self) -> User | None:
        """Get the currently authenticated user.

        Returns:
            User object or None if not authenticated.
        """
        if is_local_mode():
            # Local mode: Return a dummy local user
            return User(
                id="local",
                email="local@localhost",
                display_name="Local User",
                tier="unlimited",
                max_tunnels=999999,
                max_requests_per_day=999999999,
            )

        client = get_supabase_client()
        try:
            response = client.auth.get_user()
            if response and response.user:
                profile = await self._get_profile(response.user.id)
                return User(
                    id=response.user.id,
                    email=response.user.email or "",
                    display_name=profile.get("display_name") if profile else None,
                    tier=profile.get("tier", "free") if profile else "free",
                    max_tunnels=profile.get("max_tunnels", 5) if profile else 5,
                )
        except Exception:
            pass

        return None

    async def _create_profile(
        self,
        user_id: str,
        email: str,
        ip: str | None,
        fingerprint: str | None,
    ) -> None:
        """Create user profile with anti-abuse metadata."""
        if not is_cloud_mode():
            return

        client = get_supabase_client()

        profile_data: dict[str, Any] = {
            "id": user_id,
            "email": email,
        }

        if ip:
            profile_data["signup_ip"] = ip

            # Get IP info if available
            if self._abuse_checker:
                try:
                    ip_info = await self._abuse_checker.check_ip(ip)
                    profile_data["signup_country"] = ip_info.country
                    profile_data["is_vpn_detected"] = ip_info.is_vpn or ip_info.is_proxy
                except Exception:
                    pass

        if fingerprint:
            profile_data["signup_fingerprint"] = fingerprint

        try:
            client.table("profiles").insert(profile_data).execute()
        except Exception:
            # Profile might already exist
            pass

    async def _get_profile(self, user_id: str) -> dict[str, Any] | None:
        """Get user profile."""
        if not is_cloud_mode():
            return None

        client = get_supabase_client()
        try:
            response = (
                client.table("profiles").select("*").eq("id", user_id).single().execute()
            )
            return response.data
        except Exception:
            return None


# Singleton instance
_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    """Get the Instanton auth service singleton instance.

    Returns:
        Global AuthService instance for user authentication.
    """
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
