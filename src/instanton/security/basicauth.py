from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass

PROXY_AUTH_HEADER = "Proxy-Authorization"
PROXY_AUTH_CHALLENGE = "Proxy-Authenticate"


@dataclass
class AuthResult:
    allowed: bool
    reason: str


class BasicAuthenticator:
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    def check(self, auth_header: str | None) -> AuthResult:
        if not auth_header:
            return AuthResult(allowed=False, reason="Missing Proxy-Authorization header")

        if not auth_header.startswith("Basic "):
            return AuthResult(allowed=False, reason="Invalid authorization scheme")

        encoded = auth_header[6:]
        if not secrets.compare_digest(encoded, self._credentials):
            return AuthResult(allowed=False, reason="Invalid credentials")

        return AuthResult(allowed=True, reason="Authenticated")

    @property
    def username(self) -> str:
        return self._username


def create_basic_authenticator(username: str, password: str) -> BasicAuthenticator:
    return BasicAuthenticator(username=username, password=password)
