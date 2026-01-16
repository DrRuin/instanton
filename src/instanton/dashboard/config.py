"""Dashboard configuration."""

from __future__ import annotations

import os
from enum import Enum

from pydantic import BaseModel, Field


class DashboardMode(str, Enum):
    """Dashboard operating mode."""

    LOCAL = "local"
    CLOUD = "cloud"


class DatabaseType(str, Enum):
    """Database backend type."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    SUPABASE = "supabase"


class DashboardConfig(BaseModel):
    """Configuration for Instanton Dashboard.

    Environment Variables:
        INSTANTON_DASHBOARD_MODE: "local" or "cloud"
        INSTANTON_DATABASE_URL: Database connection string
            - sqlite:///path/to/db.sqlite or sqlite::memory:
            - postgresql://user:pass@host:port/dbname
        INSTANTON_SUPABASE_URL: Supabase project URL (cloud mode)
        INSTANTON_SUPABASE_ANON_KEY: Supabase anonymous key (cloud mode)
        INSTANTON_SUPABASE_SERVICE_KEY: Supabase service role key
        INSTANTON_IPINFO_TOKEN: ipinfo.io API token for VPN detection

    Self-Hosted Examples:
        # SQLite (simple, single file)
        INSTANTON_DATABASE_URL=sqlite:///var/lib/instanton/dashboard.db

        # In-memory SQLite (for testing)
        INSTANTON_DATABASE_URL=sqlite::memory:

        # PostgreSQL (production)
        INSTANTON_DATABASE_URL=postgresql://user:pass@localhost:5432/instanton

        # With anti-abuse enabled
        INSTANTON_ANTIABUSE_ENABLED=true
        INSTANTON_MAX_ACCOUNTS_PER_IP=5
    """

    mode: DashboardMode = Field(
        default=DashboardMode.LOCAL,
        description="Dashboard operating mode: local (self-hosted) or cloud (Supabase)",
    )

    # Server settings
    host: str = Field(default="0.0.0.0", description="Dashboard bind host")
    port: int = Field(default=4040, description="Dashboard bind port")

    # Database settings (self-hosted mode)
    database_url: str | None = Field(
        default=None,
        description=(
            "Database connection string. Supports:\n"
            "  - sqlite:///path/to/db.sqlite\n"
            "  - sqlite::memory:\n"
            "  - postgresql://user:pass@host:port/dbname"
        ),
    )

    # Supabase settings (cloud mode)
    supabase_url: str | None = Field(
        default=None,
        description="Supabase project URL",
    )
    supabase_anon_key: str | None = Field(
        default=None,
        description="Supabase anonymous key",
    )
    supabase_service_key: str | None = Field(
        default=None,
        description="Supabase service role key for admin operations",
    )

    # Legacy local storage path (fallback if no database_url)
    local_storage_path: str = Field(
        default="instanton_dashboard.db",
        description="SQLite database path (used if database_url not set)",
    )

    # Anti-abuse settings (works in both modes)
    antiabuse_enabled: bool = Field(
        default=False,
        description="Enable anti-abuse protection (self-hosted mode)",
    )
    ipinfo_token: str | None = Field(
        default=None,
        description="ipinfo.io API token for VPN/proxy detection (optional)",
    )
    max_accounts_per_ip: int = Field(
        default=3,
        description="Maximum accounts allowed per IP address",
    )
    max_accounts_per_fingerprint: int = Field(
        default=2,
        description="Maximum accounts allowed per browser fingerprint",
    )
    high_risk_threshold: int = Field(
        default=70,
        description="IP risk score threshold (0-100) for blocking signups",
    )
    block_vpn: bool = Field(
        default=True,
        description="Block signups from VPN connections",
    )
    block_proxy: bool = Field(
        default=True,
        description="Block signups from proxy connections",
    )
    block_datacenter: bool = Field(
        default=False,
        description="Block signups from datacenter IPs",
    )
    block_disposable_email: bool = Field(
        default=True,
        description="Block signups with disposable email addresses",
    )

    # Traffic log settings
    log_retention_days: int = Field(
        default=0,
        description="Days to retain traffic logs (0 = unlimited)",
    )
    max_logs: int = Field(
        default=100000,
        description="Maximum traffic logs to keep (0 = unlimited)",
    )

    # Auto-refresh settings
    inspector_refresh_interval: float = Field(
        default=2.0,
        description="Traffic inspector auto-refresh interval in seconds",
    )

    # Authentication settings (self-hosted)
    auth_enabled: bool = Field(
        default=False,
        description="Enable authentication in self-hosted mode",
    )
    auth_secret_key: str | None = Field(
        default=None,
        description="Secret key for JWT tokens (self-hosted auth)",
    )

    @classmethod
    def from_env(cls) -> DashboardConfig:
        """Create configuration from environment variables."""
        mode_str = os.getenv("INSTANTON_DASHBOARD_MODE", "local")
        mode = DashboardMode(mode_str.lower())

        # Parse boolean env vars
        def parse_bool(key: str, default: bool = False) -> bool:
            val = os.getenv(key, "").lower()
            if val in ("true", "1", "yes", "on"):
                return True
            if val in ("false", "0", "no", "off"):
                return False
            return default

        return cls(
            mode=mode,
            host=os.getenv("INSTANTON_DASHBOARD_HOST", "0.0.0.0"),
            port=int(os.getenv("INSTANTON_DASHBOARD_PORT", "4040")),
            # Database
            database_url=os.getenv("INSTANTON_DATABASE_URL"),
            local_storage_path=os.getenv(
                "INSTANTON_DASHBOARD_DB", "instanton_dashboard.db"
            ),
            # Supabase
            supabase_url=os.getenv("INSTANTON_SUPABASE_URL"),
            supabase_anon_key=os.getenv("INSTANTON_SUPABASE_ANON_KEY"),
            supabase_service_key=os.getenv("INSTANTON_SUPABASE_SERVICE_KEY"),
            # Anti-abuse
            antiabuse_enabled=parse_bool("INSTANTON_ANTIABUSE_ENABLED", False),
            ipinfo_token=os.getenv("INSTANTON_IPINFO_TOKEN"),
            max_accounts_per_ip=int(os.getenv("INSTANTON_MAX_ACCOUNTS_PER_IP", "3")),
            max_accounts_per_fingerprint=int(
                os.getenv("INSTANTON_MAX_ACCOUNTS_PER_FINGERPRINT", "2")
            ),
            block_vpn=parse_bool("INSTANTON_BLOCK_VPN", True),
            block_proxy=parse_bool("INSTANTON_BLOCK_PROXY", True),
            block_datacenter=parse_bool("INSTANTON_BLOCK_DATACENTER", False),
            block_disposable_email=parse_bool("INSTANTON_BLOCK_DISPOSABLE_EMAIL", True),
            # Logs
            log_retention_days=int(os.getenv("INSTANTON_LOG_RETENTION_DAYS", "0")),
            max_logs=int(os.getenv("INSTANTON_MAX_LOGS", "100000")),
            # Auth
            auth_enabled=parse_bool("INSTANTON_AUTH_ENABLED", False),
            auth_secret_key=os.getenv("INSTANTON_AUTH_SECRET_KEY"),
        )

    @property
    def is_cloud_mode(self) -> bool:
        """Check if running in cloud mode."""
        return self.mode == DashboardMode.CLOUD

    @property
    def is_local_mode(self) -> bool:
        """Check if running in local/self-hosted mode."""
        return self.mode == DashboardMode.LOCAL

    @property
    def database_type(self) -> DatabaseType:
        """Determine the database type from configuration."""
        if self.is_cloud_mode and self.supabase_url:
            return DatabaseType.SUPABASE

        if self.database_url:
            if self.database_url.startswith("postgresql://"):
                return DatabaseType.POSTGRESQL
            if self.database_url.startswith("postgres://"):
                return DatabaseType.POSTGRESQL

        return DatabaseType.SQLITE

    @property
    def effective_database_url(self) -> str:
        """Get the effective database URL to use."""
        if self.database_url:
            return self.database_url
        # Fall back to SQLite with local_storage_path
        return f"sqlite:///{self.local_storage_path}"

    @property
    def is_antiabuse_enabled(self) -> bool:
        """Check if anti-abuse is enabled."""
        # Always enabled in cloud mode
        if self.is_cloud_mode:
            return True
        # Configurable in local mode
        return self.antiabuse_enabled

    def validate_cloud_config(self) -> list[str]:
        """Validate cloud mode configuration.

        Returns:
            List of missing configuration items.
        """
        missing = []
        if not self.supabase_url:
            missing.append("INSTANTON_SUPABASE_URL")
        if not self.supabase_anon_key:
            missing.append("INSTANTON_SUPABASE_ANON_KEY")
        return missing

    def validate_database_config(self) -> list[str]:
        """Validate database configuration.

        Returns:
            List of configuration issues.
        """
        issues = []

        if self.database_url:
            url = self.database_url
            if not any(
                url.startswith(prefix)
                for prefix in ("sqlite://", "postgresql://", "postgres://")
            ):
                issues.append(
                    "Invalid database_url. Must start with sqlite://, postgresql://, or postgres://"
                )

            # Check PostgreSQL requires auth
            if url.startswith(("postgresql://", "postgres://")):
                if "@" not in url:
                    issues.append(
                        "PostgreSQL URL should include credentials: postgresql://user:pass@host/db"
                    )

        return issues
