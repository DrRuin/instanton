"""Instanton Cloud Dashboard.

A 100% Python web dashboard built with Shiny for Python.

Supports multiple backends:
- **SQLite** (default): Simple file-based storage for development
- **PostgreSQL**: Production-ready for self-hosted deployments
- **Supabase**: Cloud mode with managed auth and database

Two deployment modes:
- **Self-Hosted (local)**: SQLite or PostgreSQL, optional auth/anti-abuse
- **Cloud mode**: Supabase auth, 30-day log retention, anti-abuse protection

Usage:
    # Self-hosted with SQLite (default)
    instanton dashboard

    # Self-hosted with PostgreSQL
    instanton dashboard --database postgresql://user:pass@localhost/instanton

    # Self-hosted with anti-abuse enabled
    instanton dashboard --antiabuse

    # Cloud mode (Supabase)
    instanton dashboard --mode cloud
"""

from instanton.dashboard.app import create_app
from instanton.dashboard.config import DashboardConfig, DashboardMode, DatabaseType

__all__ = [
    "create_app",
    "DashboardConfig",
    "DashboardMode",
    "DatabaseType",
]
