"""Dashboard UI components."""

from instanton.dashboard.components.navbar import create_navbar
from instanton.dashboard.components.stats_card import create_stats_card
from instanton.dashboard.components.token_table import create_token_table
from instanton.dashboard.components.tunnel_card import create_tunnel_card

__all__ = [
    "create_navbar",
    "create_stats_card",
    "create_token_table",
    "create_tunnel_card",
]
