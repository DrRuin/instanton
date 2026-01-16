"""Scheduled task to clean up old traffic logs.

This module provides automated cleanup of traffic logs
older than the configured retention period (default: 30 days).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from instanton.dashboard.config import DashboardConfig

logger = logging.getLogger(__name__)


async def cleanup_old_logs(
    config: DashboardConfig,
    retention_days: int | None = None,
) -> int:
    """Delete traffic logs older than retention period.

    Args:
        config: Dashboard configuration.
        retention_days: Override retention period. If None, uses config value.

    Returns:
        Number of rows deleted.
    """
    from instanton.dashboard.config import DashboardMode
    from instanton.dashboard.services.supabase import get_local_storage, get_supabase_client

    if retention_days is None:
        retention_days = config.log_retention_days

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    cutoff_str = cutoff.isoformat()

    deleted_count = 0

    if config.mode == DashboardMode.CLOUD:
        # Delete from Supabase
        client = get_supabase_client()
        if client:
            try:
                result = (
                    client.table("traffic_logs")
                    .delete()
                    .lt("timestamp", cutoff_str)
                    .execute()
                )
                deleted_count = len(result.data) if result.data else 0
            except Exception as e:
                logger.error(f"Failed to cleanup Supabase logs: {e}")
    else:
        # Delete from local SQLite
        storage = get_local_storage()
        if storage:
            try:
                cursor = storage.conn.execute(
                    "DELETE FROM traffic_logs WHERE timestamp < ?",
                    (cutoff_str,),
                )
                deleted_count = cursor.rowcount
                storage.conn.commit()
            except Exception as e:
                logger.error(f"Failed to cleanup local logs: {e}")

    if deleted_count > 0:
        logger.info(
            f"Cleaned up {deleted_count} traffic logs older than {retention_days} days"
        )

    return deleted_count


async def run_cleanup_loop(
    config: DashboardConfig,
    interval_hours: int = 1,
) -> None:
    """Run cleanup task in a loop.

    Args:
        config: Dashboard configuration.
        interval_hours: Hours between cleanup runs.
    """
    logger.info(f"Starting cleanup loop (interval: {interval_hours}h)")

    while True:
        try:
            deleted = await cleanup_old_logs(config)
            if deleted > 0:
                logger.info(f"Cleanup completed: {deleted} logs removed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

        # Wait for next interval
        await asyncio.sleep(interval_hours * 3600)


def start_cleanup_task(config: DashboardConfig) -> asyncio.Task[None]:
    """Start the cleanup task in the background.

    Args:
        config: Dashboard configuration.

    Returns:
        asyncio Task that can be cancelled.
    """
    return asyncio.create_task(run_cleanup_loop(config))


async def cleanup_user_data(user_id: str, config: DashboardConfig) -> dict[str, int]:
    """Delete all data for a specific user.

    Used when user requests account deletion or data wipe.

    Args:
        user_id: User ID to delete data for.
        config: Dashboard configuration.

    Returns:
        Dict with counts of deleted items per table.
    """
    from instanton.dashboard.config import DashboardMode
    from instanton.dashboard.services.supabase import get_local_storage, get_supabase_client

    deleted = {
        "traffic_logs": 0,
        "tunnels": 0,
        "api_tokens": 0,
    }

    if config.mode == DashboardMode.CLOUD:
        client = get_supabase_client()
        if client:
            try:
                # Delete traffic logs
                result = (
                    client.table("traffic_logs")
                    .delete()
                    .eq("user_id", user_id)
                    .execute()
                )
                deleted["traffic_logs"] = len(result.data) if result.data else 0

                # Delete tunnels
                result = (
                    client.table("tunnels")
                    .delete()
                    .eq("user_id", user_id)
                    .execute()
                )
                deleted["tunnels"] = len(result.data) if result.data else 0

                # Delete API tokens
                result = (
                    client.table("api_tokens")
                    .delete()
                    .eq("user_id", user_id)
                    .execute()
                )
                deleted["api_tokens"] = len(result.data) if result.data else 0

            except Exception as e:
                logger.error(f"Failed to delete user data from Supabase: {e}")
    else:
        storage = get_local_storage()
        if storage:
            try:
                # Delete traffic logs
                cursor = storage.conn.execute(
                    "DELETE FROM traffic_logs WHERE user_id = ?",
                    (user_id,),
                )
                deleted["traffic_logs"] = cursor.rowcount

                # Delete tunnels
                cursor = storage.conn.execute(
                    "DELETE FROM tunnels WHERE user_id = ?",
                    (user_id,),
                )
                deleted["tunnels"] = cursor.rowcount

                # Delete API tokens
                cursor = storage.conn.execute(
                    "DELETE FROM api_tokens WHERE user_id = ?",
                    (user_id,),
                )
                deleted["api_tokens"] = cursor.rowcount

                storage.conn.commit()
            except Exception as e:
                logger.error(f"Failed to delete user data from local storage: {e}")

    logger.info(f"Deleted user data for {user_id}: {deleted}")
    return deleted


async def revoke_all_user_tokens(user_id: str, config: DashboardConfig) -> int:
    """Revoke all API tokens for a user.

    Args:
        user_id: User ID.
        config: Dashboard configuration.

    Returns:
        Number of tokens revoked.
    """
    from instanton.dashboard.config import DashboardMode
    from instanton.dashboard.services.supabase import get_local_storage, get_supabase_client

    revoked = 0
    now = datetime.now(UTC).isoformat()

    if config.mode == DashboardMode.CLOUD:
        client = get_supabase_client()
        if client:
            try:
                result = (
                    client.table("api_tokens")
                    .update({"revoked_at": now})
                    .eq("user_id", user_id)
                    .is_("revoked_at", "null")
                    .execute()
                )
                revoked = len(result.data) if result.data else 0
            except Exception as e:
                logger.error(f"Failed to revoke tokens in Supabase: {e}")
    else:
        storage = get_local_storage()
        if storage:
            try:
                cursor = storage.conn.execute(
                    "UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    (now, user_id),
                )
                revoked = cursor.rowcount
                storage.conn.commit()
            except Exception as e:
                logger.error(f"Failed to revoke tokens in local storage: {e}")

    logger.info(f"Revoked {revoked} tokens for user {user_id}")
    return revoked
