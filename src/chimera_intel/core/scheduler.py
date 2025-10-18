"""
A simple, cron-like scheduler for the Chimera Intel daemon.

This module provides the functionality to parse a cron schedule string and
determine if a job should be run at a given time. It is a lightweight,
dependency-free implementation designed specifically for the daemon's needs.
"""

from datetime import datetime
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)

# --- APScheduler Setup ---
# This creates a scheduler that runs in a background thread.


scheduler = BackgroundScheduler()
scheduler.start()


def add_job(
    func: Callable,
    trigger: str,
    cron_schedule: str,
    job_id: str,
    kwargs: Dict[str, Any],
):
    """Adds a job to the APScheduler."""
    if trigger == "cron":
        # Parse the schedule manually to preserve the correct argument order
        minute, hour, day, month, day_of_week = cron_schedule.split()
        cron_trigger = CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
        )

        scheduler.add_job(
            func=func,
            trigger=cron_trigger,
            id=job_id,
            replace_existing=True,
            kwargs=kwargs,
        )
        logger.info(
            f"Successfully added job '{job_id}' with schedule: '{cron_schedule}'"
        )


def is_time_to_run(cron_schedule: str, now: datetime) -> bool:
    """
    Checks if a command should be run based on a cron schedule string.

    Args:
        cron_schedule (str): A 5-part cron string (minute, hour, day of month, month, day of week).
        now (datetime): The current time to check against the schedule.

    Returns:
        bool: True if the job is due to run, False otherwise.
    """
    try:
        minute, hour, day_of_month, month, day_of_week = cron_schedule.split()

        # Check each part of the schedule against the current time

        if not _matches(minute, now.minute):
            return False
        if not _matches(hour, now.hour):
            return False
        if not _matches(day_of_month, now.day):
            return False
        if not _matches(month, now.month):
            return False
        # In cron, both Sunday and the 7th day can be 0 or 7.
        # Python's weekday() is Monday=0, Sunday=6. We adjust to cron's Sunday=0.

        current_day_of_week = (now.weekday() + 1) % 7
        if not _matches(day_of_week, current_day_of_week):
            return False
        return True
    except ValueError:
        logger.error(
            f"Invalid cron schedule format: '{cron_schedule}'. Expected 5 parts."
        )
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during schedule check: {e}")
        return False


def _matches(cron_part: str, time_value: int) -> bool:
    """Helper function to match a single cron field against a time value."""
    if cron_part == "*":
        return True
    # Handle lists (e.g., "1,15,30")

    if "," in cron_part:
        return any(_matches(part, time_value) for part in cron_part.split(","))
    # Handle ranges (e.g., "8-17")

    if "-" in cron_part:
        start, end = map(int, cron_part.split("-"))
        return start <= time_value <= end
    # Handle step values (e.g., "*/15")

    if "*/" in cron_part:
        step = int(cron_part.split("/")[1])
        return time_value % step == 0
    # Handle a specific value

    return int(cron_part) == time_value