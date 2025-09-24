import unittest
from datetime import datetime
from chimera_intel.core.scheduler import is_time_to_run


class TestScheduler(unittest.TestCase):
    """Test cases for the cron scheduler module."""

    def test_is_time_to_run_every_minute(self):
        """Tests the '*' wildcard for every minute."""
        now = datetime(2025, 9, 23, 10, 30)
        self.assertTrue(is_time_to_run("* * * * *", now))

    def test_is_time_to_run_specific_time_match(self):
        """Tests an exact time match."""
        now = datetime(2025, 9, 23, 10, 30)
        self.assertTrue(is_time_to_run("30 10 23 9 2", now))  # 2 is Tuesday

    def test_is_time_to_run_specific_time_no_match(self):
        """Tests a non-matching specific time."""
        now = datetime(2025, 9, 23, 10, 31)
        self.assertFalse(is_time_to_run("30 10 23 9 2", now))

    def test_is_time_to_run_range_match(self):
        """Tests a matching time within a range."""
        now = datetime(2025, 9, 23, 14, 0)  # 2 PM
        self.assertTrue(is_time_to_run("* 9-17 * * *", now))

    def test_is_time_to_run_range_no_match(self):
        """Tests a non-matching time outside a range."""
        now = datetime(2025, 9, 23, 18, 0)  # 6 PM
        self.assertFalse(is_time_to_run("* 9-17 * * *", now))

    def test_is_time_to_run_step_match(self):
        """Tests a matching time with a step value."""
        now = datetime(2025, 9, 23, 10, 30)  # 10:30 AM
        self.assertTrue(is_time_to_run("*/15 * * * *", now))  # Matches 0, 15, 30, 45

    def test_is_time_to_run_step_no_match(self):
        """Tests a non-matching time with a step value."""
        now = datetime(2025, 9, 23, 10, 31)
        self.assertFalse(is_time_to_run("*/15 * * * *", now))

    def test_is_time_to_run_list_match(self):
        """Tests a matching time within a list of values."""
        now = datetime(2025, 9, 23, 8, 0)
        self.assertTrue(is_time_to_run("0 8,18 * * *", now))  # Run at 8 AM and 6 PM


if __name__ == "__main__":
    unittest.main()
