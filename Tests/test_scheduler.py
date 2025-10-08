import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

from chimera_intel.core.scheduler import is_time_to_run, add_job


class TestScheduler(unittest.TestCase):
    """Test cases for the cron-like scheduler module."""

    # --- is_time_to_run Function Tests ---

    def test_is_time_to_run_exact_match(self):
        """Tests an exact match for a cron schedule."""
        now = datetime(2023, 10, 26, 14, 30)
        schedule = "30 14 26 10 *"
        self.assertTrue(is_time_to_run(schedule, now))

    def test_is_time_to_run_wildcard_match(self):
        """Tests a schedule with wildcards."""
        now = datetime(2023, 10, 26, 14, 30)
        schedule = "* * * * *"
        self.assertTrue(is_time_to_run(schedule, now))

    def test_is_time_to_run_step_match(self):
        """Tests a schedule with a step value (e.g., every 15 minutes)."""
        now = datetime(2023, 10, 26, 14, 30)
        schedule = "*/15 * * * *"
        self.assertTrue(is_time_to_run(schedule, now))

        now_fail = datetime(2023, 10, 26, 14, 31)
        self.assertFalse(is_time_to_run(schedule, now_fail))

    def test_is_time_to_run_range_match(self):
        """Tests a schedule with a range value (e.g., between 9am and 5pm)."""
        now = datetime(2023, 10, 26, 14, 30)
        schedule = "* 9-17 * * *"
        self.assertTrue(is_time_to_run(schedule, now))

        now_fail = datetime(2023, 10, 26, 8, 30)
        self.assertFalse(is_time_to_run(schedule, now_fail))

    def test_is_time_to_run_list_match(self):
        """Tests a schedule with a list of values (e.g., on Monday and Friday)."""
        # Monday

        now = datetime(2023, 10, 23, 14, 30)
        schedule = "* * * * 1,5"
        self.assertTrue(is_time_to_run(schedule, now))

        # Wednesday

        now_fail = datetime(2023, 10, 25, 14, 30)
        self.assertFalse(is_time_to_run(schedule, now_fail))

    def test_is_time_to_run_no_match(self):
        """Tests a schedule that does not match the current time."""
        now = datetime(2023, 10, 26, 14, 30)
        schedule = "0 0 1 1 *"
        self.assertFalse(is_time_to_run(schedule, now))

    def test_is_time_to_run_invalid_format(self):
        """Tests that an invalid cron string is handled gracefully."""
        now = datetime.now()
        schedule = "this is not a cron string"
        self.assertFalse(is_time_to_run(schedule, now))

    # --- add_job Function Tests ---

    @patch("chimera_intel.core.scheduler.scheduler")
    def test_add_job_success(self, mock_scheduler):
        """Tests the successful addition of a job to the APScheduler."""
        # Arrange

        def dummy_func():
            pass

        cron_schedule = "0 * * * *"
        job_id = "test_job"
        kwargs = {"arg1": "value1"}

        # Act

        add_job(dummy_func, "cron", cron_schedule, job_id, kwargs)

        # Assert

        mock_scheduler.add_job.assert_called_once()
        # Check that the trigger was created correctly

        call_args = mock_scheduler.add_job.call_args
        self.assertEqual(call_args.kwargs["id"], job_id)
        self.assertEqual(call_args.kwargs["func"], dummy_func)
        self.assertEqual(call_args.kwargs["trigger"].__class__.__name__, "CronTrigger")
        self.assertEqual(
            str(call_args.kwargs["trigger"]),
            "cron[minute='0', hour='*', day='*', month='*', day_of_week='*']",
        )


if __name__ == "__main__":
    unittest.main()
