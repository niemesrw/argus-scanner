"""Time mocking fixtures for testing schedulers and time-based operations."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from contextlib import contextmanager
import time as time_module
from typing import Optional, Generator, Any


class FrozenTime:
    """Context manager and fixture for freezing time."""

    def __init__(self, target_time: Optional[datetime] = None):
        """
        Initialize frozen time.

        Args:
            target_time: The datetime to freeze at. Defaults to current time.
        """
        self.target_time = target_time or datetime.utcnow()
        self.original_datetime = datetime
        self.patches = []

    def __enter__(self):
        """Enter the frozen time context."""
        # Patch datetime.utcnow
        utcnow_patch = patch("datetime.datetime.utcnow", return_value=self.target_time)
        self.patches.append(utcnow_patch)
        utcnow_patch.start()

        # Patch datetime.now
        now_patch = patch("datetime.datetime.now", return_value=self.target_time)
        self.patches.append(now_patch)
        now_patch.start()

        # Patch time.time
        time_patch = patch("time.time", return_value=self.target_time.timestamp())
        self.patches.append(time_patch)
        time_patch.start()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the frozen time context."""
        for patch_obj in self.patches:
            patch_obj.stop()

    def advance(self, **kwargs):
        """
        Advance the frozen time by the specified delta.

        Args:
            **kwargs: Arguments to pass to timedelta (days, hours, minutes, etc.)
        """
        delta = timedelta(**kwargs)
        self.target_time += delta

        # Update all patches
        for patch_obj in self.patches:
            if "utcnow" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time
            elif "now" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time
            elif "time" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time.timestamp()

    def set_time(self, new_time: datetime):
        """Set the frozen time to a specific datetime."""
        self.target_time = new_time

        # Update all patches
        for patch_obj in self.patches:
            if "utcnow" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time
            elif "now" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time
            elif "time" in str(patch_obj.attribute):
                patch_obj.return_value = self.target_time.timestamp()


@pytest.fixture
def frozen_time():
    """
    Fixture that provides a frozen time context manager.

    Usage:
        def test_something(frozen_time):
            with frozen_time(datetime(2023, 1, 1, 12, 0, 0)) as ft:
                # Time is now frozen at 2023-01-01 12:00:00
                assert datetime.utcnow() == datetime(2023, 1, 1, 12, 0, 0)

                # Advance time by 1 hour
                ft.advance(hours=1)
                assert datetime.utcnow() == datetime(2023, 1, 1, 13, 0, 0)
    """

    def _frozen_time(target_time: Optional[datetime] = None) -> FrozenTime:
        return FrozenTime(target_time)

    return _frozen_time


class MockSchedulerTime:
    """Mock time for APScheduler testing."""

    def __init__(self, start_time: Optional[datetime] = None):
        """Initialize mock scheduler time."""
        self.current_time = start_time or datetime.utcnow()
        self.scheduled_jobs = []
        self.executed_jobs = []

    def add_job(self, func, trigger, **kwargs):
        """Mock add_job method for scheduler."""
        job = {
            "func": func,
            "trigger": trigger,
            "kwargs": kwargs,
            "id": kwargs.get("id", f"job_{len(self.scheduled_jobs)}"),
            "next_run_time": self._calculate_next_run_time(trigger, kwargs),
        }
        self.scheduled_jobs.append(job)
        return job

    def _calculate_next_run_time(self, trigger, kwargs):
        """Calculate next run time based on trigger type."""
        if trigger == "interval":
            interval = timedelta(**kwargs.get("interval", {"seconds": 60}))
            return self.current_time + interval
        elif trigger == "cron":
            # Simplified cron calculation
            return self.current_time + timedelta(hours=1)
        elif trigger == "date":
            return kwargs.get("run_date", self.current_time + timedelta(minutes=1))
        return self.current_time

    def advance_time(self, **kwargs):
        """Advance scheduler time and execute due jobs."""
        delta = timedelta(**kwargs)
        self.current_time += delta

        # Check and execute due jobs
        for job in self.scheduled_jobs:
            if (
                job["next_run_time"] <= self.current_time
                and job not in self.executed_jobs
            ):
                # Execute the job
                job["func"](**job.get("kwargs", {}).get("kwargs", {}))
                self.executed_jobs.append(job)

                # Calculate next run time for recurring jobs
                if job["trigger"] in ["interval", "cron"]:
                    job["next_run_time"] = self._calculate_next_run_time(
                        job["trigger"], job["kwargs"]
                    )

    def get_jobs(self):
        """Get all scheduled jobs."""
        return self.scheduled_jobs

    def remove_job(self, job_id):
        """Remove a job by ID."""
        self.scheduled_jobs = [j for j in self.scheduled_jobs if j["id"] != job_id]

    def shutdown(self):
        """Mock scheduler shutdown."""
        pass


@pytest.fixture
def mock_scheduler_time():
    """
    Fixture for mocking APScheduler with controllable time.

    Usage:
        def test_scheduler(mock_scheduler_time):
            scheduler = mock_scheduler_time(datetime(2023, 1, 1))

            # Add a job
            scheduler.add_job(my_func, 'interval', seconds=60)

            # Advance time by 61 seconds
            scheduler.advance_time(seconds=61)

            # Job should have executed
            assert len(scheduler.executed_jobs) == 1
    """

    def _mock_scheduler(start_time: Optional[datetime] = None) -> MockSchedulerTime:
        return MockSchedulerTime(start_time)

    return _mock_scheduler


@contextmanager
def advance_time(
    seconds: float = 0, minutes: float = 0, hours: float = 0, days: float = 0
) -> Generator[Mock, None, None]:
    """
    Context manager that mocks time progression.

    Usage:
        with advance_time(minutes=5) as time_mock:
            start = time.time()
            # Do something
            time_mock.tick(60)  # Advance by 60 seconds
            # time.time() now returns start + 60
    """
    original_time = time_module.time
    start_time = original_time()
    elapsed = 0.0

    def mock_time():
        return start_time + elapsed

    time_mock = Mock()
    time_mock.tick = lambda seconds: setattr(time_mock, "_elapsed", elapsed + seconds)

    with patch("time.time", side_effect=mock_time):
        yield time_mock

    # Calculate total elapsed time
    total_seconds = seconds + (minutes * 60) + (hours * 3600) + (days * 86400)
    elapsed = total_seconds


@pytest.fixture
def time_machine():
    """
    Advanced time manipulation fixture.

    Provides various time control methods:
    - freeze(): Freeze time at current moment
    - travel_to(datetime): Jump to specific time
    - advance(timedelta): Move forward in time
    - rewind(timedelta): Move backward in time
    - tick(): Advance by 1 second
    """

    class TimeMachine:
        def __init__(self):
            self.current_time = datetime.utcnow()
            self.is_frozen = False
            self.patches = []

        def freeze(self):
            """Freeze time at current moment."""
            self.is_frozen = True
            self._apply_patches()
            return self

        def travel_to(self, target_time: datetime):
            """Travel to a specific time."""
            self.current_time = target_time
            self.is_frozen = True
            self._apply_patches()
            return self

        def advance(self, **kwargs):
            """Advance time by specified delta."""
            delta = timedelta(**kwargs)
            self.current_time += delta
            if self.is_frozen:
                self._update_patches()
            return self

        def rewind(self, **kwargs):
            """Rewind time by specified delta."""
            delta = timedelta(**kwargs)
            self.current_time -= delta
            if self.is_frozen:
                self._update_patches()
            return self

        def tick(self):
            """Advance time by 1 second."""
            return self.advance(seconds=1)

        def _apply_patches(self):
            """Apply time patches."""
            # Clear existing patches
            self._clear_patches()

            # Apply new patches
            utcnow_patch = patch(
                "datetime.datetime.utcnow", return_value=self.current_time
            )
            now_patch = patch("datetime.datetime.now", return_value=self.current_time)
            time_patch = patch("time.time", return_value=self.current_time.timestamp())

            self.patches = [utcnow_patch, now_patch, time_patch]
            for p in self.patches:
                p.start()

        def _update_patches(self):
            """Update existing patches with new time."""
            for p in self.patches:
                if "utcnow" in str(p.attribute):
                    p.return_value = self.current_time
                elif "now" in str(p.attribute):
                    p.return_value = self.current_time
                elif "time" in str(p.attribute):
                    p.return_value = self.current_time.timestamp()

        def _clear_patches(self):
            """Stop all active patches."""
            for p in self.patches:
                try:
                    p.stop()
                except:
                    pass
            self.patches = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self._clear_patches()
            self.is_frozen = False

    return TimeMachine()


# Utility functions for common time operations
def mock_sleep(monkeypatch):
    """
    Mock time.sleep to return immediately.

    Usage:
        def test_something(monkeypatch):
            mock_sleep(monkeypatch)
            time.sleep(10)  # Returns immediately
    """
    monkeypatch.setattr(time_module, "sleep", lambda x: None)


def accelerated_sleep(monkeypatch, acceleration_factor: float = 10.0):
    """
    Make time.sleep run faster by a factor.

    Usage:
        def test_something(monkeypatch):
            accelerated_sleep(monkeypatch, 100)  # Sleep 100x faster
            time.sleep(10)  # Actually sleeps for 0.1 seconds
    """
    original_sleep = time_module.sleep
    monkeypatch.setattr(
        time_module, "sleep", lambda x: original_sleep(x / acceleration_factor)
    )
