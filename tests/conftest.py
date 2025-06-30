"""
Main pytest configuration file.

This file imports all fixtures from the fixtures package and makes them
available to all tests in the project.
"""

import pytest
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import all fixtures
from tests.fixtures.database import *
from tests.fixtures.network import *
from tests.fixtures.time import *
from tests.fixtures.config import *
from tests.fixtures.mock_services import *

# Additional shared fixtures


@pytest.fixture(scope="session")
def db_session():
    """Provide a transactional database session for tests."""
    from src.database.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker

    # Create in-memory database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    # Create session
    session_factory = sessionmaker(bind=engine)
    Session = scoped_session(session_factory)

    yield Session()

    # Cleanup
    Session.remove()
    Base.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def reset_database(db_session):
    """Reset database between tests."""
    # Start transaction
    db_session.begin_nested()

    yield

    # Rollback to savepoint
    db_session.rollback()


@pytest.fixture
def app():
    """Create Flask application for testing."""
    try:
        from src.web.app import create_app
        from src.config.settings import Settings

        # Use test configuration
        test_config = Settings()
        test_config.TESTING = True
        test_config.DATABASE_URL = "sqlite:///:memory:"

        app = create_app(test_config)

        with app.app_context():
            from src.database.models import init_db
            from pathlib import Path

            init_db(Path(":memory:"))
            yield app
    except ImportError:
        # If web app doesn't exist yet, create a minimal mock
        import pytest

        pytest.skip("Web app not implemented yet")


@pytest.fixture
def client(app):
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create Flask CLI runner."""
    return app.test_cli_runner()


# Pytest configuration


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "slow: Slow running tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on path."""
    for item in items:
        # Add markers based on test location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
        elif "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)

        # Mark slow tests
        if "slow" in item.name or "performance" in str(item.fspath):
            item.add_marker(pytest.mark.slow)


# Test environment setup


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables."""
    os.environ["ARGUS_ENV"] = "testing"
    os.environ["ARGUS_MOCK_MODE"] = "true"
    os.environ["ARGUS_DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["ARGUS_LOG_LEVEL"] = "ERROR"  # Reduce noise in tests

    yield

    # Cleanup (optional)
    for key in list(os.environ.keys()):
        if key.startswith("ARGUS_"):
            os.environ.pop(key, None)


# Shared test utilities


@pytest.fixture
def capture_logs():
    """Capture log messages during tests."""
    import logging
    from io import StringIO

    log_capture = StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.DEBUG)

    # Add handler to root logger
    logger = logging.getLogger()
    logger.addHandler(handler)
    original_level = logger.level
    logger.setLevel(logging.DEBUG)

    yield log_capture

    # Restore
    logger.removeHandler(handler)
    logger.setLevel(original_level)


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create temporary data directory for tests."""
    data_dir = tmp_path / "test_data"
    data_dir.mkdir()

    # Create subdirectories
    (data_dir / "logs").mkdir()
    (data_dir / "uploads").mkdir()
    (data_dir / "exports").mkdir()

    return data_dir


# Performance testing helpers


@pytest.fixture
def benchmark_timer():
    """Simple benchmark timer for performance tests."""
    import time

    class BenchmarkTimer:
        def __init__(self):
            self.times = {}

        def start(self, name):
            self.times[name] = {"start": time.time()}

        def stop(self, name):
            if name in self.times:
                self.times[name]["end"] = time.time()
                self.times[name]["duration"] = (
                    self.times[name]["end"] - self.times[name]["start"]
                )

        def get_duration(self, name):
            return self.times.get(name, {}).get("duration", 0)

        def report(self):
            for name, data in self.times.items():
                if "duration" in data:
                    print(f"{name}: {data['duration']:.3f}s")

    return BenchmarkTimer()


# Async support


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    import asyncio

    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Skip conditions

requires_network = pytest.mark.skipif(
    os.environ.get("SKIP_NETWORK_TESTS", "false").lower() == "true",
    reason="Network tests disabled",
)

requires_docker = pytest.mark.skipif(
    os.environ.get("SKIP_DOCKER_TESTS", "false").lower() == "true",
    reason="Docker tests disabled",
)

slow_test = pytest.mark.skipif(
    os.environ.get("SKIP_SLOW_TESTS", "false").lower() == "true",
    reason="Slow tests disabled",
)
