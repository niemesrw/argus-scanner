"""Configuration fixtures for testing different environments."""

import pytest
import os
from typing import Dict, Optional, Any
from contextlib import contextmanager
from unittest.mock import patch


class TestConfig:
    """Test configuration class with sensible defaults."""

    # Environment
    ARGUS_ENV = "testing"

    # Database
    DATABASE_URL = "sqlite:///:memory:"

    # Network scanning
    NETWORK_RANGE = "192.168.1.0/24"
    SCAN_INTERVAL = 300  # 5 minutes
    SCAN_TIMEOUT = 60
    MOCK_MODE = True

    # Security
    ENABLE_EXPLOIT_TESTING = False
    AUTHORIZED_NETWORKS = ["192.168.1.0/24", "10.0.0.0/8"]

    # Alerts
    ENABLE_EMAIL_ALERTS = False
    ENABLE_SLACK_ALERTS = False
    EMAIL_SMTP_SERVER = "smtp.test.local"
    EMAIL_SMTP_PORT = 587
    EMAIL_FROM = "argus@test.local"
    EMAIL_TO = ["admin@test.local"]
    SLACK_WEBHOOK_URL = "https://hooks.slack.com/test"

    # Web interface
    SECRET_KEY = "test-secret-key-not-for-production"
    DEBUG = True
    HOST = "0.0.0.0"
    PORT = 8080

    # Logging
    LOG_LEVEL = "DEBUG"
    LOG_FILE = "/tmp/argus-test.log"

    # Performance
    MAX_CONCURRENT_SCANS = 5
    MAX_SCAN_THREADS = 10

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            key: getattr(self, key)
            for key in dir(self)
            if not key.startswith("_") and key.isupper()
        }


class DevelopmentConfig(TestConfig):
    """Development environment configuration."""

    ARGUS_ENV = "development"
    DATABASE_URL = "sqlite:///data/argus-dev.db"
    DEBUG = True
    MOCK_MODE = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(TestConfig):
    """Production environment configuration."""

    ARGUS_ENV = "production"
    DATABASE_URL = "postgresql://argus:password@localhost/argus"
    DEBUG = False
    MOCK_MODE = False
    LOG_LEVEL = "INFO"

    # Stronger security in production
    SECRET_KEY = "production-secret-key-should-be-from-env"
    ENABLE_EXPLOIT_TESTING = False

    # Enable alerts
    ENABLE_EMAIL_ALERTS = True
    ENABLE_SLACK_ALERTS = True


@pytest.fixture
def test_config():
    """Basic test configuration fixture."""
    return TestConfig()


@pytest.fixture
def development_config():
    """Development configuration fixture."""
    return DevelopmentConfig()


@pytest.fixture
def production_config():
    """Production configuration fixture."""
    return ProductionConfig()


@pytest.fixture
def testing_config():
    """Alias for test_config for consistency."""
    return TestConfig()


@contextmanager
def mock_environment(env_vars: Dict[str, str]):
    """
    Context manager to temporarily set environment variables.

    Usage:
        with mock_environment({'ARGUS_ENV': 'production', 'ARGUS_MOCK_MODE': 'false'}):
            # Code runs with these env vars set
            config = load_config()
    """
    original_environ = os.environ.copy()

    try:
        # Set new environment variables
        for key, value in env_vars.items():
            os.environ[key] = str(value)

        yield
    finally:
        # Restore original environment
        os.environ.clear()
        os.environ.update(original_environ)


@pytest.fixture
def mock_env():
    """
    Fixture for mocking environment variables.

    Usage:
        def test_something(mock_env):
            with mock_env({'ARGUS_ENV': 'production'}):
                # Test with production environment
                pass
    """
    return mock_environment


class ConfigFactory:
    """Factory for creating test configurations."""

    @staticmethod
    def create(**overrides) -> TestConfig:
        """
        Create a test configuration with custom overrides.

        Args:
            **overrides: Configuration values to override

        Returns:
            TestConfig instance with overrides applied
        """
        config = TestConfig()

        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                # Allow setting new attributes
                setattr(config, key.upper(), value)

        return config

    @staticmethod
    def create_with_env(env_name: str = "testing", **overrides) -> TestConfig:
        """
        Create a configuration for a specific environment.

        Args:
            env_name: Environment name (testing, development, production)
            **overrides: Additional overrides

        Returns:
            Configuration instance for the environment
        """
        configs = {
            "testing": TestConfig,
            "development": DevelopmentConfig,
            "production": ProductionConfig,
        }

        config_class = configs.get(env_name, TestConfig)
        config = config_class()

        for key, value in overrides.items():
            setattr(config, key.upper(), value)

        return config

    @staticmethod
    def minimal() -> TestConfig:
        """Create a minimal configuration for simple tests."""
        return ConfigFactory.create(
            MOCK_MODE=True,
            ENABLE_EMAIL_ALERTS=False,
            ENABLE_SLACK_ALERTS=False,
            LOG_LEVEL="ERROR",
        )

    @staticmethod
    def with_alerts() -> TestConfig:
        """Create a configuration with alerts enabled."""
        return ConfigFactory.create(
            ENABLE_EMAIL_ALERTS=True,
            ENABLE_SLACK_ALERTS=True,
            EMAIL_SMTP_SERVER="smtp.test.local",
            SLACK_WEBHOOK_URL="https://hooks.slack.com/test/webhook",
        )

    @staticmethod
    def with_real_scanning() -> TestConfig:
        """Create a configuration for real network scanning tests."""
        return ConfigFactory.create(
            MOCK_MODE=False,
            NETWORK_RANGE="127.0.0.1/32",  # Scan only localhost
            SCAN_TIMEOUT=10,
            MAX_CONCURRENT_SCANS=1,
        )

    @staticmethod
    def with_database(db_url: str) -> TestConfig:
        """Create a configuration with custom database URL."""
        return ConfigFactory.create(DATABASE_URL=db_url)


@pytest.fixture
def config_factory():
    """Configuration factory fixture."""
    return ConfigFactory()


@pytest.fixture
def env_config(request):
    """
    Parametrized fixture for testing multiple environments.

    Usage:
        @pytest.mark.parametrize('env_config', ['testing', 'development', 'production'], indirect=True)
        def test_something(env_config):
            assert env_config.ARGUS_ENV in ['testing', 'development', 'production']
    """
    env_name = getattr(request, "param", "testing")
    return ConfigFactory.create_with_env(env_name)


def patch_config(config: TestConfig):
    """
    Patch the application configuration with test config.

    Usage:
        def test_something(test_config):
            with patch_config(test_config):
                # Application now uses test_config
                from src.config.settings import Settings
                settings = Settings()
    """
    return patch("src.config.settings.Settings", return_value=config)


@pytest.fixture
def isolated_config(tmp_path):
    """
    Create an isolated configuration with temporary directories.

    Useful for tests that need to write files.
    """
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    log_dir.mkdir()
    data_dir.mkdir()

    return ConfigFactory.create(
        LOG_FILE=str(log_dir / "argus-test.log"),
        DATABASE_URL=f"sqlite:///{data_dir}/test.db",
        DATA_DIR=str(data_dir),
    )


# Environment variable helpers
def env_vars(**kwargs) -> Dict[str, str]:
    """
    Helper to create environment variable dict with ARGUS_ prefix.

    Usage:
        env = env_vars(mock_mode=True, scan_interval=60)
        # Returns: {'ARGUS_MOCK_MODE': 'true', 'ARGUS_SCAN_INTERVAL': '60'}
    """
    return {f"ARGUS_{key.upper()}": str(value) for key, value in kwargs.items()}
