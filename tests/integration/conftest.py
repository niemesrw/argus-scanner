"""
Pytest configuration for Argus Scanner Integration tests
"""
import pytest
import tempfile
import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import Base, init_db
from src.config.settings import Settings


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )
    config.addinivalue_line(
        "markers", "database: marks tests that require database"
    )


@pytest.fixture(scope="function")
def temp_database():
    """Create a temporary database for integration tests"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
        db_path = temp_file.name
    
    # Create database URL
    db_url = f"sqlite:///{db_path}"
    
    # Initialize database
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    
    yield db_url
    
    # Cleanup
    os.unlink(db_path)


@pytest.fixture(scope="function")
def integration_settings(temp_database):
    """Settings configured for integration testing"""
    # Override settings for integration tests
    os.environ.update({
        'ARGUS_ENV': 'testing',
        'ARGUS_DATABASE_URL': temp_database,
        'ARGUS_MOCK_MODE': 'false',  # Use real operations for integration tests
        'ARGUS_NETWORK_RANGE': '127.0.0.1/32',  # Localhost only for safety
        'ARGUS_SCAN_INTERVAL': '30',
        'ARGUS_ENABLE_ALERTS': 'false',  # Disable alerts during tests
        'ARGUS_LOG_LEVEL': 'DEBUG'
    })
    
    # Create fresh settings instance
    settings = Settings()
    
    yield settings
    
    # Cleanup environment
    cleanup_vars = [
        'ARGUS_ENV', 'ARGUS_DATABASE_URL', 'ARGUS_MOCK_MODE',
        'ARGUS_NETWORK_RANGE', 'ARGUS_SCAN_INTERVAL', 'ARGUS_ENABLE_ALERTS',
        'ARGUS_LOG_LEVEL'
    ]
    for var in cleanup_vars:
        os.environ.pop(var, None)


@pytest.fixture(scope="function")
def db_session(integration_settings):
    """Database session for integration tests"""
    engine = create_engine(temp_database)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    
    yield session
    
    session.close()


@pytest.fixture(scope="function")
def controlled_network_target():
    """Safe network target for integration testing"""
    # Only test against localhost to avoid scanning external networks
    return {
        'ip': '127.0.0.1',
        'network': '127.0.0.1/32',
        'safe_ports': [22, 80, 443, 8080]  # Common ports that might be open
    }