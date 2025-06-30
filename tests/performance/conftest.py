"""
Pytest configuration for Argus Scanner Performance tests
"""

import pytest
import tempfile
import os
import psutil
import time
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import Base
from src.config.settings import Settings


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "benchmark: marks tests as benchmark tests")
    config.addinivalue_line("markers", "memory: marks tests that monitor memory usage")
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (may take several minutes)"
    )


@pytest.fixture(scope="function")
def performance_database():
    """Create a performance-optimized temporary database"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
        db_path = temp_file.name

    # Create database URL with performance optimizations
    db_url = f"sqlite:///{db_path}?cache=shared&mode=rwc"

    # Initialize database with performance settings
    engine = create_engine(
        db_url,
        # Performance optimizations for testing
        pool_pre_ping=True,
        pool_recycle=300,
        echo=False,  # Disable SQL logging for performance
    )
    Base.metadata.create_all(engine)

    yield db_url

    # Cleanup
    engine.dispose()
    os.unlink(db_path)


@pytest.fixture(scope="function")
def performance_settings(performance_database):
    """Settings optimized for performance testing"""
    # Override settings for performance tests
    os.environ.update(
        {
            "ARGUS_ENV": "performance_testing",
            "ARGUS_DATABASE_URL": performance_database,
            "ARGUS_MOCK_MODE": "true",  # Use mock mode for predictable performance
            "ARGUS_LOG_LEVEL": "WARNING",  # Reduce logging overhead
            "ARGUS_SCAN_TIMEOUT": "60",
            "ARGUS_MAX_PARALLEL_SCANS": "10",
            "ARGUS_ENABLE_ALERTS": "false",  # Disable alerts during performance tests
        }
    )

    settings = Settings()

    yield settings

    # Cleanup environment
    cleanup_vars = [
        "ARGUS_ENV",
        "ARGUS_DATABASE_URL",
        "ARGUS_MOCK_MODE",
        "ARGUS_LOG_LEVEL",
        "ARGUS_SCAN_TIMEOUT",
        "ARGUS_MAX_PARALLEL_SCANS",
        "ARGUS_ENABLE_ALERTS",
    ]
    for var in cleanup_vars:
        os.environ.pop(var, None)


@pytest.fixture(scope="function")
def performance_db_session(performance_settings):
    """High-performance database session"""
    engine = create_engine(performance_settings.db_path)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    yield session

    session.close()


@pytest.fixture(scope="function")
def memory_monitor():
    """Monitor memory usage during test execution"""
    process = psutil.Process()

    # Get initial memory usage
    initial_memory = process.memory_info()

    yield {
        "process": process,
        "initial_memory": initial_memory,
        "peak_memory": initial_memory,
    }


@pytest.fixture(scope="function")
def performance_timer():
    """High-precision timer for performance measurements"""

    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.timings = []

        def start(self):
            self.start_time = time.perf_counter()
            return self

        def stop(self):
            self.end_time = time.perf_counter()
            return self.elapsed()

        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

        def lap(self, label=""):
            if self.start_time:
                lap_time = time.perf_counter() - self.start_time
                self.timings.append((label, lap_time))
                return lap_time
            return None

        def reset(self):
            self.start_time = None
            self.end_time = None
            self.timings = []

    return PerformanceTimer()


@pytest.fixture(scope="function")
def large_dataset_factory():
    """Factory for creating large test datasets"""

    def create_devices(count=1000):
        """Create a large number of mock devices"""
        devices = []
        for i in range(count):
            device_data = {
                "ip": f"192.168.{(i // 254) + 1}.{(i % 254) + 1}",
                "mac": f"00:11:22:33:{(i // 256):02x}:{(i % 256):02x}",
                "hostname": f"device-{i:04d}",
                "status": "active",
                "device_type": ["router", "switch", "server", "workstation"][i % 4],
                "services": (
                    [
                        {"port": 22, "service": "ssh"},
                        {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"},
                    ]
                    if i % 3 == 0
                    else [{"port": 22, "service": "ssh"}]
                ),
            }
            devices.append(device_data)
        return devices

    def create_vulnerabilities(device_count=100, vulns_per_device=5):
        """Create a large number of mock vulnerabilities"""
        vulnerabilities = []
        cve_templates = ["CVE-2023-{:05d}", "CVE-2022-{:05d}", "CVE-2021-{:05d}"]

        for device_id in range(1, device_count + 1):
            for vuln_id in range(vulns_per_device):
                cve_id = cve_templates[vuln_id % 3].format(device_id * 100 + vuln_id)
                vuln_data = {
                    "device_id": device_id,
                    "cve_id": cve_id,
                    "cvss_score": 5.0 + (vuln_id % 5),
                    "severity": ["low", "medium", "high", "critical"][vuln_id % 4],
                    "description": f"Test vulnerability {vuln_id} for device {device_id}",
                }
                vulnerabilities.append(vuln_data)
        return vulnerabilities

    return {"devices": create_devices, "vulnerabilities": create_vulnerabilities}


@pytest.fixture(scope="function")
def network_range_generator():
    """Generate network ranges for performance testing"""

    def generate_ranges(size="small"):
        """Generate network ranges of different sizes"""
        ranges = {
            "small": ["192.168.1.0/28"],  # 16 IPs
            "medium": ["192.168.0.0/24"],  # 256 IPs
            "large": ["10.0.0.0/22"],  # 1024 IPs
            "xlarge": ["172.16.0.0/20"],  # 4096 IPs
        }
        return ranges.get(size, ranges["small"])

    return generate_ranges
