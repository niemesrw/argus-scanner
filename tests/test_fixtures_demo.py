"""
Demonstration of test fixtures usage.

This file shows how to use the various test fixtures created for the Argus Scanner project.
"""

import pytest
from datetime import datetime, timedelta
from src.database.models import Device, Service, Vulnerability, Scan, Alert
from src.scanner.discovery import NetworkDiscovery
from src.scheduler.tasks import ScheduledTasks
from tests.fixtures import *
from tests.fixtures.mock_services import mock_vulnerable_host


class TestDatabaseFixtures:
    """Examples of using database fixtures."""

    def test_basic_fixtures(self, test_device, test_service, test_vulnerability):
        """Test basic database fixtures."""
        # Basic fixtures provide pre-configured objects
        assert test_device.ip_address == "192.168.1.100"
        assert test_service.port == 22
        assert test_vulnerability.cve_id == "CVE-2021-44228"

    def test_factory_fixtures(
        self, device_factory, service_factory, vulnerability_factory
    ):
        """Test factory fixtures for creating custom objects."""
        # Create custom device
        device = device_factory.create(
            ip_address="10.0.0.50", hostname="custom-server", device_type="server"
        )
        assert device.ip_address == "10.0.0.50"

        # Create multiple devices
        devices = device_factory.create_batch(5, device_type="workstation")
        assert len(devices) == 5
        assert all(d.device_type == "workstation" for d in devices)

        # Create services for a device
        services = service_factory.create_for_device(
            device,
            [
                {"port": 80, "service_name": "http"},
                {"port": 443, "service_name": "https"},
            ],
        )
        assert len(services) == 2

        # Create vulnerabilities
        vulns = vulnerability_factory.create_batch(device, 3)
        assert len(vulns) == 3

    def test_populate_database(self, populate_test_database):
        """Test comprehensive database population."""
        # Populate with realistic test data
        data = populate_test_database(
            num_devices=20,
            services_per_device=4,
            vulns_per_device=2,
            num_scans=10,
            num_alerts=15,
        )

        assert len(data["devices"]) == 20
        assert len(data["services"]) > 0
        assert len(data["vulnerabilities"]) > 0
        assert len(data["scans"]) == 10
        assert len(data["alerts"]) == 15

        # Check relationships
        for service in data["services"]:
            assert service.device_id in [d.id for d in data["devices"]]


class TestNetworkFixtures:
    """Examples of using network simulation fixtures."""

    def test_mock_nmap_output(self, mock_nmap_output):
        """Test nmap output generation."""
        # Generate nmap scan results
        scan_result = mock_nmap_output(
            hosts=["192.168.1.10", "192.168.1.20"],
            include_services=True,
            include_os=True,
        )

        assert "scan" in scan_result
        assert "192.168.1.10" in scan_result["scan"]
        assert "tcp" in scan_result["scan"]["192.168.1.10"]
        assert "osmatch" in scan_result["scan"]["192.168.1.10"]

    def test_mock_device_data(self, mock_device_data):
        """Test device data generation."""
        devices = mock_device_data(count=10)

        assert len(devices) == 10
        for device in devices:
            assert "ip_address" in device
            assert "services" in device
            assert "risk_score" in device

    def test_mock_vulnerability_data(self, mock_vulnerability_data):
        """Test vulnerability data generation."""
        vulns = mock_vulnerability_data(device_id=1, count=5)

        assert len(vulns) <= 5  # May be less due to unique CVE constraint
        for vuln in vulns:
            assert "cve_id" in vuln
            assert "severity" in vuln
            assert "cvss_score" in vuln


class TestTimeFixtures:
    """Examples of using time manipulation fixtures."""

    def test_frozen_time(self, frozen_time):
        """Test freezing time at a specific point."""
        target_time = datetime(2024, 1, 1, 12, 0, 0)

        with frozen_time(target_time) as ft:
            # Time is frozen
            assert datetime.utcnow() == target_time

            # Advance time by 1 hour
            ft.advance(hours=1)
            assert datetime.utcnow() == target_time + timedelta(hours=1)

            # Set to specific time
            new_time = datetime(2024, 2, 1, 0, 0, 0)
            ft.set_time(new_time)
            assert datetime.utcnow() == new_time

    def test_mock_scheduler(self, mock_scheduler_time):
        """Test scheduler with controllable time."""
        scheduler = mock_scheduler_time(datetime(2024, 1, 1, 9, 0, 0))

        # Track job executions
        executed = []

        def job_func():
            executed.append(datetime.utcnow())

        # Add interval job
        scheduler.add_job(job_func, "interval", seconds=300)  # Every 5 minutes

        # Advance time and check executions
        scheduler.advance_time(minutes=5)
        assert len(executed) == 1

        scheduler.advance_time(minutes=10)
        assert len(executed) == 3  # Initial + 2 more

    def test_time_machine(self, time_machine):
        """Test advanced time manipulation."""
        with time_machine as tm:
            start_time = datetime.utcnow()

            # Freeze time
            tm.freeze()
            frozen_time = datetime.utcnow()
            time.sleep(0.1)  # Would normally advance time
            assert datetime.utcnow() == frozen_time

            # Travel to future
            future = datetime(2025, 12, 31, 23, 59, 59)
            tm.travel_to(future)
            assert datetime.utcnow() == future

            # Tick forward
            tm.tick()
            assert datetime.utcnow() == future + timedelta(seconds=1)


class TestConfigurationFixtures:
    """Examples of using configuration fixtures."""

    def test_config_environments(
        self, test_config, development_config, production_config
    ):
        """Test different environment configurations."""
        assert test_config.ARGUS_ENV == "testing"
        assert test_config.MOCK_MODE is True

        assert development_config.ARGUS_ENV == "development"
        assert development_config.DEBUG is True

        assert production_config.ARGUS_ENV == "production"
        assert production_config.DEBUG is False
        assert production_config.MOCK_MODE is False

    def test_config_factory(self, config_factory):
        """Test configuration factory."""
        # Create minimal config
        config = config_factory.minimal()
        assert config.MOCK_MODE is True
        assert config.LOG_LEVEL == "ERROR"

        # Create config with alerts
        alert_config = config_factory.with_alerts()
        assert alert_config.ENABLE_EMAIL_ALERTS is True
        assert alert_config.ENABLE_SLACK_ALERTS is True

        # Create custom config
        custom_config = config_factory.create(
            SCAN_INTERVAL=60, MAX_CONCURRENT_SCANS=10, CUSTOM_SETTING="test"
        )
        assert custom_config.SCAN_INTERVAL == 60
        assert hasattr(custom_config, "CUSTOM_SETTING")

    def test_mock_environment(self, mock_env):
        """Test environment variable mocking."""
        with mock_env({"ARGUS_ENV": "staging", "ARGUS_DEBUG": "false"}):
            assert os.environ["ARGUS_ENV"] == "staging"
            assert os.environ["ARGUS_DEBUG"] == "false"

        # Environment restored
        assert "ARGUS_ENV" not in os.environ or os.environ["ARGUS_ENV"] != "staging"


class TestMockServices:
    """Examples of using mock vulnerable services."""

    def test_individual_services(self, mock_ssh_service, mock_http_service):
        """Test individual mock services."""
        # SSH service is running
        assert mock_ssh_service.running
        assert mock_ssh_service.port > 0

        # Can connect to service
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("127.0.0.1", mock_ssh_service.port))
        assert result == 0  # Connection successful
        sock.close()

        # HTTP service responds
        assert mock_http_service.running

    def test_vulnerable_network(self, vulnerable_network):
        """Test complete vulnerable network environment."""
        # All services are running
        service_info = vulnerable_network.get_service_info()

        assert "ssh" in service_info
        assert "http" in service_info
        assert "mysql" in service_info

        for name, info in service_info.items():
            assert info["running"] is True
            assert info["port"] > 0

    def test_mock_vulnerable_host(self):
        """Test creating a custom vulnerable host."""
        with mock_vulnerable_host(["ssh", "http", "mysql"]) as host_info:
            # Only requested services are running
            assert len(host_info) == 3
            assert "ssh" in host_info
            assert "http" in host_info
            assert "mysql" in host_info

            # Services have assigned ports
            for service_name, info in host_info.items():
                assert info["port"] > 0
                assert info["running"] is True


class TestIntegrationScenarios:
    """Examples of combining multiple fixtures for integration tests."""

    def test_full_scan_simulation(
        self,
        populate_test_database,
        mock_nmap_output,
        frozen_time,
        config_factory,
        vulnerable_network,
    ):
        """Simulate a complete network scan with all fixtures."""
        # Set up test environment
        config = config_factory.create(
            NETWORK_RANGE="127.0.0.1/32",
            SCAN_INTERVAL=300,
            MOCK_MODE=False,  # Use real scanning against mock services
        )

        # Populate initial data
        data = populate_test_database(num_devices=5)

        # Freeze time for consistent results
        scan_time = datetime(2024, 1, 1, 10, 0, 0)
        with frozen_time(scan_time) as ft:
            # Vulnerable services are running via fixture
            service_info = vulnerable_network.get_service_info()

            # Simulate scan results
            scan_result = mock_nmap_output(hosts=["127.0.0.1"], include_services=True)

            # Process scan results (simplified)
            assert len(scan_result["scan"]) > 0

            # Advance time to next scan
            ft.advance(minutes=5)

            # Verify time advanced
            assert datetime.utcnow() == scan_time + timedelta(minutes=5)

    def test_alert_workflow(
        self, test_device, vulnerability_factory, alert_factory, time_machine, mock_env
    ):
        """Test complete alert workflow with fixtures."""
        with mock_env({"ARGUS_ENABLE_EMAIL_ALERTS": "true"}):
            with time_machine as tm:
                # Create critical vulnerability
                vuln = vulnerability_factory.create(
                    test_device, severity="critical", cvss_score=9.8
                )

                # Generate alert
                alert = alert_factory.create(test_device, vuln)
                assert alert.severity == "critical"
                assert alert.acknowledged is False

                # Advance time and acknowledge
                tm.advance(hours=2)
                alert = alert_factory.create_acknowledged(
                    test_device, vuln, acknowledged_by="security_team"
                )
                assert alert.acknowledged is True
                assert alert.acknowledged_by == "security_team"


# Parametrized tests using fixtures
@pytest.mark.parametrize(
    "env_config", ["testing", "development", "production"], indirect=True
)
def test_environment_configs(env_config):
    """Test multiple environment configurations."""
    assert env_config.ARGUS_ENV in ["testing", "development", "production"]

    if env_config.ARGUS_ENV == "production":
        assert env_config.DEBUG is False
        assert env_config.MOCK_MODE is False
    else:
        assert env_config.DEBUG is True


# Example of custom fixture combination
@pytest.fixture
def complete_test_environment(
    populate_test_database, vulnerable_network, frozen_time, config_factory
):
    """Composite fixture providing complete test environment."""
    config = config_factory.with_alerts()
    data = populate_test_database(num_devices=10)
    time_context = frozen_time(datetime(2024, 1, 1, 12, 0, 0))

    return {
        "config": config,
        "data": data,
        "network": vulnerable_network,
        "time": time_context,
    }


def test_complete_environment(complete_test_environment):
    """Test with complete environment fixture."""
    env = complete_test_environment

    assert env["config"].ENABLE_EMAIL_ALERTS is True
    assert len(env["data"]["devices"]) == 10
    assert env["network"].get_service_info()  # Services running

    with env["time"] as ft:
        start_time = datetime.utcnow()
        ft.advance(hours=1)
        assert datetime.utcnow() == start_time + timedelta(hours=1)
