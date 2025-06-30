"""
Tests for scheduler tasks module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

from src.scheduler.tasks import SchedulerService
from src.database.models import Device, Scan, ScanType, Severity
from src.config.settings import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = Mock(spec=Settings)
    settings.scan_interval = 300  # 5 minutes
    settings.network_range = "192.168.1.0/24"
    settings.db_path = ":memory:"
    settings.cve_api_key = "test_api_key"
    settings.vulnerability_db_update_interval = 3600  # 1 hour
    return settings


@pytest.fixture
def mock_db_session():
    """Create mock database session"""
    db = Mock()
    db.query.return_value = Mock()
    db.add = Mock()
    db.commit = Mock()
    db.rollback = Mock()
    return db


@pytest.fixture
def scheduler_service(mock_settings):
    """Create scheduler service instance with mocked dependencies"""
    with patch(
        "src.scheduler.tasks.BackgroundScheduler"
    ) as mock_scheduler_class, patch(
        "src.scheduler.tasks.NetworkDiscovery"
    ) as mock_discovery_class, patch(
        "src.scheduler.tasks.VulnerabilityScanner"
    ) as mock_vuln_scanner_class, patch(
        "src.scheduler.tasks.AlertManager"
    ) as mock_alert_manager_class, patch(
        "src.scheduler.tasks.get_db_session"
    ) as mock_get_db:

        mock_scheduler = Mock()
        mock_scheduler_class.return_value = mock_scheduler

        mock_discovery = Mock()
        mock_discovery_class.return_value = mock_discovery

        mock_vuln_scanner = Mock()
        mock_vuln_scanner_class.return_value = mock_vuln_scanner

        mock_alert_manager = Mock()
        mock_alert_manager_class.return_value = mock_alert_manager

        mock_db = Mock()
        mock_get_db.return_value = mock_db

        service = SchedulerService(mock_settings)
        service.scheduler = mock_scheduler
        service.discovery = mock_discovery
        service.vuln_scanner = mock_vuln_scanner
        service.alert_manager = mock_alert_manager
        service.db = mock_db

        return service


@pytest.fixture
def sample_device():
    """Create sample device for testing"""
    device = Mock(spec=Device)
    device.id = 1
    device.ip_address = "192.168.1.100"
    device.mac_address = "00:11:22:33:44:55"
    device.is_active = True
    device.risk_score = 25.0
    device.first_seen = datetime.utcnow() - timedelta(hours=2)
    device.last_seen = datetime.utcnow() - timedelta(minutes=5)
    device.services = []
    return device


@pytest.fixture
def sample_scan():
    """Create sample scan for testing"""
    scan = Mock(spec=Scan)
    scan.id = 1
    scan.scan_type = ScanType.DISCOVERY
    scan.target_range = "192.168.1.0/24"
    scan.started_at = datetime.utcnow()
    scan.completed_at = None
    scan.status = "running"
    scan.total_hosts = 0
    scan.hosts_scanned = 0
    scan.vulnerabilities_found = 0
    scan.error_message = None
    return scan


class TestSchedulerServiceInitialization:
    """Test scheduler service initialization"""

    def test_init(self, mock_settings):
        """Test scheduler service initialization"""
        with patch(
            "src.scheduler.tasks.BackgroundScheduler"
        ) as mock_scheduler_class, patch(
            "src.scheduler.tasks.NetworkDiscovery"
        ) as mock_discovery_class, patch(
            "src.scheduler.tasks.VulnerabilityScanner"
        ) as mock_vuln_scanner_class, patch(
            "src.scheduler.tasks.AlertManager"
        ) as mock_alert_manager_class, patch(
            "src.scheduler.tasks.get_db_session"
        ) as mock_get_db:

            service = SchedulerService(mock_settings)

            assert service.settings == mock_settings
            mock_scheduler_class.assert_called_once()
            mock_discovery_class.assert_called_once_with(mock_settings)
            mock_vuln_scanner_class.assert_called_once_with(mock_settings)
            mock_alert_manager_class.assert_called_once_with(mock_settings)
            mock_get_db.assert_called_once_with(mock_settings.db_path)

    def test_start_scheduler(self, scheduler_service, mock_settings):
        """Test starting the scheduler with all jobs"""
        scheduler_service.start()

        # Should add 4 jobs (discovery, vulnerability, cleanup, db update)
        assert scheduler_service.scheduler.add_job.call_count == 4
        scheduler_service.scheduler.start.assert_called_once()

        # Verify job configurations
        calls = scheduler_service.scheduler.add_job.call_args_list

        # Network discovery job
        discovery_call = calls[0]
        assert discovery_call[1]["func"] == scheduler_service.run_network_discovery
        assert discovery_call[1]["id"] == "network_discovery"

        # Vulnerability scan job
        vuln_call = calls[1]
        assert vuln_call[1]["func"] == scheduler_service.run_vulnerability_scan
        assert vuln_call[1]["id"] == "vulnerability_scan"

        # Device cleanup job
        cleanup_call = calls[2]
        assert cleanup_call[1]["func"] == scheduler_service.cleanup_inactive_devices
        assert cleanup_call[1]["id"] == "device_cleanup"

        # Vulnerability DB update job
        db_update_call = calls[3]
        assert (
            db_update_call[1]["func"] == scheduler_service.update_vulnerability_database
        )
        assert db_update_call[1]["id"] == "vuln_db_update"

    def test_start_scheduler_no_cve_api_key(self, scheduler_service, mock_settings):
        """Test starting scheduler without CVE API key (no DB update job)"""
        mock_settings.cve_api_key = None

        scheduler_service.start()

        # Should add 3 jobs (no DB update without API key)
        assert scheduler_service.scheduler.add_job.call_count == 3
        scheduler_service.scheduler.start.assert_called_once()

    def test_stop_scheduler(self, scheduler_service):
        """Test stopping the scheduler"""
        scheduler_service.stop()

        scheduler_service.scheduler.shutdown.assert_called_once()


class TestNetworkDiscovery:
    """Test network discovery task execution"""

    def test_run_network_discovery_success(self, scheduler_service, sample_scan):
        """Test successful network discovery execution"""
        # Mock discovered devices
        discovered_devices = [
            {"ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"},
            {"ip_address": "192.168.1.101", "mac_address": "00:11:22:33:44:56"},
        ]

        scheduler_service.discovery.discover_devices.return_value = discovered_devices

        # Mock database operations
        scheduler_service.db.query().filter_by().first.return_value = None

        with patch("src.scheduler.tasks.Scan") as mock_scan_class, patch.object(
            scheduler_service, "_check_new_devices"
        ) as mock_check_new, patch.object(
            scheduler_service, "_should_deep_scan"
        ) as mock_should_deep:

            mock_scan_class.return_value = sample_scan
            mock_should_deep.return_value = False

            scheduler_service.run_network_discovery()

            # Verify scan creation and completion
            mock_scan_class.assert_called_once()
            scheduler_service.db.add.assert_called()
            scheduler_service.db.commit.assert_called()

            # Verify discovery was called
            scheduler_service.discovery.discover_devices.assert_called_once()

            # Verify scan was updated
            assert sample_scan.status == "completed"
            assert sample_scan.total_hosts == 2
            assert sample_scan.hosts_scanned == 2

            # Verify new device check
            mock_check_new.assert_called_once_with(discovered_devices)

    def test_run_network_discovery_with_deep_scan(
        self, scheduler_service, sample_scan, sample_device
    ):
        """Test network discovery with deep scanning"""
        discovered_devices = [
            {"ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"}
        ]

        scheduler_service.discovery.discover_devices.return_value = discovered_devices
        scheduler_service.db.query().filter_by().first.return_value = sample_device

        with patch("src.scheduler.tasks.Scan") as mock_scan_class, patch.object(
            scheduler_service, "_check_new_devices"
        ), patch.object(scheduler_service, "_should_deep_scan") as mock_should_deep:

            mock_scan_class.return_value = sample_scan
            mock_should_deep.return_value = True

            scheduler_service.run_network_discovery()

            # Verify deep scan was triggered
            scheduler_service.discovery.deep_scan_device.assert_called_once_with(
                "192.168.1.100"
            )

    def test_run_network_discovery_error(self, scheduler_service, sample_scan):
        """Test network discovery with error handling"""
        scheduler_service.discovery.discover_devices.side_effect = Exception(
            "Network error"
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_network_discovery()

            # Verify scan was marked as failed
            assert sample_scan.status == "failed"
            assert sample_scan.error_message == "Network error"
            scheduler_service.db.commit.assert_called()


class TestVulnerabilityScanning:
    """Test vulnerability scanning task execution"""

    def test_run_vulnerability_scan_success(
        self, scheduler_service, sample_scan, sample_device
    ):
        """Test successful vulnerability scan execution"""
        active_devices = [sample_device]

        # Mock vulnerabilities found
        vulnerabilities = [
            {"cve_id": "CVE-2023-1234", "severity": "medium"},
            {"cve_id": "CVE-2023-5678", "severity": "critical"},
        ]

        scheduler_service.db.query().filter_by().all.return_value = active_devices
        scheduler_service.vuln_scanner.scan_device_vulnerabilities.return_value = (
            vulnerabilities
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_vulnerability_scan()

            # Verify scan creation and completion
            mock_scan_class.assert_called_once()
            scheduler_service.db.add.assert_called()
            scheduler_service.db.commit.assert_called()

            # Verify vulnerability scanning
            scheduler_service.vuln_scanner.scan_device_vulnerabilities.assert_called_once_with(
                sample_device.id
            )

            # Verify scan was updated
            assert sample_scan.status == "completed"
            assert sample_scan.total_hosts == 1
            assert sample_scan.hosts_scanned == 1
            assert sample_scan.vulnerabilities_found == 2

    def test_run_vulnerability_scan_with_critical_alert(
        self, scheduler_service, sample_scan, sample_device
    ):
        """Test vulnerability scan with critical vulnerability alert"""
        active_devices = [sample_device]

        # Mock critical vulnerabilities
        vulnerabilities = [
            {"cve_id": "CVE-2023-1234", "severity": "critical"},
            {"cve_id": "CVE-2023-5678", "severity": "high"},
        ]

        scheduler_service.db.query().filter_by().all.return_value = active_devices
        scheduler_service.vuln_scanner.scan_device_vulnerabilities.return_value = (
            vulnerabilities
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_vulnerability_scan()

            # Verify critical vulnerability alert was sent
            scheduler_service.alert_manager.send_critical_vulnerability_alert.assert_called_once()
            call_args = (
                scheduler_service.alert_manager.send_critical_vulnerability_alert.call_args
            )
            assert call_args[0][0] == sample_device
            critical_vulns = call_args[0][1]
            assert len(critical_vulns) == 1
            assert critical_vulns[0]["severity"] == "critical"

    def test_run_vulnerability_scan_no_devices(self, scheduler_service, sample_scan):
        """Test vulnerability scan with no active devices"""
        scheduler_service.db.query().filter_by().all.return_value = []

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_vulnerability_scan()

            # Verify scan completed with no devices
            assert sample_scan.status == "completed"
            assert sample_scan.total_hosts == 0
            assert sample_scan.vulnerabilities_found == 0

    def test_run_vulnerability_scan_error(self, scheduler_service, sample_scan):
        """Test vulnerability scan with error handling"""
        scheduler_service.db.query().filter_by().all.side_effect = Exception(
            "Database error"
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_vulnerability_scan()

            # Verify scan was marked as failed
            assert sample_scan.status == "failed"
            assert sample_scan.error_message == "Database error"
            scheduler_service.db.commit.assert_called()


class TestDeviceCleanup:
    """Test device cleanup operations"""

    def test_cleanup_inactive_devices_success(self, scheduler_service):
        """Test successful device cleanup"""
        # Mock inactive devices (not seen in 7+ days)
        inactive_device1 = Mock()
        inactive_device1.ip_address = "192.168.1.100"
        inactive_device1.is_active = True

        inactive_device2 = Mock()
        inactive_device2.ip_address = "192.168.1.101"
        inactive_device2.is_active = True

        inactive_devices = [inactive_device1, inactive_device2]

        # Mock database query
        mock_query = Mock()
        mock_filter = Mock()
        mock_filter.all.return_value = inactive_devices
        mock_query.filter.return_value = mock_filter
        scheduler_service.db.query.return_value = mock_query

        scheduler_service.cleanup_inactive_devices()

        # Verify devices were marked inactive
        assert inactive_device1.is_active == False
        assert inactive_device2.is_active == False
        scheduler_service.db.commit.assert_called_once()

    def test_cleanup_inactive_devices_no_devices(self, scheduler_service):
        """Test device cleanup with no inactive devices"""
        # Mock empty result
        mock_query = Mock()
        mock_filter = Mock()
        mock_filter.all.return_value = []
        mock_query.filter.return_value = mock_filter
        scheduler_service.db.query.return_value = mock_query

        scheduler_service.cleanup_inactive_devices()

        # Should still commit (no changes)
        scheduler_service.db.commit.assert_called_once()

    def test_cleanup_inactive_devices_error(self, scheduler_service):
        """Test device cleanup with error handling"""
        scheduler_service.db.query.side_effect = Exception("Database error")

        scheduler_service.cleanup_inactive_devices()

        # Verify rollback was called
        scheduler_service.db.rollback.assert_called_once()


class TestVulnerabilityDatabaseUpdate:
    """Test vulnerability database update operations"""

    def test_update_vulnerability_database(self, scheduler_service):
        """Test vulnerability database update"""
        # This is currently a placeholder method
        scheduler_service.update_vulnerability_database()

        # Just verify it completes without error
        # In a real implementation, this would test actual DB updates


class TestHelperMethods:
    """Test helper methods for scheduling decisions"""

    def test_should_deep_scan_no_services(self, scheduler_service, sample_device):
        """Test deep scan decision - device with no services"""
        sample_device.services = []

        result = scheduler_service._should_deep_scan(sample_device)

        assert result == True

    def test_should_deep_scan_high_risk(self, scheduler_service, sample_device):
        """Test deep scan decision - high risk device"""
        sample_device.services = [Mock()]  # Has services
        sample_device.risk_score = 75.0

        result = scheduler_service._should_deep_scan(sample_device)

        assert result == True

    def test_should_deep_scan_recently_discovered(
        self, scheduler_service, sample_device
    ):
        """Test deep scan decision - recently discovered device"""
        sample_device.services = [Mock()]  # Has services
        sample_device.risk_score = 25.0  # Low risk
        sample_device.first_seen = datetime.utcnow() - timedelta(minutes=30)  # Recent

        result = scheduler_service._should_deep_scan(sample_device)

        assert result == True

    def test_should_deep_scan_no_criteria(self, scheduler_service, sample_device):
        """Test deep scan decision - no criteria met"""
        sample_device.services = [Mock()]  # Has services
        sample_device.risk_score = 25.0  # Low risk
        sample_device.first_seen = datetime.utcnow() - timedelta(days=1)  # Old

        result = scheduler_service._should_deep_scan(sample_device)

        assert result == False

    def test_check_new_devices_new_device(self, scheduler_service):
        """Test new device detection and alerting"""
        # Mock new device
        device_info = {
            "ip_address": "192.168.1.200",
            "mac_address": "00:11:22:33:44:99",
        }

        mock_device = Mock()
        mock_device.first_seen = datetime.utcnow() - timedelta(minutes=2)  # Very recent

        scheduler_service.db.query().filter_by().first.return_value = mock_device

        scheduler_service._check_new_devices([device_info])

        # Verify alert was sent
        scheduler_service.alert_manager.send_new_device_alert.assert_called_once_with(
            device_info
        )

    def test_check_new_devices_old_device(self, scheduler_service):
        """Test new device detection - old device (no alert)"""
        device_info = {
            "ip_address": "192.168.1.200",
            "mac_address": "00:11:22:33:44:99",
        }

        mock_device = Mock()
        mock_device.first_seen = datetime.utcnow() - timedelta(hours=1)  # Old

        scheduler_service.db.query().filter_by().first.return_value = mock_device

        scheduler_service._check_new_devices([device_info])

        # Verify no alert was sent
        scheduler_service.alert_manager.send_new_device_alert.assert_not_called()

    def test_check_new_devices_no_device(self, scheduler_service):
        """Test new device detection - device not in database"""
        device_info = {
            "ip_address": "192.168.1.200",
            "mac_address": "00:11:22:33:44:99",
        }

        scheduler_service.db.query().filter_by().first.return_value = None

        scheduler_service._check_new_devices([device_info])

        # Verify no alert was sent (device not found)
        scheduler_service.alert_manager.send_new_device_alert.assert_not_called()


class TestConcurrentTaskManagement:
    """Test concurrent task execution and management"""

    def test_multiple_discovery_scans_handling(self, scheduler_service, sample_scan):
        """Test handling of multiple discovery scans"""
        # Simulate concurrent discovery calls
        discovered_devices = [
            {"ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"}
        ]

        scheduler_service.discovery.discover_devices.return_value = discovered_devices
        scheduler_service.db.query().filter_by().first.return_value = None

        with patch("src.scheduler.tasks.Scan") as mock_scan_class, patch.object(
            scheduler_service, "_check_new_devices"
        ) as mock_check_new:

            mock_scan_class.return_value = sample_scan

            # Run discovery multiple times (simulating concurrent calls)
            scheduler_service.run_network_discovery()
            scheduler_service.run_network_discovery()

            # Each should create its own scan record
            assert mock_scan_class.call_count == 2
            assert scheduler_service.db.add.call_count == 2
            assert scheduler_service.db.commit.call_count >= 2

    def test_database_transaction_isolation(self, scheduler_service, sample_scan):
        """Test database transaction isolation during errors"""
        scheduler_service.discovery.discover_devices.side_effect = Exception(
            "Network error"
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            scheduler_service.run_network_discovery()

            # Verify scan was added and committed even with error
            scheduler_service.db.add.assert_called()
            scheduler_service.db.commit.assert_called()

            # Verify error was recorded
            assert sample_scan.status == "failed"
            assert sample_scan.error_message == "Network error"


class TestTimeBasedScheduling:
    """Test time-based scheduling logic"""

    @patch("src.scheduler.tasks.datetime")
    def test_device_cleanup_time_criteria(self, mock_datetime, scheduler_service):
        """Test time-based criteria for device cleanup"""
        # Mock current time
        current_time = datetime(2023, 6, 30, 12, 0, 0)
        mock_datetime.utcnow.return_value = current_time

        # Create mock device that's 8 days old (should be cleaned up)
        old_device = Mock()
        old_device.ip_address = "192.168.1.100"
        old_device.is_active = True
        old_device.last_seen = current_time - timedelta(days=8)

        mock_query = Mock()
        mock_filter = Mock()
        mock_filter.all.return_value = [old_device]
        mock_query.filter.return_value = mock_filter
        scheduler_service.db.query.return_value = mock_query

        scheduler_service.cleanup_inactive_devices()

        # Verify device was marked inactive
        assert old_device.is_active == False

    @patch("src.scheduler.tasks.datetime")
    def test_new_device_time_window(self, mock_datetime, scheduler_service):
        """Test time window for new device alerts"""
        current_time = datetime(2023, 6, 30, 12, 0, 0)
        mock_datetime.utcnow.return_value = current_time

        device_info = {
            "ip_address": "192.168.1.200",
            "mac_address": "00:11:22:33:44:99",
        }

        # Device discovered 3 minutes ago (within 5-minute window)
        mock_device = Mock()
        mock_device.first_seen = current_time - timedelta(minutes=3)

        scheduler_service.db.query().filter_by().first.return_value = mock_device

        scheduler_service._check_new_devices([device_info])

        # Should send alert
        scheduler_service.alert_manager.send_new_device_alert.assert_called_once()


class TestErrorRecovery:
    """Test error recovery and resilience"""

    def test_discovery_partial_failure_recovery(
        self, scheduler_service, sample_scan, sample_device
    ):
        """Test that discovery fails when deep scan fails (current behavior)"""
        # First device succeeds, second fails
        discovered_devices = [
            {"ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"},
            {"ip_address": "192.168.1.101", "mac_address": "00:11:22:33:44:56"},
        ]

        scheduler_service.discovery.discover_devices.return_value = discovered_devices

        # Mock database to return device for first IP, None for second
        def mock_filter_by(**kwargs):
            mock_filter = Mock()
            if kwargs.get("ip_address") == "192.168.1.100":
                mock_filter.first.return_value = sample_device
            else:
                mock_filter.first.return_value = None
            return mock_filter

        scheduler_service.db.query().filter_by = mock_filter_by

        # Mock deep scan to fail for first device
        scheduler_service.discovery.deep_scan_device.side_effect = Exception(
            "Deep scan failed"
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class, patch.object(
            scheduler_service, "_check_new_devices"
        ), patch.object(scheduler_service, "_should_deep_scan") as mock_should_deep:

            mock_scan_class.return_value = sample_scan
            mock_should_deep.return_value = True

            # Current behavior: entire scan fails if deep scan fails
            scheduler_service.run_network_discovery()

            # Scan should be marked as failed (current behavior)
            assert sample_scan.status == "failed"
            assert sample_scan.error_message == "Deep scan failed"

    def test_vulnerability_scan_device_failure_stops_scan(
        self, scheduler_service, sample_scan
    ):
        """Test that vulnerability scan fails completely if any device fails (current behavior)"""
        device1 = Mock()
        device1.id = 1
        device1.ip_address = "192.168.1.100"

        device2 = Mock()
        device2.id = 2
        device2.ip_address = "192.168.1.101"

        active_devices = [device1, device2]
        scheduler_service.db.query().filter_by().all.return_value = active_devices

        # First device scan fails
        scheduler_service.vuln_scanner.scan_device_vulnerabilities.side_effect = (
            Exception("Scan failed")
        )

        with patch("src.scheduler.tasks.Scan") as mock_scan_class:
            mock_scan_class.return_value = sample_scan

            # Current behavior: entire scan fails if any device fails
            scheduler_service.run_vulnerability_scan()

            # Should have only attempted first scan before failing
            assert (
                scheduler_service.vuln_scanner.scan_device_vulnerabilities.call_count
                == 1
            )

            # Scan should be marked as failed
            assert sample_scan.status == "failed"
            assert sample_scan.error_message == "Scan failed"


@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration tests for realistic scheduling scenarios"""

    def test_full_scan_cycle(self, scheduler_service, sample_device):
        """Test complete scan cycle: discovery -> vulnerability -> cleanup"""
        # Discovery phase
        discovered_devices = [
            {"ip_address": "192.168.1.100", "mac_address": "00:11:22:33:44:55"}
        ]
        scheduler_service.discovery.discover_devices.return_value = discovered_devices
        scheduler_service.db.query().filter_by().first.return_value = sample_device

        # Vulnerability phase
        vulnerabilities = [{"cve_id": "CVE-2023-1234", "severity": "high"}]
        scheduler_service.vuln_scanner.scan_device_vulnerabilities.return_value = (
            vulnerabilities
        )
        scheduler_service.db.query().filter_by().all.return_value = [sample_device]

        with patch("src.scheduler.tasks.Scan") as mock_scan_class, patch.object(
            scheduler_service, "_check_new_devices"
        ), patch.object(scheduler_service, "_should_deep_scan") as mock_should_deep:

            mock_scan_class.return_value = Mock()
            mock_should_deep.return_value = False

            # Run discovery
            scheduler_service.run_network_discovery()

            # Run vulnerability scan
            scheduler_service.run_vulnerability_scan()

            # Run cleanup
            scheduler_service.cleanup_inactive_devices()

            # Verify all phases completed
            scheduler_service.discovery.discover_devices.assert_called_once()
            scheduler_service.vuln_scanner.scan_device_vulnerabilities.assert_called_once()

            # Verify database operations
            assert scheduler_service.db.add.call_count >= 2  # At least 2 scans added
            assert (
                scheduler_service.db.commit.call_count >= 3
            )  # Discovery, vuln, cleanup
