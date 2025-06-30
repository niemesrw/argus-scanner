"""
Performance benchmarks for scanner operations.
"""

import pytest
from unittest.mock import Mock, patch
from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.database.models import Device, Service
from tests.fixtures.network import mock_nmap_output


class TestScannerBenchmarks:
    """Benchmark tests for scanner performance."""

    @pytest.fixture
    def mock_scanner(self):
        """Create mock scanner instance."""
        scanner = NetworkDiscovery(network_range="192.168.1.0/24")
        return scanner

    @pytest.fixture
    def mock_devices(self, device_factory, db_session):
        """Create test devices for benchmarking."""
        return device_factory.create_batch(db_session, 100)

    def test_benchmark_network_discovery(
        self, benchmark, mock_scanner, mock_nmap_output
    ):
        """Benchmark network discovery performance."""
        # Mock nmap to return consistent results
        with patch("nmap.PortScanner") as mock_nmap:
            mock_instance = Mock()
            mock_instance.scan.return_value = None
            mock_instance.all_hosts.return_value = [
                "192.168.1.{}".format(i) for i in range(1, 51)
            ]

            # Mock host details
            def mock_host_details(host):
                return {
                    "tcp": {
                        22: {"state": "open", "name": "ssh"},
                        80: {"state": "open", "name": "http"},
                    },
                    "hostnames": [
                        {"name": f'host-{host.split(".")[-1]}', "type": "PTR"}
                    ],
                    "osmatch": [{"name": "Linux 4.15", "accuracy": "95"}],
                }

            mock_instance.__getitem__.side_effect = mock_host_details
            mock_nmap.return_value = mock_instance

            # Benchmark the scan operation
            result = benchmark(mock_scanner.scan_network)

            assert result is not None

    def test_benchmark_vulnerability_scan(self, benchmark, mock_devices, db_session):
        """Benchmark vulnerability scanning performance."""
        scanner = VulnerabilityScanner()

        # Mock CVE database queries
        with patch.object(scanner, "_query_cve_database") as mock_cve:
            mock_cve.return_value = [
                {
                    "cve_id": "CVE-2021-44228",
                    "severity": "critical",
                    "cvss_score": 10.0,
                    "description": "Test vulnerability",
                }
            ]

            # Benchmark vulnerability scanning for multiple devices
            def scan_all_devices():
                results = []
                for device in mock_devices[:10]:  # Scan 10 devices
                    result = scanner.scan_device(device)
                    results.append(result)
                return results

            results = benchmark(scan_all_devices)
            assert len(results) == 10

    def test_benchmark_database_operations(self, benchmark, db_session, device_factory):
        """Benchmark database query performance."""
        # Create test data
        devices = device_factory.create_batch(db_session, 50)

        def complex_query():
            # Simulate complex query with joins and filters
            from sqlalchemy import and_, or_

            query = (
                db_session.query(Device)
                .filter(
                    or_(
                        Device.risk_score > 70,
                        and_(Device.device_type == "server", Device.status == "online"),
                    )
                )
                .join(Service)
                .filter(Service.port.in_([22, 80, 443, 3306]))
                .distinct()
            )

            return query.all()

        results = benchmark(complex_query)
        assert isinstance(results, list)

    @pytest.mark.parametrize("network_size", ["/32", "/24", "/16"])
    def test_benchmark_network_size_scaling(self, benchmark, network_size):
        """Benchmark scanner performance with different network sizes."""
        scanner = NetworkDiscovery(network_range=f"192.168.0.0{network_size}")

        with patch("nmap.PortScanner") as mock_nmap:
            mock_instance = Mock()
            mock_instance.scan.return_value = None

            # Simulate different numbers of hosts based on network size
            host_counts = {"/32": 1, "/24": 50, "/16": 200}
            host_count = host_counts.get(network_size, 1)

            mock_instance.all_hosts.return_value = [
                f"192.168.{i//256}.{i%256}" for i in range(host_count)
            ]
            mock_instance.__getitem__.return_value = {"tcp": {22: {"state": "open"}}}
            mock_nmap.return_value = mock_instance

            # Benchmark with timing groups
            benchmark.group = f"Network Size {network_size}"
            result = benchmark(scanner.scan_network)

            assert result is not None

    def test_benchmark_concurrent_scans(self, benchmark, mock_scanner):
        """Benchmark concurrent scanning operations."""
        import concurrent.futures

        def run_concurrent_scans():
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Mock the actual scanning to focus on concurrency overhead
                with patch.object(mock_scanner, "_scan_host") as mock_scan:
                    mock_scan.return_value = {
                        "ip": "192.168.1.1",
                        "open_ports": [22, 80],
                    }

                    futures = []
                    for i in range(20):
                        future = executor.submit(
                            mock_scanner._scan_host, f"192.168.1.{i}"
                        )
                        futures.append(future)

                    results = [
                        f.result() for f in concurrent.futures.as_completed(futures)
                    ]
                    return results

        results = benchmark(run_concurrent_scans)
        assert len(results) == 20


class TestAlertBenchmarks:
    """Benchmark tests for alert system performance."""

    def test_benchmark_alert_generation(
        self,
        benchmark,
        alert_factory,
        device_factory,
        vulnerability_factory,
        db_session,
    ):
        """Benchmark alert generation and processing."""
        # Create test data
        devices = device_factory.create_batch(db_session, 20)

        def generate_alerts():
            alerts = []
            for device in devices:
                vulns = vulnerability_factory.create_batch(db_session, device, 3)
                for vuln in vulns:
                    if vuln.severity == "critical":
                        alert = alert_factory.create(db_session, device, vuln)
                        alerts.append(alert)
            return alerts

        alerts = benchmark(generate_alerts)
        assert len(alerts) > 0

    def test_benchmark_alert_notification(self, benchmark):
        """Benchmark alert notification sending."""
        from src.alerts.manager import AlertManager

        manager = AlertManager()

        # Mock email and Slack sending
        with patch.object(manager, "_send_email") as mock_email, patch.object(
            manager, "_send_slack"
        ) as mock_slack:

            mock_email.return_value = True
            mock_slack.return_value = True

            # Create test alert data
            alert_data = {
                "severity": "critical",
                "title": "Critical Vulnerability Found",
                "message": "CVE-2021-44228 detected on server-01",
                "device": {"hostname": "server-01", "ip": "192.168.1.100"},
                "vulnerability": {"cve_id": "CVE-2021-44228", "cvss_score": 10.0},
            }

            # Benchmark notification sending
            def send_notifications():
                results = []
                for i in range(50):  # Send 50 notifications
                    result = manager.send_alert(alert_data)
                    results.append(result)
                return results

            results = benchmark(send_notifications)
            assert all(results)


class TestWebBenchmarks:
    """Benchmark tests for web interface performance."""

    def test_benchmark_dashboard_rendering(
        self, benchmark, client, populate_test_database
    ):
        """Benchmark dashboard page rendering."""
        # Populate database with test data
        populate_test_database(num_devices=100, num_scans=50)

        def load_dashboard():
            response = client.get("/")
            assert response.status_code == 200
            return response

        response = benchmark(load_dashboard)
        assert b"Argus Scanner" in response.data

    def test_benchmark_api_endpoints(self, benchmark, client, populate_test_database):
        """Benchmark API endpoint performance."""
        populate_test_database(num_devices=50)

        endpoints = [
            "/api/devices",
            "/api/scans",
            "/api/vulnerabilities",
            "/api/alerts",
        ]

        def call_all_endpoints():
            responses = []
            for endpoint in endpoints:
                response = client.get(endpoint)
                responses.append(response)
            return responses

        responses = benchmark(call_all_endpoints)
        assert all(r.status_code == 200 for r in responses)
