"""
SQL injection prevention security tests
"""

import pytest
import sqlite3
from unittest.mock import patch, MagicMock

from src.database.models import Device, Service, Vulnerability, Alert, get_db_session
from src.web.routes import api_bp


@pytest.mark.security
class TestSQLInjectionPrevention:
    """Test SQL injection prevention across the application"""

    def test_device_search_sql_injection(
        self, security_client, security_db_session, malicious_payloads
    ):
        """Test device search endpoint against SQL injection"""

        # Create a test device first
        test_device = Device(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            hostname="test-device",
            first_seen=pytest.importorskip("datetime").datetime.now(),
            last_seen=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_device)
        security_db_session.commit()

        for payload in malicious_payloads["sql_injection"]:
            # Test search with SQL injection payload
            response = security_client.get(f"/api/devices/search?q={payload}")

            # Should not return errors that expose database structure
            assert response.status_code in [200, 400, 422]

            if response.status_code == 200:
                data = response.get_json()
                # Should return valid data structure, not database errors
                assert isinstance(data, (dict, list))

                # Should not return all devices (which would indicate successful injection)
                if isinstance(data, dict) and "devices" in data:
                    # If injection worked, it might return all devices
                    # We should only get legitimate search results
                    assert (
                        len(data["devices"]) <= 1
                    )  # Should only match our test device at most

    def test_device_filter_sql_injection(
        self, security_client, security_db_session, malicious_payloads
    ):
        """Test device filtering with SQL injection attempts"""

        # Create test devices
        devices = [
            Device(
                mac_address=f"00:11:22:33:44:{i:02x}",
                ip_address=f"192.168.1.{i}",
                hostname=f"device-{i}",
                first_seen=pytest.importorskip("datetime").datetime.now(),
                last_seen=pytest.importorskip("datetime").datetime.now(),
            )
            for i in range(1, 4)
        ]

        for device in devices:
            security_db_session.add(device)
        security_db_session.commit()

        for payload in malicious_payloads["sql_injection"]:
            # Test various filter parameters
            filter_params = [
                f"hostname={payload}",
                f"ip_address={payload}",
                f"mac_address={payload}",
                f"status={payload}",
            ]

            for param in filter_params:
                response = security_client.get(f"/api/devices?{param}")

                # Should handle injection attempts safely
                assert response.status_code in [200, 400, 422]

                if response.status_code == 200:
                    data = response.get_json()
                    assert isinstance(data, (dict, list))

                    # Should not return all devices (successful injection indicator)
                    if isinstance(data, dict) and "devices" in data:
                        # Should filter correctly, not return everything
                        assert len(data["devices"]) <= len(devices)

    def test_vulnerability_search_sql_injection(
        self, security_client, security_db_session, malicious_payloads
    ):
        """Test vulnerability search against SQL injection"""

        # Create a test vulnerability
        test_device = Device(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            hostname="test-device",
            first_seen=pytest.importorskip("datetime").datetime.now(),
            last_seen=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_device)
        security_db_session.commit()

        test_vuln = Vulnerability(
            device_id=test_device.id,
            cve_id="CVE-2023-12345",
            description="Test vulnerability",
            severity="high",
            cvss_score=7.5,
            discovered_at=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_vuln)
        security_db_session.commit()

        for payload in malicious_payloads["sql_injection"]:
            # Test vulnerability search with injection payload
            response = security_client.get(f"/api/vulnerabilities/search?q={payload}")

            assert response.status_code in [200, 400, 422]

            if response.status_code == 200:
                data = response.get_json()
                assert isinstance(data, (dict, list))

                # Should not return excessive results (injection indicator)
                if isinstance(data, dict) and "vulnerabilities" in data:
                    assert len(data["vulnerabilities"]) <= 1

    def test_alert_filter_sql_injection(
        self, security_client, security_db_session, malicious_payloads
    ):
        """Test alert filtering with SQL injection attempts"""

        # Create test alert
        test_device = Device(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            hostname="test-device",
            first_seen=pytest.importorskip("datetime").datetime.now(),
            last_seen=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_device)
        security_db_session.commit()

        test_alert = Alert(
            device_id=test_device.id,
            severity="high",
            message="Test alert message",
            triggered_at=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_alert)
        security_db_session.commit()

        for payload in malicious_payloads["sql_injection"]:
            # Test alert filtering with injection payload
            response = security_client.get(f"/api/alerts?severity={payload}")

            assert response.status_code in [200, 400, 422]

            if response.status_code == 200:
                data = response.get_json()
                assert isinstance(data, (dict, list))

    def test_raw_sql_injection_protection(
        self, security_db_session, malicious_payloads
    ):
        """Test that raw SQL execution is protected"""

        # Test direct database session usage
        for payload in malicious_payloads["sql_injection"]:
            try:
                # This should use parameterized queries and not be vulnerable
                result = (
                    security_db_session.query(Device)
                    .filter(Device.hostname == payload)
                    .first()
                )

                # Should execute without error
                assert result is None or isinstance(result, Device)

            except Exception as e:
                # Should not get database-specific errors that reveal structure
                error_msg = str(e).lower()
                assert "sqlite" not in error_msg
                assert "syntax error" not in error_msg
                assert "table" not in error_msg

    def test_orm_injection_protection(self, security_db_session, malicious_payloads):
        """Test ORM-level injection protection"""

        # Test various ORM operations with malicious input
        for payload in malicious_payloads["sql_injection"]:
            try:
                # Test query filtering
                devices = (
                    security_db_session.query(Device)
                    .filter(Device.ip_address.like(f"%{payload}%"))
                    .all()
                )

                assert isinstance(devices, list)

                # Test count operations
                count = (
                    security_db_session.query(Device)
                    .filter(Device.hostname.contains(payload))
                    .count()
                )

                assert isinstance(count, int)
                assert count >= 0

            except Exception as e:
                # Should handle gracefully without exposing database details
                error_msg = str(e).lower()
                assert "sqlite" not in error_msg
                assert "sql" not in error_msg

    def test_parameterized_query_usage(self, security_db_session):
        """Test that parameterized queries are used correctly"""

        # Test with special characters that could cause issues
        special_inputs = [
            "device'; DROP TABLE devices; --",
            "test' OR '1'='1",
            "normal-device-name",
            "device with spaces",
            "device'with'quotes",
        ]

        for test_input in special_inputs:
            # Test device creation
            device = Device(
                mac_address="00:11:22:33:44:55",
                ip_address="192.168.1.100",
                hostname=test_input,
                first_seen=pytest.importorskip("datetime").datetime.now(),
                last_seen=pytest.importorskip("datetime").datetime.now(),
            )

            try:
                security_db_session.add(device)
                security_db_session.commit()

                # Test retrieval
                retrieved = (
                    security_db_session.query(Device)
                    .filter(Device.hostname == test_input)
                    .first()
                )

                assert retrieved is not None
                assert retrieved.hostname == test_input

            except Exception as e:
                # Should handle gracefully
                security_db_session.rollback()
                assert "constraint" in str(e).lower() or "integrity" in str(e).lower()

            finally:
                # Cleanup
                security_db_session.query(Device).filter(
                    Device.hostname == test_input
                ).delete()
                security_db_session.commit()

    def test_time_based_injection_protection(self, security_client, malicious_payloads):
        """Test protection against time-based SQL injection"""

        # Time-based injection payloads
        time_based_payloads = [
            "'; WAITFOR DELAY '00:00:05'; --",
            "' OR (SELECT COUNT(*) FROM sysobjects) > 0 WAITFOR DELAY '00:00:05'; --",
            "'; SELECT SLEEP(5); --",
            "' UNION SELECT SLEEP(5); --",
        ]

        import time

        for payload in time_based_payloads:
            start_time = time.time()

            response = security_client.get(f"/api/devices/search?q={payload}")

            end_time = time.time()
            response_time = end_time - start_time

            # Should not take significantly longer (no time-based injection)
            assert (
                response_time < 2.0
            ), f"Response took too long: {response_time}s for payload: {payload}"
            assert response.status_code in [200, 400, 422]

    def test_union_based_injection_protection(
        self, security_client, security_db_session, malicious_payloads
    ):
        """Test protection against UNION-based SQL injection"""

        # Create test data
        test_device = Device(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            hostname="test-device",
            first_seen=pytest.importorskip("datetime").datetime.now(),
            last_seen=pytest.importorskip("datetime").datetime.now(),
        )
        security_db_session.add(test_device)
        security_db_session.commit()

        union_payloads = [
            "' UNION SELECT * FROM devices; --",
            "' UNION SELECT 1,2,3,4,5; --",
            "' UNION SELECT username,password FROM users; --",
            "' UNION ALL SELECT * FROM sqlite_master; --",
        ]

        for payload in union_payloads:
            response = security_client.get(f"/api/devices/search?q={payload}")

            assert response.status_code in [200, 400, 422]

            if response.status_code == 200:
                data = response.get_json()

                # Should not return extra columns or unexpected data structure
                if isinstance(data, dict) and "devices" in data:
                    for device in data["devices"]:
                        # Should have expected device structure
                        expected_keys = {
                            "id",
                            "mac_address",
                            "ip_address",
                            "hostname",
                            "first_seen",
                            "last_seen",
                        }
                        actual_keys = set(device.keys())

                        # Should not have extra columns from injection
                        assert not (
                            actual_keys - expected_keys
                        ), f"Unexpected keys found: {actual_keys - expected_keys}"

    def test_blind_injection_protection(self, security_client):
        """Test protection against blind SQL injection"""

        blind_payloads = [
            "' AND 1=1; --",
            "' AND 1=2; --",
            "' AND (SELECT COUNT(*) FROM devices) > 0; --",
            "' AND (SELECT COUNT(*) FROM sqlite_master) > 0; --",
        ]

        # Test that different payloads don't produce different response patterns
        responses = []

        for payload in blind_payloads:
            response = security_client.get(f"/api/devices/search?q={payload}")
            responses.append((response.status_code, len(response.get_data())))

        # All responses should be similar (no information leakage)
        status_codes = [r[0] for r in responses]
        response_lengths = [r[1] for r in responses]

        # Should not have dramatically different response patterns
        assert len(set(status_codes)) <= 2, "Response status codes vary too much"

        # Response lengths should be similar for similar payloads
        if len(set(response_lengths)) > 1:
            max_length = max(response_lengths)
            min_length = min(response_lengths)
            # Allow some variation but not dramatic differences
            assert (
                max_length - min_length
            ) / max_length < 0.5, "Response lengths vary too much"
