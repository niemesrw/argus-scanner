"""
Input validation security tests
"""

import pytest
import json
from unittest.mock import patch

from src.web.routes import api_bp
from src.database.models import Device, Service, Vulnerability, Alert


@pytest.mark.security
class TestInputValidation:
    """Test input validation for all API endpoints"""

    def test_api_device_creation_input_validation(
        self, security_client, malicious_payloads, invalid_inputs
    ):
        """Test device creation API input validation"""

        # Test SQL injection in device data
        for payload in malicious_payloads["sql_injection"]:
            device_data = {
                "mac_address": payload,
                "ip_address": "192.168.1.100",
                "hostname": "test-device",
            }

            response = security_client.post(
                "/api/devices", json=device_data, content_type="application/json"
            )

            # Should reject malicious input
            assert response.status_code in [
                400,
                422,
            ], f"Should reject SQL injection payload: {payload}"

            # Check response doesn't contain error details that could help attackers
            response_data = response.get_json()
            if response_data and "error" in response_data:
                error_msg = response_data["error"].lower()
                # Should not expose database details
                assert "sql" not in error_msg
                assert "database" not in error_msg
                assert "sqlite" not in error_msg

    def test_api_search_input_validation(self, security_client, malicious_payloads):
        """Test search API input validation"""

        # Test XSS in search queries
        for payload in malicious_payloads["xss"]:
            response = security_client.get(f"/api/devices/search?q={payload}")

            # Should handle XSS payload safely
            assert response.status_code in [
                200,
                400,
            ], f"Should handle XSS payload: {payload}"

            # Response should not contain unescaped script tags
            response_text = response.get_data(as_text=True)
            assert "<script>" not in response_text.lower()
            assert "javascript:" not in response_text.lower()

    def test_api_parameter_length_validation(self, security_client, invalid_inputs):
        """Test parameter length validation"""

        # Test oversized hostname
        device_data = {
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.100",
            "hostname": invalid_inputs["long_strings"],  # 10,000 char string
        }

        response = security_client.post(
            "/api/devices", json=device_data, content_type="application/json"
        )

        # Should reject oversized input
        assert response.status_code in [400, 422, 413]

    def test_api_data_type_validation(self, security_client, invalid_inputs):
        """Test data type validation"""

        # Test invalid data types
        test_cases = [
            {
                "mac_address": 123,
                "ip_address": "192.168.1.1",
                "hostname": "test",
            },  # number instead of string
            {
                "mac_address": "00:11:22:33:44:55",
                "ip_address": [],
                "hostname": "test",
            },  # array instead of string
            {
                "mac_address": "00:11:22:33:44:55",
                "ip_address": "192.168.1.1",
                "hostname": {},
            },  # object instead of string
        ]

        for test_case in test_cases:
            response = security_client.post(
                "/api/devices", json=test_case, content_type="application/json"
            )

            # Should reject invalid data types
            assert response.status_code in [
                400,
                422,
            ], f"Should reject invalid data types: {test_case}"

    def test_api_required_fields_validation(self, security_client):
        """Test required fields validation"""

        # Test missing required fields
        incomplete_data_cases = [
            {},  # Empty data
            {"mac_address": "00:11:22:33:44:55"},  # Missing IP and hostname
            {"ip_address": "192.168.1.1"},  # Missing MAC and hostname
            {"hostname": "test-device"},  # Missing MAC and IP
        ]

        for incomplete_data in incomplete_data_cases:
            response = security_client.post(
                "/api/devices", json=incomplete_data, content_type="application/json"
            )

            # Should reject incomplete data
            assert response.status_code in [
                400,
                422,
            ], f"Should reject incomplete data: {incomplete_data}"

    def test_api_ip_address_format_validation(self, security_client):
        """Test IP address format validation"""

        invalid_ips = [
            "999.999.999.999",  # Invalid IP ranges
            "192.168.1",  # Incomplete IP
            "192.168.1.1.1",  # Too many octets
            "not.an.ip.address",  # Non-numeric
            "192.168.1.-1",  # Negative octet
            "192.168.1.256",  # Octet too large
            "localhost",  # Hostname instead of IP
            "::1",  # IPv6 (if not supported)
        ]

        for invalid_ip in invalid_ips:
            device_data = {
                "mac_address": "00:11:22:33:44:55",
                "ip_address": invalid_ip,
                "hostname": "test-device",
            }

            response = security_client.post(
                "/api/devices", json=device_data, content_type="application/json"
            )

            # Should reject invalid IP formats
            assert response.status_code in [
                400,
                422,
            ], f"Should reject invalid IP: {invalid_ip}"

    def test_api_mac_address_format_validation(self, security_client):
        """Test MAC address format validation"""

        invalid_macs = [
            "00:11:22:33:44",  # Too short
            "00:11:22:33:44:55:66",  # Too long
            "00-11-22-33-44-55",  # Wrong delimiter (might be valid depending on implementation)
            "XX:11:22:33:44:55",  # Invalid hex chars
            "00:11:22:33:44:GG",  # Invalid hex chars
            "not-a-mac-address",  # Completely invalid
            "00:11:22:33:44:",  # Incomplete
        ]

        for invalid_mac in invalid_macs:
            device_data = {
                "mac_address": invalid_mac,
                "ip_address": "192.168.1.100",
                "hostname": "test-device",
            }

            response = security_client.post(
                "/api/devices", json=device_data, content_type="application/json"
            )

            # Should reject invalid MAC formats
            assert response.status_code in [
                400,
                422,
            ], f"Should reject invalid MAC: {invalid_mac}"

    def test_json_payload_validation(self, security_client, invalid_inputs):
        """Test JSON payload validation"""

        # Test malformed JSON
        response = security_client.post(
            "/api/devices",
            data=invalid_inputs["malformed_json"],
            content_type="application/json",
        )

        # Should reject malformed JSON
        assert response.status_code in [400, 422]

        # Test oversized JSON payload
        oversized_payload = json.dumps({"data": "A" * 100000})  # Large JSON
        response = security_client.post(
            "/api/devices", data=oversized_payload, content_type="application/json"
        )

        # Should reject oversized payload
        assert response.status_code in [400, 413, 422]

    def test_unicode_and_encoding_validation(self, security_client, invalid_inputs):
        """Test Unicode and encoding validation"""

        # Test Unicode attacks
        device_data = {
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.100",
            "hostname": invalid_inputs["unicode_attacks"],
        }

        response = security_client.post(
            "/api/devices", json=device_data, content_type="application/json"
        )

        # Should handle Unicode safely
        assert response.status_code in [200, 400, 422]

        # Test null byte injection
        device_data["hostname"] = invalid_inputs["null_bytes"]
        response = security_client.post(
            "/api/devices", json=device_data, content_type="application/json"
        )

        # Should reject null bytes
        assert response.status_code in [400, 422]

    def test_content_type_validation(self, security_client):
        """Test content type validation"""

        valid_device_data = {
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.100",
            "hostname": "test-device",
        }

        # Test with wrong content type
        response = security_client.post(
            "/api/devices",
            data=json.dumps(valid_device_data),
            content_type="text/plain",
        )

        # Should reject wrong content type for JSON endpoints
        assert response.status_code in [400, 415]

    def test_http_method_validation(self, security_client):
        """Test HTTP method validation"""

        # Test unsupported methods on endpoints
        endpoints_to_test = ["/api/devices", "/api/vulnerabilities", "/api/alerts"]

        for endpoint in endpoints_to_test:
            # Test methods that should not be allowed
            unsupported_methods = ["PUT", "DELETE", "PATCH"]

            for method in unsupported_methods:
                response = security_client.open(endpoint, method=method)

                # Should return method not allowed
                assert response.status_code in [
                    405
                ], f"Method {method} should not be allowed on {endpoint}"
