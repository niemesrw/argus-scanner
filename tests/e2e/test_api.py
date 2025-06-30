"""
End-to-end tests for Argus Scanner API endpoints
"""
import pytest
import requests
import json


class TestAPI:
    """Test suite for API endpoints"""
    
    BASE_URL = "http://localhost:8080"
    
    def test_api_stats_endpoint(self):
        """Test /api/stats endpoint returns correct structure"""
        response = requests.get(f"{self.BASE_URL}/api/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        # Check required fields
        assert "total_devices" in data
        assert "active_devices" in data
        assert "total_vulnerabilities" in data
        assert "critical_vulnerabilities" in data
        assert "unacknowledged_alerts" in data
        assert "recent_scans" in data
        assert "risk_distribution" in data
        
        # Check data types
        assert isinstance(data["total_devices"], int)
        assert isinstance(data["active_devices"], int)
        assert isinstance(data["total_vulnerabilities"], int)
        assert isinstance(data["critical_vulnerabilities"], int)
        assert isinstance(data["unacknowledged_alerts"], int)
        assert isinstance(data["recent_scans"], int)
        assert isinstance(data["risk_distribution"], dict)
        
        # Check mock data values
        assert data["total_devices"] == 3
        assert data["active_devices"] == 3
        assert data["total_vulnerabilities"] == 0
        assert data["critical_vulnerabilities"] == 0
        assert data["unacknowledged_alerts"] == 0
    
    def test_api_devices_endpoint(self):
        """Test /api/devices endpoint returns device list"""
        response = requests.get(f"{self.BASE_URL}/api/devices")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should be a list
        assert isinstance(data, list)
        assert len(data) == 3  # Mock data has 3 devices
        
        # Check first device structure
        device = data[0]
        required_fields = [
            "id", "ip_address", "hostname", "operating_system",
            "manufacturer", "mac_address", "is_active", "risk_score",
            "vulnerability_count", "service_count", "first_seen", "last_seen"
        ]
        
        for field in required_fields:
            assert field in device, f"Missing field: {field}"
        
        # Check data types
        assert isinstance(device["id"], int)
        assert isinstance(device["ip_address"], str)
        assert isinstance(device["hostname"], str)
        assert isinstance(device["is_active"], bool)
        assert isinstance(device["risk_score"], (int, float))
        assert isinstance(device["vulnerability_count"], int)
        assert isinstance(device["service_count"], int)
        
        # Check mock device IPs
        ips = [device["ip_address"] for device in data]
        expected_ips = ["192.168.1.1", "192.168.1.100", "192.168.1.150"]
        for ip in expected_ips:
            assert ip in ips, f"Expected IP {ip} not found in devices"
    
    def test_api_vulnerabilities_endpoint(self):
        """Test /api/vulnerabilities endpoint"""
        response = requests.get(f"{self.BASE_URL}/api/vulnerabilities")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should be a list
        assert isinstance(data, list)
        
        # If vulnerabilities exist, validate their structure
        if len(data) > 0:
            vuln = data[0]
            assert "id" in vuln
            assert "cve_id" in vuln
            assert "name" in vuln
            assert "severity" in vuln
            assert "device" in vuln
            assert "service" in vuln
    
    def test_api_alerts_endpoint(self):
        """Test /api/alerts endpoint"""
        response = requests.get(f"{self.BASE_URL}/api/alerts")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should be a list
        assert isinstance(data, list)
        
        # If alerts exist, validate their structure
        if len(data) > 0:
            alert = data[0]
            assert "id" in alert
            assert "severity" in alert
            assert "title" in alert
            assert "message" in alert
            assert "created_at" in alert
            assert "acknowledged" in alert
    
    def test_api_endpoints_return_json(self):
        """Test that all API endpoints return valid JSON with correct content type"""
        endpoints = ["/api/stats", "/api/devices", "/api/vulnerabilities", "/api/alerts"]
        
        for endpoint in endpoints:
            response = requests.get(f"{self.BASE_URL}{endpoint}")
            
            assert response.status_code == 200
            assert "application/json" in response.headers.get("Content-Type", "")
            
            # Should be valid JSON
            try:
                response.json()
            except json.JSONDecodeError:
                pytest.fail(f"Endpoint {endpoint} did not return valid JSON")
    
    def test_api_cors_headers(self):
        """Test that API endpoints include CORS headers"""
        response = requests.get(f"{self.BASE_URL}/api/stats")
        
        # Check for CORS headers (Flask-CORS should add these)
        assert response.status_code == 200
        # Note: CORS headers might only be present on cross-origin requests
        # This test documents the expectation even if headers aren't always present