"""
Unit tests for web routes module
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import json

from src.web.routes import api_bp, dashboard_bp
from src.database.models import Device, Service, Vulnerability, Alert, Scan, Severity, ScanType


class TestAPIRoutes:
    """Test suite for API route functions"""
    
    @pytest.fixture
    def app(self):
        """Create test Flask app"""
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['DB_PATH'] = ':memory:'
        app.config['SETTINGS'] = Mock()
        app.register_blueprint(api_bp, url_prefix='/api')
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @patch('src.web.routes.get_db_session')
    def test_get_stats_endpoint(self, mock_get_db_session, client):
        """Test /api/stats endpoint functionality"""
        # Mock database session and queries
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Mock query results
        mock_db.query.return_value.count.return_value = 5
        mock_db.query.return_value.filter_by.return_value.count.return_value = 3
        mock_db.query.return_value.filter.return_value.count.return_value = 2
        mock_db.query.return_value.group_by.return_value.all.return_value = [
            ('High', 2), ('Medium', 1), ('Low', 2)
        ]
        
        response = client.get('/api/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify expected fields are present
        expected_fields = [
            'total_devices', 'active_devices', 'total_vulnerabilities',
            'critical_vulnerabilities', 'unacknowledged_alerts', 
            'recent_scans', 'risk_distribution'
        ]
        for field in expected_fields:
            assert field in data
        
        # Verify database session was closed
        mock_db.close.assert_called_once()
    
    @patch('src.web.routes.get_db_session')
    def test_get_devices_endpoint(self, mock_get_db_session, client):
        """Test /api/devices endpoint functionality"""
        # Mock database session
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Create mock device
        mock_device = Mock()
        mock_device.id = 1
        mock_device.hostname = 'test-device'
        mock_device.ip_address = '192.168.1.100'
        mock_device.mac_address = 'AA:BB:CC:DD:EE:FF'
        mock_device.device_type = 'Computer'
        mock_device.operating_system = 'Linux'
        mock_device.manufacturer = 'Dell'
        mock_device.is_active = True
        mock_device.risk_score = 25.5
        mock_device.last_seen = datetime(2025, 1, 1, 12, 0, 0)
        mock_device.first_seen = datetime(2025, 1, 1, 10, 0, 0)
        mock_device.services = []  # Mock empty services list
        
        mock_db.query.return_value.order_by.return_value.all.return_value = [mock_device]
        
        response = client.get('/api/devices')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert isinstance(data, list)
        assert len(data) == 1
        
        device_data = data[0]
        assert device_data['id'] == 1
        assert device_data['hostname'] == 'test-device'
        assert device_data['ip_address'] == '192.168.1.100'
        assert device_data['is_active'] is True
        assert device_data['risk_score'] == 25.5
        
        mock_db.close.assert_called_once()
    
    @patch('src.web.routes.get_db_session')
    def test_get_vulnerabilities_endpoint(self, mock_get_db_session, client):
        """Test /api/vulnerabilities endpoint functionality"""
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Mock empty vulnerabilities list
        mock_db.query.return_value.join.return_value.join.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/vulnerabilities')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert isinstance(data, list)
        assert len(data) == 0
        
        mock_db.close.assert_called_once()
    
    @patch('src.web.routes.get_db_session')
    def test_get_vulnerabilities_with_filters(self, mock_get_db_session, client):
        """Test /api/vulnerabilities endpoint with query filters"""
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Mock the query chain
        mock_query = mock_db.query.return_value.join.return_value.join.return_value
        mock_filtered_query = mock_query.filter.return_value
        mock_filtered_query.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/vulnerabilities?severity=critical&exploit_available=true')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert isinstance(data, list)
        # Verify filters were applied
        assert mock_query.filter.call_count >= 1
        
        mock_db.close.assert_called_once()
    
    @patch('src.web.routes.get_db_session')
    def test_get_alerts_endpoint(self, mock_get_db_session, client):
        """Test /api/alerts endpoint functionality"""
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Create mock alert
        mock_alert = Mock()
        mock_alert.id = 1
        mock_alert.severity = Severity.HIGH
        mock_alert.title = 'Test Alert'
        mock_alert.message = 'Test message'
        mock_alert.created_at = datetime(2025, 1, 1, 12, 0, 0)
        mock_alert.acknowledged = False
        mock_alert.acknowledged_at = None
        mock_alert.acknowledged_by = None
        mock_alert.notification_sent = True
        
        mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_alert]
        
        response = client.get('/api/alerts')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert isinstance(data, list)
        assert len(data) == 1
        
        alert_data = data[0]
        assert alert_data['id'] == 1
        assert alert_data['severity'] == 'high'
        assert alert_data['title'] == 'Test Alert'
        assert alert_data['acknowledged'] is False
        assert alert_data['notification_sent'] is True
        
        mock_db.close.assert_called_once()
    
    @patch('src.web.routes.get_db_session')
    @patch('src.web.routes.AlertManager')
    def test_acknowledge_alert(self, mock_alert_manager, mock_get_db_session, client):
        """Test acknowledging an alert"""
        mock_manager_instance = Mock()
        mock_alert_manager.return_value = mock_manager_instance
        
        response = client.post('/api/alerts/1/acknowledge', 
                             json={'acknowledged_by': 'test_user'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        
        mock_manager_instance.acknowledge_alert.assert_called_once_with(1, 'test_user')
    
    @patch('src.web.routes.get_db_session')
    def test_resolve_alert(self, mock_get_db_session, client):
        """Test resolving an alert"""
        mock_db = Mock()
        mock_get_db_session.return_value = mock_db
        
        # Mock alert object
        mock_alert = Mock()
        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_alert
        
        response = client.post('/api/alerts/1/resolve',
                             json={},
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Verify alert was marked as resolved
        assert mock_alert.acknowledged is True
        mock_db.commit.assert_called_once()
        mock_db.close.assert_called_once()


class TestDashboardRoutes:
    """Test suite for dashboard route functions"""
    
    @pytest.fixture
    def app(self):
        """Create test Flask app"""
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.register_blueprint(dashboard_bp)
        
        # Mock template rendering
        app.jinja_env.get_template = Mock()
        
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @patch('src.web.routes.render_template')
    def test_index_route(self, mock_render_template, client):
        """Test dashboard index route"""
        mock_render_template.return_value = 'dashboard html'
        
        response = client.get('/')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('dashboard.html')
    
    @patch('src.web.routes.render_template')
    def test_devices_route(self, mock_render_template, client):
        """Test devices page route"""
        mock_render_template.return_value = 'devices html'
        
        response = client.get('/devices')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('devices.html')
    
    @patch('src.web.routes.render_template')
    def test_device_detail_route(self, mock_render_template, client):
        """Test device detail page route"""
        mock_render_template.return_value = 'device detail html'
        
        response = client.get('/devices/123')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('device_detail.html', device_id=123)
    
    @patch('src.web.routes.render_template')
    def test_vulnerabilities_route(self, mock_render_template, client):
        """Test vulnerabilities page route"""
        mock_render_template.return_value = 'vulns html'
        
        response = client.get('/vulnerabilities')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('vulnerabilities.html')
    
    @patch('src.web.routes.render_template')
    def test_alerts_route(self, mock_render_template, client):
        """Test alerts page route"""
        mock_render_template.return_value = 'alerts html'
        
        response = client.get('/alerts')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('alerts.html')
    
    @patch('src.web.routes.render_template')
    def test_scans_route(self, mock_render_template, client):
        """Test scans page route"""
        mock_render_template.return_value = 'scans html'
        
        response = client.get('/scans')
        
        assert response.status_code == 200
        mock_render_template.assert_called_once_with('scans.html')


class TestScanningRoutes:
    """Test suite for scanning-related API routes"""
    
    @pytest.fixture
    def app(self):
        """Create test Flask app"""
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['SETTINGS'] = Mock()
        app.register_blueprint(api_bp, url_prefix='/api')
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @patch('src.web.routes.NetworkDiscovery')
    def test_start_discovery_scan(self, mock_discovery_class, client):
        """Test starting a discovery scan"""
        mock_discovery = Mock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.discover_devices.return_value = [
            {'ip_address': '192.168.1.1'}, 
            {'ip_address': '192.168.1.2'}
        ]
        
        response = client.post('/api/scan/start', 
                             json={'scan_type': 'discovery'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert data['devices_found'] == 2
        
        mock_discovery.discover_devices.assert_called_once()
    
    def test_start_vulnerability_scan(self, client):
        """Test starting a vulnerability scan"""
        response = client.post('/api/scan/start', 
                             json={'scan_type': 'vulnerability'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert 'message' in data
    
    def test_start_scan_invalid_type(self, client):
        """Test starting scan with invalid type"""
        response = client.post('/api/scan/start', 
                             json={'scan_type': 'invalid'})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert 'error' in data
    
    @patch('src.web.routes.NetworkDiscovery')
    def test_start_scan_with_exception(self, mock_discovery_class, client):
        """Test scan start with exception handling"""
        mock_discovery = Mock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.discover_devices.side_effect = Exception('Network error')
        
        response = client.post('/api/scan/start', 
                             json={'scan_type': 'discovery'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        
        assert 'error' in data
        assert 'Network error' in data['error']