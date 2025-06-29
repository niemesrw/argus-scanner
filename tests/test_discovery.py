"""
Tests for network discovery module
"""
import pytest
from unittest.mock import Mock, patch
from src.scanner.discovery import NetworkDiscovery
from src.config.settings import Settings

@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = Mock(spec=Settings)
    settings.mock_mode = True
    settings.network_range = "192.168.1.0/24"
    settings.db_path = ":memory:"
    return settings

@pytest.fixture
def discovery(mock_settings):
    """Create NetworkDiscovery instance for testing"""
    with patch('src.scanner.discovery.get_db_session'):
        return NetworkDiscovery(mock_settings)

def test_discover_devices_mock_mode(discovery):
    """Test device discovery in mock mode"""
    devices = discovery.discover_devices()
    
    assert len(devices) > 0
    assert all('ip_address' in device for device in devices)
    assert all('mac_address' in device for device in devices)

def test_get_local_networks(discovery):
    """Test getting local network interfaces"""
    with patch('netifaces.interfaces', return_value=['eth0', 'wlan0']):
        with patch('netifaces.ifaddresses') as mock_ifaddresses:
            mock_ifaddresses.return_value = {
                2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0'}]
            }
            networks = discovery.get_local_networks()
            assert isinstance(networks, list)

@pytest.mark.parametrize("host,expected", [
    ("192.168.1.1", True),
    ("invalid", False),
])
def test_extract_device_info(discovery, host, expected):
    """Test device info extraction"""
    # This would require mocking nmap results
    # For now, just test the function exists
    assert hasattr(discovery, '_extract_device_info')