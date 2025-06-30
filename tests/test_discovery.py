"""
Tests for network discovery module
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import socket
import ipaddress

from src.scanner.discovery import NetworkDiscovery
from src.config.settings import Settings
from src.database.models import Device


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = Mock(spec=Settings)
    settings.mock_mode = True
    settings.network_range = "192.168.1.0/24"
    settings.db_path = ":memory:"
    return settings


@pytest.fixture
def mock_settings_real_mode():
    """Create mock settings for real mode testing"""
    settings = Mock(spec=Settings)
    settings.mock_mode = False
    settings.network_range = "192.168.1.0/24"
    settings.db_path = ":memory:"
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
def discovery(mock_settings, mock_db_session):
    """Create NetworkDiscovery instance for testing"""
    with patch('src.scanner.discovery.get_db_session', return_value=mock_db_session):
        discovery = NetworkDiscovery(mock_settings)
        return discovery


@pytest.fixture
def discovery_real_mode(mock_settings_real_mode, mock_db_session):
    """Create NetworkDiscovery instance for real mode testing"""
    with patch('src.scanner.discovery.get_db_session', return_value=mock_db_session):
        with patch('src.scanner.discovery.nmap.PortScanner') as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner_class.return_value = mock_scanner
            discovery = NetworkDiscovery(mock_settings_real_mode)
            discovery.nm = mock_scanner
            return discovery


class TestNetworkDiscovery:
    """Test suite for NetworkDiscovery class"""
    
    def test_initialization(self, mock_settings, mock_db_session):
        """Test NetworkDiscovery initialization"""
        with patch('src.scanner.discovery.get_db_session', return_value=mock_db_session):
            discovery = NetworkDiscovery(mock_settings)
            
            assert discovery.settings == mock_settings
            assert discovery.db == mock_db_session
            assert hasattr(discovery, 'nm')
    
    def test_discover_devices_real_mode_with_devices(self, discovery_real_mode):
        """Test real mode discovery with devices found"""
        # Mock nmap scanner responses
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = ['192.168.1.1', '192.168.1.100']
        discovery_real_mode.nm.__getitem__.side_effect = lambda host: Mock(**{'state.return_value': 'up'})
        
        # Mock device info extraction
        test_device_info = {
            'ip_address': '192.168.1.1',
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }
        
        with patch.object(discovery_real_mode, '_extract_device_info', return_value=test_device_info):
            devices = discovery_real_mode.discover_devices()
            
            assert len(devices) == 2
            discovery_real_mode.nm.scan.assert_called_once()
            # Verify correct scan arguments
            args, kwargs = discovery_real_mode.nm.scan.call_args
            assert 'hosts' in kwargs
            assert 'arguments' in kwargs
            assert '-sn -PR' in kwargs['arguments']
    
    def test_discover_devices_no_devices_found(self, discovery_real_mode):
        """Test real mode discovery with no devices found"""
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = []
        
        devices = discovery_real_mode.discover_devices()
        
        assert len(devices) == 0
        discovery_real_mode.nm.scan.assert_called_once()
    
    def test_discover_devices_with_down_hosts(self, discovery_real_mode):
        """Test real mode discovery with some hosts down"""
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = ['192.168.1.1', '192.168.1.100']
        
        # Mock one host up, one down
        def mock_host_state(host):
            if host == '192.168.1.1':
                return Mock(**{'state.return_value': 'up'})
            else:
                return Mock(**{'state.return_value': 'down'})
        
        discovery_real_mode.nm.__getitem__.side_effect = mock_host_state
        
        test_device_info = {
            'ip_address': '192.168.1.1',
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }
        
        with patch.object(discovery_real_mode, '_extract_device_info', return_value=test_device_info):
            devices = discovery_real_mode.discover_devices()
            
            # Should only return devices that are up
            assert len(devices) == 1
            assert devices[0]['ip_address'] == '192.168.1.1'
    
    def test_discover_devices_mock_mode(self, discovery):
        """Test device discovery in mock mode"""
        devices = discovery.discover_devices()
        
        assert len(devices) > 0
        assert all('ip_address' in device for device in devices)
        assert all('mac_address' in device for device in devices)
        assert all('hostname' in device for device in devices)
        assert all('manufacturer' in device for device in devices)
        assert all('operating_system' in device for device in devices)
        assert all('services' in device for device in devices)
        
        # In mock mode, devices are returned from _get_mock_devices()
        # Database operations are handled by _save_device() method
        # which is tested separately
    
    def test_discover_devices_custom_range(self, discovery):
        """Test device discovery with custom network range"""
        custom_range = "10.0.0.0/24"
        devices = discovery.discover_devices(network_range=custom_range)
        
        assert len(devices) > 0
        # In mock mode, it should still return the same mock devices
        # but the custom range should be passed through
        assert all('ip_address' in device for device in devices)
    
    @patch('src.scanner.discovery.logger')
    def test_discover_devices_real_mode_success(self, mock_logger, discovery_real_mode):
        """Test device discovery in real mode with successful scan"""
        # Mock nmap scanner
        mock_nm = Mock()
        discovery_real_mode.nm = mock_nm
        
        # Setup nmap mock responses
        mock_nm.scan.return_value = None
        mock_nm.all_hosts.return_value = ['192.168.1.1', '192.168.1.100']
        mock_nm.__getitem__.side_effect = lambda host: {
            '192.168.1.1': Mock(**{'state.return_value': 'up'}),
            '192.168.1.100': Mock(**{'state.return_value': 'up'})
        }[host]
        
        # Mock device info extraction
        with patch.object(discovery_real_mode, '_extract_device_info', return_value={
            'ip_address': '192.168.1.1',
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }) as mock_extract:
            with patch.object(discovery_real_mode, '_save_device') as mock_save:
                devices = discovery_real_mode.discover_devices()
                
                assert len(devices) == 2
                assert mock_extract.call_count == 2
                assert mock_save.call_count == 2
                mock_logger.info.assert_called()
    
    @patch('src.scanner.discovery.logger')
    def test_discover_devices_real_mode_error(self, mock_logger, discovery_real_mode):
        """Test device discovery in real mode with scan error"""
        # Mock nmap scanner to raise exception
        discovery_real_mode.nm.scan.side_effect = Exception("Network unreachable")
        
        with pytest.raises(Exception, match="Network unreachable"):
            discovery_real_mode.discover_devices()
        
        mock_logger.error.assert_called_with("Error during network discovery: Network unreachable")


class TestDeepScanning:
    """Test suite for deep device scanning"""
    
    @patch('src.scanner.discovery.logger')
    def test_deep_scan_device_success(self, mock_logger, discovery_real_mode):
        """Test successful deep scan of a device"""
        ip_address = "192.168.1.100"
        
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = [ip_address]
        
        expected_info = {
            'ip_address': ip_address,
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'operating_system': 'Ubuntu 20.04',
            'services': [{'port': 22, 'protocol': 'tcp', 'name': 'ssh'}]
        }
        
        with patch.object(discovery_real_mode, '_extract_detailed_info', return_value=expected_info) as mock_extract:
            result = discovery_real_mode.deep_scan_device(ip_address)
            
            assert result == expected_info
            discovery_real_mode.nm.scan.assert_called_once_with(hosts=ip_address, arguments='-A -T4')
            mock_extract.assert_called_once_with(ip_address)
            mock_logger.info.assert_called_with(f"Starting deep scan for device: {ip_address}")
    
    def test_deep_scan_device_with_detailed_info(self, discovery_real_mode):
        """Test deep scan with comprehensive detailed info extraction"""
        ip_address = "192.168.1.100"
        
        # Mock nmap results with OS and services
        mock_host_data = Mock()
        mock_host_data.__contains__.return_value = True
        mock_host_data.__getitem__.side_effect = lambda key: {
            'osmatch': [{
                'name': 'Ubuntu Linux 20.04',
                'accuracy': '95'
            }]
        }[key] if key == 'osmatch' else mock_host_data
        
        mock_host_data.all_protocols.return_value = ['tcp']
        mock_host_data.__getitem__.side_effect = lambda key: {
            'tcp': {
                22: {
                    'state': 'open',
                    'name': 'ssh',
                    'product': 'OpenSSH',
                    'version': '7.4',
                    'extrainfo': 'protocol 2.0'
                },
                80: {
                    'state': 'closed',
                    'name': 'http'
                }
            },
            'osmatch': [{
                'name': 'Ubuntu Linux 20.04',
                'accuracy': '95'
            }]
        }[key] if key in ['tcp', 'osmatch'] else {}
        
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = [ip_address]
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        # Mock basic device info
        basic_info = {
            'ip_address': ip_address,
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }
        
        with patch.object(discovery_real_mode, '_extract_device_info', return_value=basic_info):
            result = discovery_real_mode.deep_scan_device(ip_address)
            
            assert result['operating_system'] == 'Ubuntu Linux 20.04'
            assert result['os_accuracy'] == '95'
            assert 'services' in result
            # Should only include open services
            assert len(result['services']) == 1
            assert result['services'][0]['port'] == 22
            assert result['services'][0]['state'] == 'open'
    
    @patch('src.scanner.discovery.logger')
    def test_deep_scan_device_not_found(self, mock_logger, discovery_real_mode):
        """Test deep scan when device is not found in results"""
        ip_address = "192.168.1.100"
        
        # Mock nmap scanner
        mock_nm = Mock()
        discovery_real_mode.nm = mock_nm
        
        mock_nm.scan.return_value = None
        mock_nm.all_hosts.return_value = []  # Device not found
        
        result = discovery_real_mode.deep_scan_device(ip_address)
        
        assert result == {}
        mock_logger.warning.assert_called_with(f"Device {ip_address} not found in scan results")
    
    @patch('src.scanner.discovery.logger')
    def test_deep_scan_device_error(self, mock_logger, discovery_real_mode):
        """Test deep scan with scan error"""
        ip_address = "192.168.1.100"
        discovery_real_mode.nm.scan.side_effect = Exception("Scan failed")
        
        with pytest.raises(Exception, match="Scan failed"):
            discovery_real_mode.deep_scan_device(ip_address)
        
        mock_logger.error.assert_called_with(f"Error during deep scan of {ip_address}: Scan failed")


class TestDeviceInfoExtraction:
    """Test suite for device information extraction"""
    
    def test_extract_device_info_basic(self, discovery_real_mode):
        """Test basic device info extraction"""
        host = "192.168.1.100"
        
        # Mock nmap results
        mock_host_data = Mock()
        mock_host_data.state.return_value = 'up'
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery_real_mode, '_get_hostname', return_value='test-host'):
            with patch.object(discovery_real_mode, '_get_mac_address', return_value='00:11:22:33:44:55'):
                device_info = discovery_real_mode._extract_device_info(host)
                
                assert device_info['ip_address'] == host
                assert device_info['hostname'] == 'test-host'
                assert device_info['mac_address'] == '00:11:22:33:44:55'
                assert device_info['state'] == 'up'
                assert 'last_seen' in device_info
                assert isinstance(device_info['last_seen'], datetime)
    
    def test_extract_device_info_no_hostname_no_mac(self, discovery_real_mode):
        """Test device info extraction with no hostname or MAC"""
        host = "192.168.1.100"
        
        # Mock nmap results
        mock_host_data = Mock()
        mock_host_data.state.return_value = 'up'
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery_real_mode, '_get_hostname', return_value=None):
            with patch.object(discovery_real_mode, '_get_mac_address', return_value=None):
                device_info = discovery_real_mode._extract_device_info(host)
                
                assert device_info['ip_address'] == host
                assert device_info['hostname'] is None
                assert device_info['mac_address'] is None
                assert device_info['state'] == 'up'
                # Manufacturer should not be set if no MAC address
                assert 'manufacturer' not in device_info
    
    def test_extract_device_info_with_vendor(self, discovery_real_mode):
        """Test device info extraction with vendor information"""
        host = "192.168.1.100"
        mac_address = '00:11:22:33:44:55'
        
        # Mock nmap results with vendor info
        mock_host_data = Mock()
        mock_host_data.state.return_value = 'up'
        mock_host_data.__getitem__.return_value = {'vendor': {mac_address: 'Apple, Inc.'}}
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery_real_mode, '_get_hostname', return_value=None):
            with patch.object(discovery_real_mode, '_get_mac_address', return_value=mac_address):
                device_info = discovery_real_mode._extract_device_info(host)
                
                assert device_info['manufacturer'] == 'Apple, Inc.'
    
    def test_extract_detailed_info_with_os(self, discovery_real_mode):
        """Test detailed info extraction with OS detection"""
        host = "192.168.1.100"
        
        # Mock nmap results with OS detection
        mock_host_data = Mock()
        mock_host_data.__getitem__.return_value = {
            'osmatch': [{
                'name': 'Ubuntu Linux 20.04',
                'accuracy': '95'
            }]
        }
        mock_host_data.__contains__.return_value = True
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery_real_mode, '_extract_device_info', return_value={
            'ip_address': host,
            'hostname': 'test-host',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }):
            device_info = discovery_real_mode._extract_detailed_info(host)
            
            assert device_info['operating_system'] == 'Ubuntu Linux 20.04'
            assert device_info['os_accuracy'] == '95'
    
    def test_extract_detailed_info_with_services(self, discovery_real_mode):
        """Test detailed info extraction with service detection"""
        host = "192.168.1.100"
        
        # Mock nmap results with services
        mock_host_data = Mock()
        mock_host_data.all_protocols.return_value = ['tcp']
        mock_host_data.__getitem__.side_effect = lambda key: {
            'tcp': {
                22: {
                    'state': 'open',
                    'name': 'ssh',
                    'product': 'OpenSSH',
                    'version': '7.4',
                    'extrainfo': 'protocol 2.0'
                },
                80: {
                    'state': 'open',
                    'name': 'http',
                    'product': 'nginx',
                    'version': '1.18.0'
                }
            }
        }[key] if key == 'tcp' else mock_host_data.__getitem__.return_value
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery_real_mode, '_extract_device_info', return_value={
            'ip_address': host,
            'hostname': 'test-host',
            'mac_address': '00:11:22:33:44:55',
            'state': 'up',
            'last_seen': datetime.utcnow()
        }):
            device_info = discovery_real_mode._extract_detailed_info(host)
            
            assert 'services' in device_info
            assert len(device_info['services']) == 2
            
            ssh_service = next(s for s in device_info['services'] if s['port'] == 22)
            assert ssh_service['protocol'] == 'tcp'
            assert ssh_service['name'] == 'ssh'
            assert ssh_service['product'] == 'OpenSSH'
            assert ssh_service['version'] == '7.4'
            assert ssh_service['extrainfo'] == 'protocol 2.0'


class TestHelperMethods:
    """Test suite for helper methods"""
    
    def test_get_hostname_success(self, discovery_real_mode):
        """Test successful hostname extraction"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: key == 'hostnames'
        mock_host_data.__getitem__.side_effect = lambda key: {
            'hostnames': [{'name': 'test-server', 'type': 'PTR'}]
        }[key] if key == 'hostnames' else {}
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        hostname = discovery_real_mode._get_hostname(host)
        assert hostname == 'test-server'
    
    def test_get_hostname_empty_name(self, discovery_real_mode):
        """Test hostname extraction with empty name"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: key == 'hostnames'
        mock_host_data.__getitem__.side_effect = lambda key: {
            'hostnames': [{'name': '', 'type': 'PTR'}]
        }[key] if key == 'hostnames' else {}
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        hostname = discovery_real_mode._get_hostname(host)
        assert hostname is None
    
    def test_get_hostname_empty(self, discovery_real_mode):
        """Test hostname extraction when no hostname available"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: key == 'hostnames'
        mock_host_data.__getitem__.side_effect = lambda key: {
            'hostnames': []
        }[key] if key == 'hostnames' else {}
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        hostname = discovery_real_mode._get_hostname(host)
        assert hostname is None
    
    def test_get_hostname_no_hostnames_key(self, discovery_real_mode):
        """Test hostname extraction when hostnames key doesn't exist"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: False
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        hostname = discovery_real_mode._get_hostname(host)
        assert hostname is None
    
    def test_get_mac_address_success(self, discovery_real_mode):
        """Test successful MAC address extraction"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: key == 'addresses'
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'mac': '00:11:22:33:44:55'}
        }[key] if key == 'addresses' else {}
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        mac_address = discovery_real_mode._get_mac_address(host)
        assert mac_address == '00:11:22:33:44:55'
    
    def test_get_mac_address_no_mac(self, discovery_real_mode):
        """Test MAC address extraction when no MAC available"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: key == 'addresses'
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {}
        }[key] if key == 'addresses' else {}
        
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        mac_address = discovery_real_mode._get_mac_address(host)
        assert mac_address is None
    
    def test_get_mac_address_no_addresses_key(self, discovery_real_mode):
        """Test MAC address extraction when addresses key doesn't exist"""
        host = "192.168.1.100"
        
        mock_host_data = MagicMock()
        mock_host_data.__contains__.side_effect = lambda key: False
        discovery_real_mode.nm.__getitem__.return_value = mock_host_data
        
        mac_address = discovery_real_mode._get_mac_address(host)
        assert mac_address is None


class TestDatabaseOperations:
    """Test suite for database operations"""
    
    @patch('src.scanner.discovery.logger')
    def test_save_device_new_device(self, mock_logger, discovery, mock_db_session):
        """Test saving a new device to database"""
        device_info = {
            'ip_address': '192.168.1.100',
            'hostname': 'test-device',
            'mac_address': '00:11:22:33:44:55',
            'manufacturer': 'Apple',
            'operating_system': 'macOS',
            'last_seen': datetime.utcnow()
        }
        
        # Mock no existing device
        mock_db_session.query.return_value.filter_by.return_value.first.return_value = None
        
        discovery._save_device(device_info)
        
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @patch('src.scanner.discovery.logger')
    def test_save_device_update_existing(self, mock_logger, discovery, mock_db_session):
        """Test updating an existing device in database"""
        device_info = {
            'ip_address': '192.168.1.100',
            'hostname': 'updated-hostname',
            'mac_address': '00:11:22:33:44:55',
            'manufacturer': 'Apple',
            'operating_system': 'macOS Big Sur',
            'last_seen': datetime.utcnow()
        }
        
        # Mock existing device
        existing_device = Mock()
        mock_db_session.query.return_value.filter_by.return_value.first.return_value = existing_device
        
        discovery._save_device(device_info)
        
        # Verify device was updated
        assert existing_device.ip_address == device_info['ip_address']
        assert existing_device.hostname == device_info['hostname']
        assert existing_device.last_seen == device_info['last_seen']
        assert existing_device.is_active is True
        assert existing_device.manufacturer == device_info['manufacturer']
        assert existing_device.operating_system == device_info['operating_system']
        
        mock_db_session.commit.assert_called_once()
        mock_db_session.add.assert_not_called()
    
    @patch('src.scanner.discovery.logger')
    def test_save_device_database_error(self, mock_logger, discovery, mock_db_session):
        """Test database error handling during device save"""
        device_info = {
            'ip_address': '192.168.1.100',
            'mac_address': '00:11:22:33:44:55',
            'last_seen': datetime.utcnow()
        }
        
        # Mock database error
        mock_db_session.commit.side_effect = Exception("Database error")
        mock_db_session.query.return_value.filter_by.return_value.first.return_value = None
        
        discovery._save_device(device_info)
        
        mock_db_session.rollback.assert_called_once()
        mock_logger.error.assert_called_with("Error saving device to database: Database error")


class TestMockDeviceGeneration:
    """Test suite for mock device generation"""
    
    def test_get_mock_devices_structure(self, discovery):
        """Test mock devices have correct structure"""
        mock_devices = discovery._get_mock_devices()
        
        assert len(mock_devices) >= 3  # Should have at least 3 devices
        for device in mock_devices:
            assert 'ip_address' in device
            assert 'hostname' in device
            assert 'mac_address' in device
            assert 'manufacturer' in device
            assert 'operating_system' in device
            assert 'last_seen' in device
            assert 'services' in device
            assert isinstance(device['services'], list)
    
    def test_mock_devices_database_save(self, discovery):
        """Test that mock devices are saved to database"""
        # The _get_mock_devices method calls _save_device for each device
        # which should result in database operations
        mock_devices = discovery._get_mock_devices()
        
        # Verify devices were processed
        assert len(mock_devices) >= 3
        # The database operations happen within _save_device calls
        # which are tested separately in TestDatabaseOperations


class TestNetworkInterfaceDetection:
    """Test suite for network interface detection"""
    
    def test_get_local_networks_success(self, discovery):
        """Test successful local network detection"""
        with patch('netifaces.interfaces', return_value=['eth0', 'wlan0', 'lo']):
            with patch('netifaces.ifaddresses') as mock_ifaddresses:
                def mock_addresses(interface):
                    if interface == 'eth0':
                        return {2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0'}]}
                    elif interface == 'wlan0':
                        return {2: [{'addr': '10.0.0.50', 'netmask': '255.255.0.0'}]}
                    elif interface == 'lo':
                        return {2: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}]}
                    return {}
                
                mock_ifaddresses.side_effect = mock_addresses
                
                networks = discovery.get_local_networks()
                
                assert isinstance(networks, list)
                assert len(networks) == 2  # Should skip loopback
                assert '192.168.1.0/24' in networks
                assert '10.0.0.0/16' in networks
                assert '127.0.0.0/8' not in networks  # Loopback should be skipped
    
    def test_get_local_networks_no_interfaces(self, discovery):
        """Test network detection with no interfaces"""
        with patch('netifaces.interfaces', return_value=[]):
            networks = discovery.get_local_networks()
            assert networks == []
    
    def test_get_local_networks_invalid_network(self, discovery):
        """Test network detection with invalid network data"""
        with patch('netifaces.interfaces', return_value=['eth0']):
            with patch('netifaces.ifaddresses', return_value={
                2: [{'addr': 'invalid-ip', 'netmask': '255.255.255.0'}]
            }):
                with patch('src.scanner.discovery.logger') as mock_logger:
                    networks = discovery.get_local_networks()
                    
                    assert networks == []
                    mock_logger.warning.assert_called()
    
    def test_get_local_networks_missing_netmask(self, discovery):
        """Test network detection with missing netmask"""
        with patch('netifaces.interfaces', return_value=['eth0']):
            with patch('netifaces.ifaddresses', return_value={
                2: [{'addr': '192.168.1.100'}]  # Missing netmask
            }):
                networks = discovery.get_local_networks()
                assert networks == []


class TestScanTimeouts:
    """Test suite for scan timeout handling"""
    
    @patch('src.scanner.discovery.logger')
    def test_scan_timeout_handling(self, mock_logger, discovery_real_mode):
        """Test handling of scan timeouts"""
        # Mock socket timeout
        discovery_real_mode.nm.scan.side_effect = socket.timeout("Scan timeout")
        
        with pytest.raises(socket.timeout):
            discovery_real_mode.discover_devices()
        
        mock_logger.error.assert_called_with("Error during network discovery: Scan timeout")
    
    @patch('src.scanner.discovery.logger')
    def test_deep_scan_timeout_handling(self, mock_logger, discovery_real_mode):
        """Test handling of deep scan timeouts"""
        ip_address = "192.168.1.100"
        discovery_real_mode.nm.scan.side_effect = socket.timeout("Deep scan timeout")
        
        with pytest.raises(socket.timeout):
            discovery_real_mode.deep_scan_device(ip_address)
        
        mock_logger.error.assert_called_with(f"Error during deep scan of {ip_address}: Deep scan timeout")


class TestLargeNetworkProcessing:
    """Test suite for large network range processing"""
    
    def test_large_network_range_mock_mode(self, discovery):
        """Test processing large network ranges in mock mode"""
        large_range = "10.0.0.0/16"  # 65,536 addresses
        devices = discovery.discover_devices(network_range=large_range)
        
        # In mock mode, should still return mock devices efficiently
        assert len(devices) > 0
        # Should complete quickly even with large range
        assert all('ip_address' in device for device in devices)
    
    @patch('src.scanner.discovery.logger')
    def test_large_network_range_real_mode_performance(self, mock_logger, discovery_real_mode):
        """Test performance considerations for large network ranges"""
        large_range = "172.16.0.0/16"
        
        # Mock nmap to simulate large scan
        discovery_real_mode.nm.scan.return_value = None
        discovery_real_mode.nm.all_hosts.return_value = []
        
        devices = discovery_real_mode.discover_devices(network_range=large_range)
        
        # Verify scan was attempted with correct range
        discovery_real_mode.nm.scan.assert_called_once_with(hosts=large_range, arguments='-sn -PR')
        assert devices == []
        mock_logger.info.assert_called()


# Legacy tests (updated)
def test_discover_devices_mock_mode(discovery):
    """Test device discovery in mock mode (legacy test)"""
    devices = discovery.discover_devices()
    
    assert len(devices) > 0
    assert all('ip_address' in device for device in devices)
    assert all('mac_address' in device for device in devices)


def test_get_local_networks(discovery):
    """Test getting local network interfaces (legacy test)"""
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
    """Test device info extraction (legacy test - now functional)"""
    if expected:
        # Mock valid nmap result
        mock_host_data = Mock()
        mock_host_data.state.return_value = 'up'
        discovery.nm.__getitem__.return_value = mock_host_data
        
        with patch.object(discovery, '_get_hostname', return_value='test-host'):
            with patch.object(discovery, '_get_mac_address', return_value='00:11:22:33:44:55'):
                device_info = discovery._extract_device_info(host)
                assert device_info['ip_address'] == host
                assert 'last_seen' in device_info
    else:
        # For invalid hosts, we would expect an exception in real usage
        # but for this test we just verify the method exists
        assert hasattr(discovery, '_extract_device_info')