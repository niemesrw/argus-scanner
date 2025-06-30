"""
Integration tests for real network scanning operations
"""
import pytest
import socket
from unittest.mock import patch
from datetime import datetime, timedelta

from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.database.models import Device, Vulnerability


@pytest.mark.integration
@pytest.mark.network
class TestNetworkScanningIntegration:
    """Integration tests for network scanning with real operations"""
    
    def test_localhost_discovery(self, integration_settings, db_session, controlled_network_target):
        """Test real network discovery against localhost"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Perform real scan against localhost
        devices = discovery.discover_devices(controlled_network_target['network'])
        
        # Should find at least localhost
        assert len(devices) >= 1
        
        # Verify localhost is detected
        localhost_found = any(
            device['ip'] == '127.0.0.1' 
            for device in devices
        )
        assert localhost_found, "Localhost should be discovered"
        
        # Verify device was saved to database
        saved_device = db_session.query(Device).filter_by(ip_address='127.0.0.1').first()
        assert saved_device is not None
        assert saved_device.status == 'active'
    
    def test_port_scanning_integration(self, integration_settings, db_session, controlled_network_target):
        """Test real port scanning against localhost"""
        discovery = NetworkDiscovery(integration_settings)
        
        # First discover the device
        devices = discovery.discover_devices(controlled_network_target['network'])
        localhost_device = next(
            (d for d in devices if d['ip'] == '127.0.0.1'), 
            None
        )
        assert localhost_device is not None
        
        # Perform detailed scan with port detection
        detailed_info = discovery.scan_device_ports(
            localhost_device['ip'], 
            controlled_network_target['safe_ports']
        )
        
        # Verify scan results structure
        assert 'ip' in detailed_info
        assert 'ports' in detailed_info
        assert 'services' in detailed_info
        assert detailed_info['ip'] == '127.0.0.1'
        
        # Check that some basic information was gathered
        assert isinstance(detailed_info['ports'], list)
        assert isinstance(detailed_info['services'], list)
    
    def test_vulnerability_scanning_integration(self, integration_settings, db_session):
        """Test real vulnerability scanning workflow"""
        # Create a test device in the database
        test_device = Device(
            ip_address='127.0.0.1',
            hostname='localhost',
            mac_address='00:00:00:00:00:00',
            status='active',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            services=[
                {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0'},
                {'port': 80, 'service': 'http', 'version': 'Apache 2.4'},
            ]
        )
        db_session.add(test_device)
        db_session.commit()
        
        # Initialize vulnerability scanner
        vuln_scanner = VulnerabilityScanner(integration_settings)
        
        # Perform vulnerability scan (this will use real CVE data if available)
        vulnerabilities = vuln_scanner.scan_device(test_device)
        
        # Verify results structure
        assert isinstance(vulnerabilities, list)
        
        # If vulnerabilities were found, verify they were saved
        if vulnerabilities:
            saved_vulns = db_session.query(Vulnerability).filter_by(
                device_id=test_device.id
            ).all()
            assert len(saved_vulns) == len(vulnerabilities)
            
            for vuln in saved_vulns:
                assert vuln.cve_id is not None
                assert vuln.severity in ['low', 'medium', 'high', 'critical']
                assert vuln.description is not None
    
    def test_network_interface_detection(self, integration_settings):
        """Test real network interface detection"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Get local network interfaces
        interfaces = discovery.get_network_interfaces()
        
        # Should find at least loopback interface
        assert len(interfaces) >= 1
        
        # Verify interface structure
        for interface in interfaces:
            assert 'name' in interface
            assert 'addresses' in interface
            assert isinstance(interface['addresses'], list)
            
        # Should find loopback interface
        lo_interface = next(
            (iface for iface in interfaces if iface['name'] == 'lo'), 
            None
        )
        assert lo_interface is not None
        assert '127.0.0.1' in [addr['addr'] for addr in lo_interface['addresses']]
    
    @pytest.mark.slow
    def test_scan_timeout_handling(self, integration_settings, controlled_network_target):
        """Test handling of scan timeouts with real network operations"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Test with a very short timeout to force timeout scenario
        start_time = datetime.now()
        
        # Mock socket timeout for a controlled test
        with patch('socket.create_connection') as mock_connect:
            mock_connect.side_effect = socket.timeout("Connection timed out")
            
            devices = discovery.discover_devices(controlled_network_target['network'])
            
        end_time = datetime.now()
        
        # Should handle timeout gracefully
        assert isinstance(devices, list)
        # Scan should not hang indefinitely
        assert (end_time - start_time).total_seconds() < 30
    
    def test_database_persistence_integration(self, integration_settings, db_session):
        """Test that scan results persist correctly in database"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Perform scan
        devices = discovery.discover_devices('127.0.0.1/32')
        
        # Verify database persistence
        db_devices = db_session.query(Device).all()
        assert len(db_devices) >= 1
        
        # Verify device details are persisted
        for db_device in db_devices:
            assert db_device.ip_address is not None
            assert db_device.first_seen is not None
            assert db_device.last_seen is not None
            assert db_device.status == 'active'
            
        # Test device update on subsequent scan
        original_count = len(db_devices)
        
        # Run another scan
        devices = discovery.discover_devices('127.0.0.1/32')
        
        # Device count should remain the same (update, not duplicate)
        updated_devices = db_session.query(Device).all()
        assert len(updated_devices) == original_count
        
        # last_seen should be updated
        for device in updated_devices:
            if device.ip_address == '127.0.0.1':
                assert device.last_seen > device.first_seen
    
    def test_service_detection_integration(self, integration_settings, db_session):
        """Test real service detection and database storage"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Scan localhost with service detection
        devices = discovery.discover_devices('127.0.0.1/32')
        localhost_device = next(
            (d for d in devices if d['ip'] == '127.0.0.1'), 
            None
        )
        
        if localhost_device:
            # Perform service scan
            services = discovery.detect_services(localhost_device['ip'])
            
            # Verify service structure
            assert isinstance(services, list)
            
            if services:  # If any services were detected
                for service in services:
                    assert 'port' in service
                    assert 'protocol' in service
                    assert isinstance(service['port'], int)
                    assert service['protocol'] in ['tcp', 'udp']
                
                # Verify services are saved to database
                db_device = db_session.query(Device).filter_by(
                    ip_address='127.0.0.1'
                ).first()
                assert db_device is not None
                assert db_device.services is not None
                assert len(db_device.services) > 0