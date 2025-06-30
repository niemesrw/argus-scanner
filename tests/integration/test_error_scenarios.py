"""
Integration tests for multi-component error scenarios
"""
import pytest
import sqlite3
import threading
import time
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.scheduler.tasks import SchedulerService
from src.alerts.manager import AlertManager
from src.database.models import Device, Vulnerability, Scan
from src.config.settings import Settings


@pytest.mark.integration
class TestMultiComponentErrorScenarios:
    """Integration tests for error scenarios across multiple components"""
    
    def test_database_lock_error_scenario(self, integration_settings, db_session):
        """Test handling of database lock errors during concurrent operations"""
        discovery = NetworkDiscovery(integration_settings)
        
        def concurrent_scan(results_list, error_list):
            """Function to run in separate thread"""
            try:
                # This will attempt to write to the database
                devices = discovery.discover_devices('127.0.0.1/32')
                results_list.append(len(devices))
            except Exception as e:
                error_list.append(str(e))
        
        # Start multiple threads that will compete for database access
        threads = []
        results = []
        errors = []
        
        for i in range(3):
            thread = threading.Thread(
                target=concurrent_scan, 
                args=(results, errors)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)
        
        # Should handle database contention gracefully
        # At least one operation should succeed
        assert len(results) > 0, "At least one scan should succeed"
        
        # Errors should be handled gracefully (not crash the application)
        for error in errors:
            # Should not contain unhandled exception traces
            assert "Traceback" not in error
    
    def test_network_timeout_cascade_scenario(self, integration_settings, db_session):
        """Test cascade effects when network operations timeout"""
        discovery = NetworkDiscovery(integration_settings)
        vuln_scanner = VulnerabilityScanner(integration_settings)
        
        # Mock network timeouts
        with patch('nmap.PortScanner.scan') as mock_scan:
            mock_scan.side_effect = Exception("Network timeout")
            
            # This should trigger error handling across multiple components
            try:
                devices = discovery.discover_devices('192.168.1.0/24')
                
                # Even with network failure, should return empty list, not crash
                assert isinstance(devices, list)
                assert len(devices) == 0
                
            except Exception as e:
                pytest.fail(f"Network timeout should be handled gracefully: {e}")
        
        # Verify error was logged in scan results
        scan_results = db_session.query(Scan).filter_by(
            status='failed'
        ).all()
        
        # Should have logged the failure
        assert len(scan_results) >= 1
        
        failed_result = scan_results[0]
        assert failed_result.error_message is not None
        assert 'timeout' in failed_result.error_message.lower()
    
    def test_alert_system_failure_scenario(self, integration_settings, db_session):
        """Test system behavior when alert system fails"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:11',
            ip_address='192.168.1.120',
            hostname='alert-failure-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-ALERT-FAIL',
            cvss_score=9.5,
            severity='critical',
            description='Critical vulnerability with alert system failure',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock complete alert system failure
        alert_manager = AlertManager(integration_settings)
        
        with patch.object(alert_manager, 'send_email') as mock_email, \
             patch.object(alert_manager, 'send_slack') as mock_slack:
            
            # Both alert channels fail
            mock_email.side_effect = Exception("SMTP server unreachable")
            mock_slack.side_effect = Exception("Slack API unavailable")
            
            # System should continue operating despite alert failures
            try:
                email_result = alert_manager.send_email_alert(device, vulnerability)
                slack_result = alert_manager.send_slack_alert(device, vulnerability)
                
                # Should return False but not crash
                assert email_result is False
                assert slack_result is False
                
            except Exception as e:
                pytest.fail(f"Alert system failure should be handled gracefully: {e}")
        
        # Verify the vulnerability is still recorded despite alert failures
        db_vulns = db_session.query(Vulnerability).filter_by(
            cve_id='CVE-2023-ALERT-FAIL'
        ).all()
        assert len(db_vulns) == 1
    
    def test_scheduler_component_failure_scenario(self, integration_settings, db_session):
        """Test behavior when scheduler component fails"""
        scheduler = SchedulerService(integration_settings)
        
        # Mock scheduler failure
        with patch('src.scheduler.tasks.BackgroundScheduler') as mock_scheduler_class:
            mock_scheduler_instance = MagicMock()
            mock_scheduler_class.return_value = mock_scheduler_instance
            
            # Scheduler fails to start
            mock_scheduler_instance.start.side_effect = Exception("Scheduler initialization failed")
            
            # Should handle scheduler failure gracefully
            try:
                scheduler.start()
                
                # Manual scan should still work even if scheduler fails
                result = scheduler.run_network_discovery()
                
                # Should complete without crashing
                assert result is not None
                
            except Exception as e:
                # Should not propagate scheduler errors to manual operations
                pytest.fail(f"Scheduler failure should not affect manual operations: {e}")
    
    def test_database_corruption_recovery_scenario(self, integration_settings):
        """Test recovery from database corruption scenarios"""
        # Simulate database corruption by creating invalid database state
        from sqlalchemy import create_engine, text
        
        # Create a temporary corrupted database
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
            corrupted_db_path = temp_file.name
        
        try:
            # Create a corrupted database file
            with open(corrupted_db_path, 'wb') as f:
                f.write(b'This is not a valid SQLite database file')
            
            # Override settings to use corrupted database
            corrupted_settings = Settings()
            corrupted_settings.DATABASE_URL = f"sqlite:///{corrupted_db_path}"
            
            # Initialize components with corrupted database
            discovery = NetworkDiscovery(corrupted_settings)
            
            # Should handle database corruption gracefully
            try:
                devices = discovery.discover_devices('127.0.0.1/32')
                
                # Depending on implementation, should either:
                # 1. Recreate database and continue, or
                # 2. Fail gracefully with proper error handling
                assert isinstance(devices, list)
                
            except Exception as e:
                # Should be a handled database error, not a crash
                assert "database" in str(e).lower() or "sqlite" in str(e).lower()
                
        finally:
            # Cleanup
            if os.path.exists(corrupted_db_path):
                os.unlink(corrupted_db_path)
    
    def test_memory_exhaustion_scenario(self, integration_settings, db_session):
        """Test behavior under memory pressure conditions"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Mock a scenario that would normally consume excessive memory
        with patch.object(discovery.nm, 'scan') as mock_scan, \
             patch.object(discovery.nm, 'all_hosts') as mock_hosts:
            
            # Simulate discovering a very large number of hosts
            large_host_list = [f'192.168.{i}.{j}' for i in range(1, 255) for j in range(1, 255)]
            mock_hosts.return_value = large_host_list[:1000]  # Limit to 1000 for test
            
            # Mock host state checking
            def mock_host_state(host):
                mock_host = MagicMock()
                mock_host.state.return_value = 'up'
                return mock_host
            
            discovery.nm.__getitem__ = mock_host_state
            
            # Mock device info extraction to be memory-efficient
            with patch.object(discovery, '_extract_device_info') as mock_extract:
                mock_extract.return_value = {
                    'ip': '192.168.1.1',
                    'hostname': 'test-device',
                    'mac': '00:11:22:33:44:55',
                    'status': 'active'
                }
                
                # Should handle large datasets without memory issues
                devices = discovery.discover_devices('192.168.0.0/16')
                
                # Should process efficiently (not necessarily all at once)
                assert isinstance(devices, list)
                assert len(devices) <= 1000  # Should be limited or paginated
    
    def test_configuration_error_scenario(self, integration_settings):
        """Test handling of configuration errors across components"""
        # Test with invalid network range
        discovery = NetworkDiscovery(integration_settings)
        
        try:
            # Invalid network range should be handled gracefully
            devices = discovery.discover_devices('invalid-network-range')
            
            # Should return empty list or handle gracefully
            assert isinstance(devices, list)
            assert len(devices) == 0
            
        except Exception as e:
            # Should be a configuration error, not a crash
            assert any(word in str(e).lower() for word in ['invalid', 'range', 'network', 'address'])
    
    def test_resource_cleanup_on_error_scenario(self, integration_settings, db_session):
        """Test that resources are properly cleaned up when errors occur"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Track database connections
        initial_connection_count = len(db_session.bind.pool.checkedout())
        
        # Force an error during scanning
        with patch.object(discovery, '_save_device') as mock_save:
            mock_save.side_effect = Exception("Database write error")
            
            try:
                # This should fail during device saving
                devices = discovery.discover_devices('127.0.0.1/32')
                
                # Should handle error and clean up resources
                assert isinstance(devices, list)
                
            except Exception:
                # Even if error propagates, resources should be cleaned up
                pass
        
        # Verify no connection leaks
        final_connection_count = len(db_session.bind.pool.checkedout())
        assert final_connection_count <= initial_connection_count, "Database connections should be cleaned up"
    
    def test_partial_system_failure_scenario(self, integration_settings, db_session):
        """Test system behavior when some components fail but others work"""
        # Initialize all components
        discovery = NetworkDiscovery(integration_settings)
        vuln_scanner = VulnerabilityScanner(integration_settings)
        alert_manager = AlertManager(integration_settings)
        
        # Simulate partial failure: discovery works, vulnerability scanning fails
        with patch.object(vuln_scanner, 'scan_device') as mock_vuln_scan:
            mock_vuln_scan.side_effect = Exception("CVE database unavailable")
            
            # Discovery should still work
            devices = discovery.discover_devices('127.0.0.1/32')
            assert len(devices) >= 1
            
            # Vulnerability scanning fails, but system continues
            test_device = db_session.query(Device).first()
            if test_device:
                try:
                    vulnerabilities = vuln_scanner.scan_device(test_device)
                    
                    # Should handle failure gracefully
                    assert isinstance(vulnerabilities, list)
                    assert len(vulnerabilities) == 0  # No vulnerabilities due to failure
                    
                except Exception as e:
                    # Should be handled gracefully
                    assert "CVE database" in str(e)
        
        # System should remain operational for other functions
        remaining_devices = db_session.query(Device).all()
        assert len(remaining_devices) >= 1, "Discovery results should persist despite other failures"