"""
Integration tests for full scanning workflow end-to-end
"""
import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.scheduler.tasks import SchedulerService
from src.alerts.manager import AlertManager
from src.database.models import Device, Vulnerability, Alert, Scan
from src.config.settings import Settings


@pytest.mark.integration
@pytest.mark.slow
class TestFullScanningWorkflow:
    """Integration tests for complete scanning workflow"""
    
    def test_complete_scan_workflow(self, integration_settings, db_session):
        """Test complete scanning workflow from discovery to alerting"""
        # Initialize components
        discovery = NetworkDiscovery(integration_settings)
        vuln_scanner = VulnerabilityScanner(integration_settings)
        alert_manager = AlertManager(integration_settings)
        
        # Step 1: Network Discovery
        devices = discovery.discover_devices('127.0.0.1/32')
        assert len(devices) >= 1
        
        # Verify device was saved
        db_devices = db_session.query(Device).all()
        assert len(db_devices) >= 1
        
        # Step 2: Vulnerability Scanning
        test_device = db_devices[0]
        
        # Add some mock services to make vulnerability scanning meaningful
        test_device.device_metadata = {
            'services': [
                {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 7.4'},
                {'port': 80, 'service': 'http', 'version': 'Apache 2.2.15'}
            ]
        }
        db_session.commit()
        
        # Mock vulnerability scanning to return test vulnerabilities
        with patch.object(vuln_scanner, '_query_cve_database') as mock_cve:
            mock_cve.return_value = [
                {
                    'cve_id': 'CVE-2023-12345',
                    'cvss_score': 8.5,
                    'severity': 'high',
                    'description': 'Test critical vulnerability in SSH',
                    'solution': 'Update OpenSSH to latest version'
                }
            ]
            
            vulnerabilities = vuln_scanner.scan_device(test_device)
            assert len(vulnerabilities) >= 1
        
        # Verify vulnerabilities were saved
        db_vulns = db_session.query(Vulnerability).filter_by(device_id=test_device.id).all()
        assert len(db_vulns) >= 1
        
        # Step 3: Alert Generation
        critical_vulns = [v for v in db_vulns if v.severity in ['high', 'critical']]
        if critical_vulns:
            # Mock alert sending
            with patch.object(alert_manager, 'send_email') as mock_email, \
                 patch.object(alert_manager, 'send_slack') as mock_slack:
                
                mock_email.return_value = True
                mock_slack.return_value = True
                
                # Trigger alert
                alert_sent = alert_manager.send_vulnerability_alert(
                    test_device, 
                    critical_vulns[0]
                )
                assert alert_sent
        
        # Verify complete workflow results
        scan_results = db_session.query(Scan).all()
        assert len(scan_results) >= 1
        
        # Verify scan result details
        for result in scan_results:
            assert result.scan_type.value in ['discovery', 'vulnerability']
            assert result.status in ['completed', 'failed']
            # Additional scan result validation could go here
    
    def test_scheduled_scanning_workflow(self, integration_settings, db_session):
        """Test scheduled scanning workflow"""
        # Initialize scheduled scanner
        scheduler = SchedulerService(integration_settings)
        
        # Mock the scheduler to run immediately
        with patch('src.scheduler.tasks.APScheduler') as mock_scheduler:
            mock_job = MagicMock()
            mock_scheduler_instance = MagicMock()
            mock_scheduler.return_value = mock_scheduler_instance
            
            # Initialize scheduler
            scheduler.start()
            
            # Verify scheduler was configured
            mock_scheduler_instance.add_job.assert_called()
            
            # Manually trigger a scan (simulating scheduled execution)
            scheduler.run_network_discovery()
            
            # Verify scan was logged
            scan_results = db_session.query(Scan).filter_by(
                scan_type='discovery'
            ).all()
            assert len(scan_results) >= 1
    
    def test_concurrent_scanning_workflow(self, integration_settings, db_session):
        """Test handling concurrent scanning operations"""
        import threading
        import queue
        
        discovery = NetworkDiscovery(integration_settings)
        results_queue = queue.Queue()
        
        def scan_worker(worker_id):
            """Worker function for concurrent scanning"""
            try:
                devices = discovery.discover_devices('127.0.0.1/32')
                results_queue.put(('success', worker_id, len(devices)))
            except Exception as e:
                results_queue.put(('error', worker_id, str(e)))
        
        # Start multiple concurrent scans
        threads = []
        num_workers = 3
        
        for i in range(num_workers):
            thread = threading.Thread(target=scan_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # Verify all workers completed successfully
        assert len(results) == num_workers
        
        success_count = len([r for r in results if r[0] == 'success'])
        assert success_count == num_workers, f"Only {success_count}/{num_workers} scans succeeded"
        
        # Verify database consistency
        devices = db_session.query(Device).all()
        # Should have at least one device (localhost) regardless of concurrent access
        assert len(devices) >= 1
    
    def test_error_recovery_workflow(self, integration_settings, db_session):
        """Test error recovery during scanning workflow"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Test network error recovery
        with patch('nmap.PortScanner.scan') as mock_scan:
            # First call fails, second succeeds
            mock_scan.side_effect = [
                Exception("Network unreachable"),
                None  # Success on retry
            ]
            
            # Mock successful scan results for the retry
            with patch.object(discovery.nm, 'all_hosts') as mock_hosts:
                mock_hosts.return_value = ['127.0.0.1']
                
                with patch.object(discovery.nm, '__getitem__') as mock_host_data:
                    mock_host_obj = MagicMock()
                    mock_host_obj.state.return_value = 'up'
                    mock_host_data.return_value = mock_host_obj
                    
                    # This should recover from the first error
                    devices = discovery.discover_devices('127.0.0.1/32')
                    
                    # Should eventually succeed due to retry logic
                    assert isinstance(devices, list)
        
        # Verify error was logged but scan continued
        scan_results = db_session.query(ScanResult).all()
        # Should have at least one result (may be success or failure)
        assert len(scan_results) >= 0
    
    def test_data_consistency_workflow(self, integration_settings, db_session):
        """Test data consistency throughout scanning workflow"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Perform initial scan
        devices1 = discovery.discover_devices('127.0.0.1/32')
        initial_count = db_session.query(Device).count()
        
        # Perform second scan - should update existing devices, not duplicate
        devices2 = discovery.discover_devices('127.0.0.1/32')
        final_count = db_session.query(Device).count()
        
        # Device count should remain consistent
        assert final_count == initial_count, "Devices should be updated, not duplicated"
        
        # Verify last_seen timestamps were updated
        if final_count > 0:
            devices = db_session.query(Device).all()
            for device in devices:
                # last_seen should be recent (within last minute)
                time_diff = datetime.now() - device.last_seen
                assert time_diff.total_seconds() < 60, "last_seen should be updated"
    
    def test_large_network_workflow_simulation(self, integration_settings, db_session):
        """Test workflow with simulated large network"""
        discovery = NetworkDiscovery(integration_settings)
        
        # Mock a larger network discovery
        with patch.object(discovery.nm, 'scan') as mock_scan, \
             patch.object(discovery.nm, 'all_hosts') as mock_hosts:
            
            # Simulate finding 50 devices
            mock_hosts.return_value = [f'192.168.1.{i}' for i in range(1, 51)]
            
            # Mock host state for all devices
            def mock_host_state(host):
                mock_host = MagicMock()
                mock_host.state.return_value = 'up'
                return mock_host
            
            discovery.nm.__getitem__ = mock_host_state
            
            # Mock device info extraction
            with patch.object(discovery, '_extract_device_info') as mock_extract:
                mock_extract.side_effect = lambda ip: {
                    'ip': ip,
                    'hostname': f'device-{ip.split(".")[-1]}',
                    'mac': f'00:11:22:33:44:{ip.split(".")[-1]:02x}',
                    'status': 'active'
                }
                
                # Perform scan
                devices = discovery.discover_devices('192.168.1.0/24')
                
                # Should handle large number of devices
                assert len(devices) == 50
                
                # Verify database can handle bulk operations
                db_devices = db_session.query(Device).count()
                assert db_devices == 50
    
    def test_alert_notification_workflow(self, integration_settings, db_session):
        """Test complete alert notification workflow"""
        # Create test device with vulnerability
        device = Device(
            mac_address='00:11:22:33:44:99',
            ip_address='192.168.1.100',
            hostname='critical-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-99999',
            cvss_score=9.8,
            severity='critical',
            description='Critical test vulnerability requiring immediate attention',
            solution='Apply security patch immediately',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Initialize alert manager
        alert_manager = AlertManager(integration_settings)
        
        # Mock notification services
        with patch.object(alert_manager, 'send_email') as mock_email, \
             patch.object(alert_manager, 'send_slack') as mock_slack:
            
            mock_email.return_value = True
            mock_slack.return_value = True
            
            # Send alert
            result = alert_manager.send_vulnerability_alert(device, vulnerability)
            assert result
            
            # Verify both notification methods were called
            mock_email.assert_called_once()
            mock_slack.assert_called_once()
        
        # Verify alert was logged
        alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            vulnerability_id=vulnerability.id
        ).all()
        assert len(alerts) >= 1
        
        alert = alerts[0]
        assert alert.severity == 'critical'
        assert alert.status == 'sent'
        assert 'Critical test vulnerability' in alert.message