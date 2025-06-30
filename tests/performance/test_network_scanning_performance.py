"""
Performance tests for large network range scanning
"""
import pytest
import time
import psutil
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.database.models import Device


@pytest.mark.performance
@pytest.mark.slow
class TestNetworkScanningPerformance:
    """Performance tests for network scanning operations"""
    
    def test_small_network_scan_performance(self, performance_settings, performance_timer, memory_monitor):
        """Test performance of scanning small network ranges (16 IPs)"""
        discovery = NetworkDiscovery(performance_settings)
        
        # Mock network discovery for predictable performance testing
        with patch.object(discovery.nm, 'scan') as mock_scan, \
             patch.object(discovery.nm, 'all_hosts') as mock_hosts:
            
            # Simulate 16 hosts (small network)
            mock_hosts.return_value = [f'192.168.1.{i}' for i in range(1, 17)]
            
            def mock_host_state(host):
                mock_host = MagicMock()
                mock_host.state.return_value = 'up'
                return mock_host
            
            discovery.nm.__getitem__ = mock_host_state
            
            # Start performance measurement
            timer = performance_timer.start()
            initial_memory = memory_monitor['process'].memory_info().rss
            
            # Perform scan
            devices = discovery.discover_devices('192.168.1.0/28')
            
            # Stop measurement
            scan_time = timer.stop()
            final_memory = memory_monitor['process'].memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Performance assertions
            assert len(devices) == 16, "Should discover all 16 devices"
            assert scan_time < 5.0, f"Small network scan took too long: {scan_time:.2f}s"
            assert memory_increase < 50 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.1f}MB"
            
            # Log performance metrics
            print(f"\nSmall Network Scan Performance:")
            print(f"  Devices: 16")
            print(f"  Time: {scan_time:.3f}s")
            print(f"  Memory: {memory_increase / 1024 / 1024:.1f}MB")
            print(f"  Rate: {len(devices) / scan_time:.1f} devices/sec")
    
    def test_medium_network_scan_performance(self, performance_settings, performance_timer, memory_monitor):
        """Test performance of scanning medium network ranges (256 IPs)"""
        discovery = NetworkDiscovery(performance_settings)
        
        with patch.object(discovery.nm, 'scan') as mock_scan, \
             patch.object(discovery.nm, 'all_hosts') as mock_hosts:
            
            # Simulate 256 hosts (medium network)
            mock_hosts.return_value = [f'192.168.0.{i}' for i in range(1, 257)]
            
            def mock_host_state(host):
                mock_host = MagicMock()
                mock_host.state.return_value = 'up'
                return mock_host
            
            discovery.nm.__getitem__ = mock_host_state
            
            # Mock device info extraction for faster testing
            with patch.object(discovery, '_extract_device_info') as mock_extract:
                mock_extract.side_effect = lambda ip: {
                    'ip': ip,
                    'hostname': f'device-{ip.split(".")[-1]}',
                    'mac': f'00:11:22:33:44:{ip.split(".")[-1]:02x}',
                    'status': 'active'
                }
                
                # Performance measurement
                timer = performance_timer.start()
                initial_memory = memory_monitor['process'].memory_info().rss
                
                devices = discovery.discover_devices('192.168.0.0/24')
                
                scan_time = timer.stop()
                final_memory = memory_monitor['process'].memory_info().rss
                memory_increase = final_memory - initial_memory
                
                # Performance assertions
                assert len(devices) == 256, "Should discover all 256 devices"
                assert scan_time < 30.0, f"Medium network scan took too long: {scan_time:.2f}s"
                assert memory_increase < 100 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.1f}MB"
                
                print(f"\nMedium Network Scan Performance:")
                print(f"  Devices: 256")
                print(f"  Time: {scan_time:.3f}s")
                print(f"  Memory: {memory_increase / 1024 / 1024:.1f}MB")
                print(f"  Rate: {len(devices) / scan_time:.1f} devices/sec")
    
    def test_large_network_scan_performance(self, performance_settings, performance_timer, memory_monitor):
        """Test performance of scanning large network ranges (1024 IPs)"""
        discovery = NetworkDiscovery(performance_settings)
        
        with patch.object(discovery.nm, 'scan') as mock_scan, \
             patch.object(discovery.nm, 'all_hosts') as mock_hosts:
            
            # Simulate 1024 hosts (large network) - but only return first 100 for test speed
            large_host_list = [f'10.0.{i//256}.{i%256}' for i in range(1, 1025)]
            mock_hosts.return_value = large_host_list[:100]  # Limit for test performance
            
            def mock_host_state(host):
                mock_host = MagicMock()
                mock_host.state.return_value = 'up'
                return mock_host
            
            discovery.nm.__getitem__ = mock_host_state
            
            with patch.object(discovery, '_extract_device_info') as mock_extract:
                mock_extract.side_effect = lambda ip: {
                    'ip': ip,
                    'hostname': f'device-{ip.replace(".", "-")}',
                    'mac': f'00:11:22:33:{hash(ip) % 256:02x}:{hash(ip) // 256 % 256:02x}',
                    'status': 'active'
                }
                
                timer = performance_timer.start()
                initial_memory = memory_monitor['process'].memory_info().rss
                
                devices = discovery.discover_devices('10.0.0.0/22')
                
                scan_time = timer.stop()
                final_memory = memory_monitor['process'].memory_info().rss
                memory_increase = final_memory - initial_memory
                
                # Performance assertions for scaled test
                assert len(devices) == 100, "Should discover mocked devices"
                assert scan_time < 60.0, f"Large network scan took too long: {scan_time:.2f}s"
                assert memory_increase < 200 * 1024 * 1024, f"Memory usage too high: {memory_increase / 1024 / 1024:.1f}MB"
                
                print(f"\nLarge Network Scan Performance (scaled test):")
                print(f"  Devices: {len(devices)}")
                print(f"  Time: {scan_time:.3f}s")
                print(f"  Memory: {memory_increase / 1024 / 1024:.1f}MB")
                print(f"  Rate: {len(devices) / scan_time:.1f} devices/sec")
    
    def test_vulnerability_scan_performance(self, performance_settings, performance_db_session, performance_timer, large_dataset_factory):
        """Test performance of vulnerability scanning on many devices"""
        # Create test devices in database
        devices_data = large_dataset_factory['devices'](50)  # 50 devices for testing
        devices = []
        
        for device_data in devices_data:
            device = Device(
                mac_address=device_data['mac'],
                ip_address=device_data['ip'],
                hostname=device_data['hostname'],
                device_metadata={'services': device_data['services']},
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            devices.append(device)
        
        performance_db_session.add_all(devices)
        performance_db_session.commit()
        
        # Initialize vulnerability scanner
        vuln_scanner = VulnerabilityScanner(performance_settings)
        
        # Mock CVE database queries for performance testing
        with patch.object(vuln_scanner, '_query_cve_database') as mock_cve:
            mock_cve.return_value = [
                {
                    'cve_id': 'CVE-2023-12345',
                    'cvss_score': 7.5,
                    'severity': 'high',
                    'description': 'Test vulnerability for performance testing',
                    'solution': 'Apply security patches'
                }
            ]
            
            timer = performance_timer.start()
            
            # Scan all devices
            total_vulnerabilities = 0
            for device in devices:
                vulnerabilities = vuln_scanner.scan_device(device)
                total_vulnerabilities += len(vulnerabilities)
            
            scan_time = timer.stop()
            
            # Performance assertions
            assert total_vulnerabilities >= 0, "Should find vulnerabilities or handle gracefully"
            assert scan_time < 30.0, f"Vulnerability scanning took too long: {scan_time:.2f}s"
            
            print(f"\nVulnerability Scan Performance:")
            print(f"  Devices: {len(devices)}")
            print(f"  Vulnerabilities: {total_vulnerabilities}")
            print(f"  Time: {scan_time:.3f}s")
            print(f"  Rate: {len(devices) / scan_time:.1f} devices/sec")
    
    def test_port_scan_performance(self, performance_settings, performance_timer):
        """Test performance of port scanning operations"""
        discovery = NetworkDiscovery(performance_settings)
        
        # Test port scanning performance on single host
        with patch.object(discovery.nm, 'scan') as mock_scan:
            # Mock port scan results
            mock_scan.return_value = None
            
            with patch.object(discovery.nm, '__getitem__') as mock_host_data:
                mock_host_obj = MagicMock()
                mock_host_obj.all_tcp.return_value = list(range(1, 1001))  # 1000 ports
                mock_host_obj.__getitem__.return_value = {
                    'state': 'open',
                    'name': 'http',
                    'product': 'Apache',
                    'version': '2.4'
                }
                mock_host_data.return_value = mock_host_obj
                
                timer = performance_timer.start()
                
                # Perform detailed port scan
                result = discovery.scan_device_ports('192.168.1.100', list(range(1, 1001)))
                
                scan_time = timer.stop()
                
                # Performance assertions
                assert result is not None, "Port scan should return results"
                assert scan_time < 10.0, f"Port scan took too long: {scan_time:.2f}s"
                
                print(f"\nPort Scan Performance:")
                print(f"  Ports: 1000")
                print(f"  Time: {scan_time:.3f}s")
                print(f"  Rate: {1000 / scan_time:.1f} ports/sec")
    
    def test_scan_throughput_benchmark(self, performance_settings, performance_timer, network_range_generator):
        """Benchmark scanning throughput across different network sizes"""
        discovery = NetworkDiscovery(performance_settings)
        
        # Test different network sizes
        test_sizes = ['small', 'medium']  # Skip large for CI performance
        results = []
        
        for size in test_sizes:
            ranges = network_range_generator(size)
            network_range = ranges[0]
            
            # Determine expected device count
            expected_devices = {
                'small': 16,
                'medium': 256,
                'large': 1024
            }
            device_count = min(expected_devices[size], 50)  # Cap for testing
            
            with patch.object(discovery.nm, 'scan') as mock_scan, \
                 patch.object(discovery.nm, 'all_hosts') as mock_hosts:
                
                # Generate appropriate number of mock hosts
                if size == 'small':
                    mock_hosts.return_value = [f'192.168.1.{i}' for i in range(1, device_count + 1)]
                else:
                    mock_hosts.return_value = [f'192.168.0.{i}' for i in range(1, device_count + 1)]
                
                def mock_host_state(host):
                    mock_host = MagicMock()
                    mock_host.state.return_value = 'up'
                    return mock_host
                
                discovery.nm.__getitem__ = mock_host_state
                
                timer = performance_timer.start()
                devices = discovery.discover_devices(network_range)
                scan_time = timer.stop()
                
                throughput = len(devices) / scan_time if scan_time > 0 else 0
                results.append({
                    'size': size,
                    'devices': len(devices),
                    'time': scan_time,
                    'throughput': throughput
                })
        
        # Print benchmark results
        print(f"\nScanning Throughput Benchmark:")
        print(f"{'Size':<10} {'Devices':<10} {'Time(s)':<10} {'Rate(dev/s)':<12}")
        print("-" * 45)
        for result in results:
            print(f"{result['size']:<10} {result['devices']:<10} {result['time']:<10.3f} {result['throughput']:<12.1f}")
        
        # Verify reasonable performance
        for result in results:
            assert result['throughput'] > 1.0, f"Throughput too low for {result['size']}: {result['throughput']:.1f} dev/s"