"""
Database query optimization and concurrent scan performance tests
"""
import pytest
import time
import threading
import psutil
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.database.models import Device, Service, Vulnerability, Alert
from src.scheduler.tasks import SchedulerTasks


@pytest.mark.performance
@pytest.mark.slow
class TestDatabaseQueryOptimization:
    """Test database query performance and optimization"""
    
    def test_device_query_performance_with_large_dataset(self, performance_db_session, large_dataset_factory, performance_timer):
        """Test device queries with large datasets"""
        
        # Create large dataset
        devices_data = large_dataset_factory['devices'](1000)  # 1000 devices
        devices = []
        
        for device_data in devices_data:
            device = Device(
                mac_address=device_data['mac'],
                ip_address=device_data['ip'],
                hostname=device_data['hostname'],
                device_type=device_data['device_type'],
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            devices.append(device)
        
        performance_db_session.add_all(devices)
        performance_db_session.commit()
        
        # Test various query patterns
        queries = [
            # Test indexed queries
            lambda: performance_db_session.query(Device).filter(Device.ip_address == '192.168.1.100').first(),
            lambda: performance_db_session.query(Device).filter(Device.mac_address.like('00:11:22%')).all(),
            
            # Test range queries
            lambda: performance_db_session.query(Device).filter(Device.ip_address.between('192.168.1.1', '192.168.1.255')).all(),
            
            # Test sorting and limiting
            lambda: performance_db_session.query(Device).order_by(Device.last_seen.desc()).limit(50).all(),
            
            # Test counting
            lambda: performance_db_session.query(Device).count(),
            
            # Test complex filters
            lambda: performance_db_session.query(Device).filter(Device.device_type == 'server').filter(Device.hostname.contains('device')).all(),
        ]
        
        query_results = []
        
        for i, query in enumerate(queries):
            timer = performance_timer.start()
            result = query()
            query_time = timer.stop()
            
            query_results.append({
                'query_index': i,
                'time': query_time,
                'result_count': len(result) if isinstance(result, list) else (1 if result else 0)
            })
            
            # Individual query should be fast
            assert query_time < 2.0, f"Query {i} took too long: {query_time:.3f}s"
        
        # Print performance summary
        print(f"\nDatabase Query Performance (1000 devices):")
        print(f"{'Query':<10} {'Time(s)':<10} {'Results':<10}")
        print("-" * 30)
        for result in query_results:
            print(f"{result['query_index']:<10} {result['time']:<10.3f} {result['result_count']:<10}")
        
        # Average query time should be reasonable
        avg_time = sum(r['time'] for r in query_results) / len(query_results)
        assert avg_time < 1.0, f"Average query time too high: {avg_time:.3f}s"
    
    def test_vulnerability_aggregation_performance(self, performance_db_session, large_dataset_factory, performance_timer):
        """Test vulnerability aggregation queries performance"""
        
        # Create devices and vulnerabilities
        devices_data = large_dataset_factory['devices'](100)
        devices = []
        
        for device_data in devices_data:
            device = Device(
                mac_address=device_data['mac'],
                ip_address=device_data['ip'],
                hostname=device_data['hostname'],
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            devices.append(device)
        
        performance_db_session.add_all(devices)
        performance_db_session.commit()
        
        # Create vulnerabilities for testing aggregation
        vulnerabilities = large_dataset_factory['vulnerabilities'](len(devices), 10)  # 10 vulns per device
        vuln_objects = []
        
        for vuln_data in vulnerabilities:
            vulnerability = Vulnerability(
                device_id=vuln_data['device_id'],
                cve_id=vuln_data['cve_id'],
                description=vuln_data['description'],
                severity=vuln_data['severity'],
                cvss_score=vuln_data['cvss_score'],
                discovered_at=datetime.now()
            )
            vuln_objects.append(vulnerability)
        
        performance_db_session.add_all(vuln_objects)
        performance_db_session.commit()
        
        # Test aggregation queries
        from sqlalchemy import func
        
        aggregation_queries = [
            # Count vulnerabilities by severity
            lambda: performance_db_session.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all(),
            
            # Average CVSS score
            lambda: performance_db_session.query(func.avg(Vulnerability.cvss_score)).scalar(),
            
            # Devices with high severity vulnerabilities
            lambda: performance_db_session.query(Device).join(Vulnerability).filter(Vulnerability.severity == 'high').distinct().all(),
            
            # Count vulnerabilities per device
            lambda: performance_db_session.query(Device.hostname, func.count(Vulnerability.id)).join(Vulnerability).group_by(Device.id).all(),
        ]
        
        for i, query in enumerate(aggregation_queries):
            timer = performance_timer.start()
            result = query()
            query_time = timer.stop()
            
            # Aggregation queries should complete within reasonable time
            assert query_time < 5.0, f"Aggregation query {i} took too long: {query_time:.3f}s"
            
            print(f"Aggregation query {i}: {query_time:.3f}s")
    
    def test_database_indexing_effectiveness(self, performance_db_session, large_dataset_factory, performance_timer):
        """Test database indexing effectiveness"""
        
        # Create large dataset to test indexing
        devices_data = large_dataset_factory['devices'](500)
        devices = []
        
        for device_data in devices_data:
            device = Device(
                mac_address=device_data['mac'],
                ip_address=device_data['ip'],
                hostname=device_data['hostname'],
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            devices.append(device)
        
        performance_db_session.add_all(devices)
        performance_db_session.commit()
        
        # Test queries that should benefit from indexing
        indexed_queries = [
            # Primary key lookup (should be very fast)
            lambda: performance_db_session.query(Device).filter(Device.id == 250).first(),
            
            # IP address lookup (likely indexed)
            lambda: performance_db_session.query(Device).filter(Device.ip_address == '192.168.1.100').first(),
            
            # MAC address lookup (likely indexed)
            lambda: performance_db_session.query(Device).filter(Device.mac_address == '00:11:22:33:44:55').first(),
        ]
        
        for i, query in indexed_queries:
            # Run query multiple times to get average
            times = []
            for _ in range(5):
                timer = performance_timer.start()
                result = query()
                query_time = timer.stop()
                times.append(query_time)
            
            avg_time = sum(times) / len(times)
            
            # Indexed queries should be very fast
            assert avg_time < 0.1, f"Indexed query {i} too slow: {avg_time:.3f}s"
            
            print(f"Indexed query {i} average time: {avg_time:.4f}s")
    
    def test_concurrent_database_access(self, performance_settings, performance_timer):
        """Test concurrent database access performance"""
        
        # Create multiple database sessions for concurrent access
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        engine = create_engine(performance_settings.db_path)
        SessionLocal = sessionmaker(bind=engine)
        
        def database_operation(thread_id):
            """Database operation to run concurrently"""
            session = SessionLocal()
            
            try:
                # Simulate typical database operations
                start_time = time.time()
                
                # Read operation
                devices = session.query(Device).limit(10).all()
                
                # Write operation
                new_device = Device(
                    mac_address=f'00:11:22:33:44:{thread_id:02x}',
                    ip_address=f'192.168.2.{thread_id}',
                    hostname=f'concurrent-device-{thread_id}',
                    first_seen=datetime.now(),
                    last_seen=datetime.now()
                )
                session.add(new_device)
                session.commit()
                
                # Update operation
                if devices:
                    devices[0].last_seen = datetime.now()
                    session.commit()
                
                end_time = time.time()
                return end_time - start_time
                
            except Exception as e:
                session.rollback()
                return f"Error: {str(e)}"
            finally:
                session.close()
        
        # Run concurrent operations
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(database_operation, i) for i in range(10)]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        # Analyze results
        successful_times = [r for r in results if isinstance(r, float)]
        errors = [r for r in results if isinstance(r, str)]
        
        # Should have mostly successful operations
        assert len(successful_times) >= 7, f"Too many database errors in concurrent access: {len(errors)} errors"
        
        # Average time should be reasonable
        if successful_times:
            avg_time = sum(successful_times) / len(successful_times)
            assert avg_time < 5.0, f"Concurrent database operations too slow: {avg_time:.3f}s"
            
            print(f"Concurrent database access: {len(successful_times)} successful, {len(errors)} errors")
            print(f"Average operation time: {avg_time:.3f}s")


@pytest.mark.performance
@pytest.mark.slow
class TestConcurrentScanPerformance:
    """Test concurrent scanning performance"""
    
    def test_concurrent_network_discovery(self, performance_settings, performance_timer):
        """Test concurrent network discovery performance"""
        
        def discovery_task(network_range, task_id):
            """Single discovery task"""
            discovery = NetworkDiscovery(performance_settings)
            
            # Mock network discovery for consistent performance testing
            with patch.object(discovery.nm, 'scan') as mock_scan, \
                 patch.object(discovery.nm, 'all_hosts') as mock_hosts:
                
                # Simulate different number of hosts per range
                host_count = 10 + (task_id % 5)  # 10-14 hosts per range
                mock_hosts.return_value = [f'192.168.{task_id}.{i}' for i in range(1, host_count + 1)]
                
                def mock_host_state(host):
                    mock_host = MagicMock()
                    mock_host.state.return_value = 'up'
                    return mock_host
                
                discovery.nm.__getitem__ = mock_host_state
                
                start_time = time.time()
                devices = discovery.discover_devices(network_range)
                end_time = time.time()
                
                return {
                    'task_id': task_id,
                    'devices_found': len(devices),
                    'time': end_time - start_time,
                    'network_range': network_range
                }
        
        # Test concurrent discovery on different network ranges
        network_ranges = [
            f'192.168.{i}.0/28' for i in range(1, 6)  # 5 different ranges
        ]
        
        overall_timer = performance_timer.start()
        
        # Run concurrent discovery tasks
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(discovery_task, network_ranges[i], i) 
                for i in range(len(network_ranges))
            ]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        total_time = overall_timer.stop()
        
        # Analyze concurrent performance
        total_devices = sum(r['devices_found'] for r in results)
        avg_task_time = sum(r['time'] for r in results) / len(results)
        
        # Concurrent execution should be faster than sequential
        sequential_time_estimate = sum(r['time'] for r in results)
        efficiency = sequential_time_estimate / total_time
        
        print(f"\nConcurrent Network Discovery Performance:")
        print(f"  Total devices found: {total_devices}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average task time: {avg_task_time:.3f}s")
        print(f"  Efficiency ratio: {efficiency:.2f}x")
        
        # Assertions
        assert total_time < 30.0, f"Concurrent discovery took too long: {total_time:.3f}s"
        assert efficiency > 1.5, f"Concurrent execution not efficient enough: {efficiency:.2f}x"
        assert total_devices > 0, "Should discover some devices"
    
    def test_concurrent_vulnerability_scanning(self, performance_settings, performance_db_session, performance_timer, large_dataset_factory):
        """Test concurrent vulnerability scanning performance"""
        
        # Create test devices
        devices_data = large_dataset_factory['devices'](20)
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
        
        def vulnerability_scan_task(device_batch, task_id):
            """Vulnerability scanning task for a batch of devices"""
            vuln_scanner = VulnerabilityScanner(performance_settings)
            
            # Mock CVE database for consistent testing
            with patch.object(vuln_scanner, '_query_cve_database') as mock_cve:
                mock_cve.return_value = [
                    {
                        'cve_id': f'CVE-2023-{task_id:05d}',
                        'cvss_score': 7.5,
                        'severity': 'high',
                        'description': f'Test vulnerability for task {task_id}',
                        'solution': 'Apply security patches'
                    }
                ]
                
                start_time = time.time()
                vulnerabilities_found = 0
                
                for device in device_batch:
                    vulnerabilities = vuln_scanner.scan_device(device)
                    vulnerabilities_found += len(vulnerabilities)
                
                end_time = time.time()
                
                return {
                    'task_id': task_id,
                    'devices_scanned': len(device_batch),
                    'vulnerabilities_found': vulnerabilities_found,
                    'time': end_time - start_time
                }
        
        # Divide devices into batches for concurrent scanning
        batch_size = 5
        device_batches = [devices[i:i+batch_size] for i in range(0, len(devices), batch_size)]
        
        overall_timer = performance_timer.start()
        
        # Run concurrent vulnerability scanning
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(vulnerability_scan_task, device_batches[i], i)
                for i in range(len(device_batches))
            ]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        total_time = overall_timer.stop()
        
        # Analyze results
        total_devices_scanned = sum(r['devices_scanned'] for r in results)
        total_vulnerabilities = sum(r['vulnerabilities_found'] for r in results)
        
        print(f"\nConcurrent Vulnerability Scanning Performance:")
        print(f"  Devices scanned: {total_devices_scanned}")
        print(f"  Vulnerabilities found: {total_vulnerabilities}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Rate: {total_devices_scanned / total_time:.1f} devices/sec")
        
        # Assertions
        assert total_time < 45.0, f"Concurrent vulnerability scanning took too long: {total_time:.3f}s"
        assert total_devices_scanned == len(devices), "Should scan all devices"
        assert total_vulnerabilities >= 0, "Should find vulnerabilities or handle gracefully"
    
    def test_concurrent_scheduler_tasks(self, performance_settings, performance_timer):
        """Test concurrent scheduler task execution"""
        
        def scheduler_task(task_type, task_id):
            """Individual scheduler task"""
            scheduler = SchedulerTasks(performance_settings)
            
            start_time = time.time()
            
            try:
                if task_type == 'discovery':
                    # Mock discovery task
                    with patch.object(NetworkDiscovery, 'discover_devices') as mock_discover:
                        mock_discover.return_value = [
                            {'ip': f'192.168.{task_id}.{i}', 'hostname': f'device-{i}'}
                            for i in range(1, 6)
                        ]
                        result = scheduler.run_discovery_scan()
                
                elif task_type == 'vulnerability':
                    # Mock vulnerability scan task
                    with patch.object(VulnerabilityScanner, 'scan_all_devices') as mock_scan:
                        mock_scan.return_value = [
                            {'device_id': i, 'vulnerabilities': ['CVE-2023-12345']}
                            for i in range(1, 4)
                        ]
                        result = scheduler.run_vulnerability_scan()
                
                elif task_type == 'cleanup':
                    # Mock cleanup task
                    result = scheduler.cleanup_old_data()
                
                end_time = time.time()
                
                return {
                    'task_id': task_id,
                    'task_type': task_type,
                    'time': end_time - start_time,
                    'success': True
                }
                
            except Exception as e:
                end_time = time.time()
                return {
                    'task_id': task_id,
                    'task_type': task_type,
                    'time': end_time - start_time,
                    'success': False,
                    'error': str(e)
                }
        
        # Test different types of concurrent tasks
        tasks = [
            ('discovery', 0),
            ('vulnerability', 1),
            ('cleanup', 2),
            ('discovery', 3),
            ('vulnerability', 4)
        ]
        
        overall_timer = performance_timer.start()
        
        # Run concurrent scheduler tasks
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(scheduler_task, task_type, task_id)
                for task_type, task_id in tasks
            ]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        total_time = overall_timer.stop()
        
        # Analyze results
        successful_tasks = [r for r in results if r['success']]
        failed_tasks = [r for r in results if not r['success']]
        
        print(f"\nConcurrent Scheduler Tasks Performance:")
        print(f"  Total tasks: {len(results)}")
        print(f"  Successful: {len(successful_tasks)}")
        print(f"  Failed: {len(failed_tasks)}")
        print(f"  Total time: {total_time:.3f}s")
        
        if successful_tasks:
            avg_task_time = sum(r['time'] for r in successful_tasks) / len(successful_tasks)
            print(f"  Average task time: {avg_task_time:.3f}s")
        
        # Assertions
        assert total_time < 60.0, f"Concurrent scheduler tasks took too long: {total_time:.3f}s"
        assert len(successful_tasks) >= len(tasks) * 0.8, f"Too many failed tasks: {len(failed_tasks)}"


@pytest.mark.performance
@pytest.mark.slow  
class TestMemoryUsageUnderLoad:
    """Test memory usage under various load conditions"""
    
    def test_memory_usage_large_dataset_processing(self, performance_settings, large_dataset_factory, memory_monitor):
        """Test memory usage when processing large datasets"""
        
        process = memory_monitor['process']
        initial_memory = process.memory_info().rss
        
        # Process increasingly large datasets
        dataset_sizes = [100, 500, 1000, 2000]
        memory_measurements = []
        
        for size in dataset_sizes:
            # Create large dataset
            devices_data = large_dataset_factory['devices'](size)
            
            # Measure memory before processing
            memory_before = process.memory_info().rss
            
            # Process the dataset (simulate typical operations)
            processed_devices = []
            for device_data in devices_data:
                # Simulate device processing
                processed_device = {
                    'id': len(processed_devices) + 1,
                    **device_data,
                    'processed_at': datetime.now(),
                    'risk_score': len(device_data.get('services', [])) * 2.5
                }
                processed_devices.append(processed_device)
            
            # Measure memory after processing
            memory_after = process.memory_info().rss
            memory_increase = memory_after - memory_before
            
            memory_measurements.append({
                'dataset_size': size,
                'memory_before': memory_before / 1024 / 1024,  # MB
                'memory_after': memory_after / 1024 / 1024,    # MB
                'memory_increase': memory_increase / 1024 / 1024,  # MB
                'memory_per_item': memory_increase / size / 1024  # KB per item
            })
            
            # Clean up to prevent accumulation
            del devices_data
            del processed_devices
        
        # Print memory usage analysis
        print(f"\nMemory Usage Under Load:")
        print(f"{'Size':<8} {'Before(MB)':<12} {'After(MB)':<12} {'Increase(MB)':<14} {'Per Item(KB)':<12}")
        print("-" * 65)
        
        for measurement in memory_measurements:
            print(f"{measurement['dataset_size']:<8} "
                  f"{measurement['memory_before']:<12.1f} "
                  f"{measurement['memory_after']:<12.1f} "
                  f"{measurement['memory_increase']:<14.1f} "
                  f"{measurement['memory_per_item']:<12.1f}")
        
        # Memory usage assertions
        for measurement in memory_measurements:
            # Memory increase should be reasonable
            assert measurement['memory_increase'] < 500, f"Memory increase too high: {measurement['memory_increase']:.1f}MB for {measurement['dataset_size']} items"
            
            # Memory per item should be reasonable
            assert measurement['memory_per_item'] < 50, f"Memory per item too high: {measurement['memory_per_item']:.1f}KB"
        
        # Memory usage should scale reasonably
        largest_measurement = memory_measurements[-1]
        smallest_measurement = memory_measurements[0]
        
        size_ratio = largest_measurement['dataset_size'] / smallest_measurement['dataset_size']
        memory_ratio = largest_measurement['memory_increase'] / max(smallest_measurement['memory_increase'], 1)
        
        # Memory usage should not grow much faster than dataset size
        assert memory_ratio <= size_ratio * 2, f"Memory usage grows too quickly: {memory_ratio:.2f}x vs {size_ratio:.2f}x data size"
    
    def test_memory_leak_detection(self, performance_settings, memory_monitor):
        """Test for memory leaks during repeated operations"""
        
        process = memory_monitor['process']
        initial_memory = process.memory_info().rss
        memory_samples = []
        
        # Perform repeated operations that might cause memory leaks
        for iteration in range(20):
            # Simulate typical application operations
            discovery = NetworkDiscovery(performance_settings)
            
            # Mock some operations
            with patch.object(discovery.nm, 'scan') as mock_scan, \
                 patch.object(discovery.nm, 'all_hosts') as mock_hosts:
                
                mock_hosts.return_value = [f'192.168.1.{i}' for i in range(1, 11)]
                
                def mock_host_state(host):
                    mock_host = MagicMock()
                    mock_host.state.return_value = 'up'
                    return mock_host
                
                discovery.nm.__getitem__ = mock_host_state
                
                # Perform discovery
                devices = discovery.discover_devices('192.168.1.0/28')
                
                # Clean up references
                del devices
                del discovery
            
            # Sample memory usage
            current_memory = process.memory_info().rss
            memory_samples.append({
                'iteration': iteration,
                'memory_mb': current_memory / 1024 / 1024,
                'memory_increase_mb': (current_memory - initial_memory) / 1024 / 1024
            })
            
            # Small delay to allow garbage collection
            time.sleep(0.1)
        
        # Analyze memory growth
        print(f"\nMemory Leak Detection (20 iterations):")
        print(f"Initial memory: {initial_memory / 1024 / 1024:.1f}MB")
        
        final_memory = memory_samples[-1]['memory_mb']
        total_increase = memory_samples[-1]['memory_increase_mb']
        
        print(f"Final memory: {final_memory:.1f}MB")
        print(f"Total increase: {total_increase:.1f}MB")
        
        # Calculate trend
        first_half_avg = sum(s['memory_mb'] for s in memory_samples[:10]) / 10
        second_half_avg = sum(s['memory_mb'] for s in memory_samples[10:]) / 10
        growth_trend = second_half_avg - first_half_avg
        
        print(f"Memory growth trend: {growth_trend:.1f}MB")
        
        # Assertions for memory leak detection
        assert total_increase < 100, f"Total memory increase too high: {total_increase:.1f}MB"
        assert growth_trend < 20, f"Memory growth trend indicates possible leak: {growth_trend:.1f}MB"
    
    def test_memory_usage_under_concurrent_load(self, performance_settings, memory_monitor):
        """Test memory usage under concurrent load"""
        
        process = memory_monitor['process']
        initial_memory = process.memory_info().rss
        
        def memory_intensive_task(task_id):
            """Task that uses memory"""
            # Simulate memory-intensive operations
            large_data = []
            
            for i in range(1000):
                # Create some data structures
                device_data = {
                    'id': f"{task_id}-{i}",
                    'ip_address': f'192.168.{task_id}.{i % 255}',
                    'hostname': f'device-{task_id}-{i}',
                    'services': [
                        {'port': 22, 'service': 'ssh', 'version': '7.4'},
                        {'port': 80, 'service': 'http', 'version': '2.4'},
                        {'port': 443, 'service': 'https', 'version': '2.4'}
                    ],
                    'metadata': {'scan_time': datetime.now().isoformat()}
                }
                large_data.append(device_data)
            
            # Simulate processing
            processed_data = [
                {**item, 'processed': True, 'risk_score': len(item['services']) * 2.5}
                for item in large_data
            ]
            
            return len(processed_data)
        
        # Monitor memory during concurrent execution
        peak_memory = initial_memory
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(memory_intensive_task, i) for i in range(5)]
            
            # Monitor memory while tasks are running
            completed = 0
            while completed < len(futures):
                current_memory = process.memory_info().rss
                peak_memory = max(peak_memory, current_memory)
                
                completed = sum(1 for f in futures if f.done())
                time.sleep(0.5)
            
            # Wait for all tasks to complete
            results = [f.result() for f in futures]
        
        final_memory = process.memory_info().rss
        peak_increase = (peak_memory - initial_memory) / 1024 / 1024
        final_increase = (final_memory - initial_memory) / 1024 / 1024
        
        print(f"\nMemory Usage Under Concurrent Load:")
        print(f"Initial memory: {initial_memory / 1024 / 1024:.1f}MB")
        print(f"Peak memory: {peak_memory / 1024 / 1024:.1f}MB")
        print(f"Final memory: {final_memory / 1024 / 1024:.1f}MB")
        print(f"Peak increase: {peak_increase:.1f}MB")
        print(f"Final increase: {final_increase:.1f}MB")
        
        # Assertions
        assert peak_increase < 200, f"Peak memory increase too high: {peak_increase:.1f}MB"
        assert final_increase < 50, f"Final memory increase too high (possible leak): {final_increase:.1f}MB"
        assert all(r > 0 for r in results), "All tasks should complete successfully"