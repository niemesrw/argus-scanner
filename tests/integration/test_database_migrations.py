"""
Integration tests for database migrations and schema changes
"""
import pytest
import tempfile
import os
from pathlib import Path
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from src.database.models import Base, Device, Vulnerability, ScanResult, Alert
from src.config.settings import Settings


@pytest.mark.integration
@pytest.mark.database
class TestDatabaseMigrations:
    """Integration tests for database schema and migrations"""
    
    def test_fresh_database_creation(self, temp_database):
        """Test creating a fresh database with all tables"""
        engine = create_engine(temp_database)
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        # Verify all expected tables exist
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        expected_tables = ['devices', 'vulnerabilities', 'scan_results', 'alerts']
        for table in expected_tables:
            assert table in tables, f"Table {table} should exist"
    
    def test_database_schema_validation(self, temp_database):
        """Test that database schema matches model definitions"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        
        inspector = inspect(engine)
        
        # Test Device table schema
        device_columns = {col['name']: col for col in inspector.get_columns('devices')}
        required_device_cols = [
            'id', 'mac_address', 'ip_address', 'hostname', 'device_type',
            'manufacturer', 'operating_system', 'os_version', 'first_seen',
            'last_seen', 'is_active', 'risk_score', 'notes', 'device_metadata'
        ]
        
        for col_name in required_device_cols:
            assert col_name in device_columns, f"Device table missing column: {col_name}"
        
        # Test Vulnerability table schema
        vuln_columns = {col['name']: col for col in inspector.get_columns('vulnerabilities')}
        required_vuln_cols = [
            'id', 'device_id', 'cve_id', 'cvss_score', 'severity',
            'description', 'solution', 'discovered_at', 'is_fixed'
        ]
        
        for col_name in required_vuln_cols:
            assert col_name in vuln_columns, f"Vulnerability table missing column: {col_name}"
    
    def test_foreign_key_constraints(self, temp_database):
        """Test foreign key relationships work correctly"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Create a device
            device = Device(
                mac_address='00:11:22:33:44:55',
                ip_address='192.168.1.100',
                hostname='test-device',
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device)
            session.commit()
            
            # Create a vulnerability linked to the device
            vulnerability = Vulnerability(
                device_id=device.id,
                cve_id='CVE-2023-12345',
                cvss_score=7.5,
                severity='high',
                description='Test vulnerability',
                solution='Update software',
                discovered_at=datetime.now()
            )
            session.add(vulnerability)
            session.commit()
            
            # Verify the relationship
            retrieved_device = session.query(Device).filter_by(id=device.id).first()
            assert retrieved_device is not None
            assert len(retrieved_device.vulnerabilities) == 1
            assert retrieved_device.vulnerabilities[0].cve_id == 'CVE-2023-12345'
            
            # Verify reverse relationship
            retrieved_vuln = session.query(Vulnerability).filter_by(id=vulnerability.id).first()
            assert retrieved_vuln is not None
            assert retrieved_vuln.device.ip_address == '192.168.1.100'
            
        finally:
            session.close()
    
    def test_database_constraints_validation(self, temp_database):
        """Test database constraints are properly enforced"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Test unique constraint on MAC address
            device1 = Device(
                mac_address='00:11:22:33:44:55',
                ip_address='192.168.1.100',
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device1)
            session.commit()
            
            # Try to add another device with same MAC address
            device2 = Device(
                mac_address='00:11:22:33:44:55',  # Same MAC
                ip_address='192.168.1.101',
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device2)
            
            # This should raise an integrity error
            with pytest.raises(Exception):  # SQLAlchemy will raise IntegrityError
                session.commit()
                
        finally:
            session.rollback()
            session.close()
    
    def test_json_field_storage_retrieval(self, temp_database):
        """Test JSON field storage and retrieval"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Create device with JSON metadata
            metadata = {
                'ports': [22, 80, 443],
                'services': [
                    {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0'},
                    {'port': 80, 'service': 'http', 'version': 'Apache 2.4'}
                ],
                'os_details': {
                    'kernel': '5.4.0',
                    'architecture': 'x86_64'
                }
            }
            
            device = Device(
                mac_address='00:11:22:33:44:66',
                ip_address='192.168.1.200',
                device_metadata=metadata,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device)
            session.commit()
            
            # Retrieve and verify JSON data
            retrieved_device = session.query(Device).filter_by(
                mac_address='00:11:22:33:44:66'
            ).first()
            
            assert retrieved_device is not None
            assert retrieved_device.device_metadata is not None
            assert retrieved_device.device_metadata['ports'] == [22, 80, 443]
            assert len(retrieved_device.device_metadata['services']) == 2
            assert retrieved_device.device_metadata['os_details']['kernel'] == '5.4.0'
            
        finally:
            session.close()
    
    def test_enum_field_storage(self, temp_database):
        """Test enum field storage and validation"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Create device
            device = Device(
                mac_address='00:11:22:33:44:77',
                ip_address='192.168.1.300',
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device)
            session.commit()
            
            # Create vulnerability with enum severity
            vulnerability = Vulnerability(
                device_id=device.id,
                cve_id='CVE-2023-54321',
                cvss_score=9.0,
                severity='critical',  # This should be stored as enum
                description='Critical test vulnerability',
                discovered_at=datetime.now()
            )
            session.add(vulnerability)
            session.commit()
            
            # Retrieve and verify enum value
            retrieved_vuln = session.query(Vulnerability).filter_by(
                cve_id='CVE-2023-54321'
            ).first()
            
            assert retrieved_vuln is not None
            assert retrieved_vuln.severity == 'critical'
            
        finally:
            session.close()
    
    def test_database_indexing_performance(self, temp_database):
        """Test database indexing for performance-critical queries"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Create multiple devices for performance testing
            devices = []
            for i in range(100):
                device = Device(
                    mac_address=f'00:11:22:33:44:{i:02x}',
                    ip_address=f'192.168.1.{i}',
                    hostname=f'device-{i}',
                    first_seen=datetime.now(),
                    last_seen=datetime.now()
                )
                devices.append(device)
            
            session.add_all(devices)
            session.commit()
            
            # Test query performance on IP address (should be indexed)
            import time
            start_time = time.time()
            
            result = session.query(Device).filter_by(ip_address='192.168.1.50').first()
            
            query_time = time.time() - start_time
            
            # Query should be fast (under 0.1 seconds for 100 records)
            assert query_time < 0.1, f"Query took too long: {query_time} seconds"
            assert result is not None
            assert result.hostname == 'device-50'
            
        finally:
            session.close()
    
    def test_database_backup_restore_simulation(self, temp_database):
        """Test database backup and restore simulation"""
        engine = create_engine(temp_database)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        
        try:
            # Create test data
            device = Device(
                mac_address='00:11:22:33:44:88',
                ip_address='192.168.1.400',
                hostname='backup-test-device',
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            session.add(device)
            session.commit()
            
            # Simulate backup by dumping data
            backup_data = session.query(Device).all()
            assert len(backup_data) == 1
            
            # Simulate data loss by clearing table
            session.query(Device).delete()
            session.commit()
            
            # Verify data is gone
            remaining_data = session.query(Device).all()
            assert len(remaining_data) == 0
            
            # Simulate restore by re-adding data
            restored_device = Device(
                mac_address=backup_data[0].mac_address,
                ip_address=backup_data[0].ip_address,
                hostname=backup_data[0].hostname,
                first_seen=backup_data[0].first_seen,
                last_seen=backup_data[0].last_seen
            )
            session.add(restored_device)
            session.commit()
            
            # Verify restore
            restored_data = session.query(Device).all()
            assert len(restored_data) == 1
            assert restored_data[0].hostname == 'backup-test-device'
            
        finally:
            session.close()