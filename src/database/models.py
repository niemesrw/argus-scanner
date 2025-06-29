"""
Database models for Argus Scanner
"""
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, 
    Float, Boolean, ForeignKey, Text, JSON, Enum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.sql import func

import enum

Base = declarative_base()

class ScanType(enum.Enum):
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    VULNERABILITY = "vulnerability"
    SERVICE_DETECTION = "service_detection"

class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True)
    mac_address = Column(String(17), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=False)  # Support IPv6
    hostname = Column(String(255), nullable=True)
    device_type = Column(String(50), nullable=True)
    manufacturer = Column(String(100), nullable=True)
    operating_system = Column(String(100), nullable=True)
    os_version = Column(String(50), nullable=True)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    risk_score = Column(Float, default=0.0)
    notes = Column(Text, nullable=True)
    device_metadata = Column(JSON, nullable=True)
    
    # Relationships
    services = relationship("Service", back_populates="device", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="device")

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20), default="open")
    service_name = Column(String(50), nullable=True)
    product = Column(String(100), nullable=True)
    version = Column(String(50), nullable=True)
    extra_info = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    cve_id = Column(String(20), nullable=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(Severity), default=Severity.INFO)
    cvss_score = Column(Float, nullable=True)
    exploit_available = Column(Boolean, default=False)
    exploit_tested = Column(Boolean, default=False)
    exploit_successful = Column(Boolean, default=False)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=func.now())
    last_checked = Column(DateTime, default=func.now())
    
    # Relationships
    service = relationship("Service", back_populates="vulnerabilities")
    alerts = relationship("Alert", back_populates="vulnerability")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    target_range = Column(String(255), nullable=False)
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")
    total_hosts = Column(Integer, default=0)
    hosts_scanned = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    scan_metadata = Column(JSON, nullable=True)
    
    # Relationships
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    timestamp = Column(DateTime, default=func.now())
    result_type = Column(String(50), nullable=False)
    data = Column(JSON, nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="results")
    device = relationship("Device", back_populates="scan_results")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    severity = Column(Enum(Severity), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=func.now())
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)
    notification_sent = Column(Boolean, default=False)
    alert_metadata = Column(JSON, nullable=True)
    
    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="alerts")

# Database initialization
def init_db(db_path: Path) -> Session:
    """Initialize database and return session"""
    # Create directory if it doesn't exist
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create engine
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False}
    )
    
    # Create tables
    Base.metadata.create_all(engine)
    
    # Create session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    return SessionLocal

def get_db_session(db_path: Path) -> Session:
    """Get database session"""
    SessionLocal = init_db(db_path)
    return SessionLocal()