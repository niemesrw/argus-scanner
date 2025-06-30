"""Database fixtures for testing."""

import pytest
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import random
import string

from src.database.models import Device, Service, Vulnerability, Scan, Alert, ScanResult


@pytest.fixture
def test_device(db_session) -> Device:
    """Create a basic test device."""
    device = Device(
        ip_address="192.168.1.100",
        hostname="test-server-01",
        mac_address="AA:BB:CC:DD:EE:FF",
        manufacturer="Test Corp",
        device_type="server",
        operating_system="Ubuntu 20.04 LTS",
        risk_score=45.0,
    )
    db_session.add(device)
    db_session.commit()
    return device


@pytest.fixture
def test_service(db_session, test_device) -> Service:
    """Create a basic test service."""
    service = Service(
        device_id=test_device.id,
        port=22,
        protocol="tcp",
        service_name="ssh",
        version="OpenSSH 8.2p1",
        state="open",
        product="OpenSSH",
    )
    db_session.add(service)
    db_session.commit()
    return service


@pytest.fixture
def test_vulnerability(db_session, test_service) -> Vulnerability:
    """Create a basic test vulnerability."""
    from src.database.models import Severity

    vulnerability = Vulnerability(
        service_id=test_service.id,
        cve_id="CVE-2021-44228",
        name="Log4j Remote Code Execution",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        description="Log4j Remote Code Execution vulnerability",
        remediation="Update to Log4j 2.17.0 or later",
        exploit_available=True,
    )
    db_session.add(vulnerability)
    db_session.commit()
    return vulnerability


@pytest.fixture
def test_scan(db_session) -> Scan:
    """Create a basic test scan."""
    from src.database.models import ScanType

    scan = Scan(
        scan_type=ScanType.VULNERABILITY,
        status="completed",
        target_range="192.168.1.0/24",
        started_at=datetime.utcnow() - timedelta(minutes=30),
        completed_at=datetime.utcnow(),
        total_hosts=25,
        hosts_scanned=15,
        vulnerabilities_found=7,
        error_message=None,
    )
    db_session.add(scan)
    db_session.commit()
    return scan


@pytest.fixture
def test_alert(db_session, test_vulnerability) -> Alert:
    """Create a basic test alert."""
    from src.database.models import Severity

    alert = Alert(
        vulnerability_id=test_vulnerability.id,
        severity=Severity.CRITICAL,
        title="Critical Vulnerability Detected",
        message=f"Critical vulnerability {test_vulnerability.cve_id} found",
        acknowledged=False,
        acknowledged_at=None,
        acknowledged_by=None,
    )
    db_session.add(alert)
    db_session.commit()
    return alert


class DeviceFactory:
    """Factory for creating test devices with various configurations."""

    @staticmethod
    def create(db_session, **kwargs) -> Device:
        """Create a device with customizable attributes."""
        defaults = {
            "ip_address": f"192.168.1.{random.randint(2, 254)}",
            "hostname": f"test-device-{random.randint(1000, 9999)}",
            "mac_address": ":".join(
                [f"{random.randint(0, 255):02X}" for _ in range(6)]
            ),
            "manufacturer": random.choice(["Dell", "HP", "Cisco", "Apple", "Unknown"]),
            "device_type": random.choice(
                ["server", "workstation", "router", "switch", "printer"]
            ),
            "operating_system": random.choice(
                ["Ubuntu 20.04", "Windows 10", "CentOS 8", "macOS 11", "Unknown"]
            ),
            "is_active": True,
            "risk_score": round(random.uniform(0, 100), 1),
        }
        defaults.update(kwargs)

        device = Device(**defaults)
        db_session.add(device)
        db_session.commit()
        return device

    @staticmethod
    def create_batch(db_session, count: int, **kwargs) -> List[Device]:
        """Create multiple devices."""
        return [DeviceFactory.create(db_session, **kwargs) for _ in range(count)]


class ServiceFactory:
    """Factory for creating test services."""

    COMMON_SERVICES = [
        {"port": 22, "service_name": "ssh", "product": "OpenSSH"},
        {"port": 80, "service_name": "http", "product": "Apache"},
        {"port": 443, "service_name": "https", "product": "nginx"},
        {"port": 3306, "service_name": "mysql", "product": "MySQL"},
        {"port": 5432, "service_name": "postgresql", "product": "PostgreSQL"},
        {"port": 6379, "service_name": "redis", "product": "Redis"},
        {"port": 27017, "service_name": "mongodb", "product": "MongoDB"},
        {"port": 3389, "service_name": "rdp", "product": "Microsoft RDP"},
        {"port": 445, "service_name": "smb", "product": "Samba"},
        {"port": 21, "service_name": "ftp", "product": "vsftpd"},
    ]

    @staticmethod
    def create(db_session, device: Device, **kwargs) -> Service:
        """Create a service for a device."""
        service_template = random.choice(ServiceFactory.COMMON_SERVICES)
        defaults = {
            "device_id": device.id,
            "port": service_template["port"],
            "protocol": "tcp",
            "service_name": service_template["service_name"],
            "version": f"{service_template['product']} {random.randint(1, 9)}.{random.randint(0, 9)}",
            "state": "open",
            "product": service_template["product"],
        }
        defaults.update(kwargs)

        service = Service(**defaults)
        db_session.add(service)
        db_session.commit()
        return service

    @staticmethod
    def create_for_device(
        db_session, device: Device, services: List[Dict]
    ) -> List[Service]:
        """Create specific services for a device."""
        created_services = []
        for service_data in services:
            service = ServiceFactory.create(db_session, device, **service_data)
            created_services.append(service)
        return created_services


class VulnerabilityFactory:
    """Factory for creating test vulnerabilities."""

    CVE_TEMPLATES = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": 10.0,
            "description": "Log4j Remote Code Execution vulnerability",
            "solution": "Update to Log4j 2.17.0 or later",
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2021-34527",
            "severity": "critical",
            "cvss_score": 8.8,
            "description": "Windows Print Spooler Remote Code Execution",
            "solution": "Apply security update KB5004945",
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2020-0601",
            "severity": "high",
            "cvss_score": 8.1,
            "description": "Windows CryptoAPI Spoofing Vulnerability",
            "solution": "Apply Windows security updates",
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2019-0708",
            "severity": "critical",
            "cvss_score": 9.8,
            "description": "BlueKeep RDP Remote Code Execution",
            "solution": "Apply security patch or disable RDP",
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2022-26134",
            "severity": "critical",
            "cvss_score": 9.8,
            "description": "Atlassian Confluence Remote Code Execution",
            "solution": "Update to patched version",
            "exploit_available": True,
        },
    ]

    @staticmethod
    def create(db_session, service: Service, **kwargs) -> Vulnerability:
        """Create a vulnerability for a service."""
        from src.database.models import Severity

        template = random.choice(VulnerabilityFactory.CVE_TEMPLATES)
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        defaults = {
            "service_id": service.id,
            "cve_id": template["cve_id"],
            "name": template["description"],
            "severity": severity_map.get(template["severity"], Severity.MEDIUM),
            "cvss_score": template["cvss_score"],
            "description": template["description"],
            "remediation": template["solution"],
            "exploit_available": template["exploit_available"],
        }
        defaults.update(kwargs)

        vulnerability = Vulnerability(**defaults)
        db_session.add(vulnerability)
        db_session.commit()
        return vulnerability

    @staticmethod
    def create_batch(
        db_session, service: Service, count: int, **kwargs
    ) -> List[Vulnerability]:
        """Create multiple vulnerabilities for a service."""
        vulnerabilities = []
        used_cves = set()

        for _ in range(count):
            # Ensure unique CVEs per device
            available_templates = [
                t
                for t in VulnerabilityFactory.CVE_TEMPLATES
                if t["cve_id"] not in used_cves
            ]
            if not available_templates:
                break

            template = random.choice(available_templates)
            used_cves.add(template["cve_id"])

            vuln = VulnerabilityFactory.create(
                db_session,
                service,
                cve_id=template["cve_id"],
                name=template["description"],
                cvss_score=template["cvss_score"],
                description=template["description"],
                remediation=template["solution"],
                exploit_available=template["exploit_available"],
                **kwargs,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


class ScanFactory:
    """Factory for creating test scans."""

    @staticmethod
    def create(db_session, **kwargs) -> Scan:
        """Create a scan with customizable attributes."""
        duration = random.randint(5, 60)  # minutes
        started_at = datetime.utcnow() - timedelta(
            minutes=duration + random.randint(0, 1440)
        )

        from src.database.models import ScanType

        defaults = {
            "scan_type": random.choice(
                [
                    ScanType.DISCOVERY,
                    ScanType.PORT_SCAN,
                    ScanType.VULNERABILITY,
                    ScanType.SERVICE_DETECTION,
                ]
            ),
            "status": "completed",
            "target_range": "192.168.1.0/24",
            "started_at": started_at,
            "completed_at": started_at + timedelta(minutes=duration),
            "total_hosts": random.randint(20, 100),
            "hosts_scanned": random.randint(5, 50),
            "vulnerabilities_found": random.randint(0, 20),
            "error_message": None,
        }
        defaults.update(kwargs)

        scan = Scan(**defaults)
        db_session.add(scan)
        db_session.commit()
        return scan

    @staticmethod
    def create_running(db_session, **kwargs) -> Scan:
        """Create a currently running scan."""
        defaults = {
            "status": "running",
            "started_at": datetime.utcnow() - timedelta(minutes=random.randint(1, 10)),
            "completed_at": None,
            "total_hosts": random.randint(20, 50),
            "hosts_scanned": random.randint(0, 10),
            "vulnerabilities_found": 0,
        }
        defaults.update(kwargs)
        return ScanFactory.create(db_session, **defaults)

    @staticmethod
    def create_failed(db_session, error_message: str = None, **kwargs) -> Scan:
        """Create a failed scan."""
        defaults = {
            "status": "failed",
            "error_message": error_message or "Network timeout during scan",
            "total_hosts": 0,
            "hosts_scanned": 0,
            "vulnerabilities_found": 0,
        }
        defaults.update(kwargs)
        return ScanFactory.create(db_session, **defaults)


class AlertFactory:
    """Factory for creating test alerts."""

    @staticmethod
    def create(
        db_session,
        vulnerability: Optional[Vulnerability] = None,
        **kwargs,
    ) -> Alert:
        """Create an alert."""
        from src.database.models import Severity

        if vulnerability:
            title = f"{vulnerability.severity.value.title()} Vulnerability Detected"
            message = f"{vulnerability.cve_id} found"
            severity = vulnerability.severity
        else:
            severity = random.choice(
                [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            )
            title = f"{severity.value.title()} Security Event"
            message = f"Security event detected"

        defaults = {
            "vulnerability_id": vulnerability.id if vulnerability else None,
            "severity": severity,
            "title": title,
            "message": message,
            "acknowledged": False,
            "acknowledged_at": None,
            "acknowledged_by": None,
        }
        defaults.update(kwargs)

        alert = Alert(**defaults)
        db_session.add(alert)
        db_session.commit()
        return alert

    @staticmethod
    def create_acknowledged(
        db_session,
        vulnerability: Optional[Vulnerability] = None,
        acknowledged_by: str = "admin",
        **kwargs,
    ) -> Alert:
        """Create an acknowledged alert."""
        ack_time = datetime.utcnow() - timedelta(minutes=random.randint(10, 60))
        defaults = {
            "acknowledged": True,
            "acknowledged_at": ack_time,
            "acknowledged_by": acknowledged_by,
        }
        defaults.update(kwargs)
        return AlertFactory.create(db_session, vulnerability, **defaults)


# Fixture instances
@pytest.fixture
def device_factory(db_session):
    """Device factory fixture."""
    return DeviceFactory()


@pytest.fixture
def service_factory(db_session):
    """Service factory fixture."""
    return ServiceFactory()


@pytest.fixture
def vulnerability_factory(db_session):
    """Vulnerability factory fixture."""
    return VulnerabilityFactory()


@pytest.fixture
def scan_factory(db_session):
    """Scan factory fixture."""
    return ScanFactory()


@pytest.fixture
def alert_factory(db_session):
    """Alert factory fixture."""
    return AlertFactory()


@pytest.fixture
def populate_test_database(db_session):
    """Populate database with comprehensive test data."""

    def _populate(
        num_devices: int = 10,
        services_per_device: int = 3,
        vulns_per_device: int = 2,
        num_scans: int = 5,
        num_alerts: int = 10,
    ) -> Dict[str, Any]:
        """
        Populate the test database with realistic data.

        Returns a dictionary with all created objects for reference.
        """
        data = {
            "devices": [],
            "services": [],
            "vulnerabilities": [],
            "scans": [],
            "alerts": [],
        }

        # Create devices with varying characteristics
        for i in range(num_devices):
            device_type = ["server", "workstation", "router", "switch", "printer"][
                i % 5
            ]
            device = DeviceFactory.create(
                db_session,
                ip_address=f"192.168.1.{100 + i}",
                hostname=f"test-{device_type}-{i:02d}",
                device_type=device_type,
                is_active=True if i < num_devices - 2 else False,
            )
            data["devices"].append(device)

            # Create services for each device
            for _ in range(random.randint(1, services_per_device)):
                service = ServiceFactory.create(db_session, device)
                data["services"].append(service)

            # Create vulnerabilities for services
            for service in data["services"][
                -services_per_device:
            ]:  # For recent services
                if random.random() > 0.3:  # 70% chance of vulnerabilities
                    vulns = VulnerabilityFactory.create_batch(
                        db_session, service, random.randint(1, vulns_per_device)
                    )
                    data["vulnerabilities"].extend(vulns)

                    # Create alerts for critical vulnerabilities
                    for vuln in vulns:
                        from src.database.models import Severity

                        if vuln.severity == Severity.CRITICAL and random.random() > 0.5:
                            alert = AlertFactory.create(db_session, vuln)
                            data["alerts"].append(alert)

        # Create scan history
        for i in range(num_scans):
            if i == 0:
                # Current running scan
                scan = ScanFactory.create_running(db_session)
            elif i == num_scans - 1:
                # Recent failed scan
                scan = ScanFactory.create_failed(db_session)
            else:
                # Completed scans
                scan = ScanFactory.create(db_session)
            data["scans"].append(scan)

        # Create additional alerts without vulnerabilities
        remaining_alerts = num_alerts - len(data["alerts"])
        for _ in range(remaining_alerts):
            alert = AlertFactory.create(db_session)
            data["alerts"].append(alert)

        # Acknowledge some alerts
        for alert in random.sample(data["alerts"], min(3, len(data["alerts"]))):
            alert.acknowledged = True
            alert.acknowledged_at = datetime.utcnow() - timedelta(
                hours=random.randint(1, 24)
            )
            alert.acknowledged_by = "test_admin"

        db_session.commit()
        return data

    return _populate
