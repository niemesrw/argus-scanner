"""Network simulation fixtures for testing."""

import pytest
import json
import random
from typing import Dict, List, Optional, Any
from datetime import datetime


@pytest.fixture
def mock_network_response():
    """Mock network response data."""

    def _response(
        status_code: int = 200,
        headers: Optional[Dict] = None,
        content: Optional[str] = None,
        json_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Generate a mock network response."""
        return {
            "status_code": status_code,
            "headers": headers or {"Content-Type": "application/json"},
            "content": content or "",
            "json": json_data or {},
            "elapsed": random.uniform(0.1, 2.0),
            "url": "http://mock-service.local",
        }

    return _response


@pytest.fixture
def mock_nmap_output():
    """Generate mock nmap scan output."""

    def _nmap_output(
        hosts: Optional[List[str]] = None,
        include_services: bool = True,
        include_os: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate realistic nmap output structure.

        Args:
            hosts: List of IP addresses to include
            include_services: Whether to include service detection
            include_os: Whether to include OS detection
        """
        if not hosts:
            hosts = [f"192.168.1.{i}" for i in range(100, 105)]

        scan_result = {
            "nmap": {
                "command_line": "nmap -sV -O -A 192.168.1.0/24",
                "scaninfo": {"tcp": {"method": "syn", "services": "1-65535"}},
                "scanstats": {
                    "timestr": datetime.utcnow().isoformat(),
                    "elapsed": "45.23",
                    "uphosts": str(len(hosts)),
                    "downhosts": "0",
                    "totalhosts": str(len(hosts)),
                },
            },
            "scan": {},
        }

        # Generate host data
        for host_ip in hosts:
            host_data = {
                "hostnames": [
                    {"name": f'host-{host_ip.split(".")[-1]}.local', "type": "PTR"}
                ],
                "addresses": {"ipv4": host_ip, "mac": _generate_mac_address()},
                "vendor": {
                    _generate_mac_address(): random.choice(
                        ["Dell Inc.", "HP", "Cisco Systems", "Intel Corp"]
                    )
                },
                "status": {"state": "up", "reason": "arp-response"},
            }

            if include_services:
                host_data["tcp"] = _generate_services()

            if include_os:
                host_data["osmatch"] = _generate_os_match()

            scan_result["scan"][host_ip] = host_data

        return scan_result

    def _generate_mac_address() -> str:
        """Generate a random MAC address."""
        return ":".join([f"{random.randint(0, 255):02X}" for _ in range(6)])

    def _generate_services() -> Dict[int, Dict]:
        """Generate random services for a host."""
        common_services = [
            (22, "ssh", "OpenSSH", "8.2p1"),
            (80, "http", "Apache httpd", "2.4.41"),
            (443, "https", "nginx", "1.18.0"),
            (3306, "mysql", "MySQL", "8.0.23"),
            (5432, "postgresql", "PostgreSQL", "13.2"),
            (6379, "redis", "Redis", "6.2.1"),
            (8080, "http-proxy", "Apache Tomcat", "9.0.45"),
            (3389, "ms-wbt-server", "Microsoft Terminal Services", ""),
            (445, "microsoft-ds", "Samba smbd", "4.13.5"),
            (21, "ftp", "vsftpd", "3.0.3"),
        ]

        services = {}
        # Select random subset of services
        num_services = random.randint(1, 5)
        selected_services = random.sample(common_services, num_services)

        for port, name, product, version in selected_services:
            services[port] = {
                "state": "open",
                "reason": "syn-ack",
                "name": name,
                "product": product,
                "version": version,
                "extrainfo": "",
                "conf": "10",
                "cpe": f'cpe:/a:{product.lower().replace(" ", "_")}:{version}',
            }

        return services

    def _generate_os_match() -> List[Dict]:
        """Generate OS detection results."""
        os_options = [
            ("Linux 4.15 - 5.6", "Linux", "4.X|5.X"),
            ("Ubuntu 18.04|20.04", "Linux", "4.X|5.X"),
            ("Microsoft Windows 10", "Windows", "10"),
            ("Microsoft Windows Server 2016|2019", "Windows", "Server 2016|2019"),
            ("Apple macOS 10.15 - 11.0", "Mac OS X", "10.15.X|11.X"),
            ("FreeBSD 12.0 - 13.0", "FreeBSD", "12.X|13.X"),
        ]

        selected_os = random.choice(os_options)
        return [
            {
                "name": selected_os[0],
                "accuracy": str(random.randint(85, 99)),
                "line": str(random.randint(10000, 99999)),
                "osclass": [
                    {
                        "type": "general purpose",
                        "vendor": selected_os[1].split()[0],
                        "osfamily": selected_os[1],
                        "osgen": selected_os[2],
                        "accuracy": str(random.randint(85, 99)),
                    }
                ],
            }
        ]

    return _nmap_output


@pytest.fixture
def mock_device_data():
    """Generate mock device data."""

    def _device_data(count: int = 5) -> List[Dict[str, Any]]:
        """Generate a list of mock devices."""
        devices = []
        device_types = [
            "server",
            "workstation",
            "router",
            "switch",
            "printer",
            "firewall",
            "access_point",
        ]
        manufacturers = ["Dell", "HP", "Cisco", "Juniper", "Apple", "Lenovo", "ASUS"]

        for i in range(count):
            device = {
                "ip_address": f"192.168.1.{100 + i}",
                "hostname": f"device-{i:03d}.local",
                "mac_address": ":".join(
                    [f"{random.randint(0, 255):02X}" for _ in range(6)]
                ),
                "manufacturer": random.choice(manufacturers),
                "device_type": random.choice(device_types),
                "os": _get_os_for_device_type(random.choice(device_types)),
                "open_ports": random.sample(range(1, 65535), random.randint(1, 10)),
                "services": _generate_device_services(),
                "last_seen": datetime.utcnow().isoformat(),
                "status": "online" if random.random() > 0.1 else "offline",
                "risk_score": round(random.uniform(0, 100), 1),
            }
            devices.append(device)

        return devices

    def _get_os_for_device_type(device_type: str) -> str:
        """Get appropriate OS based on device type."""
        os_mapping = {
            "server": [
                "Ubuntu 20.04 LTS",
                "CentOS 8",
                "Windows Server 2019",
                "Debian 11",
            ],
            "workstation": ["Windows 10", "macOS 11.0", "Ubuntu 20.04", "Fedora 34"],
            "router": ["Cisco IOS 15.2", "DD-WRT 3.0", "OpenWrt 19.07", "pfSense 2.5"],
            "switch": ["Cisco IOS 15.0", "Juniper Junos", "Arista EOS"],
            "printer": ["HP Firmware", "Canon Firmware", "Epson Firmware"],
            "firewall": ["pfSense 2.5", "OPNsense 21.1", "Fortinet FortiOS"],
            "access_point": ["DD-WRT", "OpenWrt", "Ubiquiti UniFi"],
        }
        return random.choice(os_mapping.get(device_type, ["Unknown OS"]))

    def _generate_device_services() -> List[Dict[str, Any]]:
        """Generate services for a device."""
        all_services = [
            {"port": 22, "name": "SSH", "version": "OpenSSH 8.2"},
            {"port": 80, "name": "HTTP", "version": "Apache 2.4"},
            {"port": 443, "name": "HTTPS", "version": "nginx 1.18"},
            {"port": 3306, "name": "MySQL", "version": "8.0.23"},
            {"port": 5432, "name": "PostgreSQL", "version": "13.2"},
            {"port": 3389, "name": "RDP", "version": "Microsoft RDP 10.0"},
            {"port": 445, "name": "SMB", "version": "Samba 4.13"},
            {"port": 8080, "name": "HTTP-Proxy", "version": "Tomcat 9.0"},
        ]

        num_services = random.randint(1, 4)
        return random.sample(all_services, num_services)

    return _device_data


@pytest.fixture
def mock_service_data():
    """Generate mock service data."""

    def _service_data(device_id: int, count: int = 3) -> List[Dict[str, Any]]:
        """Generate mock services for a device."""
        service_templates = [
            {
                "port": 22,
                "protocol": "tcp",
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "name": "http",
                "product": "Apache",
                "version": "2.4.41",
            },
            {
                "port": 443,
                "protocol": "tcp",
                "name": "https",
                "product": "nginx",
                "version": "1.18.0",
            },
            {
                "port": 3306,
                "protocol": "tcp",
                "name": "mysql",
                "product": "MySQL",
                "version": "8.0.23",
            },
            {
                "port": 5432,
                "protocol": "tcp",
                "name": "postgresql",
                "product": "PostgreSQL",
                "version": "13.2",
            },
            {
                "port": 6379,
                "protocol": "tcp",
                "name": "redis",
                "product": "Redis",
                "version": "6.2.1",
            },
            {
                "port": 27017,
                "protocol": "tcp",
                "name": "mongodb",
                "product": "MongoDB",
                "version": "4.4.5",
            },
            {
                "port": 8080,
                "protocol": "tcp",
                "name": "http-proxy",
                "product": "Tomcat",
                "version": "9.0.45",
            },
            {
                "port": 25,
                "protocol": "tcp",
                "name": "smtp",
                "product": "Postfix",
                "version": "3.5.9",
            },
            {
                "port": 110,
                "protocol": "tcp",
                "name": "pop3",
                "product": "Dovecot",
                "version": "2.3.13",
            },
        ]

        selected_services = random.sample(
            service_templates, min(count, len(service_templates))
        )
        services = []

        for template in selected_services:
            service = {
                "device_id": device_id,
                "port": template["port"],
                "protocol": template["protocol"],
                "service_name": template["name"],
                "product": template["product"],
                "version": template["version"],
                "state": "open",
                "banner": f"{template['product']}/{template['version']}",
                "cpe": f"cpe:/a:{template['product'].lower()}:{template['version']}",
                "os_type": (
                    "Linux" if template["port"] not in [3389, 445] else "Windows"
                ),
            }
            services.append(service)

        return services

    return _service_data


@pytest.fixture
def mock_vulnerability_data():
    """Generate mock vulnerability data."""

    def _vulnerability_data(device_id: int, count: int = 2) -> List[Dict[str, Any]]:
        """Generate mock vulnerabilities for a device."""
        vulnerability_db = [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "critical",
                "cvss_score": 10.0,
                "description": "Apache Log4j2 Remote Code Execution",
                "solution": "Update Log4j to version 2.17.0 or later",
                "exploit_available": True,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            },
            {
                "cve_id": "CVE-2021-34527",
                "severity": "critical",
                "cvss_score": 8.8,
                "description": "Windows Print Spooler Remote Code Execution",
                "solution": "Apply security update or disable Print Spooler service",
                "exploit_available": True,
                "references": [
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
                ],
            },
            {
                "cve_id": "CVE-2020-1472",
                "severity": "critical",
                "cvss_score": 10.0,
                "description": "Zerologon - Windows Netlogon Elevation of Privilege",
                "solution": "Apply August 2020 security updates",
                "exploit_available": True,
                "references": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472"
                ],
            },
            {
                "cve_id": "CVE-2019-11510",
                "severity": "critical",
                "cvss_score": 10.0,
                "description": "Pulse Secure VPN Arbitrary File Reading",
                "solution": "Update to Pulse Connect Secure 9.0R3.4 or later",
                "exploit_available": True,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11510"],
            },
            {
                "cve_id": "CVE-2022-22963",
                "severity": "high",
                "cvss_score": 9.8,
                "description": "Spring Cloud Function SpEL Code Injection",
                "solution": "Update Spring Cloud Function to 3.1.7+ or 3.2.3+",
                "exploit_available": False,
                "references": ["https://tanzu.vmware.com/security/cve-2022-22963"],
            },
            {
                "cve_id": "CVE-2021-26855",
                "severity": "critical",
                "cvss_score": 9.8,
                "description": "Microsoft Exchange Server Remote Code Execution",
                "solution": "Apply Exchange Server security updates",
                "exploit_available": True,
                "references": [
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"
                ],
            },
            {
                "cve_id": "CVE-2018-13379",
                "severity": "high",
                "cvss_score": 9.8,
                "description": "Fortinet FortiOS Path Traversal",
                "solution": "Update FortiOS to patched version",
                "exploit_available": True,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"],
            },
            {
                "cve_id": "CVE-2020-0601",
                "severity": "high",
                "cvss_score": 8.1,
                "description": "Windows CryptoAPI Spoofing Vulnerability",
                "solution": "Apply Windows security updates",
                "exploit_available": False,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0601"],
            },
        ]

        selected_vulns = random.sample(
            vulnerability_db, min(count, len(vulnerability_db))
        )
        vulnerabilities = []

        for vuln_template in selected_vulns:
            vulnerability = {
                "device_id": device_id,
                "cve_id": vuln_template["cve_id"],
                "severity": vuln_template["severity"],
                "cvss_score": vuln_template["cvss_score"],
                "description": vuln_template["description"],
                "solution": vuln_template["solution"],
                "exploit_available": vuln_template["exploit_available"],
                "references": vuln_template["references"],
                "discovered_at": datetime.utcnow().isoformat(),
                "last_updated": datetime.utcnow().isoformat(),
                "affected_service": _get_affected_service(vuln_template["cve_id"]),
                "acknowledged": False,
            }
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _get_affected_service(cve_id: str) -> str:
        """Map CVE to affected service."""
        service_mapping = {
            "CVE-2021-44228": "Apache Log4j",
            "CVE-2021-34527": "Windows Print Spooler",
            "CVE-2020-1472": "Windows Netlogon",
            "CVE-2019-11510": "Pulse Secure VPN",
            "CVE-2022-22963": "Spring Cloud",
            "CVE-2021-26855": "Microsoft Exchange",
            "CVE-2018-13379": "FortiOS SSL VPN",
            "CVE-2020-0601": "Windows CryptoAPI",
        }
        return service_mapping.get(cve_id, "Unknown Service")

    return _vulnerability_data
