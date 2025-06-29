"""
Network discovery module using nmap
"""
import logging
import ipaddress
from typing import List, Dict, Optional, Set
from datetime import datetime
import nmap
import netifaces

from src.database.models import Device, get_db_session
from src.config.settings import Settings

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    """Handles network discovery and device identification"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.nm = nmap.PortScanner()
        self.db = get_db_session(settings.db_path)
        
    def discover_devices(self, network_range: Optional[str] = None) -> List[Dict]:
        """Discover devices on the network"""
        target_range = network_range or self.settings.network_range
        
        logger.info(f"Starting network discovery for range: {target_range}")
        
        # If in mock mode, return fake data
        if self.settings.mock_mode:
            return self._get_mock_devices()
        
        try:
            # Perform ARP scan for local network discovery
            # -sn: Ping scan, no port scan
            # -PR: ARP ping (works on local network)
            self.nm.scan(hosts=target_range, arguments='-sn -PR')
            
            discovered_devices = []
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device_info = self._extract_device_info(host)
                    discovered_devices.append(device_info)
                    self._save_device(device_info)
            
            logger.info(f"Discovered {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"Error during network discovery: {e}")
            raise
    
    def deep_scan_device(self, ip_address: str) -> Dict:
        """Perform detailed scan of a specific device"""
        logger.info(f"Starting deep scan for device: {ip_address}")
        
        try:
            # Comprehensive scan with OS detection and service version
            # -A: Enable OS detection, version detection, script scanning
            # -T4: Aggressive timing
            self.nm.scan(hosts=ip_address, arguments='-A -T4')
            
            if ip_address in self.nm.all_hosts():
                return self._extract_detailed_info(ip_address)
            else:
                logger.warning(f"Device {ip_address} not found in scan results")
                return {}
                
        except Exception as e:
            logger.error(f"Error during deep scan of {ip_address}: {e}")
            raise
    
    def _extract_device_info(self, host: str) -> Dict:
        """Extract basic device information from scan results"""
        device_info = {
            'ip_address': host,
            'hostname': self._get_hostname(host),
            'mac_address': self._get_mac_address(host),
            'state': self.nm[host].state(),
            'last_seen': datetime.utcnow()
        }
        
        # Try to get vendor from MAC address
        if device_info['mac_address']:
            device_info['manufacturer'] = self.nm[host]['vendor'].get(
                device_info['mac_address'], 'Unknown'
            )
        
        return device_info
    
    def _extract_detailed_info(self, host: str) -> Dict:
        """Extract detailed information from deep scan"""
        device_info = self._extract_device_info(host)
        
        # Add OS detection results
        if 'osmatch' in self.nm[host]:
            if self.nm[host]['osmatch']:
                best_match = self.nm[host]['osmatch'][0]
                device_info['operating_system'] = best_match.get('name', 'Unknown')
                device_info['os_accuracy'] = best_match.get('accuracy', 0)
        
        # Add open ports and services
        device_info['services'] = []
        
        for proto in self.nm[host].all_protocols():
            ports = self.nm[host][proto].keys()
            
            for port in ports:
                service = self.nm[host][proto][port]
                if service['state'] == 'open':
                    service_info = {
                        'port': port,
                        'protocol': proto,
                        'name': service.get('name', 'unknown'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', '')
                    }
                    device_info['services'].append(service_info)
        
        return device_info
    
    def _get_hostname(self, host: str) -> Optional[str]:
        """Get hostname for IP address"""
        if 'hostnames' in self.nm[host]:
            hostnames = self.nm[host]['hostnames']
            if hostnames and hostnames[0]['name']:
                return hostnames[0]['name']
        return None
    
    def _get_mac_address(self, host: str) -> Optional[str]:
        """Get MAC address for IP address"""
        if 'addresses' in self.nm[host]:
            if 'mac' in self.nm[host]['addresses']:
                return self.nm[host]['addresses']['mac']
        return None
    
    def _save_device(self, device_info: Dict) -> None:
        """Save or update device in database"""
        try:
            # Check if device exists
            existing = self.db.query(Device).filter_by(
                mac_address=device_info.get('mac_address')
            ).first()
            
            if existing:
                # Update existing device
                existing.ip_address = device_info['ip_address']
                existing.hostname = device_info.get('hostname')
                existing.last_seen = device_info['last_seen']
                existing.is_active = True
                
                if 'manufacturer' in device_info:
                    existing.manufacturer = device_info['manufacturer']
                if 'operating_system' in device_info:
                    existing.operating_system = device_info['operating_system']
            else:
                # Create new device
                device = Device(
                    mac_address=device_info.get('mac_address', f"unknown_{device_info['ip_address']}"),
                    ip_address=device_info['ip_address'],
                    hostname=device_info.get('hostname'),
                    manufacturer=device_info.get('manufacturer'),
                    operating_system=device_info.get('operating_system'),
                    first_seen=device_info['last_seen'],
                    last_seen=device_info['last_seen']
                )
                self.db.add(device)
            
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Error saving device to database: {e}")
            self.db.rollback()
    
    def _get_mock_devices(self) -> List[Dict]:
        """Return mock devices for development/testing"""
        mock_devices = [
            {
                'ip_address': '192.168.1.1',
                'hostname': 'router.local',
                'mac_address': '00:11:22:33:44:55',
                'manufacturer': 'Netgear',
                'operating_system': 'Linux 2.6.x',
                'last_seen': datetime.utcnow(),
                'services': [
                    {'port': 80, 'protocol': 'tcp', 'name': 'http', 'product': 'nginx', 'version': '1.21.0'},
                    {'port': 443, 'protocol': 'tcp', 'name': 'https', 'product': 'nginx', 'version': '1.21.0'},
                    {'port': 22, 'protocol': 'tcp', 'name': 'ssh', 'product': 'OpenSSH', 'version': '7.4'}
                ]
            },
            {
                'ip_address': '192.168.1.100',
                'hostname': 'workstation-01',
                'mac_address': 'AA:BB:CC:DD:EE:FF',
                'manufacturer': 'Apple',
                'operating_system': 'Mac OS X 10.15.x',
                'last_seen': datetime.utcnow(),
                'services': [
                    {'port': 5900, 'protocol': 'tcp', 'name': 'vnc', 'product': 'Apple Remote Desktop', 'version': '3.9'},
                    {'port': 22, 'protocol': 'tcp', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.1'}
                ]
            },
            {
                'ip_address': '192.168.1.150',
                'hostname': 'web-server',
                'mac_address': '11:22:33:44:55:66',
                'manufacturer': 'Dell',
                'operating_system': 'Ubuntu 20.04',
                'last_seen': datetime.utcnow(),
                'services': [
                    {'port': 80, 'protocol': 'tcp', 'name': 'http', 'product': 'Apache', 'version': '2.4.41'},
                    {'port': 3306, 'protocol': 'tcp', 'name': 'mysql', 'product': 'MySQL', 'version': '5.7.31'},
                    {'port': 22, 'protocol': 'tcp', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2'}
                ]
            }
        ]
        
        # Save mock devices to database
        for device in mock_devices:
            self._save_device(device)
        
        return mock_devices
    
    def get_local_networks(self) -> List[str]:
        """Get list of local network interfaces and their subnets"""
        networks = []
        
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        ip = addr['addr']
                        netmask = addr['netmask']
                        
                        # Skip loopback
                        if ip == '127.0.0.1':
                            continue
                        
                        # Calculate network CIDR
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            networks.append(str(network))
                        except Exception as e:
                            logger.warning(f"Error calculating network for {interface}: {e}")
        
        return networks