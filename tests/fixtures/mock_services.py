"""Mock vulnerable services for testing security scanning."""

import pytest
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple, Callable
from contextlib import contextmanager
import random
import json


class MockService:
    """Base class for mock network services."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        self.connections = []
        self.banner = "Mock Service 1.0"

    def start(self):
        """Start the mock service."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        # Get the actual port if 0 was specified
        self.port = self.server_socket.getsockname()[1]

        self.running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()

        # Give the server a moment to start
        time.sleep(0.1)

    def stop(self):
        """Stop the mock service."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.thread:
            self.thread.join(timeout=1)

    def _run_server(self):
        """Run the server loop."""
        while self.running:
            try:
                self.server_socket.settimeout(0.5)
                client_socket, address = self.server_socket.accept()
                self.connections.append((client_socket, address))

                # Handle connection in a new thread
                handler_thread = threading.Thread(
                    target=self._handle_connection, args=(client_socket, address)
                )
                handler_thread.daemon = True
                handler_thread.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle a client connection. Override in subclasses."""
        try:
            # Send banner
            client_socket.send(f"{self.banner}\r\n".encode())
            client_socket.close()
        except Exception:
            pass


class MockSSHService(MockService):
    """Mock SSH service with vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.banner = (
            "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7.1"  # Old vulnerable version
        )
        self.weak_passwords = {"admin": "admin", "root": "toor", "user": "123456"}

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle SSH connection."""
        try:
            # Send SSH banner
            client_socket.send(f"{self.banner}\r\n".encode())

            # Simple SSH handshake simulation
            data = client_socket.recv(1024)
            if data:
                # Send server key exchange init
                client_socket.send(b"\x00\x00\x00\x0c\x0a\x14")  # Simplified

            client_socket.close()
        except Exception:
            pass


class MockHTTPService(MockService):
    """Mock HTTP service with common vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_header = (
            "Apache/2.2.14 (Ubuntu) PHP/5.3.2"  # Old vulnerable versions
        )
        self.vulnerabilities = {
            "directory_traversal": True,
            "sql_injection": True,
            "xss": True,
            "exposed_files": [".git/config", ".env", "backup.sql"],
        }

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle HTTP connection."""
        try:
            # Read request
            request = client_socket.recv(4096).decode("utf-8", errors="ignore")

            if not request:
                client_socket.close()
                return

            # Parse request line
            lines = request.split("\r\n")
            if lines:
                request_line = lines[0].split(" ")
                if len(request_line) >= 2:
                    method = request_line[0]
                    path = request_line[1]

                    response = self._generate_response(method, path)
                    client_socket.send(response.encode())

            client_socket.close()
        except Exception:
            pass

    def _generate_response(self, method: str, path: str) -> str:
        """Generate HTTP response based on request."""
        # Check for directory traversal
        if "../" in path:
            if "etc/passwd" in path:
                body = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
                return self._http_response(200, body, content_type="text/plain")

        # Check for exposed files
        for exposed_file in self.vulnerabilities["exposed_files"]:
            if exposed_file in path:
                if ".git/config" in path:
                    body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true"
                elif ".env" in path:
                    body = "DB_PASSWORD=secret123\nAPI_KEY=sk-1234567890abcdef"
                else:
                    body = "-- MySQL dump\n-- Database: vulnerable_app"
                return self._http_response(200, body, content_type="text/plain")

        # SQL injection vulnerable endpoint
        if "/search" in path and "q=" in path:
            if "'" in path or "OR" in path.upper():
                body = "<h1>Database Error</h1><p>MySQL Error: You have an error in your SQL syntax</p>"
                return self._http_response(500, body)

        # XSS vulnerable endpoint
        if "/comment" in path:
            body = f"<html><body><h1>Comments</h1><div>{path}</div></body></html>"
            return self._http_response(200, body)

        # Default response
        body = "<html><body><h1>Mock Vulnerable Web Server</h1></body></html>"
        return self._http_response(200, body)

    def _http_response(
        self, status: int, body: str, content_type: str = "text/html"
    ) -> str:
        """Generate HTTP response."""
        status_text = {200: "OK", 500: "Internal Server Error"}.get(status, "OK")
        response = f"HTTP/1.1 {status} {status_text}\r\n"
        response += f"Server: {self.server_header}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += body
        return response


class MockFTPService(MockService):
    """Mock FTP service with vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.banner = "220 ProFTPD 1.3.3a Server"  # Old vulnerable version
        self.anonymous_enabled = True
        self.weak_users = {"ftp": "ftp", "anonymous": ""}

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle FTP connection."""
        try:
            # Send banner
            client_socket.send(f"{self.banner}\r\n".encode())

            while True:
                data = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()
                if not data:
                    break

                command = data.split(" ")[0].upper()

                if command == "USER":
                    if self.anonymous_enabled and data.split(" ")[1].lower() in [
                        "anonymous",
                        "ftp",
                    ]:
                        client_socket.send(b"331 Please specify the password.\r\n")
                    else:
                        client_socket.send(b"331 Password required.\r\n")
                elif command == "PASS":
                    client_socket.send(b"230 Login successful.\r\n")
                elif command == "SYST":
                    client_socket.send(b"215 UNIX Type: L8\r\n")
                elif command == "QUIT":
                    client_socket.send(b"221 Goodbye.\r\n")
                    break
                else:
                    client_socket.send(b"500 Unknown command.\r\n")

            client_socket.close()
        except Exception:
            pass


class MockSMBService(MockService):
    """Mock SMB/NetBIOS service with vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shares = ["ADMIN$", "C$", "IPC$", "Public"]
        self.null_sessions_allowed = True

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle SMB connection."""
        try:
            # Simplified SMB response - just enough to be detected
            # Send NBT Session Request positive response
            client_socket.send(b"\x82\x00\x00\x00")

            # Wait for SMB negotiation
            data = client_socket.recv(1024)
            if data:
                # Send SMB response header indicating SMBv1 (vulnerable)
                response = b"\x00\x00\x00\x45"  # NetBIOS header
                response += b"\xff\x53\x4d\x42"  # SMB header
                response += b"\x72"  # SMB Command: Negotiate Protocol
                response += b"\x00\x00\x00\x00"  # NT Status: Success
                client_socket.send(response)

            client_socket.close()
        except Exception:
            pass


class MockMySQLService(MockService):
    """Mock MySQL service with vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = "5.5.62-0ubuntu0.14.04.1"  # Old vulnerable version
        self.weak_users = {"root": "", "mysql": "mysql"}

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle MySQL connection."""
        try:
            # Send MySQL handshake packet
            packet = self._create_handshake_packet()
            client_socket.send(packet)

            # Wait for auth response
            data = client_socket.recv(1024)
            if data:
                # Send auth OK for demonstration
                client_socket.send(b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00")

            client_socket.close()
        except Exception:
            pass

    def _create_handshake_packet(self) -> bytes:
        """Create MySQL handshake packet."""
        packet = b"\x4a\x00\x00\x00"  # Packet length and number
        packet += b"\x0a"  # Protocol version 10
        packet += self.version.encode() + b"\x00"  # Server version
        packet += b"\x01\x00\x00\x00"  # Thread ID
        packet += b"\x00" * 8  # Auth plugin data part 1
        packet += b"\x00"  # Filler
        packet += b"\x00\x00"  # Capability flags
        packet += b"\x21"  # Character set
        packet += b"\x00\x00"  # Status flags
        packet += b"\x00" * 13  # Reserved
        return packet


class MockRedisService(MockService):
    """Mock Redis service with vulnerabilities."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.no_auth_required = True
        self.version = "2.8.4"  # Old vulnerable version

    def _handle_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle Redis connection."""
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                # Parse Redis protocol
                command = self._parse_redis_command(data)

                if command:
                    response = self._handle_redis_command(command)
                    client_socket.send(response)

                    if command[0].upper() == "QUIT":
                        break

            client_socket.close()
        except Exception:
            pass

    def _parse_redis_command(self, data: bytes) -> Optional[List[str]]:
        """Parse Redis RESP protocol."""
        try:
            # Simplified parsing
            lines = data.decode("utf-8", errors="ignore").split("\r\n")
            command = []
            i = 0
            while i < len(lines):
                if lines[i].startswith("*"):
                    # Array
                    count = int(lines[i][1:])
                    i += 1
                elif lines[i].startswith("$"):
                    # Bulk string
                    i += 1
                    if i < len(lines):
                        command.append(lines[i])
                i += 1
            return command if command else None
        except:
            return None

    def _handle_redis_command(self, command: List[str]) -> bytes:
        """Handle Redis command."""
        cmd = command[0].upper()

        if cmd == "PING":
            return b"+PONG\r\n"
        elif cmd == "INFO":
            info = f"redis_version:{self.version}\r\nredis_mode:standalone\r\n"
            return f"${len(info)}\r\n{info}\r\n".encode()
        elif cmd == "CONFIG" and len(command) > 2 and command[1].upper() == "GET":
            if command[2] == "dir":
                return b"*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n"
            elif command[2] == "dbfilename":
                return b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n"
        elif cmd == "QUIT":
            return b"+OK\r\n"

        return b"-ERR unknown command\r\n"


class VulnerableServiceManager:
    """Manager for running multiple vulnerable services."""

    def __init__(self):
        self.services: Dict[str, MockService] = {}

    def add_service(self, name: str, service: MockService):
        """Add a service to manage."""
        self.services[name] = service

    def start_all(self):
        """Start all services."""
        for name, service in self.services.items():
            service.start()

    def stop_all(self):
        """Stop all services."""
        for name, service in self.services.items():
            service.stop()

    def get_service_info(self) -> Dict[str, Dict[str, any]]:
        """Get information about running services."""
        info = {}
        for name, service in self.services.items():
            info[name] = {
                "host": service.host,
                "port": service.port,
                "running": service.running,
                "connections": len(service.connections),
            }
        return info


@pytest.fixture
def mock_ssh_service():
    """Fixture for mock SSH service."""
    service = MockSSHService()
    service.start()
    yield service
    service.stop()


@pytest.fixture
def mock_http_service():
    """Fixture for mock HTTP service."""
    service = MockHTTPService()
    service.start()
    yield service
    service.stop()


@pytest.fixture
def mock_ftp_service():
    """Fixture for mock FTP service."""
    service = MockFTPService()
    service.start()
    yield service
    service.stop()


@pytest.fixture
def mock_mysql_service():
    """Fixture for mock MySQL service."""
    service = MockMySQLService()
    service.start()
    yield service
    service.stop()


@pytest.fixture
def mock_redis_service():
    """Fixture for mock Redis service."""
    service = MockRedisService()
    service.start()
    yield service
    service.stop()


@pytest.fixture
def vulnerable_network():
    """
    Fixture that creates a complete vulnerable network environment.

    Returns a VulnerableServiceManager with multiple services running.
    """
    manager = VulnerableServiceManager()

    # Add various vulnerable services
    manager.add_service("ssh", MockSSHService(port=2222))
    manager.add_service("http", MockHTTPService(port=8080))
    manager.add_service("ftp", MockFTPService(port=2121))
    manager.add_service("mysql", MockMySQLService(port=3306))
    manager.add_service("redis", MockRedisService(port=6379))
    manager.add_service("smb", MockSMBService(port=445))

    # Start all services
    manager.start_all()

    # Wait for services to be ready
    time.sleep(0.5)

    yield manager

    # Cleanup
    manager.stop_all()


@contextmanager
def mock_vulnerable_host(services: List[str] = None):
    """
    Context manager to create a vulnerable host with specified services.

    Args:
        services: List of service names to run. If None, runs all services.

    Usage:
        with mock_vulnerable_host(['ssh', 'http']) as host_info:
            # host_info contains service details
            ssh_port = host_info['ssh']['port']
    """
    available_services = {
        "ssh": MockSSHService,
        "http": MockHTTPService,
        "ftp": MockFTPService,
        "mysql": MockMySQLService,
        "redis": MockRedisService,
        "smb": MockSMBService,
    }

    if services is None:
        services = list(available_services.keys())

    manager = VulnerableServiceManager()

    for service_name in services:
        if service_name in available_services:
            service_class = available_services[service_name]
            manager.add_service(service_name, service_class())

    manager.start_all()
    time.sleep(0.5)

    try:
        yield manager.get_service_info()
    finally:
        manager.stop_all()
