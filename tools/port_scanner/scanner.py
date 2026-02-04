"""Core port scanning logic."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

from shared.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of a port scan."""

    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None


# Common port-to-service mapping
COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


class PortScanner:
    """
    TCP port scanner with service detection.

    Attributes:
        host: Target hostname or IP address
        timeout: Connection timeout in seconds
        max_workers: Maximum number of parallel threads
    """

    def __init__(self, host: str, timeout: float = 1.0, max_workers: int = 100):
        """
        Initialize port scanner.

        Args:
            host: Target hostname or IP address
            timeout: Connection timeout in seconds
            max_workers: Maximum number of parallel scanning threads
        """
        self.host = host
        self.timeout = timeout
        self.max_workers = max_workers
        self._resolve_host()

    def _resolve_host(self) -> None:
        """Resolve hostname to IP address."""
        try:
            self.ip = socket.gethostbyname(self.host)
            logger.debug(f"Resolved {self.host} to {self.ip}")
        except socket.gaierror as e:
            logger.error(f"Failed to resolve host {self.host}: {e}")
            raise ValueError(f"Cannot resolve host: {self.host}")

    def scan_port(self, port: int) -> ScanResult:
        """
        Scan a single TCP port.

        Args:
            port: Port number to scan

        Returns:
            ScanResult with port status
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((self.ip, port))

            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = self._grab_banner(sock)
                return ScanResult(port=port, state="open", service=service, banner=banner)
            else:
                return ScanResult(port=port, state="closed")

        except socket.timeout:
            return ScanResult(port=port, state="filtered")
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return ScanResult(port=port, state="error")
        finally:
            sock.close()

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """
        Attempt to grab service banner.

        Args:
            sock: Connected socket

        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else None
        except:
            return None

    def scan_ports(self, ports: List[int]) -> List[ScanResult]:
        """
        Scan multiple ports in parallel.

        Args:
            ports: List of port numbers to scan

        Returns:
            List of ScanResult objects
        """
        logger.info(f"Scanning {len(ports)} ports on {self.host} ({self.ip})")

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)

                    if result.state == "open":
                        logger.debug(f"Port {port} is OPEN ({result.service})")

                except Exception as e:
                    logger.error(f"Exception scanning port {port}: {e}")
                    results.append(ScanResult(port=port, state="error"))

        results.sort(key=lambda x: x.port)
        return results

    def scan_range(self, start_port: int, end_port: int) -> List[ScanResult]:
        """
        Scan a range of ports.

        Args:
            start_port: First port in range
            end_port: Last port in range (inclusive)

        Returns:
            List of ScanResult objects
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(ports)

    def scan_top_ports(self, count: int = 100) -> List[ScanResult]:
        """
        Scan most common ports.

        Args:
            count: Number of top ports to scan

        Returns:
            List of ScanResult objects
        """
        top_ports = sorted(COMMON_PORTS.keys())[:count]
        return self.scan_ports(top_ports)
