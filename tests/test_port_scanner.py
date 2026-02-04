"""Tests for Port Scanner."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from tools.port_scanner.cli import parse_ports
from tools.port_scanner.scanner import COMMON_PORTS, PortScanner, ScanResult


class TestPortParser:
    """Test port parsing functionality."""

    def test_parse_single_port(self):
        """Test parsing a single port."""
        result = parse_ports("80")
        assert result == [80]

    def test_parse_multiple_ports(self):
        """Test parsing multiple comma-separated ports."""
        result = parse_ports("80,443,8080")
        assert result == [80, 443, 8080]

    def test_parse_port_range(self):
        """Test parsing a port range."""
        result = parse_ports("20-25")
        assert result == [20, 21, 22, 23, 24, 25]

    def test_parse_mixed_format(self):
        """Test parsing mixed format (single, multiple, range)."""
        result = parse_ports("22,80,443,8000-8003")
        assert result == [22, 80, 443, 8000, 8001, 8002, 8003]

    def test_parse_removes_duplicates(self):
        """Test that duplicate ports are removed."""
        result = parse_ports("80,80,443,443")
        assert result == [80, 443]

    def test_parse_sorts_ports(self):
        """Test that ports are sorted."""
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_invalid_port_too_low(self):
        """Test that port < 1 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid port number"):
            parse_ports("0")

    def test_invalid_port_too_high(self):
        """Test that port > 65535 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid port number"):
            parse_ports("65536")

    def test_invalid_port_range(self):
        """Test that invalid range raises ValueError."""
        with pytest.raises(ValueError, match="Invalid port range"):
            parse_ports("100-50")

    def test_invalid_format(self):
        """Test that non-numeric input raises ValueError."""
        with pytest.raises(ValueError, match="Invalid port number"):
            parse_ports("abc")


class TestPortScanner:
    """Test PortScanner functionality."""

    def test_init_with_valid_host(self):
        """Test initialization with valid hostname."""
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            scanner = PortScanner("example.com")
            assert scanner.host == "example.com"
            assert scanner.ip == "93.184.216.34"
            assert scanner.timeout == 1.0
            assert scanner.max_workers == 100

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost", timeout=2.5)
            assert scanner.timeout == 2.5

    def test_init_with_custom_workers(self):
        """Test initialization with custom max_workers."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost", max_workers=50)
            assert scanner.max_workers == 50

    def test_init_with_invalid_host(self):
        """Test that invalid hostname raises ValueError."""
        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            with pytest.raises(ValueError, match="Cannot resolve host"):
                PortScanner("invalid.host.that.does.not.exist")

    def test_scan_port_open(self):
        """Test scanning an open port."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0  # Port is open

        with patch("socket.socket", return_value=mock_socket):
            result = scanner.scan_port(80)

        assert result.port == 80
        assert result.state == "open"
        assert result.service == "http"

    def test_scan_port_closed(self):
        """Test scanning a closed port."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1  # Port is closed

        with patch("socket.socket", return_value=mock_socket):
            result = scanner.scan_port(12345)

        assert result.port == 12345
        assert result.state == "closed"

    def test_scan_port_timeout(self):
        """Test scanning a filtered port (timeout)."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = socket.timeout

        with patch("socket.socket", return_value=mock_socket):
            result = scanner.scan_port(8080)

        assert result.port == 8080
        assert result.state == "filtered"

    def test_common_ports_mapping(self):
        """Test that common ports are correctly mapped to services."""
        assert COMMON_PORTS[22] == "ssh"
        assert COMMON_PORTS[80] == "http"
        assert COMMON_PORTS[443] == "https"
        assert COMMON_PORTS[3306] == "mysql"
        assert COMMON_PORTS[5432] == "postgresql"

    def test_scan_ports_returns_sorted_results(self):
        """Test that scan_ports returns results sorted by port number."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        # Mock all ports as closed for simplicity
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        with patch("socket.socket", return_value=mock_socket):
            results = scanner.scan_ports([443, 22, 80])

        assert len(results) == 3
        assert results[0].port == 22
        assert results[1].port == 80
        assert results[2].port == 443

    def test_scan_range(self):
        """Test scanning a port range."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        with patch("socket.socket", return_value=mock_socket):
            results = scanner.scan_range(20, 25)

        assert len(results) == 6
        assert results[0].port == 20
        assert results[-1].port == 25

    def test_scan_top_ports(self):
        """Test scanning top common ports."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            scanner = PortScanner("localhost")

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        with patch("socket.socket", return_value=mock_socket):
            results = scanner.scan_top_ports(count=10)

        assert len(results) == 10
        # Should include common ports like 20, 21, 22, etc.
        port_numbers = [r.port for r in results]
        assert 22 in port_numbers  # SSH
        assert 80 in port_numbers  # HTTP


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        result = ScanResult(port=80, state="open", service="http")
        assert result.port == 80
        assert result.state == "open"
        assert result.service == "http"
        assert result.banner is None

    def test_scan_result_with_banner(self):
        """Test ScanResult with banner."""
        result = ScanResult(port=80, state="open", service="http", banner="Apache/2.4")
        assert result.banner == "Apache/2.4"

    def test_scan_result_defaults(self):
        """Test ScanResult default values."""
        result = ScanResult(port=80, state="open")
        assert result.service is None
        assert result.banner is None
