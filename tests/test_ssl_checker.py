"""Tests for SSL Certificate Checker."""

import socket
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tools.ssl_checker.checker import CertificateInfo, SSLChecker


def create_test_certificate(
    hostname: str = "example.com",
    days_valid: int = 365,
    issuer_cn: str = "Test CA",
    self_signed: bool = False,
) -> x509.Certificate:
    """
    Create a test X509 certificate.

    Args:
        hostname: Common name for the certificate
        days_valid: Number of days the certificate is valid
        issuer_cn: Issuer common name
        self_signed: Whether to create a self-signed certificate

    Returns:
        X509 Certificate object
    """
    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create subject
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )

    # Create issuer
    if self_signed:
        issuer = subject
    else:
        issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org"),
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            ]
        )

    # Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName(f"www.{hostname}")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert


class TestCertificateInfo:
    """Test CertificateInfo dataclass."""

    def test_certificate_info_creation(self):
        """Test creating a CertificateInfo."""
        now = datetime.utcnow()
        info = CertificateInfo(
            hostname="example.com",
            port=443,
            issued_to="example.com",
            issued_by="Test CA",
            valid_from=now,
            valid_until=now + timedelta(days=365),
            days_remaining=365,
            is_expired=False,
            is_expiring_soon=False,
            serial_number="ABC123",
            signature_algorithm="sha256WithRSAEncryption",
            version=3,
            subject_alt_names=["example.com", "www.example.com"],
            is_self_signed=False,
            is_valid_chain=True,
        )

        assert info.hostname == "example.com"
        assert info.port == 443
        assert info.days_remaining == 365
        assert info.is_expired is False
        assert info.error is None

    def test_certificate_info_with_error(self):
        """Test CertificateInfo with error."""
        now = datetime.utcnow()
        info = CertificateInfo(
            hostname="invalid.com",
            port=443,
            issued_to="N/A",
            issued_by="N/A",
            valid_from=now,
            valid_until=now,
            days_remaining=0,
            is_expired=True,
            is_expiring_soon=False,
            serial_number="N/A",
            signature_algorithm="N/A",
            version=0,
            subject_alt_names=[],
            is_self_signed=False,
            is_valid_chain=False,
            error="Connection failed",
        )

        assert info.error == "Connection failed"
        assert info.is_expired is True


class TestSSLChecker:
    """Test SSLChecker functionality."""

    def test_init_default(self):
        """Test initialization with defaults."""
        checker = SSLChecker()
        assert checker.timeout == 5.0
        assert checker.warning_days == 30

    def test_init_custom_params(self):
        """Test initialization with custom parameters."""
        checker = SSLChecker(timeout=10.0, warning_days=60)
        assert checker.timeout == 10.0
        assert checker.warning_days == 60

    def test_check_certificate_timeout(self):
        """Test certificate check with timeout."""
        checker = SSLChecker(timeout=1.0)

        with patch("socket.create_connection", side_effect=socket.timeout):
            result = checker.check_certificate("example.com")

        assert result.error == "Connection timeout"
        assert result.is_expired is True

    def test_check_certificate_dns_error(self):
        """Test certificate check with DNS error."""
        checker = SSLChecker()

        with patch("socket.create_connection", side_effect=socket.gaierror("DNS error")):
            result = checker.check_certificate("invalid.host")

        assert "DNS resolution failed" in result.error
        assert result.issued_to == "N/A"

    def test_check_certificate_ssl_verification_error(self):
        """Test certificate check with SSL verification error."""
        checker = SSLChecker()

        mock_socket = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("Cert invalid")

        with patch("socket.create_connection", return_value=mock_socket):
            with patch("ssl.create_default_context", return_value=mock_context):
                result = checker.check_certificate("untrusted.com")

        assert "Verification failed" in result.error

    def test_parse_certificate_valid(self):
        """Test parsing a valid certificate."""
        checker = SSLChecker(warning_days=30)
        cert = create_test_certificate(hostname="example.com", days_valid=365)

        result = checker._parse_certificate(cert, "example.com", 443, is_valid_chain=True)

        assert result.hostname == "example.com"
        assert result.port == 443
        assert result.issued_to == "example.com"
        assert result.days_remaining > 360
        assert result.is_expired is False
        assert result.is_expiring_soon is False
        assert result.is_valid_chain is True
        assert "example.com" in result.subject_alt_names
        assert "www.example.com" in result.subject_alt_names

    def test_parse_certificate_expiring_soon(self):
        """Test parsing a certificate expiring soon."""
        checker = SSLChecker(warning_days=30)
        cert = create_test_certificate(hostname="example.com", days_valid=15)

        result = checker._parse_certificate(cert, "example.com", 443, is_valid_chain=True)

        assert result.is_expired is False
        assert result.is_expiring_soon is True
        assert result.days_remaining < 30

    def test_parse_certificate_expired(self):
        """Test parsing an expired certificate."""
        checker = SSLChecker()
        cert = create_test_certificate(hostname="example.com", days_valid=-10)

        result = checker._parse_certificate(cert, "example.com", 443, is_valid_chain=True)

        assert result.is_expired is True
        assert result.days_remaining < 0

    def test_parse_certificate_self_signed(self):
        """Test parsing a self-signed certificate."""
        checker = SSLChecker()
        cert = create_test_certificate(hostname="example.com", self_signed=True)

        result = checker._parse_certificate(cert, "example.com", 443, is_valid_chain=False)

        assert result.is_self_signed is True
        assert result.is_valid_chain is False

    def test_get_common_name_success(self):
        """Test extracting common name from certificate."""
        checker = SSLChecker()
        cert = create_test_certificate(hostname="test.example.com")

        cn = checker._get_common_name(cert.subject)
        assert cn == "test.example.com"

    def test_get_common_name_none(self):
        """Test getting common name when not present."""
        checker = SSLChecker()

        # Create name without CN
        name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])

        cn = checker._get_common_name(name)
        assert cn is None

    def test_create_error_info(self):
        """Test creating error info."""
        checker = SSLChecker()

        result = checker._create_error_info("example.com", 443, "Test error")

        assert result.hostname == "example.com"
        assert result.port == 443
        assert result.error == "Test error"
        assert result.is_expired is True
        assert result.issued_to == "N/A"

    def test_check_multiple(self):
        """Test checking multiple hostnames."""
        checker = SSLChecker()

        # Mock the check_certificate method
        mock_results = [
            CertificateInfo(
                hostname="example.com",
                port=443,
                issued_to="example.com",
                issued_by="CA",
                valid_from=datetime.utcnow(),
                valid_until=datetime.utcnow() + timedelta(days=365),
                days_remaining=365,
                is_expired=False,
                is_expiring_soon=False,
                serial_number="123",
                signature_algorithm="sha256",
                version=3,
                subject_alt_names=[],
                is_self_signed=False,
                is_valid_chain=True,
            ),
            CertificateInfo(
                hostname="google.com",
                port=443,
                issued_to="google.com",
                issued_by="CA",
                valid_from=datetime.utcnow(),
                valid_until=datetime.utcnow() + timedelta(days=180),
                days_remaining=180,
                is_expired=False,
                is_expiring_soon=False,
                serial_number="456",
                signature_algorithm="sha256",
                version=3,
                subject_alt_names=[],
                is_self_signed=False,
                is_valid_chain=True,
            ),
        ]

        with patch.object(checker, "check_certificate", side_effect=mock_results):
            results = checker.check_multiple(["example.com", "google.com"])

        assert len(results) == 2
        assert results[0].hostname == "example.com"
        assert results[1].hostname == "google.com"

    def test_check_from_file(self, tmp_path):
        """Test checking certificates from file."""
        checker = SSLChecker()

        # Create test file
        test_file = tmp_path / "hosts.txt"
        test_file.write_text("example.com\ngoogle.com\n\n# comment\ngithub.com\n")

        mock_result = CertificateInfo(
            hostname="test",
            port=443,
            issued_to="test",
            issued_by="CA",
            valid_from=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(days=365),
            days_remaining=365,
            is_expired=False,
            is_expiring_soon=False,
            serial_number="123",
            signature_algorithm="sha256",
            version=3,
            subject_alt_names=[],
            is_self_signed=False,
            is_valid_chain=True,
        )

        with patch.object(checker, "check_certificate", return_value=mock_result):
            results = checker.check_from_file(str(test_file))

        # Should check 3 valid hostnames (excluding empty line and comment)
        assert len(results) == 3

    def test_serial_number_formatting(self):
        """Test that serial number is formatted as hex."""
        checker = SSLChecker()
        cert = create_test_certificate()

        result = checker._parse_certificate(cert, "example.com", 443, True)

        # Serial number should be uppercase hex
        assert result.serial_number.isupper()
        assert all(c in "0123456789ABCDEF" for c in result.serial_number)

    def test_certificate_dates_utc(self):
        """Test that certificate dates are in UTC."""
        checker = SSLChecker()
        cert = create_test_certificate()

        result = checker._parse_certificate(cert, "example.com", 443, True)

        # Dates should not have timezone info (UTC naive)
        assert result.valid_from.tzinfo is None
        assert result.valid_until.tzinfo is None
