"""Core SSL certificate checking logic."""

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from shared.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CertificateInfo:
    """Information about an SSL certificate."""

    hostname: str
    port: int
    issued_to: str
    issued_by: str
    valid_from: datetime
    valid_until: datetime
    days_remaining: int
    is_expired: bool
    is_expiring_soon: bool
    serial_number: str
    signature_algorithm: str
    version: int
    subject_alt_names: List[str]
    is_self_signed: bool
    is_valid_chain: bool
    error: Optional[str] = None


class SSLChecker:
    """
    SSL/TLS certificate checker and validator.

    Attributes:
        timeout: Connection timeout in seconds
        warning_days: Days before expiration to trigger warning
    """

    def __init__(self, timeout: float = 5.0, warning_days: int = 30):
        """
        Initialize SSL checker.

        Args:
            timeout: Connection timeout in seconds
            warning_days: Days before expiration to show warning
        """
        self.timeout = timeout
        self.warning_days = warning_days

    def check_certificate(self, hostname: str, port: int = 443) -> CertificateInfo:
        """
        Check SSL certificate for a hostname.

        Args:
            hostname: Domain name to check
            port: Port number (default 443)

        Returns:
            CertificateInfo with certificate details
        """
        logger.info(f"Checking certificate for {hostname}:{port}")

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Get certificate chain validation status
                    is_valid_chain = True  # If we got here, chain is valid

            return self._parse_certificate(cert, hostname, port, is_valid_chain)

        except ssl.SSLCertVerificationError as e:
            logger.warning(f"Certificate verification failed for {hostname}: {e}")
            return self._create_error_info(hostname, port, f"Verification failed: {e}")

        except socket.timeout:
            logger.error(f"Connection timeout for {hostname}:{port}")
            return self._create_error_info(hostname, port, "Connection timeout")

        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {hostname}: {e}")
            return self._create_error_info(hostname, port, f"DNS resolution failed: {e}")

        except Exception as e:
            logger.error(f"Unexpected error checking {hostname}: {e}")
            return self._create_error_info(hostname, port, f"Error: {e}")

    def _parse_certificate(
        self, cert: x509.Certificate, hostname: str, port: int, is_valid_chain: bool
    ) -> CertificateInfo:
        """
        Parse certificate and extract information.

        Args:
            cert: X509 certificate object
            hostname: Hostname being checked
            port: Port number
            is_valid_chain: Whether certificate chain is valid

        Returns:
            CertificateInfo object
        """
        # Get subject (issued to)
        subject = cert.subject
        issued_to = self._get_common_name(subject) or hostname

        # Get issuer (issued by)
        issuer = cert.issuer
        issued_by = self._get_common_name(issuer) or "Unknown"

        # Get validity dates
        valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
        valid_until = cert.not_valid_after_utc.replace(tzinfo=None)

        # Calculate days remaining
        now = datetime.utcnow()
        days_remaining = (valid_until - now).days
        is_expired = days_remaining < 0
        is_expiring_soon = 0 <= days_remaining <= self.warning_days

        # Get serial number
        serial_number = format(cert.serial_number, 'x').upper()

        # Get signature algorithm
        signature_algorithm = cert.signature_algorithm_oid._name

        # Get version
        version = cert.version.value

        # Get Subject Alternative Names (SANs)
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = [
                san.value for san in san_ext.value if isinstance(san, x509.DNSName)
            ]
        except x509.ExtensionNotFound:
            pass

        # Check if self-signed
        is_self_signed = issued_to == issued_by

        return CertificateInfo(
            hostname=hostname,
            port=port,
            issued_to=issued_to,
            issued_by=issued_by,
            valid_from=valid_from,
            valid_until=valid_until,
            days_remaining=days_remaining,
            is_expired=is_expired,
            is_expiring_soon=is_expiring_soon,
            serial_number=serial_number,
            signature_algorithm=signature_algorithm,
            version=version,
            subject_alt_names=san_list,
            is_self_signed=is_self_signed,
            is_valid_chain=is_valid_chain,
        )

    def _get_common_name(self, name: x509.Name) -> Optional[str]:
        """
        Extract Common Name from X509 Name.

        Args:
            name: X509 Name object

        Returns:
            Common name or None
        """
        try:
            cn_list = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_list:
                return cn_list[0].value
        except:
            pass
        return None

    def _create_error_info(self, hostname: str, port: int, error: str) -> CertificateInfo:
        """
        Create CertificateInfo for error cases.

        Args:
            hostname: Hostname
            port: Port
            error: Error message

        Returns:
            CertificateInfo with error
        """
        now = datetime.utcnow()
        return CertificateInfo(
            hostname=hostname,
            port=port,
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
            error=error,
        )

    def check_multiple(self, hostnames: List[str], port: int = 443) -> List[CertificateInfo]:
        """
        Check certificates for multiple hostnames.

        Args:
            hostnames: List of hostnames to check
            port: Port number (default 443)

        Returns:
            List of CertificateInfo objects
        """
        results = []
        for hostname in hostnames:
            result = self.check_certificate(hostname, port)
            results.append(result)
        return results

    def check_from_file(self, filepath: str, port: int = 443) -> List[CertificateInfo]:
        """
        Check certificates for hostnames listed in a file.

        Args:
            filepath: Path to file with hostnames (one per line)
            port: Port number (default 443)

        Returns:
            List of CertificateInfo objects
        """
        with open(filepath, "r") as f:
            hostnames = [line.strip() for line in f if line.strip()]

        return self.check_multiple(hostnames, port)
