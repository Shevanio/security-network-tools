"""Core DNS enumeration logic."""

import socket
from dataclasses import dataclass
from typing import Dict, List, Optional

from shared.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DNSRecord:
    """DNS record information."""

    domain: str
    record_type: str
    value: str
    ttl: Optional[int] = None


class DNSEnumerator:
    """DNS enumeration and reconnaissance tool."""

    def __init__(self):
        """Initialize DNS enumerator."""
        logger.debug("Initialized DNSEnumerator")

    def query(self, domain: str, record_type: str = "A") -> List[DNSRecord]:
        """
        Query DNS records.

        Args:
            domain: Domain name
            record_type: Record type (A, AAAA, MX, TXT, etc.)

        Returns:
            List of DNSRecord objects
        """
        logger.info(f"Querying {record_type} records for {domain}")

        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, record_type)

            records = []
            for rdata in answers:
                records.append(
                    DNSRecord(
                        domain=domain,
                        record_type=record_type,
                        value=str(rdata),
                        ttl=answers.rrset.ttl if hasattr(answers, "rrset") else None,
                    )
                )

            return records

        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def enumerate_subdomains(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Enumerate subdomains.

        Args:
            domain: Base domain
            wordlist: List of subdomain prefixes to try

        Returns:
            List of found subdomains
        """
        if wordlist is None:
            wordlist = ["www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "webdisk",
                       "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
                       "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
                       "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists"]

        found = []

        for prefix in wordlist:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
                logger.info(f"Found: {subdomain}")
            except socket.gaierror:
                pass

        return found

    def get_all_records(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """
        Get all common DNS record types.

        Args:
            domain: Domain name

        Returns:
            Dict of record_type -> List[DNSRecord]
        """
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
        all_records = {}

        for rtype in record_types:
            records = self.query(domain, rtype)
            if records:
                all_records[rtype] = records

        return all_records
