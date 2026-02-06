"""Core IP geolocation logic."""

from dataclasses import dataclass
from typing import List, Optional

import httpx

from shared.logger import get_logger

logger = get_logger(__name__)


@dataclass
class IPGeolocation:
    """Geolocation information for an IP address."""

    ip: str
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    continent: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    error: Optional[str] = None


class IPGeolocator:
    """
    Lookup IP address geolocation and information.

    Uses free ipapi.co API (no registration required).
    Rate limit: 1000 requests/day.
    """

    def __init__(self, timeout: float = 10.0):
        """
        Initialize IP geolocator.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = "https://ipapi.co"
        logger.debug("Initialized IPGeolocator")

    def lookup(self, ip: str) -> IPGeolocation:
        """
        Lookup geolocation for an IP address.

        Args:
            ip: IP address to lookup

        Returns:
            IPGeolocation object
        """
        logger.info(f"Looking up IP: {ip}")

        try:
            url = f"{self.base_url}/{ip}/json/"

            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url)

                if response.status_code == 429:
                    return self._create_error_geo(ip, "Rate limit exceeded. Try again later.")

                if response.status_code != 200:
                    return self._create_error_geo(ip, f"API error: {response.status_code}")

                data = response.json()

                # Check for error in response
                if data.get("error"):
                    return self._create_error_geo(ip, data.get("reason", "Unknown error"))

                return IPGeolocation(
                    ip=ip,
                    city=data.get("city"),
                    region=data.get("region"),
                    country=data.get("country_name"),
                    country_code=data.get("country_code"),
                    continent=data.get("continent_code"),
                    latitude=data.get("latitude"),
                    longitude=data.get("longitude"),
                    timezone=data.get("timezone"),
                    isp=data.get("org"),
                    org=data.get("org"),
                    asn=data.get("asn"),
                )

        except httpx.RequestError as e:
            logger.error(f"Network error: {e}")
            return self._create_error_geo(ip, f"Network error: {e}")

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return self._create_error_geo(ip, f"Error: {e}")

    def lookup_multiple(self, ips: List[str]) -> List[IPGeolocation]:
        """
        Lookup multiple IP addresses.

        Args:
            ips: List of IP addresses

        Returns:
            List of IPGeolocation objects
        """
        results = []
        for ip in ips:
            result = self.lookup(ip)
            results.append(result)
        return results

    def lookup_from_file(self, filepath: str) -> List[IPGeolocation]:
        """
        Lookup IPs from file (one per line).

        Args:
            filepath: Path to file with IPs

        Returns:
            List of IPGeolocation objects
        """
        with open(filepath, "r") as f:
            ips = [line.strip() for line in f if line.strip()]

        return self.lookup_multiple(ips)

    def get_my_ip(self) -> IPGeolocation:
        """
        Get geolocation for current public IP.

        Returns:
            IPGeolocation object
        """
        logger.info("Looking up own IP address")

        try:
            url = f"{self.base_url}/json/"

            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url)

                if response.status_code != 200:
                    return self._create_error_geo("unknown", f"API error: {response.status_code}")

                data = response.json()

                ip = data.get("ip", "unknown")

                return IPGeolocation(
                    ip=ip,
                    city=data.get("city"),
                    region=data.get("region"),
                    country=data.get("country_name"),
                    country_code=data.get("country_code"),
                    continent=data.get("continent_code"),
                    latitude=data.get("latitude"),
                    longitude=data.get("longitude"),
                    timezone=data.get("timezone"),
                    isp=data.get("org"),
                    org=data.get("org"),
                    asn=data.get("asn"),
                )

        except Exception as e:
            logger.error(f"Failed to get own IP: {e}")
            return self._create_error_geo("unknown", f"Error: {e}")

    def _create_error_geo(self, ip: str, error: str) -> IPGeolocation:
        """Create IPGeolocation for error cases."""
        return IPGeolocation(ip=ip, error=error)
