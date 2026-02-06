"""CLI interface for IP Geolocation Tool."""

import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shared.cli import create_table, error, handle_errors, info, print_table, success
from shared.logger import setup_logger

from .locator import IPGeolocation, IPGeolocator

console = Console()


def display_geolocation(geo: IPGeolocation, detailed: bool = False) -> None:
    """Display geolocation information."""
    if geo.error:
        error(f"Failed to lookup {geo.ip}")
        error(f"Error: {geo.error}")
        return

    if detailed:
        # Detailed view with panel
        title = f"[bold cyan]{geo.ip}[/bold cyan]"
        console.print(Panel(title, title="IP Geolocation"))

        console.print("\n[bold yellow]📍 Location:[/bold yellow]")
        console.print(f"  City:       {geo.city or 'N/A'}")
        console.print(f"  Region:     {geo.region or 'N/A'}")
        console.print(f"  Country:    {geo.country or 'N/A'} ({geo.country_code or 'N/A'})")
        console.print(f"  Continent:  {geo.continent or 'N/A'}")
        console.print(f"  Timezone:   {geo.timezone or 'N/A'}")

        if geo.latitude and geo.longitude:
            console.print(f"\n[bold yellow]🗺️  Coordinates:[/bold yellow]")
            console.print(f"  Latitude:   {geo.latitude}")
            console.print(f"  Longitude:  {geo.longitude}")
            console.print(f"  Map:        https://www.google.com/maps?q={geo.latitude},{geo.longitude}")

        console.print(f"\n[bold yellow]🌐 Network:[/bold yellow]")
        console.print(f"  ISP:        {geo.isp or 'N/A'}")
        console.print(f"  ASN:        {geo.asn or 'N/A'}")

        console.print()

    else:
        # Compact view
        location = f"{geo.city or '?'}, {geo.region or '?'}, {geo.country or '?'}"
        console.print(f"{geo.ip}: {location} ({geo.isp or 'Unknown ISP'})")


def display_table(geolocations: List[IPGeolocation]) -> None:
    """Display multiple geolocations in table."""
    if not geolocations:
        info("No results")
        return

    table = create_table(title="IP Geolocation Results")
    table.add_column("IP Address", style="cyan")
    table.add_column("City", style="yellow")
    table.add_column("Country", style="green")
    table.add_column("ISP", style="dim")
    table.add_column("Coordinates", style="magenta")

    for geo in geolocations:
        if geo.error:
            table.add_row(
                geo.ip,
                "[red]ERROR[/red]",
                geo.error[:30],
                "-",
                "-",
            )
        else:
            coords = f"{geo.latitude:.2f}, {geo.longitude:.2f}" if geo.latitude and geo.longitude else "-"
            table.add_row(
                geo.ip,
                geo.city or "-",
                f"{geo.country or '-'} ({geo.country_code or '-'})",
                (geo.isp or "-")[:30],
                coords,
            )

    print_table(table)


@click.command()
@click.option("--ip", "-i", multiple=True, help="IP address to lookup")
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True, path_type=Path),
    help="File with IPs (one per line)",
)
@click.option(
    "--my-ip",
    is_flag=True,
    help="Lookup own public IP",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "detailed", "json"], case_sensitive=False),
    default="table",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@handle_errors
def main(
    ip: tuple,
    file: Optional[Path],
    my_ip: bool,
    output: str,
    verbose: bool,
):
    """
    IP Geolocation Tool - Lookup IP address information.

    Get geolocation, ISP, and ASN information for IP addresses.

    Examples:

        \b
        # Lookup single IP
        ip-geo --ip 8.8.8.8

        \b
        # Lookup multiple IPs
        ip-geo --ip 8.8.8.8 --ip 1.1.1.1

        \b
        # Lookup from file
        ip-geo --file ips.txt

        \b
        # Get own public IP info
        ip-geo --my-ip

        \b
        # Detailed output
        ip-geo --ip 8.8.8.8 --output detailed

        \b
        # JSON output
        ip-geo --ip 8.8.8.8 --output json
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logger(__name__, level=log_level)

    # Initialize locator
    locator = IPGeolocator()

    # Determine what to lookup
    results = []

    if my_ip:
        info("Looking up own public IP")
        result = locator.get_my_ip()
        results.append(result)

    elif file:
        info(f"Loading IPs from {file}")
        results = locator.lookup_from_file(str(file))

    elif ip:
        ips_list = list(ip)
        info(f"Looking up {len(ips_list)} IP(s)")
        results = locator.lookup_multiple(ips_list)

    else:
        error("Please specify --ip, --file, or --my-ip")
        sys.exit(1)

    # Check for errors
    errors = [r for r in results if r.error]
    if errors:
        for r in errors:
            error(f"{r.ip}: {r.error}")

    valid_results = [r for r in results if not r.error]

    if not valid_results:
        error("No valid results")
        sys.exit(1)

    # Output
    if output == "json":
        data = [
            {
                "ip": r.ip,
                "city": r.city,
                "region": r.region,
                "country": r.country,
                "country_code": r.country_code,
                "continent": r.continent,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "timezone": r.timezone,
                "isp": r.isp,
                "asn": r.asn,
            }
            for r in valid_results
        ]
        print(json.dumps({"results": data, "count": len(data)}, indent=2))

    elif output == "detailed":
        for result in valid_results:
            display_geolocation(result, detailed=True)

    else:  # table
        display_table(valid_results)

    success(f"Lookup completed! {len(valid_results)} result(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
