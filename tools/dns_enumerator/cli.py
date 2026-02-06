"""CLI interface for DNS Enumerator."""

import json
import sys
from typing import Optional

import click

from shared.cli import create_table, error, handle_errors, info, print_table, success
from shared.logger import setup_logger

from .enumerator import DNSEnumerator


@click.command()
@click.argument("domain")
@click.option(
    "--record-type",
    "-r",
    default="A",
    help="DNS record type (A, AAAA, MX, TXT, NS, etc.)",
)
@click.option(
    "--all",
    "-a",
    is_flag=True,
    help="Query all common record types",
)
@click.option(
    "--subdomains",
    "-s",
    is_flag=True,
    help="Enumerate subdomains",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@handle_errors
def main(
    domain: str,
    record_type: str,
    all: bool,
    subdomains: bool,
    output: str,
    verbose: bool,
):
    """
    DNS Enumerator - DNS reconnaissance tool.

    Examples:

        \b
        # Query A records
        dns-enum example.com

        \b
        # Query MX records
        dns-enum example.com --record-type MX

        \b
        # Get all records
        dns-enum example.com --all

        \b
        # Enumerate subdomains
        dns-enum example.com --subdomains
    """
    log_level = "DEBUG" if verbose else "INFO"
    setup_logger(__name__, level=log_level)

    enumerator = DNSEnumerator()

    if subdomains:
        info(f"Enumerating subdomains for {domain}")
        found = enumerator.enumerate_subdomains(domain)

        if found:
            success(f"Found {len(found)} subdomain(s)")
            for sub in found:
                print(f"  {sub}")
        else:
            info("No subdomains found")

        sys.exit(0)

    if all:
        info(f"Querying all record types for {domain}")
        all_records = enumerator.get_all_records(domain)

        if output == "json":
            data = {rtype: [r.value for r in records] for rtype, records in all_records.items()}
            print(json.dumps(data, indent=2))
        else:
            for rtype, records in all_records.items():
                table = create_table(title=f"{rtype} Records")
                table.add_column("Value", style="cyan")
                table.add_column("TTL", justify="right", style="dim")

                for record in records:
                    table.add_row(record.value, str(record.ttl) if record.ttl else "-")

                print_table(table)

        sys.exit(0)

    # Single record type query
    info(f"Querying {record_type} records for {domain}")
    records = enumerator.query(domain, record_type)

    if not records:
        error(f"No {record_type} records found for {domain}")
        sys.exit(1)

    if output == "json":
        data = [{"value": r.value, "ttl": r.ttl} for r in records]
        print(json.dumps(data, indent=2))
    else:
        table = create_table(title=f"{record_type} Records for {domain}")
        table.add_column("Value", style="cyan")
        table.add_column("TTL", justify="right", style="dim")

        for record in records:
            table.add_row(record.value, str(record.ttl) if record.ttl else "-")

        print_table(table)

    success(f"Found {len(records)} record(s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
