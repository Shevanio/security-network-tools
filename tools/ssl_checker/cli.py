"""CLI interface for SSL Certificate Checker."""

import json
import sys
from pathlib import Path
from typing import List, Optional

import click

from shared.cli import create_table, error, handle_errors, info, print_table, success, warning
from shared.logger import setup_logger

from .checker import CertificateInfo, SSLChecker


def format_table(results: List[CertificateInfo]) -> None:
    """
    Display certificate results as a table.

    Args:
        results: List of certificate information
    """
    if not results:
        info("No certificates to display")
        return

    table = create_table(title="SSL Certificate Check Results")
    table.add_column("Hostname", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Issued To", style="dim")
    table.add_column("Issued By", style="dim")
    table.add_column("Valid Until", style="yellow")
    table.add_column("Days Left", style="bold", justify="right")

    for cert in results:
        if cert.error:
            table.add_row(
                f"{cert.hostname}:{cert.port}",
                "❌ ERROR",
                "-",
                "-",
                "-",
                "-",
                style="red",
            )
            continue

        # Status with icon
        if cert.is_expired:
            status = "❌ EXPIRED"
            status_style = "bold red"
        elif cert.is_expiring_soon:
            status = "⚠️  EXPIRING"
            status_style = "bold yellow"
        else:
            status = "✅ VALID"
            status_style = "bold green"

        # Days remaining with color
        if cert.days_remaining < 0:
            days_style = "red"
            days_text = f"{abs(cert.days_remaining)} (expired)"
        elif cert.is_expiring_soon:
            days_style = "yellow"
            days_text = str(cert.days_remaining)
        else:
            days_style = "green"
            days_text = str(cert.days_remaining)

        table.add_row(
            f"{cert.hostname}:{cert.port}",
            status,
            cert.issued_to[:30],
            cert.issued_by[:30],
            cert.valid_until.strftime("%Y-%m-%d"),
            days_text,
            style=status_style if cert.is_expired or cert.is_expiring_soon else None,
        )

    print_table(table)

    # Summary
    total = len(results)
    errors = sum(1 for c in results if c.error)
    expired = sum(1 for c in results if not c.error and c.is_expired)
    expiring = sum(1 for c in results if not c.error and c.is_expiring_soon)
    valid = total - errors - expired - expiring

    info(f"\nSummary: {total} checked | ✅ {valid} valid | ⚠️  {expiring} expiring | ❌ {expired} expired | 🔥 {errors} errors")


def format_detailed(cert: CertificateInfo) -> None:
    """
    Display detailed certificate information.

    Args:
        cert: Certificate information
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    if cert.error:
        error(f"Failed to check {cert.hostname}:{cert.port}")
        error(f"Error: {cert.error}")
        return

    # Header
    if cert.is_expired:
        status = Text("❌ CERTIFICATE EXPIRED", style="bold red")
    elif cert.is_expiring_soon:
        status = Text("⚠️  CERTIFICATE EXPIRING SOON", style="bold yellow")
    else:
        status = Text("✅ CERTIFICATE VALID", style="bold green")

    console.print(Panel(status, title=f"{cert.hostname}:{cert.port}"))

    # Details
    console.print("\n[bold cyan]Certificate Information:[/bold cyan]")
    console.print(f"  Issued To:       {cert.issued_to}")
    console.print(f"  Issued By:       {cert.issued_by}")
    console.print(f"  Valid From:      {cert.valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    console.print(f"  Valid Until:     {cert.valid_until.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Days remaining with color
    if cert.is_expired:
        console.print(f"  Days Remaining:  [red]{cert.days_remaining} (EXPIRED)[/red]")
    elif cert.is_expiring_soon:
        console.print(f"  Days Remaining:  [yellow]{cert.days_remaining} (WARNING)[/yellow]")
    else:
        console.print(f"  Days Remaining:  [green]{cert.days_remaining}[/green]")

    console.print(f"\n[bold cyan]Technical Details:[/bold cyan]")
    console.print(f"  Serial Number:   {cert.serial_number}")
    console.print(f"  Signature Alg:   {cert.signature_algorithm}")
    console.print(f"  Version:         {cert.version}")
    console.print(f"  Self-Signed:     {cert.is_self_signed}")
    console.print(f"  Valid Chain:     {cert.is_valid_chain}")

    if cert.subject_alt_names:
        console.print(f"\n[bold cyan]Subject Alternative Names:[/bold cyan]")
        for san in cert.subject_alt_names:
            console.print(f"  - {san}")

    console.print()


def format_json(results: List[CertificateInfo]) -> str:
    """
    Format certificate results as JSON.

    Args:
        results: List of certificate information

    Returns:
        JSON string
    """
    data = []
    for cert in results:
        cert_data = {
            "hostname": cert.hostname,
            "port": cert.port,
            "issued_to": cert.issued_to,
            "issued_by": cert.issued_by,
            "valid_from": cert.valid_from.isoformat(),
            "valid_until": cert.valid_until.isoformat(),
            "days_remaining": cert.days_remaining,
            "is_expired": cert.is_expired,
            "is_expiring_soon": cert.is_expiring_soon,
            "serial_number": cert.serial_number,
            "signature_algorithm": cert.signature_algorithm,
            "version": cert.version,
            "subject_alt_names": cert.subject_alt_names,
            "is_self_signed": cert.is_self_signed,
            "is_valid_chain": cert.is_valid_chain,
            "error": cert.error,
        }
        data.append(cert_data)

    return json.dumps({"certificates": data, "total": len(data)}, indent=2)


@click.command()
@click.option("--host", "-h", help="Hostname to check (can specify multiple times)", multiple=True)
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="File with hostnames (one per line)",
)
@click.option("--port", "-p", type=int, default=443, show_default=True, help="Port number")
@click.option(
    "--timeout",
    default=5.0,
    type=float,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--warn-days",
    default=30,
    type=int,
    show_default=True,
    help="Days before expiration to show warning",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "detailed", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@handle_errors
def main(
    host: tuple,
    file: Optional[Path],
    port: int,
    timeout: float,
    warn_days: int,
    output: str,
    verbose: bool,
):
    """
    SSL Certificate Checker - Validate SSL/TLS certificates.

    Check SSL certificates for expiration, validity, and chain trust.

    Examples:

        \b
        # Check single domain
        ssl-checker --host example.com

        \b
        # Check multiple domains
        ssl-checker --host google.com --host github.com

        \b
        # Check from file
        ssl-checker --file domains.txt

        \b
        # Custom warning threshold
        ssl-checker --host example.com --warn-days 60

        \b
        # Detailed output for single domain
        ssl-checker --host example.com --output detailed

        \b
        # JSON output
        ssl-checker --host example.com --output json
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logger(__name__, level=log_level)

    # Validate input
    if not host and not file:
        error("Either --host or --file must be specified")
        sys.exit(1)

    # Initialize checker
    checker = SSLChecker(timeout=timeout, warning_days=warn_days)

    # Get hostnames
    hostnames = list(host) if host else []
    if file:
        try:
            results_from_file = checker.check_from_file(str(file), port=port)
            if output == "table":
                format_table(results_from_file)
            elif output == "json":
                print(format_json(results_from_file))
            elif output == "detailed":
                for cert in results_from_file:
                    format_detailed(cert)

            # Exit code based on results
            has_errors = any(c.error or c.is_expired for c in results_from_file)
            sys.exit(1 if has_errors else 0)

        except Exception as e:
            error(f"Failed to process file: {e}")
            sys.exit(1)

    # Check certificates
    if len(hostnames) == 1 and output == "detailed":
        # Single host with detailed output
        cert = checker.check_certificate(hostnames[0], port=port)
        format_detailed(cert)

        # Exit code
        if cert.error or cert.is_expired:
            sys.exit(1)
        elif cert.is_expiring_soon:
            warning(f"Certificate expiring in {cert.days_remaining} days")
            sys.exit(0)
        else:
            success("Certificate is valid")
            sys.exit(0)

    else:
        # Multiple hosts or table/json output
        results = checker.check_multiple(hostnames, port=port)

        if output == "table":
            format_table(results)
        elif output == "json":
            print(format_json(results))
        elif output == "detailed":
            for cert in results:
                format_detailed(cert)

        # Exit code based on results
        has_errors = any(c.error or c.is_expired for c in results)
        sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
