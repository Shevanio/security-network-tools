"""CLI interface for Port Scanner."""

import json
import sys
from typing import List, Optional

import click

from shared.cli import create_table, error, handle_errors, info, print_table, success
from shared.logger import setup_logger

from .scanner import PortScanner, ScanResult


def parse_ports(ports_str: str) -> List[int]:
    """
    Parse port specification string.

    Supports:
        - Single port: "80"
        - Multiple ports: "80,443,8080"
        - Range: "1-1000"
        - Mixed: "22,80,443,8000-9000"

    Args:
        ports_str: Port specification string

    Returns:
        List of port numbers

    Raises:
        ValueError: If port specification is invalid
    """
    port_list = []

    for part in ports_str.split(","):
        part = part.strip()

        if "-" in part:
            # Range: "1-1000"
            try:
                start, end = part.split("-")
                start_port = int(start.strip())
                end_port = int(end.strip())

                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Invalid port range: {part}")

                port_list.extend(range(start_port, end_port + 1))
            except (ValueError, AttributeError) as e:
                raise ValueError(f"Invalid port range: {part}") from e
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port}")
                port_list.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port number: {part}") from e

    return sorted(set(port_list))


def format_table(results: List[ScanResult], show_closed: bool = False) -> None:
    """
    Display scan results as a table.

    Args:
        results: List of scan results
        show_closed: Whether to show closed ports
    """
    table = create_table(title="Port Scan Results")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("State", style="bold")
    table.add_column("Service", style="yellow")
    table.add_column("Banner", style="dim")

    open_count = 0

    for result in results:
        if result.state == "open":
            open_count += 1
            state_style = "bold green"
        elif result.state == "closed":
            if not show_closed:
                continue
            state_style = "red"
        elif result.state == "filtered":
            state_style = "yellow"
        else:
            state_style = "dim"

        table.add_row(
            str(result.port),
            result.state.upper(),
            result.service or "-",
            result.banner[:50] if result.banner else "-",
            style=state_style if result.state != "open" else None,
        )

    print_table(table)

    # Summary
    info(f"Found {open_count} open ports out of {len(results)} scanned")


def format_json(results: List[ScanResult]) -> str:
    """
    Format scan results as JSON.

    Args:
        results: List of scan results

    Returns:
        JSON string
    """
    data = {
        "total_scanned": len(results),
        "open_ports": [
            {
                "port": r.port,
                "state": r.state,
                "service": r.service,
                "banner": r.banner,
            }
            for r in results
            if r.state == "open"
        ],
        "all_ports": [
            {
                "port": r.port,
                "state": r.state,
                "service": r.service,
                "banner": r.banner,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


def format_csv(results: List[ScanResult]) -> str:
    """
    Format scan results as CSV.

    Args:
        results: List of scan results

    Returns:
        CSV string
    """
    lines = ["port,state,service,banner"]

    for result in results:
        banner = (result.banner or "").replace(",", ";").replace("\n", " ")
        lines.append(f"{result.port},{result.state},{result.service or ''},{banner}")

    return "\n".join(lines)


@click.command()
@click.option("--host", "-h", required=True, help="Target hostname or IP address")
@click.option("--ports", "-p", help="Ports to scan (e.g., 80,443 or 1-1000)")
@click.option("--top-ports", "-t", type=int, help="Scan N most common ports")
@click.option(
    "--timeout",
    default=1.0,
    type=float,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--workers",
    default=100,
    type=int,
    show_default=True,
    help="Maximum number of parallel threads",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "csv"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format",
)
@click.option("--show-closed", is_flag=True, help="Show closed ports in table output")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@handle_errors
def main(
    host: str,
    ports: Optional[str],
    top_ports: Optional[int],
    timeout: float,
    workers: int,
    output: str,
    show_closed: bool,
    verbose: bool,
):
    """
    Port Scanner - TCP port analysis tool.

    Examples:

        \b
        # Scan specific ports
        port-scanner --host example.com --ports 80,443,8080

        \b
        # Scan port range
        port-scanner --host 192.168.1.1 --ports 1-1000

        \b
        # Scan top 100 common ports
        port-scanner --host example.com --top-ports 100

        \b
        # Export to JSON
        port-scanner --host example.com --ports 1-1000 --output json > results.json
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logger(__name__, level=log_level)

    # Validate input
    if not ports and not top_ports:
        error("Either --ports or --top-ports must be specified")
        sys.exit(1)

    if ports and top_ports:
        error("Cannot specify both --ports and --top-ports")
        sys.exit(1)

    # Initialize scanner
    info(f"Initializing port scanner for {host}")
    scanner = PortScanner(host=host, timeout=timeout, max_workers=workers)

    # Perform scan
    try:
        if ports:
            port_list = parse_ports(ports)
            info(f"Scanning {len(port_list)} ports...")
            results = scanner.scan_ports(port_list)
        else:
            info(f"Scanning top {top_ports} common ports...")
            results = scanner.scan_top_ports(count=top_ports)

    except ValueError as e:
        error(str(e))
        sys.exit(1)

    # Output results
    if output == "table":
        format_table(results, show_closed=show_closed)
    elif output == "json":
        print(format_json(results))
    elif output == "csv":
        print(format_csv(results))

    # Exit code based on results
    open_ports = [r for r in results if r.state == "open"]
    if open_ports:
        success(f"Scan completed. Found {len(open_ports)} open port(s)")
        sys.exit(0)
    else:
        info("Scan completed. No open ports found")
        sys.exit(0)


if __name__ == "__main__":
    main()
