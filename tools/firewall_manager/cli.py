"""CLI for the Firewall Manager."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .manager import (
    Direction,
    FirewallBackend,
    FirewallManager,
    FirewallRule,
    Protocol,
    RuleAction,
)

console = Console()


@click.group()
@click.option(
    "--backend",
    type=click.Choice(["iptables", "ufw"]),
    default="ufw",
    help="Firewall backend to use",
)
@click.pass_context
def main(ctx: click.Context, backend: str) -> None:
    """Firewall Manager - Simplified firewall management for iptables and ufw.

    ⚠️  WARNING: This tool requires root privileges (sudo).
    """
    ctx.ensure_object(dict)
    ctx.obj["backend"] = FirewallBackend(backend)


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show firewall status.

    Examples:

        # Check firewall status
        sudo firewall-mgr status

        # Check with specific backend
        sudo firewall-mgr --backend iptables status
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])
        fw_status = manager.get_status()

        # Display status
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Key", style="cyan")
        info_table.add_column("Value", style="white")

        info_table.add_row("Backend", fw_status.backend.value)
        info_table.add_row(
            "Status", "[green]Active[/green]" if fw_status.enabled else "[red]Inactive[/red]"
        )
        info_table.add_row("Rules", str(fw_status.rule_count))
        if fw_status.default_policy:
            info_table.add_row("Default Policy", fw_status.default_policy)

        title = "[green]Firewall Active[/green]" if fw_status.enabled else "[yellow]Firewall Inactive[/yellow]"
        style = "green" if fw_status.enabled else "yellow"

        console.print(Panel(info_table, title=title, border_style=style))

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.pass_context
def enable(ctx: click.Context) -> None:
    """Enable the firewall.

    Examples:

        # Enable firewall
        sudo firewall-mgr enable
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print("[cyan]Enabling firewall...[/cyan]")
        success = manager.enable()

        if success:
            console.print(
                Panel(
                    "[green]Firewall enabled successfully[/green]",
                    title="[green]✓ Enabled[/green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to enable firewall[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.pass_context
def disable(ctx: click.Context) -> None:
    """Disable the firewall.

    Examples:

        # Disable firewall
        sudo firewall-mgr disable
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print("[cyan]Disabling firewall...[/cyan]")
        success = manager.disable()

        if success:
            console.print(
                Panel(
                    "[yellow]Firewall disabled[/yellow]",
                    title="[yellow]⚠ Disabled[/yellow]",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to disable firewall[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.option(
    "--action",
    type=click.Choice(["allow", "deny", "reject"]),
    required=True,
    help="Action to take",
)
@click.option("--port", type=int, help="Port number")
@click.option(
    "--protocol",
    type=click.Choice(["tcp", "udp", "icmp", "all"]),
    default="tcp",
    help="Protocol",
)
@click.option("--source", help="Source IP or CIDR")
@click.option("--destination", help="Destination IP or CIDR")
@click.option(
    "--direction",
    type=click.Choice(["in", "out", "both"]),
    default="in",
    help="Traffic direction",
)
@click.option("--comment", help="Rule comment/description")
@click.pass_context
def add(
    ctx: click.Context,
    action: str,
    port: int,
    protocol: str,
    source: str,
    destination: str,
    direction: str,
    comment: str,
) -> None:
    """Add a firewall rule.

    Examples:

        # Allow SSH
        sudo firewall-mgr add --action allow --port 22 --protocol tcp

        # Allow HTTP/HTTPS
        sudo firewall-mgr add --action allow --port 80 --comment "HTTP traffic"
        sudo firewall-mgr add --action allow --port 443 --comment "HTTPS traffic"

        # Deny from specific IP
        sudo firewall-mgr add --action deny --source 192.168.1.100

        # Allow database from internal network
        sudo firewall-mgr add --action allow --port 5432 --source 10.0.0.0/8
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        rule = FirewallRule(
            action=RuleAction(action),
            port=port,
            protocol=Protocol(protocol),
            source=source,
            destination=destination,
            direction=Direction(direction),
            comment=comment,
        )

        console.print("[cyan]Adding firewall rule...[/cyan]")
        success = manager.add_rule(rule)

        if success:
            rule_desc = _format_rule_description(rule)
            console.print(
                Panel(
                    f"[green]{rule_desc}[/green]",
                    title="[green]✓ Rule Added[/green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to add rule[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.pass_context
def list(ctx: click.Context) -> None:
    """List all firewall rules.

    Examples:

        # List all rules
        sudo firewall-mgr list
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])
        rules = manager.list_rules()

        if not rules:
            console.print(
                Panel(
                    "[yellow]No rules found[/yellow]",
                    title="[yellow]Firewall Rules[/yellow]",
                    border_style="yellow",
                )
            )
            return

        # Display rules
        console.print(f"\n[cyan]Firewall Rules ({ctx.obj['backend'].value}):[/cyan]\n")
        for rule in rules:
            if rule.strip():
                console.print(rule)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.confirmation_option(prompt="Are you sure you want to reset the firewall?")
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Reset firewall to default state (removes all rules).

    Examples:

        # Reset firewall
        sudo firewall-mgr reset
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print("[cyan]Resetting firewall...[/cyan]")
        success = manager.reset()

        if success:
            console.print(
                Panel(
                    "[yellow]Firewall reset to default state[/yellow]",
                    title="[yellow]⚠ Reset Complete[/yellow]",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to reset firewall[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.argument("backup_file", type=click.Path(path_type=Path))
@click.pass_context
def backup(ctx: click.Context, backup_file: Path) -> None:
    """Backup current firewall rules.

    Examples:

        # Backup rules
        sudo firewall-mgr backup /backups/firewall_rules.json
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print("[cyan]Backing up firewall rules...[/cyan]")
        success = manager.backup_rules(backup_file)

        if success:
            console.print(
                Panel(
                    f"[green]Rules backed up to: {backup_file}[/green]",
                    title="[green]✓ Backup Complete[/green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to backup rules[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.argument("backup_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def restore(ctx: click.Context, backup_file: Path) -> None:
    """Restore firewall rules from backup.

    Examples:

        # Restore rules
        sudo firewall-mgr restore /backups/firewall_rules.json
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print("[cyan]Restoring firewall rules...[/cyan]")
        success = manager.restore_rules(backup_file)

        if success:
            console.print(
                Panel(
                    f"[green]Rules restored from: {backup_file}[/green]",
                    title="[green]✓ Restore Complete[/green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[red]Failed to restore rules (UFW restore not supported in this version)[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


@main.command()
@click.argument(
    "template",
    type=click.Choice(["ssh", "web", "database"]),
)
@click.pass_context
def template(ctx: click.Context, template: str) -> None:
    """Apply a predefined firewall template.

    Available templates:
      - ssh: Allow SSH (port 22)
      - web: Allow HTTP (80) and HTTPS (443)
      - database: Allow PostgreSQL (5432) and MySQL (3306) from internal networks

    Examples:

        # Apply SSH template
        sudo firewall-mgr template ssh

        # Apply web server template
        sudo firewall-mgr template web
    """
    try:
        manager = FirewallManager(ctx.obj["backend"])

        console.print(f"[cyan]Applying {template} template...[/cyan]")
        success = manager.apply_template(template)

        if success:
            console.print(
                Panel(
                    f"[green]Template '{template}' applied successfully[/green]",
                    title="[green]✓ Template Applied[/green]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]Failed to apply template '{template}'[/red]",
                    title="[red]✗ Failed[/red]",
                    border_style="red",
                )
            )
            sys.exit(1)

    except PermissionError as e:
        console.print(
            Panel(
                f"[red]{str(e)}[/red]",
                title="[red]✗ Permission Denied[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error: {str(e)}[/red]",
                title="[red]✗ Failed[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


def _format_rule_description(rule: FirewallRule) -> str:
    """Format a rule into a human-readable description."""
    parts = [rule.action.value.upper()]

    if rule.port:
        parts.append(f"port {rule.port}")

    parts.append(rule.protocol.value)

    if rule.source:
        parts.append(f"from {rule.source}")

    if rule.destination:
        parts.append(f"to {rule.destination}")

    parts.append(f"({rule.direction.value})")

    if rule.comment:
        parts.append(f"- {rule.comment}")

    return " ".join(parts)


if __name__ == "__main__":
    main()
