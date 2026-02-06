"""Firewall management with support for iptables and ufw backends."""

import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class FirewallBackend(Enum):
    """Supported firewall backends."""

    IPTABLES = "iptables"
    UFW = "ufw"


class RuleAction(Enum):
    """Firewall rule action."""

    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"


class Protocol(Enum):
    """Network protocol."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


class Direction(Enum):
    """Traffic direction."""

    IN = "in"
    OUT = "out"
    BOTH = "both"


@dataclass
class FirewallRule:
    """Represents a firewall rule."""

    action: RuleAction
    port: Optional[int] = None
    protocol: Protocol = Protocol.TCP
    source: Optional[str] = None
    destination: Optional[str] = None
    direction: Direction = Direction.IN
    comment: Optional[str] = None


@dataclass
class FirewallStatus:
    """Firewall status information."""

    enabled: bool
    backend: FirewallBackend
    rule_count: int
    default_policy: Optional[str] = None


class FirewallManager:
    """Manages firewall rules using iptables or ufw."""

    def __init__(self, backend: FirewallBackend = FirewallBackend.UFW):
        """Initialize the firewall manager.

        Args:
            backend: Firewall backend to use (iptables or ufw)
        """
        self.backend = backend
        self._validate_permissions()
        self._validate_backend()

    def _validate_permissions(self) -> None:
        """Validate that the user has root permissions."""
        if os.geteuid() != 0:
            raise PermissionError(
                "Firewall management requires root privileges. Run with sudo."
            )

    def _validate_backend(self) -> None:
        """Validate that the backend is available."""
        backend_cmd = self.backend.value
        try:
            subprocess.run(
                ["which", backend_cmd],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError(
                f"Backend '{backend_cmd}' not found. Install it first."
            )

    def get_status(self) -> FirewallStatus:
        """Get the current firewall status.

        Returns:
            FirewallStatus with current state
        """
        if self.backend == FirewallBackend.UFW:
            return self._get_ufw_status()
        else:
            return self._get_iptables_status()

    def enable(self) -> bool:
        """Enable the firewall.

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                subprocess.run(
                    ["ufw", "--force", "enable"],
                    check=True,
                    capture_output=True,
                )
            else:
                # iptables is always "enabled" if rules exist
                # Just ensure iptables-persistent is configured
                pass

            return True
        except subprocess.CalledProcessError:
            return False

    def disable(self) -> bool:
        """Disable the firewall.

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                subprocess.run(
                    ["ufw", "disable"],
                    check=True,
                    capture_output=True,
                )
            else:
                # Flush all iptables rules
                subprocess.run(["iptables", "-F"], check=True)
                subprocess.run(["iptables", "-X"], check=True)

            return True
        except subprocess.CalledProcessError:
            return False

    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule.

        Args:
            rule: Rule to add

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                return self._add_ufw_rule(rule)
            else:
                return self._add_iptables_rule(rule)
        except Exception:
            return False

    def delete_rule(self, rule: FirewallRule) -> bool:
        """Delete a firewall rule.

        Args:
            rule: Rule to delete

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                return self._delete_ufw_rule(rule)
            else:
                return self._delete_iptables_rule(rule)
        except Exception:
            return False

    def list_rules(self) -> List[str]:
        """List all firewall rules.

        Returns:
            List of rule strings
        """
        try:
            if self.backend == FirewallBackend.UFW:
                result = subprocess.run(
                    ["ufw", "status", "numbered"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return result.stdout.split("\n")
            else:
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v", "--line-numbers"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return result.stdout.split("\n")
        except subprocess.CalledProcessError:
            return []

    def reset(self) -> bool:
        """Reset firewall to default state.

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                subprocess.run(
                    ["ufw", "--force", "reset"],
                    check=True,
                    capture_output=True,
                )
            else:
                # Flush all chains
                subprocess.run(["iptables", "-F"], check=True)
                subprocess.run(["iptables", "-X"], check=True)
                subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
                subprocess.run(["iptables", "-t", "nat", "-X"], check=True)
                subprocess.run(["iptables", "-t", "mangle", "-F"], check=True)
                subprocess.run(["iptables", "-t", "mangle", "-X"], check=True)
                # Set default policies to ACCEPT
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)

            return True
        except subprocess.CalledProcessError:
            return False

    def backup_rules(self, backup_path: Path) -> bool:
        """Backup current firewall rules.

        Args:
            backup_path: Path to save backup

        Returns:
            True if successful
        """
        try:
            if self.backend == FirewallBackend.UFW:
                # UFW stores rules in /etc/ufw/
                # We'll export the status
                result = subprocess.run(
                    ["ufw", "status", "verbose"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                rules_output = result.stdout
            else:
                # Export iptables rules
                result = subprocess.run(
                    ["iptables-save"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                rules_output = result.stdout

            # Save to file
            backup_data = {
                "timestamp": datetime.now().isoformat(),
                "backend": self.backend.value,
                "rules": rules_output,
            }

            with open(backup_path, "w") as f:
                json.dump(backup_data, f, indent=2)

            return True
        except Exception:
            return False

    def restore_rules(self, backup_path: Path) -> bool:
        """Restore firewall rules from backup.

        Args:
            backup_path: Path to backup file

        Returns:
            True if successful
        """
        try:
            if not backup_path.exists():
                return False

            # Load backup
            with open(backup_path, "r") as f:
                backup_data = json.load(f)

            # Verify backend matches
            if backup_data["backend"] != self.backend.value:
                raise ValueError(
                    f"Backup is for {backup_data['backend']}, "
                    f"but current backend is {self.backend.value}"
                )

            rules_output = backup_data["rules"]

            if self.backend == FirewallBackend.UFW:
                # For UFW, we need to parse and re-add rules
                # This is a simplified approach
                return False  # Not implemented for UFW
            else:
                # Restore iptables rules
                subprocess.run(
                    ["iptables-restore"],
                    input=rules_output,
                    text=True,
                    check=True,
                )
                return True

        except Exception:
            return False

    def apply_template(self, template_name: str) -> bool:
        """Apply a predefined firewall template.

        Args:
            template_name: Name of template (ssh, web, database)

        Returns:
            True if successful
        """
        templates = {
            "ssh": [
                FirewallRule(
                    action=RuleAction.ALLOW,
                    port=22,
                    protocol=Protocol.TCP,
                    comment="SSH access",
                )
            ],
            "web": [
                FirewallRule(
                    action=RuleAction.ALLOW,
                    port=80,
                    protocol=Protocol.TCP,
                    comment="HTTP",
                ),
                FirewallRule(
                    action=RuleAction.ALLOW,
                    port=443,
                    protocol=Protocol.TCP,
                    comment="HTTPS",
                ),
            ],
            "database": [
                FirewallRule(
                    action=RuleAction.ALLOW,
                    port=5432,
                    protocol=Protocol.TCP,
                    source="10.0.0.0/8",
                    comment="PostgreSQL from internal",
                ),
                FirewallRule(
                    action=RuleAction.ALLOW,
                    port=3306,
                    protocol=Protocol.TCP,
                    source="10.0.0.0/8",
                    comment="MySQL from internal",
                ),
            ],
        }

        template_rules = templates.get(template_name)
        if not template_rules:
            return False

        # Apply all rules in template
        for rule in template_rules:
            if not self.add_rule(rule):
                return False

        return True

    def _get_ufw_status(self) -> FirewallStatus:
        """Get UFW firewall status."""
        try:
            result = subprocess.run(
                ["ufw", "status", "verbose"],
                check=True,
                capture_output=True,
                text=True,
            )

            output = result.stdout.lower()
            enabled = "status: active" in output

            # Count rules (approximate)
            lines = result.stdout.split("\n")
            rule_count = sum(1 for line in lines if " -> " in line)

            # Extract default policy
            default_policy = None
            for line in lines:
                if "default:" in line.lower():
                    default_policy = line.strip()
                    break

            return FirewallStatus(
                enabled=enabled,
                backend=FirewallBackend.UFW,
                rule_count=rule_count,
                default_policy=default_policy,
            )
        except subprocess.CalledProcessError:
            return FirewallStatus(
                enabled=False,
                backend=FirewallBackend.UFW,
                rule_count=0,
            )

    def _get_iptables_status(self) -> FirewallStatus:
        """Get iptables firewall status."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                check=True,
                capture_output=True,
                text=True,
            )

            # Count rules (excluding chain headers and policy lines)
            lines = result.stdout.split("\n")
            rule_count = sum(
                1
                for line in lines
                if line
                and not line.startswith("Chain")
                and not line.startswith("target")
            )

            # iptables is considered "enabled" if rules exist
            enabled = rule_count > 0

            return FirewallStatus(
                enabled=enabled,
                backend=FirewallBackend.IPTABLES,
                rule_count=rule_count,
            )
        except subprocess.CalledProcessError:
            return FirewallStatus(
                enabled=False,
                backend=FirewallBackend.IPTABLES,
                rule_count=0,
            )

    def _add_ufw_rule(self, rule: FirewallRule) -> bool:
        """Add a UFW rule."""
        cmd = ["ufw"]

        # Build command
        if rule.direction == Direction.IN:
            cmd.append("allow")
        elif rule.direction == Direction.OUT:
            cmd.extend(["allow", "out"])

        # Add protocol and port
        if rule.port:
            cmd.append(f"{rule.port}/{rule.protocol.value}")
        else:
            cmd.append(rule.protocol.value)

        # Add source if specified
        if rule.source:
            cmd.extend(["from", rule.source])

        # Add comment if specified
        if rule.comment:
            cmd.extend(["comment", rule.comment])

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _delete_ufw_rule(self, rule: FirewallRule) -> bool:
        """Delete a UFW rule."""
        # Build the same command as add, but with 'delete' prefix
        cmd = ["ufw", "delete"]

        if rule.direction == Direction.IN:
            cmd.append("allow")
        elif rule.direction == Direction.OUT:
            cmd.extend(["allow", "out"])

        if rule.port:
            cmd.append(f"{rule.port}/{rule.protocol.value}")
        else:
            cmd.append(rule.protocol.value)

        if rule.source:
            cmd.extend(["from", rule.source])

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _add_iptables_rule(self, rule: FirewallRule) -> bool:
        """Add an iptables rule."""
        chain = "INPUT" if rule.direction == Direction.IN else "OUTPUT"
        cmd = ["iptables", "-A", chain]

        # Protocol
        if rule.protocol != Protocol.ALL:
            cmd.extend(["-p", rule.protocol.value])

        # Source
        if rule.source:
            cmd.extend(["-s", rule.source])

        # Destination
        if rule.destination:
            cmd.extend(["-d", rule.destination])

        # Port (destination port for INPUT, source port for OUTPUT)
        if rule.port:
            if rule.direction == Direction.IN:
                cmd.extend(["--dport", str(rule.port)])
            else:
                cmd.extend(["--sport", str(rule.port)])

        # Action
        action_map = {
            RuleAction.ALLOW: "ACCEPT",
            RuleAction.DENY: "DROP",
            RuleAction.REJECT: "REJECT",
        }
        cmd.extend(["-j", action_map[rule.action]])

        # Comment
        if rule.comment:
            cmd.extend(["-m", "comment", "--comment", rule.comment])

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _delete_iptables_rule(self, rule: FirewallRule) -> bool:
        """Delete an iptables rule."""
        # Build the same command as add, but with '-D' instead of '-A'
        chain = "INPUT" if rule.direction == Direction.IN else "OUTPUT"
        cmd = ["iptables", "-D", chain]

        if rule.protocol != Protocol.ALL:
            cmd.extend(["-p", rule.protocol.value])

        if rule.source:
            cmd.extend(["-s", rule.source])

        if rule.destination:
            cmd.extend(["-d", rule.destination])

        if rule.port:
            if rule.direction == Direction.IN:
                cmd.extend(["--dport", str(rule.port)])
            else:
                cmd.extend(["--sport", str(rule.port)])

        action_map = {
            RuleAction.ALLOW: "ACCEPT",
            RuleAction.DENY: "DROP",
            RuleAction.REJECT: "REJECT",
        }
        cmd.extend(["-j", action_map[rule.action]])

        if rule.comment:
            cmd.extend(["-m", "comment", "--comment", rule.comment])

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
