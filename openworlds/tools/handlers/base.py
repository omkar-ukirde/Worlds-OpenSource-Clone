"""Base class for all tool handlers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from openworlds.world_engine.models import Host, Manifest, User


class BaseHandler(ABC):
    """Abstract base for a simulated tool handler.

    Each handler must implement:
        execute(args: list[str]) -> str
    """

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.domain = manifest.domain

    @abstractmethod
    def execute(self, args: list[str]) -> str:
        """Execute the tool with the given arguments."""
        ...

    def find_host_by_ip(self, ip: str) -> Host | None:
        """Find a host by IP address."""
        return next((h for h in self.manifest.hosts if h.ip == ip), None)

    def find_host_by_name(self, name: str) -> Host | None:
        """Find a host by hostname or FQDN."""
        name_lower = name.lower()
        return next(
            (h for h in self.manifest.hosts
             if h.hostname.lower() == name_lower or h.fqdn.lower() == name_lower),
            None,
        )

    def find_host(self, target: str) -> Host | None:
        """Find a host by IP, hostname, or FQDN."""
        return self.find_host_by_ip(target) or self.find_host_by_name(target)

    def find_user(self, sam: str) -> User | None:
        """Find a user by SAMAccountName."""
        return next(
            (u for u in self.manifest.users
             if u.sam_account_name.lower() == sam.lower()),
            None,
        )

    def get_dc(self) -> Host | None:
        """Get the first domain controller."""
        from openworlds.world_engine.models import HostType
        return next(
            (h for h in self.manifest.hosts
             if h.host_type == HostType.DOMAIN_CONTROLLER),
            None,
        )

    def parse_credentials(self, args: list[str]) -> tuple[str, str, str]:
        """Parse DOMAIN/user:password from args.

        Looks for patterns like 'NORTH.local/j.smith:Password1'
        Returns (domain, username, password).
        """
        for arg in args:
            if "/" in arg and ":" in arg:
                domain_user, password = arg.rsplit(":", 1)
                domain, user = domain_user.split("/", 1)
                return domain, user, password
            elif "/" in arg:
                domain, user = arg.split("/", 1)
                return domain, user, ""
        return "", "", ""
