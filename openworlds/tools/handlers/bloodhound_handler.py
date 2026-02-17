"""BloodHound handler — simulates BloodHound data collection."""

from __future__ import annotations

import json

from openworlds.tools.handlers.base import BaseHandler


class BloodHoundHandler(BaseHandler):
    """Simulates bloodhound-python collection output."""

    def execute(self, args: list[str]) -> str:
        """Simulate BloodHound data collection.

        Usage: bloodhound-python -u user -p pass -d domain -c All
        """
        lines = [
            f"INFO: Found AD domain: {self.domain.name}",
            f"INFO: Getting TGT for user",
            f"INFO: Connecting to LDAP server: {self._get_dc_fqdn()}",
            f"INFO: Found {len(self.manifest.users)} users",
            f"INFO: Found {len(self.manifest.groups)} groups",
            f"INFO: Found {len(self.manifest.hosts)} computers",
            f"INFO: Found {len(self.manifest.ous)} OUs",
            f"INFO: Enumerating group memberships",
            f"INFO: Found {sum(len(g.members) for g in self.manifest.groups)} group memberships",
            f"INFO: Enumerating ACLs",
            f"INFO: Found {len(self.manifest.acls)} ACL entries",
            f"INFO: Enumerating local admin access",
        ]

        # Count local admin relationships
        la_count = sum(len(h.local_admins) for h in self.manifest.hosts)
        lines.extend([
            f"INFO: Found {la_count} local admin relationships",
            f"INFO: Done in {len(self.manifest.users) * 0.1:.1f}s",
            f"INFO: Compressing output to {self.domain.netbios_name}_bloodhound.zip",
        ])

        return "\n".join(lines)

    def _get_dc_fqdn(self) -> str:
        """Get the FQDN of the first DC."""
        dc = self.get_dc()
        return dc.fqdn if dc else f"DC01.{self.domain.name}"
