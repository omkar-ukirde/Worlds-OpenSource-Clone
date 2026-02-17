"""CrackMapExec handler — simulates credential spraying and enumeration."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import HostType


class CrackMapExecHandler(BaseHandler):
    """Simulates CrackMapExec (cme) for SMB enumeration and spraying."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated CrackMapExec.

        Supports:
            cme smb TARGET -u user -p password
            cme smb TARGET -u user -H hash
            cme smb SUBNET/24 -u user -p password
        """
        if not args:
            return "Usage: crackmapexec {smb,ldap,winrm} TARGET [options]"

        protocol = args[0] if args else "smb"

        # Parse credentials
        username = ""
        password = ""
        nt_hash = ""
        target = ""

        for i, arg in enumerate(args[1:], 1):
            if arg == "-u" and i + 1 < len(args):
                username = args[i + 1]
            elif arg == "-p" and i + 1 < len(args):
                password = args[i + 1]
            elif arg == "-H" and i + 1 < len(args):
                nt_hash = args[i + 1]
            elif not arg.startswith("-") and not target:
                target = arg

        if not target:
            return "[-] No target specified"

        # If target is a subnet, scan all hosts
        if "/" in target:
            return self._spray_subnet(protocol, username, password, nt_hash)

        host = self.find_host(target)
        if not host:
            return f"[-] {target}: Connection refused"

        # Verify credentials
        user = self.find_user(username)
        auth_success = False
        if user:
            if password and user.password == password:
                auth_success = True
            elif nt_hash and user.nt_hash == nt_hash:
                auth_success = True

        is_admin = username in (host.local_admins if host else [])
        status = "[+]" if auth_success else "[-]"
        admin_tag = "(Pwn3d!)" if auth_success and is_admin else ""

        return (
            f"SMB         {host.ip:<15} 445    {host.hostname:<15} "
            f"[*] {host.os} (name:{host.hostname}) (domain:{self.domain.name}) "
            f"(signing:{'True' if host.host_type == HostType.DOMAIN_CONTROLLER else 'False'}) (SMBv1:False)\n"
            f"SMB         {host.ip:<15} 445    {host.hostname:<15} "
            f"{status} {self.domain.netbios_name}\\{username}:{password or nt_hash} {admin_tag}"
        )

    def _spray_subnet(
        self, protocol: str, username: str, password: str, nt_hash: str
    ) -> str:
        """Spray credentials across all hosts."""
        lines = []
        user = self.find_user(username)

        for host in self.manifest.hosts:
            auth_success = False
            if user:
                if password and user.password == password:
                    auth_success = True
                elif nt_hash and user.nt_hash == nt_hash:
                    auth_success = True

            is_admin = username in host.local_admins
            status = "[+]" if auth_success else "[-]"
            admin_tag = "(Pwn3d!)" if auth_success and is_admin else ""

            lines.append(
                f"SMB         {host.ip:<15} 445    {host.hostname:<15} "
                f"{status} {self.domain.netbios_name}\\{username}:{password or nt_hash} {admin_tag}"
            )

        return "\n".join(lines)
