"""Secretsdump handler — simulates credential dumping via Impacket."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import ACLRight, UserType


class SecretsdumpHandler(BaseHandler):
    """Simulates impacket-secretsdump output."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated secretsdump.

        Supports:
            secretsdump DOMAIN/user:password@TARGET
            secretsdump -just-dc DOMAIN/user:password@TARGET  (DCSync)
        """
        domain, username, password = self.parse_credentials(args)
        target_host = self._parse_target(args)
        just_dc = "-just-dc" in args or "-just-dc-ntlm" in args

        # Verify auth
        user = self.find_user(username)
        if not user or user.password != password:
            return (
                f"Impacket v0.11.0 - Copyright 2023 Fortra\n\n"
                f"[-] ERROR: {domain}\\{username}: "
                f"STATUS_LOGON_FAILURE (The attempted logon is invalid)"
            )

        host = self.find_host(target_host) if target_host else self.get_dc()
        if not host:
            return f"[-] ERROR: Could not connect to {target_host}"

        lines = [
            "Impacket v0.11.0 - Copyright 2023 Fortra",
            "",
            f"[*] Target: {host.fqdn}",
            "[*] Dumping credentials...",
        ]

        if just_dc:
            return self._dcsync_output(lines, user, host)
        else:
            return self._local_dump_output(lines, user, host)

    def _dcsync_output(self, lines: list[str], user: object, host: object) -> str:
        """Simulate DCSync — dump all domain hashes."""
        # Check if user has DCSync rights
        has_dcsync = any(
            acl.source == user.sam_account_name  # type: ignore
            and acl.right == ACLRight.DS_REPLICATION_GET_CHANGES_ALL
            for acl in self.manifest.acls
        )

        if not has_dcsync and user.user_type != UserType.ADMIN:  # type: ignore
            lines.append(
                f"[-] ERROR: {user.sam_account_name} does not have "  # type: ignore
                f"replication rights (DS-Replication-Get-Changes-All)"
            )
            return "\n".join(lines)

        lines.append("[*] Using the DRSUAPI method to get NTDS.DIT secrets")
        lines.append("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)")

        # Dump all users
        for u in self.manifest.users:
            rid = u.sid.split("-")[-1]
            lines.append(
                f"{self.domain.netbios_name}\\{u.sam_account_name}:{rid}:"
                f"aad3b435b51404eeaad3b435b51404ee:{u.nt_hash}:::"
            )

        # Machine account
        for h in self.manifest.hosts:
            lines.append(
                f"{h.hostname}$:1000:aad3b435b51404eeaad3b435b51404ee:"
                f"{'a' * 32}:::"
            )

        lines.extend([
            "[*] Kerberos keys grabbed",
            "[*] Cleaning up...",
        ])
        return "\n".join(lines)

    def _local_dump_output(self, lines: list[str], user: object, host: object) -> str:
        """Simulate local credential dump (SAM/LSA/NTDS)."""
        # Check if user is local admin on this host
        if user.sam_account_name not in host.local_admins:  # type: ignore
            lines.append(
                f"[-] ERROR: {user.sam_account_name} does not have "  # type: ignore
                f"admin privileges on {host.hostname}"  # type: ignore
            )
            return "\n".join(lines)

        lines.extend([
            "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)",
            f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{'b' * 32}:::",
            f"Guest:501:aad3b435b51404eeaad3b435b51404ee:{'0' * 32}:::",
        ])

        # Dump cached credentials of local admins
        lines.append("[*] Dumping cached domain logon information (domain/uid:hash)")
        for admin_sam in host.local_admins:  # type: ignore
            admin_user = self.find_user(admin_sam)
            if admin_user:
                lines.append(
                    f"{self.domain.netbios_name}/{admin_user.sam_account_name}:"
                    f"$DCC2$10240#{admin_user.sam_account_name}#{'c' * 32}"
                )

        lines.append("[*] Cleaning up...")
        return "\n".join(lines)

    def _parse_target(self, args: list[str]) -> str:
        """Parse target from DOMAIN/user:password@TARGET format."""
        for arg in args:
            if "@" in arg:
                return arg.split("@")[-1]
        return ""
