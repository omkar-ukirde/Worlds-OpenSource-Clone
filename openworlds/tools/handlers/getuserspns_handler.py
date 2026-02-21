"""GetUserSPNs handler — simulates Kerberoasting via Impacket."""

from __future__ import annotations

import hashlib
import random

from openworlds.tools.handlers.base import BaseHandler


class GetUserSPNsHandler(BaseHandler):
    """Simulates impacket-GetUserSPNs for Kerberoasting."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated GetUserSPNs.

        Usage: GetUserSPNs DOMAIN/user:password -dc-ip IP -request
        """
        domain, username, password = self.parse_credentials(args)
        request_mode = "-request" in args

        user = self.find_user(username)
        if not user or user.password != password:
            return (
                f"Impacket v0.11.0 - Copyright 2023 Fortra\n\n"
                f"[-] ERROR: {domain}\\{username}: STATUS_LOGON_FAILURE"
            )

        # Find Kerberoastable users
        spn_users = [u for u in self.manifest.users if u.spn]

        if not spn_users:
            return (
                "Impacket v0.11.0 - Copyright 2023 Fortra\n\n"
                "No entries found!"
            )

        lines = [
            "Impacket v0.11.0 - Copyright 2023 Fortra",
            "",
            "ServicePrincipalName                    Name                    MemberOf",
            "--------------------------------------  ----------------------  --------",
        ]

        for u in spn_users:
            member_of_str = ", ".join(u.member_of[:2]) if u.member_of else ""
            lines.append(
                f"{u.spn:<39} {u.sam_account_name:<23} {member_of_str}"
            )

        if request_mode:
            lines.extend(["", ""])
            for u in spn_users:
                # Generate a realistic-looking Kerberos ticket hash
                ticket_hash = self._generate_krb5tgs_hash(u.sam_account_name, u.nt_hash)
                lines.append(ticket_hash)
                lines.append("")

        return "\n".join(lines)

    def _generate_krb5tgs_hash(self, sam: str, nt_hash: str) -> str:
        """Generate a realistic Kerberos TGS-REP hash for hashcat."""
        # Generate deterministic but realistic-looking hash
        rng = random.Random(nt_hash)
        hash_body = "".join(
            rng.choice("0123456789abcdef") for _ in range(680)
        )
        checksum = hashlib.sha256(nt_hash.encode()).hexdigest()[:32]

        return (
            f"$krb5tgs$23$*{sam}${self.domain.netbios_name.upper()}"
            f"${self.domain.name}/{sam}*$"
            f"{checksum}${hash_body}"
        )
