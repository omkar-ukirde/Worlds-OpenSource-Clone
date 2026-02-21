"""GetNPUsers handler — simulates AS-REP Roasting via Impacket."""

from __future__ import annotations

import hashlib
import random

from openworlds.tools.handlers.base import BaseHandler


class GetNPUsersHandler(BaseHandler):
    """Simulates impacket-GetNPUsers for AS-REP Roasting."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated GetNPUsers.

        Usage: GetNPUsers DOMAIN/ -dc-ip IP -usersfile users.txt -format hashcat
        """
        # Find AS-REP roastable users
        asrep_users = [u for u in self.manifest.users if u.asrep_roastable]

        if not asrep_users:
            return (
                "Impacket v0.11.0 - Copyright 2023 Fortra\n\n"
                "No entries found!"
            )

        lines = [
            "Impacket v0.11.0 - Copyright 2023 Fortra",
            "",
        ]

        for u in asrep_users:
            hash_str = self._generate_asrep_hash(u.sam_account_name, u.nt_hash)
            lines.extend([
                f"[*] {u.sam_account_name} does not require Kerberos preauthentication",
                hash_str,
                "",
            ])

        return "\n".join(lines)

    def _generate_asrep_hash(self, sam: str, nt_hash: str) -> str:
        """Generate a realistic AS-REP hash for hashcat."""
        rng = random.Random(nt_hash)
        hash_body = "".join(
            rng.choice("0123456789ABCDEF") for _ in range(470)
        )
        checksum = hashlib.sha256(nt_hash.encode()).hexdigest()[:32].upper()

        return (
            f"$krb5asrep$23${sam}@{self.domain.name.upper()}"
            f":{checksum}${hash_body}"
        )
