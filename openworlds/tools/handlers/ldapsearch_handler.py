"""Ldapsearch handler — simulates LDAP queries against AD."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler


class LdapsearchHandler(BaseHandler):
    """Simulates ldapsearch/LDAP enumeration output."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated ldapsearch.

        Supports:
            ldapsearch -x -H ldap://DC -b 'DC=...' '(objectClass=user)'
            ldapsearch -x -H ldap://DC -b 'DC=...' '(objectClass=group)'
            ldapsearch -x -H ldap://DC -b 'DC=...' '(servicePrincipalName=*)'
        """
        # Parse filter
        ldap_filter = ""
        _base_dn = ""
        for i, arg in enumerate(args):
            if arg == "-b" and i + 1 < len(args):
                _base_dn = args[i + 1].strip("'\"")
            elif not arg.startswith("-") and "=" in arg:
                ldap_filter = arg.strip("'\"")

        if "user" in ldap_filter.lower() or "person" in ldap_filter.lower():
            return self._enum_users()
        elif "group" in ldap_filter.lower():
            return self._enum_groups()
        elif "serviceprincipalname" in ldap_filter.lower() or "spn" in ldap_filter.lower():
            return self._enum_spns()
        elif "useraccountcontrol" in ldap_filter.lower() or "4194304" in ldap_filter:
            return self._enum_asrep()
        elif "computer" in ldap_filter.lower():
            return self._enum_computers()
        else:
            return self._enum_users()  # Default to user enumeration

    def _enum_users(self) -> str:
        """Enumerate all user objects."""
        lines = ["# extended LDIF", "#", "# LDAPv3",
                 f"# base <{''.join(f'DC={p},' for p in self.domain.name.split('.'))[:-1]}> with scope subtree",
                 "# filter: (objectClass=person)", "# requesting: ALL", "#", ""]

        for user in self.manifest.users:
            lines.extend([
                f"# {user.display_name}",
                f"dn: {user.dn}",
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: user",
                f"cn: {user.display_name}",
                f"sAMAccountName: {user.sam_account_name}",
                f"userPrincipalName: {user.upn}",
                f"distinguishedName: {user.dn}",
                f"objectSid: {user.sid}",
                "memberOf: " + "\nmemberOf: ".join(
                    f"CN={g},CN=Users,{''.join(f'DC={p},' for p in self.domain.name.split('.'))[:-1]}"
                    for g in user.member_of
                ) if user.member_of else "",
            ])

            if user.spn:
                lines.append(f"servicePrincipalName: {user.spn}")
            if user.description:
                lines.append(f"description: {user.description}")
            if user.admin_count:
                lines.append("adminCount: 1")

            lines.extend(["", ""])

        lines.append(f"# numEntries: {len(self.manifest.users)}")
        return "\n".join(lines)

    def _enum_groups(self) -> str:
        """Enumerate group objects."""
        lines = ["# extended LDIF", "# filter: (objectClass=group)", "#", ""]

        for group in self.manifest.groups:
            lines.extend([
                f"dn: {group.dn}",
                "objectClass: top",
                "objectClass: group",
                f"cn: {group.name}",
                f"sAMAccountName: {group.sam_account_name}",
                f"objectSid: {group.sid}",
                f"groupType: {group.group_type}",
            ])
            for member in group.members[:10]:  # Limit for readability
                lines.append(
                    f"member: CN={member},{''.join(f'DC={p},' for p in self.domain.name.split('.'))[:-1]}"
                )
            lines.extend(["", ""])

        lines.append(f"# numEntries: {len(self.manifest.groups)}")
        return "\n".join(lines)

    def _enum_spns(self) -> str:
        """Enumerate users with SPNs (Kerberoastable)."""
        spn_users = [u for u in self.manifest.users if u.spn]
        lines = ["# filter: (servicePrincipalName=*)", "#", ""]

        for user in spn_users:
            lines.extend([
                f"dn: {user.dn}",
                f"sAMAccountName: {user.sam_account_name}",
                f"servicePrincipalName: {user.spn}",
                "", "",
            ])

        lines.append(f"# numEntries: {len(spn_users)}")
        return "\n".join(lines)

    def _enum_asrep(self) -> str:
        """Enumerate AS-REP roastable users."""
        asrep_users = [u for u in self.manifest.users if u.asrep_roastable]
        lines = ["# filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)", "#", ""]

        for user in asrep_users:
            lines.extend([
                f"dn: {user.dn}",
                f"sAMAccountName: {user.sam_account_name}",
                "userAccountControl: 4260352",
                "", "",
            ])

        lines.append(f"# numEntries: {len(asrep_users)}")
        return "\n".join(lines)

    def _enum_computers(self) -> str:
        """Enumerate computer objects."""
        lines = ["# filter: (objectClass=computer)", "#", ""]

        for host in self.manifest.hosts:
            dc_components = ",".join(f"DC={p}" for p in self.domain.name.split("."))
            lines.extend([
                f"dn: CN={host.hostname},OU=Computers,{dc_components}",
                "objectClass: computer",
                f"cn: {host.hostname}",
                f"dNSHostName: {host.fqdn}",
                f"operatingSystem: {host.os}",
                f"operatingSystemVersion: {host.os_build}",
                "", "",
            ])

        lines.append(f"# numEntries: {len(self.manifest.hosts)}")
        return "\n".join(lines)
