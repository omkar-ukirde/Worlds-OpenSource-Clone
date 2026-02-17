"""Path Validator — validates attack paths from initial access to Domain Admin.

Uses NetworkX to build a directed graph where:
    - Nodes = principals (users, service accounts, groups)
    - Edges = attack steps (kerberoast, acl_abuse, credential_pivot, etc.)

Then performs BFS/DFS to find all valid paths from the starting user to
Domain Admin. If no path exists, signals that re-injection is needed.
"""

from __future__ import annotations

import uuid

import networkx as nx

from openworlds.world_engine.models import (
    ACLRight,
    AttackPath,
    AttackStep,
    HostType,
    Manifest,
    PasswordStrength,
    UserType,
)


class PathValidator:
    """Validates that at least one attack path exists in the manifest.

    Usage:
        validator = PathValidator(manifest)
        paths = validator.find_attack_paths()
        if not paths:
            # Re-inject vulnerabilities
            ...
        manifest.attack_paths = paths
    """

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.graph = nx.DiGraph()
        self._user_map = {u.sam_account_name: u for u in manifest.users}
        self._group_map = {g.sam_account_name: g for g in manifest.groups}
        self._host_map = {h.hostname: h for h in manifest.hosts}

    def build_graph(self) -> None:
        """Build the attack graph from manifest data."""
        self._add_kerberoasting_edges()
        self._add_asrep_roasting_edges()
        self._add_acl_abuse_edges()
        self._add_credential_pivot_edges()
        self._add_adcs_edges()
        self._add_share_credential_edges()
        self._add_local_admin_edges()
        self._add_group_membership_edges()

    def find_attack_paths(
        self,
        starting_user: str | None = None,
        max_length: int | None = None,
    ) -> list[AttackPath]:
        """Find all attack paths from starting user to Domain Admin.

        Args:
            starting_user: The SAMAccountName to start from.
                          If None, uses config.starting_user or picks a random
                          low-privilege user.
            max_length: Maximum path length. Defaults to config.max_attack_path_length.

        Returns:
            List of AttackPath objects. Empty if no path exists.
        """
        self.build_graph()

        # Determine starting user
        start = starting_user or self.manifest.config.starting_user
        if not start:
            # Pick a random standard user
            standard_users = [
                u.sam_account_name
                for u in self.manifest.users
                if u.user_type == UserType.STANDARD
            ]
            if standard_users:
                start = standard_users[0]
            else:
                return []

        # Determine target — Domain Admin or any admin
        target = "DomainAdmins"
        max_len = max_length or self.manifest.config.max_attack_path_length

        if start not in self.graph:
            return []

        # Collect paths to DA group and individual admin users
        raw_paths: list[list[str]] = []
        path_cap = 20  # Cap to avoid explosion

        # Paths to DomainAdmins group
        if target in self.graph:
            try:
                for p in nx.all_simple_paths(
                    self.graph, source=start, target=target, cutoff=max_len
                ):
                    raw_paths.append(p)
                    if len(raw_paths) >= path_cap:
                        break
            except nx.NetworkXError:
                pass

        # Paths to individual admin users
        if len(raw_paths) < path_cap:
            admin_targets = [
                u.sam_account_name
                for u in self.manifest.users
                if u.user_type == UserType.ADMIN
            ]
            for admin in admin_targets:
                if len(raw_paths) >= path_cap:
                    break
                if admin in self.graph and admin != start:
                    try:
                        for p in nx.all_simple_paths(
                            self.graph, source=start, target=admin, cutoff=max_len
                        ):
                            raw_paths.append(p)
                            if len(raw_paths) >= path_cap:
                                break
                    except nx.NetworkXError:
                        continue

        # Convert to AttackPath objects
        attack_paths = []
        for raw_path in raw_paths:
            # Filter by minimum length
            if len(raw_path) - 1 < self.manifest.config.min_attack_path_length:
                continue

            attack_path = self._path_to_attack_path(raw_path, start)
            if attack_path:
                attack_paths.append(attack_path)

        # Deduplicate by strategies used
        seen = set()
        unique_paths = []
        for path in attack_paths:
            key = tuple(path.strategies_used) + tuple(
                s.target_principal for s in path.steps
            )
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)

        return unique_paths

    def has_valid_path(self) -> bool:
        """Quick check: does at least one path exist?"""
        return len(self.find_attack_paths()) > 0

    # ------------------------------------------------------------------
    # Edge builders
    # ------------------------------------------------------------------

    def _add_kerberoasting_edges(self) -> None:
        """Standard users can Kerberoast SPN service accounts."""
        spn_users = [
            u for u in self.manifest.users
            if u.spn and u.password_strength in {
                PasswordStrength.WEAK, PasswordStrength.MEDIUM
            }
        ]
        # Only add edges from standard/service users (not all-to-all)
        standard_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.STANDARD
        ]

        for auth_user in standard_users:
            for spn_user in spn_users:
                if auth_user.sam_account_name == spn_user.sam_account_name:
                    continue
                self.graph.add_edge(
                    auth_user.sam_account_name,
                    spn_user.sam_account_name,
                    technique="kerberoasting",
                    description=(
                        f"Kerberoast {spn_user.sam_account_name} "
                        f"(SPN: {spn_user.spn})"
                    ),
                    tool_command=(
                        f"impacket-GetUserSPNs {self.manifest.domain.name}/"
                        f"{auth_user.sam_account_name}:"
                        f"{auth_user.password} -dc-ip "
                        f"{self._get_dc_ip()} -request"
                    ),
                )

    def _add_asrep_roasting_edges(self) -> None:
        """Standard users can AS-REP roast users without pre-auth."""
        roastable = [
            u for u in self.manifest.users
            if u.asrep_roastable and u.password_strength in {
                PasswordStrength.WEAK, PasswordStrength.MEDIUM
            }
        ]
        standard_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.STANDARD
        ]

        for user in standard_users:
            for target in roastable:
                if user.sam_account_name == target.sam_account_name:
                    continue
                self.graph.add_edge(
                    user.sam_account_name,
                    target.sam_account_name,
                    technique="asrep_roasting",
                    description=(
                        f"AS-REP Roast {target.sam_account_name} "
                        f"(no pre-auth required)"
                    ),
                    tool_command=(
                        f"impacket-GetNPUsers {self.manifest.domain.name}/ "
                        f"-dc-ip {self._get_dc_ip()} "
                        f"-usersfile users.txt -format hashcat"
                    ),
                )

    def _add_acl_abuse_edges(self) -> None:
        """Add edges for ACL-based attacks."""
        for acl in self.manifest.acls:
            # Map ACL rights to techniques
            if acl.right in {
                ACLRight.GENERIC_ALL, ACLRight.WRITE_DACL,
                ACLRight.WRITE_OWNER, ACLRight.FORCE_CHANGE_PASSWORD,
                ACLRight.ADD_MEMBER,
            }:
                self.graph.add_edge(
                    acl.source,
                    acl.target,
                    technique="acl_abuse",
                    description=(
                        f"ACL Abuse: {acl.source} has {acl.right.value} "
                        f"on {acl.target}"
                    ),
                    tool_command=(
                        f"# Exploit {acl.right.value} on {acl.target}"
                    ),
                )

            # DCSync edges
            if acl.right == ACLRight.DS_REPLICATION_GET_CHANGES_ALL:
                # User can DCSync → gets all domain credentials
                for admin in self.manifest.users:
                    if admin.user_type == UserType.ADMIN:
                        self.graph.add_edge(
                            acl.source,
                            admin.sam_account_name,
                            technique="dcsync",
                            description=(
                                f"DCSync: {acl.source} dumps "
                                f"{admin.sam_account_name}'s hash"
                            ),
                            tool_command=(
                                f"impacket-secretsdump "
                                f"{self.manifest.domain.name}/"
                                f"{acl.source}@{self._get_dc_ip()}"
                            ),
                        )

    def _add_credential_pivot_edges(self) -> None:
        """If user A compromised host X, and user B is local admin on X,
        then A can potentially dump B's credentials."""
        for host in self.manifest.hosts:
            # For each pair of local admins, they can pivot to each other
            for la in host.local_admins:
                if la not in self._user_map:
                    continue
                for other_la in host.local_admins:
                    if other_la == la or other_la not in self._user_map:
                        continue
                    self.graph.add_edge(
                        la,
                        other_la,
                        technique="credential_pivot",
                        description=(
                            f"Credential pivot on {host.hostname}: "
                            f"{la} → {other_la}"
                        ),
                        tool_command=(
                            f"impacket-secretsdump "
                            f"{self.manifest.domain.name}/"
                            f"{la}@{host.ip}"
                        ),
                    )

    def _add_adcs_edges(self) -> None:
        """ESC1: If user can enroll and supply SAN → impersonate anyone."""
        admins = [
            u for u in self.manifest.users if u.user_type == UserType.ADMIN
        ]
        if not admins:
            return
        # Pick only one admin target to keep graph small
        target_admin = admins[0]

        for template in self.manifest.cert_templates:
            if not template.enrollee_supplies_subject:
                continue
            if template.requires_manager_approval:
                continue

            for principal in template.enrollment_principals:
                # Skip group names — only add edges for actual users
                if principal not in self._user_map:
                    continue
                self.graph.add_edge(
                    principal,
                    target_admin.sam_account_name,
                    technique="adcs_esc1",
                    description=(
                        f"AD CS ESC1: {principal} enrolls "
                        f"{template.name} as {target_admin.sam_account_name}"
                    ),
                    tool_command=(
                        f"certipy req -u {principal} "
                        f"-target {self._get_ca_hostname()} "
                        f"-template {template.name} "
                        f"-upn {target_admin.upn}"
                    ),
                )

    def _add_share_credential_edges(self) -> None:
        """If a share contains credentials, users who can read it
        gain access to the credential target."""
        # Pre-index: for each sensitive file, find which user's creds are in it
        share_cred_map: list[tuple[str, str, str, str]] = []  # (host, share, file, target_user)
        for host in self.manifest.hosts:
            for share in host.shares:
                for f in share.files:
                    if not f.sensitive:
                        continue
                    for user in self.manifest.users:
                        if user.sam_account_name in f.content:
                            share_cred_map.append(
                                (host.hostname, share.name, f.name, user.sam_account_name)
                            )
                            break  # One target per file is enough

        # Now add edges only from individual user readers (not group explosions)
        for host in self.manifest.hosts:
            for share in host.shares:
                sensitive_files = [f for f in share.files if f.sensitive]
                if not sensitive_files:
                    continue

                # Only add edges for individual users who are readers,
                # limit to 5 readers max to avoid graph explosion
                expanded = self._expand_groups(share.readable_by)
                readers = [r for r in expanded[:5] if r in self._user_map]

                for reader in readers:
                    for hostname, sharename, fname, target_sam in share_cred_map:
                        if hostname == host.hostname and sharename == share.name:
                            if reader != target_sam:
                                self.graph.add_edge(
                                    reader,
                                    target_sam,
                                    technique="share_credential",
                                    description=(
                                        f"Found {target_sam}'s "
                                        f"credentials in {share.path}/{fname}"
                                    ),
                                    tool_command=(
                                        f"smbclient //{hostname}/{sharename} "
                                        f"-U {reader} -c 'get {fname}'"
                                    ),
                                )

    def _add_local_admin_edges(self) -> None:
        """Users who are local admins on a host can access it."""
        for host in self.manifest.hosts:
            for la in host.local_admins:
                if la in self._user_map:
                    # Local admin can dump all credentials on the host
                    self.graph.add_node(la)

    def _add_group_membership_edges(self) -> None:
        """Add edges from group membership to the group node."""
        for group in self.manifest.groups:
            if group.sam_account_name in {
                "DomainAdmins", "EnterpriseAdmins", "Administrators"
            }:
                # Members of DA are effectively Domain Admins
                for member in group.members:
                    self.graph.add_edge(
                        member,
                        "DomainAdmins",
                        technique="group_membership",
                        description=f"{member} is member of {group.name}",
                        tool_command="# Already a member",
                    )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _get_dc_ip(self) -> str:
        """Get the IP of the first Domain Controller."""
        for host in self.manifest.hosts:
            if host.host_type == HostType.DOMAIN_CONTROLLER:
                return host.ip
        return "10.0.1.10"  # fallback

    def _get_ca_hostname(self) -> str:
        """Get the hostname of the Certificate Authority."""
        for host in self.manifest.hosts:
            if host.host_type == HostType.CERTIFICATE_AUTHORITY:
                return host.hostname
        return "CA01"

    def _expand_groups(self, principals: list[str]) -> list[str]:
        """Expand group names to individual user SAMAccountNames."""
        expanded = set()
        for p in principals:
            if p in self._group_map:
                expanded.update(self._group_map[p].members)
            elif p in self._user_map:
                expanded.add(p)
        return list(expanded)

    def _path_to_attack_path(
        self, raw_path: list[str], starting_user: str
    ) -> AttackPath | None:
        """Convert a raw NetworkX path to an AttackPath model."""
        steps = []
        strategies = set()

        for i in range(len(raw_path) - 1):
            source = raw_path[i]
            target = raw_path[i + 1]

            edge_data = self.graph.edges[source, target]
            technique = edge_data.get("technique", "unknown")
            strategies.add(technique)

            # Determine starting host
            starting_host = self.manifest.config.starting_host
            if not starting_host:
                # Find a workstation
                for host in self.manifest.hosts:
                    if host.host_type == HostType.WORKSTATION:
                        starting_host = host.hostname
                        break
                if not starting_host:
                    starting_host = self.manifest.hosts[0].hostname

            steps.append(
                AttackStep(
                    step_number=i + 1,
                    technique=technique,
                    description=edge_data.get("description", ""),
                    source_principal=source,
                    target_principal=target,
                    tool_command=edge_data.get("tool_command", ""),
                )
            )

        if not steps:
            return None

        # Determine starting host for the path
        starting_host = self.manifest.config.starting_host
        if not starting_host:
            for host in self.manifest.hosts:
                if host.host_type == HostType.WORKSTATION:
                    starting_host = host.hostname
                    break
            if not starting_host:
                starting_host = self.manifest.hosts[0].hostname

        return AttackPath(
            path_id=str(uuid.uuid4())[:8],
            starting_user=starting_user,
            starting_host=starting_host,
            target="Domain Admin",
            steps=steps,
            strategies_used=sorted(strategies),
            total_steps=len(steps),
        )
