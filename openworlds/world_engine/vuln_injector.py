"""Vulnerability Injector — injects realistic AD misconfigurations.

This module takes a generated manifest and injects attack-relevant
misconfigurations based on the ManifestConfig flags:
    - Kerberoastable SPNs on service accounts
    - AS-REP roastable users
    - ACL abuse chains (GenericAll, WriteDACL, ForceChangePassword, etc.)
    - AD CS vulnerable certificate templates (ESC1-ESC3)
    - Credentials in SMB shares (SYSVOL, department shares)

Each injector method is idempotent and modifies the manifest in place.
"""

from __future__ import annotations

import random
import uuid

from openworlds.world_engine.models import (
    SPN_PATTERNS,
    ACLEntry,
    ACLRight,
    CertificateTemplate,
    HostType,
    Manifest,
    PasswordStrength,
    ShareFile,
    SMBShare,
    UserType,
)


class VulnerabilityInjector:
    """Injects attack-relevant misconfigurations into a manifest.

    Usage:
        injector = VulnerabilityInjector(manifest)
        injector.inject_all()
        # manifest is now modified with vulnerabilities
    """

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.config = manifest.config
        self.rng = random.Random(manifest.seed)

    def inject_all(self) -> None:
        """Inject all enabled vulnerability types."""
        if self.config.include_kerberoasting:
            self.inject_kerberoastable_spns()

        if self.config.include_asrep_roasting:
            self.inject_asrep_roastable()

        if self.config.include_acl_abuse:
            self.inject_acl_abuse_chains()

        if self.config.include_adcs_abuse:
            self.inject_adcs_templates()

        if self.config.include_credential_in_shares:
            self.inject_credential_in_shares()

    # ------------------------------------------------------------------
    # Kerberoasting
    # ------------------------------------------------------------------

    def inject_kerberoastable_spns(self) -> None:
        """Set SPNs on service accounts to make them Kerberoastable.

        Strategy: Pick 2-5 service accounts and assign them SPNs.
        At least one must have a weak password (crackable).
        """
        service_accounts = [
            u for u in self.manifest.users
            if u.user_type == UserType.SERVICE_ACCOUNT and u.spn is None
        ]

        if not service_accounts:
            return

        # Pick 2-5 accounts to make Kerberoastable
        num_kerberoastable = min(
            self.rng.randint(2, 5), len(service_accounts)
        )
        targets = self.rng.sample(service_accounts, num_kerberoastable)

        # Ensure at least one has a weak password
        weak_set = False
        hosts = self.manifest.hosts

        for user in targets:
            # Pick a random host FQDN for the SPN
            if hosts:
                host = self.rng.choice(hosts)
                pattern = self.rng.choice(SPN_PATTERNS)
                user.spn = pattern.format(fqdn=host.fqdn)
            else:
                user.spn = f"HTTP/svc.{self.manifest.domain.name}"

            # Ensure at least one is crackable
            if not weak_set:
                if user.password_strength != PasswordStrength.WEAK:
                    # Downgrade to weak password
                    from openworlds.world_engine.models import WEAK_PASSWORDS
                    user.password = self.rng.choice(WEAK_PASSWORDS)
                    user.password_strength = PasswordStrength.WEAK
                    user.nt_hash = user.compute_nt_hash(user.password)
                weak_set = True

    # ------------------------------------------------------------------
    # AS-REP Roasting
    # ------------------------------------------------------------------

    def inject_asrep_roastable(self) -> None:
        """Mark some users as AS-REP Roastable (DONT_REQUIRE_PREAUTH).

        Strategy: Pick 1-3 standard users and disable pre-authentication.
        At least one must have a weak password.
        """
        standard_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.STANDARD and not u.asrep_roastable
        ]

        if not standard_users:
            return

        num_roastable = min(self.rng.randint(1, 3), len(standard_users))
        targets = self.rng.sample(standard_users, num_roastable)

        for user in targets:
            user.asrep_roastable = True

            # Ensure at least one has a weak password
            if user.password_strength != PasswordStrength.WEAK:
                from openworlds.world_engine.models import WEAK_PASSWORDS
                user.password = self.rng.choice(WEAK_PASSWORDS)
                user.password_strength = PasswordStrength.WEAK
                user.nt_hash = user.compute_nt_hash(user.password)

    # ------------------------------------------------------------------
    # ACL Abuse Chains
    # ------------------------------------------------------------------

    def inject_acl_abuse_chains(self) -> None:
        """Inject ACL-based attack paths.

        Strategy: Create a chain of 2-4 ACL entries that eventually
        lead to a high-privilege target (Domain Admin or a group
        that gives admin access).

        Examples:
            user1 --GenericAll--> user2 --ForceChangePassword--> admin1
            user1 --WriteDACL--> group1 --AddMember--> Domain Admins
        """
        standard_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.STANDARD
        ]
        service_accounts = [
            u for u in self.manifest.users
            if u.user_type == UserType.SERVICE_ACCOUNT
        ]
        admin_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.ADMIN
        ]
        groups = self.manifest.groups

        if not standard_users or not admin_users:
            return

        # Chain 1: standard user -> GenericAll -> service account -> ForceChangePassword -> admin
        if service_accounts and admin_users:
            chain_source = self.rng.choice(standard_users)
            chain_mid = self.rng.choice(service_accounts)
            chain_target = self.rng.choice(admin_users)

            self.manifest.acls.extend([
                ACLEntry(
                    source=chain_source.sam_account_name,
                    target=chain_mid.sam_account_name,
                    right=ACLRight.GENERIC_ALL,
                ),
                ACLEntry(
                    source=chain_mid.sam_account_name,
                    target=chain_target.sam_account_name,
                    right=ACLRight.FORCE_CHANGE_PASSWORD,
                ),
            ])

        # Chain 2: standard user -> WriteDACL -> another user -> GenericWrite -> group
        if len(standard_users) >= 2:
            user_a = self.rng.choice(standard_users)
            user_b = self.rng.choice(
                [u for u in standard_users if u != user_a]
            )

            # Find a group that gives elevated access
            target_groups = [
                g for g in groups
                if g.sam_account_name in {
                    "ITAdmins", "SQLAdmins", "WebAdmins",
                    "BackupOperators", "ServerOperators",
                }
            ]
            if target_groups:
                target_group = self.rng.choice(target_groups)
                self.manifest.acls.extend([
                    ACLEntry(
                        source=user_a.sam_account_name,
                        target=user_b.sam_account_name,
                        right=ACLRight.WRITE_DACL,
                    ),
                    ACLEntry(
                        source=user_b.sam_account_name,
                        target=target_group.sam_account_name,
                        right=ACLRight.ADD_MEMBER,
                    ),
                ])

        # Chain 3: Group member -> GenericAll -> Domain Admins
        # (This creates a direct escalation path)
        if len(standard_users) >= 3:
            escalation_user = self.rng.choice(standard_users)
            da_group = next(
                (g for g in groups if g.sam_account_name == "DomainAdmins"),
                None,
            )
            if da_group:
                self.manifest.acls.append(
                    ACLEntry(
                        source=escalation_user.sam_account_name,
                        target=da_group.sam_account_name,
                        right=self.rng.choice([
                            ACLRight.GENERIC_ALL,
                            ACLRight.WRITE_DACL,
                            ACLRight.WRITE_OWNER,
                        ]),
                    )
                )

        # DCSync rights (for secretsdump)
        # Give one mid-tier user DCSync rights
        if service_accounts:
            dcsync_user = self.rng.choice(service_accounts)
            self.manifest.acls.extend([
                ACLEntry(
                    source=dcsync_user.sam_account_name,
                    target=self.manifest.domain.name,
                    right=ACLRight.DS_REPLICATION_GET_CHANGES,
                ),
                ACLEntry(
                    source=dcsync_user.sam_account_name,
                    target=self.manifest.domain.name,
                    right=ACLRight.DS_REPLICATION_GET_CHANGES_ALL,
                ),
            ])

    # ------------------------------------------------------------------
    # AD CS Abuse
    # ------------------------------------------------------------------

    def inject_adcs_templates(self) -> None:
        """Inject vulnerable certificate templates (ESC1-ESC3).

        Creates a CA host if none exists, then adds vulnerable templates.
        """
        # Ensure there's a CA in the network
        ca_hosts = [
            h for h in self.manifest.hosts
            if h.host_type == HostType.CERTIFICATE_AUTHORITY
        ]

        if not ca_hosts:
            # No CA to inject templates for — skip
            return

        standard_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.STANDARD
        ]

        # ESC1: Template where enrollee can supply the Subject Alternative Name
        esc1_template = CertificateTemplate(
            name="VulnWebServer",
            display_name="Vulnerable Web Server Authentication",
            oid=f"1.3.6.1.4.1.311.21.8.{self.rng.randint(1000, 9999)}",
            enrollment_principals=[
                u.sam_account_name
                for u in self.rng.sample(
                    standard_users, min(3, len(standard_users))
                )
            ] + ["DomainUsers"],
            enrollee_supplies_subject=True,  # ESC1 vuln!
            any_purpose=False,
            agent_template=False,
            requires_manager_approval=False,  # No approval needed!
            authorized_signatures_required=0,
        )
        self.manifest.cert_templates.append(esc1_template)

        # ESC2: Template with Any Purpose EKU
        esc2_template = CertificateTemplate(
            name="MisconfiguredAuth",
            display_name="Misconfigured Authentication Template",
            oid=f"1.3.6.1.4.1.311.21.8.{self.rng.randint(1000, 9999)}",
            enrollment_principals=["DomainUsers"],
            enrollee_supplies_subject=False,
            any_purpose=True,  # ESC2 vuln!
            agent_template=False,
            requires_manager_approval=False,
            authorized_signatures_required=0,
        )
        self.manifest.cert_templates.append(esc2_template)

        # Safe template (for realism — not everything is vulnerable)
        safe_template = CertificateTemplate(
            name="SecureWorkstation",
            display_name="Secure Workstation Authentication",
            oid=f"1.3.6.1.4.1.311.21.8.{self.rng.randint(1000, 9999)}",
            enrollment_principals=["DomainComputers"],
            enrollee_supplies_subject=False,
            any_purpose=False,
            agent_template=False,
            requires_manager_approval=True,
            authorized_signatures_required=1,
        )
        self.manifest.cert_templates.append(safe_template)

    # ------------------------------------------------------------------
    # Credentials in Shares
    # ------------------------------------------------------------------

    def inject_credential_in_shares(self) -> None:
        """Plant credentials in SMB shares.

        Strategies:
            1. GPP password in SYSVOL (Groups.xml with cpassword)
            2. Password in a department share script
            3. Credentials in a config file
        """
        # Strategy 1: GPP cpassword in SYSVOL
        dc_hosts = [
            h for h in self.manifest.hosts
            if h.host_type == HostType.DOMAIN_CONTROLLER
        ]
        admin_users = [
            u for u in self.manifest.users
            if u.user_type == UserType.ADMIN
        ]
        service_accounts = [
            u for u in self.manifest.users
            if u.user_type == UserType.SERVICE_ACCOUNT
        ]

        if dc_hosts and (admin_users or service_accounts):
            dc = dc_hosts[0]
            target_user = self.rng.choice(
                admin_users if admin_users else service_accounts
            )

            sysvol = next(
                (s for s in dc.shares if s.name == "SYSVOL"), None
            )
            if sysvol:
                # GPP Groups.xml with embedded password
                gpp_content = (
                    f'<?xml version="1.0" encoding="utf-8"?>\n'
                    f'<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">\n'
                    f'  <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}" '
                    f'name="{target_user.sam_account_name}" '
                    f'image="2" changed="2023-01-15 09:23:11" '
                    f'uid="{{{str(uuid.uuid4()).upper()}}}">\n'
                    f'    <Properties action="U" subAuthority="" '
                    f'newName="" fullName="{target_user.display_name}" '
                    f'description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGM'
                    f'eI8YDNLHedXMsP1B+56a2mNt2T1LtJFo6yQg==" '
                    f'changeLogon="0" noChange="1" neverExpires="1" '
                    f'acctDisabled="0" userName="{target_user.sam_account_name}"/>\n'
                    f'  </User>\n'
                    f'</Groups>'
                )
                sysvol.files.append(
                    ShareFile(
                        name="Groups.xml",
                        path=f"\\\\{dc.hostname}\\SYSVOL\\{self.manifest.domain.name}"
                             f"\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}"
                             f"\\Machine\\Preferences\\Groups\\Groups.xml",
                        content=gpp_content,
                        sensitive=True,
                    )
                )

        # Strategy 2: Password in a script on a file server
        file_servers = [
            h for h in self.manifest.hosts
            if h.host_type == HostType.FILE_SERVER
        ]
        if file_servers and service_accounts:
            fs = file_servers[0]
            cred_user = self.rng.choice(service_accounts)

            # Create a department share with a script containing credentials
            dept_share = SMBShare(
                name="IT$",
                path=f"\\\\{fs.hostname}\\IT$",
                readable_by=["ITAdmins", "DomainUsers"],
                writable_by=["ITAdmins"],
                files=[
                    ShareFile(
                        name="deploy.ps1",
                        path=f"\\\\{fs.hostname}\\IT$\\scripts\\deploy.ps1",
                        content=(
                            f"# Deployment script\n"
                            f"$cred = New-Object System.Management.Automation.PSCredential(\n"
                            f'    "{self.manifest.domain.netbios_name}\\{cred_user.sam_account_name}",\n'
                            f'    (ConvertTo-SecureString "{cred_user.password}" -AsPlainText -Force)\n'
                            f")\n"
                            f"Invoke-Command -ComputerName $targetHost -Credential $cred "
                            f"-ScriptBlock {{ ... }}\n"
                        ),
                        sensitive=True,
                    ),
                    ShareFile(
                        name="README.txt",
                        path=f"\\\\{fs.hostname}\\IT$\\README.txt",
                        content="IT Department shared scripts and tools.\n",
                        sensitive=False,
                    ),
                ],
            )
            fs.shares.append(dept_share)

        # Strategy 3: Config file with database credentials
        sql_servers = [
            h for h in self.manifest.hosts
            if h.host_type == HostType.SQL_SERVER
        ]
        if sql_servers and service_accounts:
            sql = sql_servers[0]
            db_user = self.rng.choice(service_accounts)

            config_share = SMBShare(
                name="AppConfig",
                path=f"\\\\{sql.hostname}\\AppConfig",
                readable_by=["DomainUsers"],
                writable_by=["SQLAdmins"],
                files=[
                    ShareFile(
                        name="web.config",
                        path=f"\\\\{sql.hostname}\\AppConfig\\web.config",
                        content=(
                            f'<?xml version="1.0" encoding="utf-8"?>\n'
                            f"<configuration>\n"
                            f"  <connectionStrings>\n"
                            f'    <add name="DefaultConnection"\n'
                            f'         connectionString="Server={sql.hostname};'
                            f"Database=AppDB;"
                            f"User Id={db_user.sam_account_name};"
                            f'Password={db_user.password};" />\n'
                            f"  </connectionStrings>\n"
                            f"</configuration>\n"
                        ),
                        sensitive=True,
                    ),
                ],
            )
            sql.shares.append(config_share)
