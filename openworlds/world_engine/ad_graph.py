"""Manifest Generator — creates realistic Active Directory networks.

This module generates a complete AD network manifest from a ManifestConfig.
It follows this pipeline:
    1. Generate domain & subnets
    2. Generate OUs
    3. Generate groups (built-in + random)
    4. Generate users (standard + admin + service accounts)
    5. Generate hosts with services
    6. Assign users to groups and local admin roles
    7. Map CVEs to hosts based on services

The vulnerability injection and attack path validation are handled by
separate modules (vuln_injector.py and path_validator.py).
"""

from __future__ import annotations

import random
import string
import uuid
from datetime import datetime, timedelta

from openworlds.world_engine.models import (
    ACLEntry,
    CVE,
    CVE_DATABASE,
    CertificateTemplate,
    Domain,
    GPO,
    Group,
    Host,
    HostType,
    Manifest,
    ManifestConfig,
    OrganizationalUnit,
    PasswordStrength,
    SMBShare,
    SPN_PATTERNS,
    SERVICE_ACCOUNT_PREFIXES,
    SERVICE_ACCOUNT_PURPOSES,
    SERVICE_TEMPLATES,
    Service,
    ShareFile,
    Subnet,
    User,
    UserType,
    DEPARTMENT_NAMES,
    FIRST_NAMES,
    LAST_NAMES,
    MEDIUM_PASSWORDS,
    STRONG_PASSWORDS,
    WEAK_PASSWORDS,
)


class ManifestGenerator:
    """Generates a complete AD network manifest from configuration.

    Usage:
        config = ManifestConfig(num_hosts=20, num_users=50, seed=42)
        generator = ManifestGenerator(config)
        manifest = generator.generate()
    """

    def __init__(self, config: ManifestConfig) -> None:
        self.config = config
        self.rng = random.Random(config.seed)
        self._used_ips: set[str] = set()
        self._used_names: set[str] = set()
        self._used_hostnames: set[str] = set()

    def generate(self) -> Manifest:
        """Generate a complete manifest following the pipeline."""
        domain = self._generate_domain()
        ous = self._generate_ous(domain)
        groups = self._generate_groups(domain)
        users = self._generate_users(domain, ous, groups)
        hosts = self._generate_hosts(domain, users)
        gpos = self._generate_gpos(domain, ous)

        # Assign users to local admin groups on hosts
        self._assign_local_admins(hosts, users, groups)

        # ACLs and cert templates are initially empty — vuln_injector fills them
        manifest = Manifest(
            domain=domain,
            hosts=hosts,
            users=users,
            groups=groups,
            ous=ous,
            acls=[],
            cert_templates=[],
            gpos=gpos,
            attack_paths=[],
            generated_at=datetime.now(),
            seed=self.config.seed or self.rng.randint(0, 2**32),
            config=self.config,
        )
        return manifest

    # ------------------------------------------------------------------
    # Domain & Subnet generation
    # ------------------------------------------------------------------

    def _generate_domain(self) -> Domain:
        """Generate the AD domain with subnets."""
        domain_names = [
            "NORTH", "SOUTH", "EAST", "WEST", "CORP", "ACME", "GLOBEX",
            "INITECH", "UMBRELLA", "WAYNE", "STARK", "SHIELD", "PHOENIX",
            "HORIZON", "ATLAS", "NEXUS", "VERTEX", "MATRIX", "CYBER",
        ]
        netbios = self.rng.choice(domain_names)
        fqdn = f"{netbios}.local"

        # Generate domain SID
        domain_sid = self._generate_sid()

        # Generate subnets
        subnets = self._generate_subnets()

        return Domain(
            name=fqdn,
            netbios_name=netbios,
            functional_level=self.rng.choice(["2016", "2019", "2022"]),
            domain_sid=domain_sid,
            subnets=subnets,
            forest_root=True,
        )

    def _generate_subnets(self) -> list[Subnet]:
        """Generate network subnets."""
        subnet_configs = [
            ("10.0.1.0/24", "ServerSubnet", 10),
            ("10.0.2.0/24", "WorkstationSubnet", 20),
            ("10.0.3.0/24", "DMZSubnet", 30),
            ("10.0.4.0/24", "ManagementSubnet", 40),
            ("10.0.5.0/24", "DevSubnet", 50),
            ("10.0.6.0/24", "LabSubnet", 60),
            ("10.0.7.0/24", "BackupSubnet", 70),
            ("10.0.8.0/24", "VoIPSubnet", 80),
            ("10.0.9.0/24", "GuestSubnet", 90),
            ("10.0.10.0/24", "SecuritySubnet", 100),
        ]

        subnets = []
        for i in range(min(self.config.num_subnets, len(subnet_configs))):
            cidr, name, vlan = subnet_configs[i]
            gateway = cidr.replace(".0/24", ".1")
            subnets.append(
                Subnet(cidr=cidr, name=name, vlan_id=vlan, gateway=gateway)
            )
        return subnets

    # ------------------------------------------------------------------
    # OU generation
    # ------------------------------------------------------------------

    def _generate_ous(self, domain: Domain) -> list[OrganizationalUnit]:
        """Generate organizational units in a realistic hierarchy."""
        dc_components = ",".join(f"DC={p}" for p in domain.name.split("."))
        ous: list[OrganizationalUnit] = []

        # Pick department names
        departments = self.rng.sample(
            DEPARTMENT_NAMES, min(self.config.num_ous, len(DEPARTMENT_NAMES))
        )

        # Top-level OUs
        for dept in departments:
            dn = f"OU={dept},{dc_components}"
            ous.append(
                OrganizationalUnit(
                    name=dept,
                    dn=dn,
                    parent_dn=dc_components,
                    gpos_linked=[],
                    children=[],
                )
            )

        # Add some nested OUs (Users, Computers, Servers under some depts)
        parent_ous = ous[:3]  # Nest under the first 3 departments
        for parent in parent_ous:
            for child_name in ["Users", "Computers", "Servers"]:
                child_dn = f"OU={child_name},{parent.dn}"
                child_ou = OrganizationalUnit(
                    name=f"{parent.name} {child_name}",
                    dn=child_dn,
                    parent_dn=parent.dn,
                    gpos_linked=[],
                    children=[],
                )
                ous.append(child_ou)
                parent.children.append(child_dn)

        return ous

    # ------------------------------------------------------------------
    # Group generation
    # ------------------------------------------------------------------

    def _generate_groups(self, domain: Domain) -> list[Group]:
        """Generate AD groups (built-in + custom)."""
        dc_components = ",".join(f"DC={p}" for p in domain.name.split("."))
        groups: list[Group] = []

        # Built-in groups (always present)
        builtin_groups = [
            ("Domain Admins", f"S-1-5-21-{domain.domain_sid.split('-', 4)[-1]}-512", "global"),
            ("Domain Users", f"S-1-5-21-{domain.domain_sid.split('-', 4)[-1]}-513", "global"),
            ("Domain Computers", f"S-1-5-21-{domain.domain_sid.split('-', 4)[-1]}-515", "global"),
            ("Enterprise Admins", f"S-1-5-21-{domain.domain_sid.split('-', 4)[-1]}-519", "universal"),
            ("Administrators", "S-1-5-32-544", "domain_local"),
            ("Backup Operators", "S-1-5-32-551", "domain_local"),
            ("Server Operators", "S-1-5-32-549", "domain_local"),
            ("Account Operators", "S-1-5-32-548", "domain_local"),
            ("Remote Desktop Users", "S-1-5-32-555", "domain_local"),
        ]

        for name, sid, scope in builtin_groups:
            sam = name.replace(" ", "")
            dn = f"CN={name},CN=Users,{dc_components}"
            groups.append(
                Group(
                    name=name,
                    sam_account_name=sam,
                    dn=dn,
                    sid=sid,
                    group_type="security",
                    group_scope=scope,
                    members=[],
                    member_of=[],
                )
            )

        # Custom departmental / role groups
        custom_group_names = [
            "IT Admins", "Help Desk", "Web Admins", "SQL Admins",
            "VPN Users", "Developers", "Project Managers", "Data Analysts",
            "Security Team", "Network Ops", "DevOps", "Database Team",
            "Exchange Admins", "File Share Admins", "Print Admins",
        ]

        remaining = max(0, self.config.num_groups - len(builtin_groups))
        selected_custom = self.rng.sample(
            custom_group_names, min(remaining, len(custom_group_names))
        )

        for name in selected_custom:
            sam = name.replace(" ", "")
            sid = self._generate_user_sid(domain.domain_sid)
            dn = f"CN={name},OU=Groups,{dc_components}"
            groups.append(
                Group(
                    name=name,
                    sam_account_name=sam,
                    dn=dn,
                    sid=sid,
                    group_type="security",
                    group_scope="global",
                    members=[],
                    member_of=[],
                )
            )

        return groups

    # ------------------------------------------------------------------
    # User generation
    # ------------------------------------------------------------------

    def _generate_users(
        self, domain: Domain, ous: list[OrganizationalUnit], groups: list[Group]
    ) -> list[User]:
        """Generate AD users: standard, admin, and service accounts."""
        dc_components = ",".join(f"DC={p}" for p in domain.name.split("."))
        users: list[User] = []

        # Determine user distribution
        num_service = max(3, self.config.num_users // 10)  # ~10% service accounts
        num_admin = max(2, self.config.num_users // 15)  # ~7% admins
        num_standard = self.config.num_users - num_service - num_admin

        # Get department OUs (top-level only)
        dept_ous = [ou for ou in ous if ou.parent_dn and "OU=" not in ou.parent_dn]
        if not dept_ous:
            dept_ous = ous[:1]

        # --- Standard users ---
        for i in range(num_standard):
            user = self._create_standard_user(domain, dept_ous, dc_components)
            users.append(user)

        # --- Admin users ---
        for i in range(num_admin):
            user = self._create_admin_user(domain, dc_components, i)
            users.append(user)

        # --- Service accounts ---
        for i in range(num_service):
            user = self._create_service_account(domain, dc_components, i)
            users.append(user)

        # Assign users to groups
        self._assign_group_membership(users, groups, domain)

        return users

    def _create_standard_user(
        self, domain: Domain, dept_ous: list[OrganizationalUnit], dc_components: str
    ) -> User:
        """Create a standard domain user."""
        first = self.rng.choice(FIRST_NAMES)
        last = self.rng.choice(LAST_NAMES)

        # Generate unique SAMAccountName
        sam = f"{first[0].lower()}.{last.lower()}"
        while sam in self._used_names:
            sam = f"{first[0].lower()}.{last.lower()}{self.rng.randint(1, 99)}"
        self._used_names.add(sam)

        ou = self.rng.choice(dept_ous)
        password = self.rng.choice(WEAK_PASSWORDS + MEDIUM_PASSWORDS)
        strength = (
            PasswordStrength.WEAK
            if password in WEAK_PASSWORDS
            else PasswordStrength.MEDIUM
        )

        return User(
            sam_account_name=sam,
            display_name=f"{first} {last}",
            upn=f"{sam}@{domain.name}",
            dn=f"CN={first} {last},{ou.dn}",
            user_type=UserType.STANDARD,
            password=password,
            password_strength=strength,
            nt_hash=User.compute_nt_hash(password),
            sid=self._generate_user_sid(domain.domain_sid),
            member_of=["DomainUsers"],
            ou=ou.dn,
            last_logon=self._random_timestamp(days_ago=30),
            pwd_last_set=self._random_timestamp(days_ago=90),
        )

    def _create_admin_user(
        self, domain: Domain, dc_components: str, index: int
    ) -> User:
        """Create an admin user (IT admin, DA, etc.)."""
        admin_patterns = [
            ("adm_{last}", "Admin"),
            ("{first[0]}.{last}.admin", "Admin"),
            ("admin.{last}", "Admin"),
        ]
        first = self.rng.choice(FIRST_NAMES)
        last = self.rng.choice(LAST_NAMES)

        # Generate admin username
        sam = f"adm_{last.lower()}"
        while sam in self._used_names:
            sam = f"adm_{last.lower()}{self.rng.randint(1, 99)}"
        self._used_names.add(sam)

        # Admins get stronger passwords
        password = self.rng.choice(MEDIUM_PASSWORDS + STRONG_PASSWORDS)
        strength = (
            PasswordStrength.MEDIUM
            if password in MEDIUM_PASSWORDS
            else PasswordStrength.STRONG
        )

        return User(
            sam_account_name=sam,
            display_name=f"{first} {last} (Admin)",
            upn=f"{sam}@{domain.name}",
            dn=f"CN={first} {last} (Admin),OU=IT,{dc_components}",
            user_type=UserType.ADMIN,
            password=password,
            password_strength=strength,
            nt_hash=User.compute_nt_hash(password),
            sid=self._generate_user_sid(domain.domain_sid),
            member_of=["DomainAdmins", "Administrators"],
            ou=f"OU=IT,{dc_components}",
            admin_count=True,
            last_logon=self._random_timestamp(days_ago=7),
            pwd_last_set=self._random_timestamp(days_ago=60),
        )

    def _create_service_account(
        self, domain: Domain, dc_components: str, index: int
    ) -> User:
        """Create a service account (may be Kerberoastable)."""
        prefix = self.rng.choice(SERVICE_ACCOUNT_PREFIXES)
        purpose = self.rng.choice(SERVICE_ACCOUNT_PURPOSES)

        sam = f"{prefix}{purpose}"
        while sam in self._used_names:
            sam = f"{prefix}{purpose}{self.rng.randint(1, 99)}"
        self._used_names.add(sam)

        # Service accounts often have weak passwords (realistic!)
        password = self.rng.choice(WEAK_PASSWORDS + MEDIUM_PASSWORDS)
        strength = (
            PasswordStrength.WEAK
            if password in WEAK_PASSWORDS
            else PasswordStrength.MEDIUM
        )

        return User(
            sam_account_name=sam,
            display_name=f"Service Account - {purpose.title()}",
            upn=f"{sam}@{domain.name}",
            dn=f"CN={sam},OU=Service Accounts,{dc_components}",
            user_type=UserType.SERVICE_ACCOUNT,
            password=password,
            password_strength=strength,
            nt_hash=User.compute_nt_hash(password),
            sid=self._generate_user_sid(domain.domain_sid),
            member_of=["DomainUsers"],
            ou=f"OU=Service Accounts,{dc_components}",
            description=f"Service account for {purpose} operations",
            last_logon=self._random_timestamp(days_ago=1),
            pwd_last_set=self._random_timestamp(days_ago=365),
        )

    def _assign_group_membership(
        self, users: list[User], groups: list[Group], domain: Domain
    ) -> None:
        """Assign users to groups realistically."""
        # Find key groups
        group_map = {g.sam_account_name: g for g in groups}

        # All users → Domain Users
        domain_users = group_map.get("DomainUsers")
        if domain_users:
            domain_users.members = [u.sam_account_name for u in users]

        # Admin users → Domain Admins (already set in member_of, sync to group)
        domain_admins = group_map.get("DomainAdmins")
        if domain_admins:
            domain_admins.members = [
                u.sam_account_name for u in users if u.user_type == UserType.ADMIN
            ]

        # Randomly assign standard users to custom groups
        custom_groups = [
            g for g in groups
            if g.sam_account_name not in {
                "DomainAdmins", "DomainUsers", "DomainComputers",
                "EnterpriseAdmins", "Administrators", "BackupOperators",
                "ServerOperators", "AccountOperators", "RemoteDesktopUsers",
            }
        ]
        standard_users = [u for u in users if u.user_type == UserType.STANDARD]

        for group in custom_groups:
            # Each custom group gets 20-50% of standard users
            num_members = self.rng.randint(
                len(standard_users) // 5,
                max(len(standard_users) // 2, 1),
            )
            members = self.rng.sample(standard_users, min(num_members, len(standard_users)))
            group.members = [u.sam_account_name for u in members]
            for user in members:
                if group.sam_account_name not in user.member_of:
                    user.member_of.append(group.sam_account_name)

    # ------------------------------------------------------------------
    # Host generation
    # ------------------------------------------------------------------

    def _generate_hosts(self, domain: Domain, users: list[User]) -> list[Host]:
        """Generate hosts with realistic services."""
        hosts: list[Host] = []

        # Always create at least 1 DC
        num_dcs = max(1, self.config.num_hosts // 10)
        # Distribute remaining hosts
        remaining = self.config.num_hosts - num_dcs

        # Host type distribution (after DCs)
        type_weights = {
            HostType.CERTIFICATE_AUTHORITY: 0.05,
            HostType.SQL_SERVER: 0.10,
            HostType.WEB_SERVER: 0.10,
            HostType.MAIL_SERVER: 0.05,
            HostType.FILE_SERVER: 0.10,
            HostType.CI_SERVER: 0.05,
            HostType.WORKSTATION: 0.45,
            HostType.PRINT_SERVER: 0.05,
            HostType.VPN_ENDPOINT: 0.05,
        }

        # Generate DCs
        for i in range(num_dcs):
            host = self._create_host(
                domain, HostType.DOMAIN_CONTROLLER, f"DC{i + 1:02d}",
                subnet_index=0,
            )
            hosts.append(host)

        # Generate other hosts by type
        host_types_pool: list[HostType] = []
        for htype, weight in type_weights.items():
            count = max(1, int(remaining * weight))
            host_types_pool.extend([htype] * count)

        self.rng.shuffle(host_types_pool)
        host_types_pool = host_types_pool[:remaining]

        # Build hostname counters
        type_counters: dict[HostType, int] = {}
        hostname_prefixes = {
            HostType.CERTIFICATE_AUTHORITY: "CA",
            HostType.SQL_SERVER: "SQL",
            HostType.WEB_SERVER: "WEB",
            HostType.MAIL_SERVER: "MAIL",
            HostType.FILE_SERVER: "FS",
            HostType.CI_SERVER: "CI",
            HostType.WORKSTATION: "WS",
            HostType.PRINT_SERVER: "PRINT",
            HostType.VPN_ENDPOINT: "VPN",
        }

        for htype in host_types_pool:
            type_counters[htype] = type_counters.get(htype, 0) + 1
            prefix = hostname_prefixes.get(htype, "SRV")
            hostname = f"{prefix}{type_counters[htype]:02d}"

            # Workstations go to subnet 1 (WorkstationSubnet), servers to subnet 0
            subnet_idx = 1 if htype == HostType.WORKSTATION else 0
            subnet_idx = min(subnet_idx, len(domain.subnets) - 1)

            host = self._create_host(domain, htype, hostname, subnet_index=subnet_idx)
            hosts.append(host)

        return hosts

    def _create_host(
        self, domain: Domain, host_type: HostType, hostname: str,
        subnet_index: int = 0,
    ) -> Host:
        """Create a single host with appropriate services."""
        subnet = domain.subnets[subnet_index]
        ip = self._allocate_ip(subnet)
        fqdn = f"{hostname}.{domain.name}"

        # OS assignment based on host type
        if host_type == HostType.WORKSTATION:
            os_choices = [
                ("Windows 10 Pro", "19045"),
                ("Windows 11 Pro", "22631"),
                ("Windows 10 Enterprise", "19044"),
            ]
        else:
            os_choices = [
                ("Windows Server 2019 Standard", "17763"),
                ("Windows Server 2022 Standard", "20348"),
                ("Windows Server 2016 Standard", "14393"),
            ]
        os_name, os_build = self.rng.choice(os_choices)

        # Generate services from the template
        services = self._create_services_for_host(host_type, fqdn, os_name, os_build)

        # MAC address
        mac = self._generate_mac()

        # Default shares (most Windows hosts have these)
        shares = [
            SMBShare(
                name="ADMIN$",
                path=f"\\\\{hostname}\\ADMIN$",
                readable_by=[],
                writable_by=[],
                files=[],
            ),
            SMBShare(
                name="C$",
                path=f"\\\\{hostname}\\C$",
                readable_by=[],
                writable_by=[],
                files=[],
            ),
            SMBShare(
                name="IPC$",
                path=f"\\\\{hostname}\\IPC$",
                readable_by=["DomainUsers"],
                writable_by=[],
                files=[],
            ),
        ]

        # DCs get SYSVOL and NETLOGON
        if host_type == HostType.DOMAIN_CONTROLLER:
            shares.extend([
                SMBShare(
                    name="SYSVOL",
                    path=f"\\\\{hostname}\\SYSVOL",
                    readable_by=["DomainUsers"],
                    writable_by=["DomainAdmins"],
                    files=[],
                ),
                SMBShare(
                    name="NETLOGON",
                    path=f"\\\\{hostname}\\NETLOGON",
                    readable_by=["DomainUsers"],
                    writable_by=["DomainAdmins"],
                    files=[],
                ),
            ])

        return Host(
            hostname=hostname,
            fqdn=fqdn,
            ip=ip,
            mac=mac,
            os=os_name,
            os_build=os_build,
            host_type=host_type,
            subnet=subnet.cidr,
            services=services,
            local_admins=[],
            cves=[],
            shares=shares,
            installed_software=self._random_software(host_type),
            enabled=True,
        )

    def _create_services_for_host(
        self, host_type: HostType, fqdn: str, os_name: str, os_build: str
    ) -> list[Service]:
        """Create services for a host based on its type."""
        templates = SERVICE_TEMPLATES.get(host_type, [])
        services = []

        for tmpl in templates:
            svc = Service(
                name=tmpl["name"],
                port=tmpl["port"],
                protocol=tmpl.get("protocol", "tcp"),
                version=tmpl["version"],
                product=tmpl.get("product", ""),
                extra_info=tmpl.get("extra_info", ""),
                state="open",
            )
            services.append(svc)

        return services

    # ------------------------------------------------------------------
    # GPO generation
    # ------------------------------------------------------------------

    def _generate_gpos(
        self, domain: Domain, ous: list[OrganizationalUnit]
    ) -> list[GPO]:
        """Generate Group Policy Objects."""
        dc_components = ",".join(f"DC={p}" for p in domain.name.split("."))
        gpos = [
            GPO(
                name="Default Domain Policy",
                display_name="Default Domain Policy",
                gpo_id=str(uuid.uuid4()).upper(),
                linked_ous=[dc_components],
                settings={
                    "PasswordMinLength": 8,
                    "PasswordComplexity": True,
                    "LockoutThreshold": 5,
                    "MaxPasswordAge": 90,
                },
            ),
            GPO(
                name="Default Domain Controllers Policy",
                display_name="Default Domain Controllers Policy",
                gpo_id=str(uuid.uuid4()).upper(),
                linked_ous=[f"OU=Domain Controllers,{dc_components}"],
                settings={
                    "AuditLogonEvents": True,
                    "AuditObjectAccess": True,
                },
            ),
        ]

        # Link GPOs to some OUs
        for ou in ous[:3]:
            if ou.gpos_linked is not None:
                ou.gpos_linked.append(gpos[0].name)

        return gpos

    # ------------------------------------------------------------------
    # Local admin assignment
    # ------------------------------------------------------------------

    def _assign_local_admins(
        self, hosts: list[Host], users: list[User], groups: list[Group]
    ) -> None:
        """Assign local admin rights — admins get admin on servers."""
        admin_users = [u for u in users if u.user_type == UserType.ADMIN]
        admin_sams = [u.sam_account_name for u in admin_users]

        for host in hosts:
            if host.host_type == HostType.DOMAIN_CONTROLLER:
                # DAs are local admins on DCs
                host.local_admins = admin_sams.copy()
            elif host.host_type == HostType.WORKSTATION:
                # Random 1-2 admins on workstations
                num = min(len(admin_sams), self.rng.randint(1, 2))
                host.local_admins = self.rng.sample(admin_sams, num)
            else:
                # Servers: relevant admins (e.g., SQL admins on SQL server)
                host.local_admins = self.rng.sample(
                    admin_sams, min(len(admin_sams), 2)
                )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _generate_sid(self) -> str:
        """Generate a realistic domain SID."""
        parts = [self.rng.randint(1000000000, 4294967295) for _ in range(3)]
        return f"S-1-5-21-{parts[0]}-{parts[1]}-{parts[2]}"

    def _generate_user_sid(self, domain_sid: str) -> str:
        """Generate a user/group SID under the domain SID."""
        rid = self.rng.randint(1100, 99999)
        return f"{domain_sid}-{rid}"

    def _allocate_ip(self, subnet: Subnet) -> str:
        """Allocate a unique IP from the subnet."""
        base = subnet.cidr.split("/")[0]
        octets = base.split(".")
        prefix = ".".join(octets[:3])

        for _ in range(250):
            last_octet = self.rng.randint(10, 254)
            ip = f"{prefix}.{last_octet}"
            if ip not in self._used_ips:
                self._used_ips.add(ip)
                return ip
        # Fallback
        fallback = f"{prefix}.{len(self._used_ips) + 10}"
        self._used_ips.add(fallback)
        return fallback

    def _generate_mac(self) -> str:
        """Generate a realistic VMware-style MAC address."""
        # VMware OUI prefix
        prefix = "00:50:56"
        suffix = ":".join(f"{self.rng.randint(0, 255):02x}" for _ in range(3))
        return f"{prefix}:{suffix}"

    def _random_timestamp(self, days_ago: int) -> str:
        """Generate a random timestamp within the given window."""
        delta = timedelta(days=self.rng.randint(0, days_ago))
        dt = datetime.now() - delta
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _random_software(self, host_type: HostType) -> list[str]:
        """Generate realistic installed software list."""
        common = ["Windows Defender", "Microsoft Edge", ".NET Framework 4.8"]
        type_specific = {
            HostType.DOMAIN_CONTROLLER: ["Active Directory Services", "DNS Server", "Group Policy Management"],
            HostType.SQL_SERVER: ["SQL Server Management Studio", "SQL Server 2019"],
            HostType.WEB_SERVER: ["IIS 10.0", "ASP.NET Core 6.0"],
            HostType.MAIL_SERVER: ["Microsoft Exchange 2019"],
            HostType.FILE_SERVER: ["DFS Replication", "Storage Spaces"],
            HostType.CI_SERVER: ["Jenkins 2.426", "Git 2.43", "Java 17"],
            HostType.WORKSTATION: ["Microsoft Office 365", "Teams", "Outlook"],
            HostType.CERTIFICATE_AUTHORITY: ["AD Certificate Services", "CertUtil"],
            HostType.PRINT_SERVER: ["Print Management Console"],
            HostType.VPN_ENDPOINT: ["FortiClient VPN"],
        }
        return common + type_specific.get(host_type, [])
