"""Pydantic data models for the entire simulated AD network.

Every object in the simulated environment is defined here. The Manifest model
is the single source of truth — tool handlers, trajectory generators, and
evaluators all query these models.
"""

from __future__ import annotations

import hashlib
import random
import string
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HostType(str, Enum):
    """Type of host in the simulated network."""

    DOMAIN_CONTROLLER = "domain_controller"
    CERTIFICATE_AUTHORITY = "certificate_authority"
    SQL_SERVER = "sql_server"
    WEB_SERVER = "web_server"
    MAIL_SERVER = "mail_server"
    FILE_SERVER = "file_server"
    CI_SERVER = "ci_server"
    VPN_ENDPOINT = "vpn_endpoint"
    WORKSTATION = "workstation"
    PRINT_SERVER = "print_server"


class UserType(str, Enum):
    """Type of user account."""

    STANDARD = "standard"
    ADMIN = "admin"
    SERVICE_ACCOUNT = "service_account"
    MACHINE_ACCOUNT = "machine_account"


class ACLRight(str, Enum):
    """AD ACL permission types relevant to attacks."""

    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    READ_LAPS = "ReadLAPSPassword"
    READ_GMSA = "ReadGMSAPassword"
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    DS_REPLICATION_GET_CHANGES = "DS-Replication-Get-Changes"
    DS_REPLICATION_GET_CHANGES_ALL = "DS-Replication-Get-Changes-All"


class PasswordStrength(str, Enum):
    """How hard a password is to crack."""

    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"


# ---------------------------------------------------------------------------
# Network Models
# ---------------------------------------------------------------------------


class Subnet(BaseModel):
    """An IP subnet in the simulated network."""

    cidr: str = Field(description="e.g. '10.0.1.0/24'")
    name: str = Field(description="Friendly name, e.g. 'ServerSubnet'")
    vlan_id: int = Field(ge=1, le=4094)
    gateway: str = Field(description="Gateway IP, e.g. '10.0.1.1'")


class Service(BaseModel):
    """A network service running on a host."""

    name: str = Field(description="Service name, e.g. 'ldap', 'smb', 'http'")
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", description="'tcp' or 'udp'")
    version: str = Field(description="Service version string for nmap output")
    banner: str = Field(default="", description="Service banner text")
    state: str = Field(default="open", description="'open', 'filtered', or 'closed'")
    product: str = Field(default="", description="Product name, e.g. 'Microsoft IIS httpd'")
    extra_info: str = Field(default="", description="Extra version info, e.g. '10.0'")


class ShareFile(BaseModel):
    """A file inside an SMB share."""

    name: str = Field(description="Filename, e.g. 'Groups.xml'")
    path: str = Field(description="Full path within the share")
    content: str = Field(description="File content (may contain credentials)")
    sensitive: bool = Field(default=False, description="True if contains credentials")


class SMBShare(BaseModel):
    """An SMB network share on a host."""

    name: str = Field(description="Share name, e.g. 'SYSVOL', 'IT$'")
    path: str = Field(description="UNC path, e.g. '\\\\DC01\\SYSVOL'")
    readable_by: list[str] = Field(default_factory=list, description="SAMAccountNames with read")
    writable_by: list[str] = Field(default_factory=list, description="SAMAccountNames with write")
    files: list[ShareFile] = Field(default_factory=list)


class CVE(BaseModel):
    """A known vulnerability mapped to a service."""

    cve_id: str = Field(description="e.g. 'CVE-2021-34527'")
    name: str = Field(description="Friendly name, e.g. 'PrintNightmare'")
    cvss: float = Field(ge=0.0, le=10.0)
    affected_service: str = Field(description="Service name this CVE targets")
    exploitable: bool = Field(description="Can the agent exploit this?")
    exploit_tool: str = Field(default="", description="Tool used to exploit, if any")


class Host(BaseModel):
    """A host (server or workstation) in the simulated network."""

    hostname: str = Field(description="Short hostname, e.g. 'DC01'")
    fqdn: str = Field(description="Fully qualified, e.g. 'DC01.NORTH.local'")
    ip: str = Field(description="IP address, e.g. '10.0.1.10'")
    mac: str = Field(description="MAC address, e.g. '00:50:56:a1:b2:c3'")
    os: str = Field(description="OS string, e.g. 'Windows Server 2019 Standard'")
    os_build: str = Field(description="OS build number, e.g. '17763'")
    host_type: HostType
    subnet: str = Field(description="Reference to subnet CIDR")
    services: list[Service] = Field(default_factory=list)
    local_admins: list[str] = Field(
        default_factory=list, description="SAMAccountNames of local admins"
    )
    cves: list[CVE] = Field(default_factory=list)
    shares: list[SMBShare] = Field(default_factory=list)
    installed_software: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Identity Models (Users, Groups, OUs)
# ---------------------------------------------------------------------------


class User(BaseModel):
    """An AD user (standard, admin, service account, or machine account)."""

    sam_account_name: str = Field(description="e.g. 'j.smith'")
    display_name: str = Field(description="e.g. 'John Smith'")
    upn: str = Field(description="e.g. 'j.smith@NORTH.local'")
    dn: str = Field(description="Full Distinguished Name")
    user_type: UserType
    password: str = Field(description="Simulated plaintext password")
    password_strength: PasswordStrength
    nt_hash: str = Field(description="NTLM hash of the password")
    sid: str = Field(description="User SID")
    member_of: list[str] = Field(default_factory=list, description="Group SAMAccountNames")
    ou: str = Field(description="Organizational Unit path")

    # Attack-relevant flags
    spn: str | None = Field(default=None, description="SPN if Kerberoastable")
    asrep_roastable: bool = Field(
        default=False, description="UF_DONT_REQUIRE_PREAUTH set"
    )
    admin_count: bool = Field(default=False, description="Protected by AdminSDHolder")
    description: str = Field(default="", description="May contain passwords in insecure envs")

    # Metadata
    last_logon: str = Field(default="")
    pwd_last_set: str = Field(default="")
    account_disabled: bool = Field(default=False)

    @staticmethod
    def compute_nt_hash(password: str) -> str:
        """Compute a simulated NTLM hash from a password.

        This uses MD4 via hashlib to produce a realistic 32-char hex NTLM hash.
        Falls back to a SHA-256 based fake if MD4 is unavailable (e.g. FIPS mode).
        """
        try:
            return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
        except ValueError:
            # MD4 not available (FIPS mode) — use SHA-256 truncated as fallback
            return hashlib.sha256(password.encode("utf-16-le")).hexdigest()[:32]


class Group(BaseModel):
    """An AD security or distribution group."""

    name: str = Field(description="e.g. 'Domain Admins'")
    sam_account_name: str
    dn: str
    sid: str
    group_type: str = Field(description="'security' or 'distribution'")
    group_scope: str = Field(description="'global', 'domain_local', or 'universal'")
    members: list[str] = Field(default_factory=list, description="Member SAMAccountNames")
    member_of: list[str] = Field(default_factory=list, description="Parent groups")


class OrganizationalUnit(BaseModel):
    """An AD Organizational Unit (OU)."""

    name: str = Field(description="e.g. 'IT Department'")
    dn: str = Field(description="e.g. 'OU=IT,DC=NORTH,DC=local'")
    parent_dn: str | None = Field(default=None, description="Parent OU DN")
    gpos_linked: list[str] = Field(default_factory=list, description="Linked GPO names")
    children: list[str] = Field(default_factory=list, description="Child OU DNs")


# ---------------------------------------------------------------------------
# Security Models (ACLs, Certs, GPOs)
# ---------------------------------------------------------------------------


class ACLEntry(BaseModel):
    """An AD Access Control Entry granting a right from source to target."""

    source: str = Field(description="SAMAccountName of principal with the right")
    target: str = Field(description="SAMAccountName of target object")
    right: ACLRight
    inherited: bool = Field(default=False)


class CertificateTemplate(BaseModel):
    """An AD CS certificate template (may be vulnerable to ESC1-ESC3)."""

    name: str = Field(description="Template name, e.g. 'UserAuth'")
    display_name: str
    oid: str = Field(description="Template OID")

    # Enrollment permissions
    enrollment_principals: list[str] = Field(
        default_factory=list, description="Who can enroll"
    )

    # Vulnerable flags
    enrollee_supplies_subject: bool = Field(
        default=False, description="ESC1: attacker controls SAN"
    )
    any_purpose: bool = Field(default=False, description="ESC2: cert for anything")
    agent_template: bool = Field(default=False, description="ESC3: enrollment agent abuse")

    # Requirements
    requires_manager_approval: bool = Field(default=True)
    authorized_signatures_required: int = Field(default=1)


class GPO(BaseModel):
    """A Group Policy Object."""

    name: str = Field(description="GPO name, e.g. 'Default Domain Policy'")
    display_name: str
    gpo_id: str = Field(description="GPO GUID")
    linked_ous: list[str] = Field(
        default_factory=list, description="OUs this GPO is linked to"
    )
    settings: dict[str, Any] = Field(
        default_factory=dict, description="GPO settings (key-value)"
    )


# ---------------------------------------------------------------------------
# Attack Path Models
# ---------------------------------------------------------------------------


class AttackStep(BaseModel):
    """A single step in an attack path."""

    step_number: int
    technique: str = Field(description="e.g. 'kerberoasting', 'acl_abuse'")
    description: str = Field(description="Human-readable description of what happens")
    source_principal: str = Field(description="Who performs this step")
    target_principal: str = Field(description="Who/what is being attacked")
    tool_command: str = Field(description="The tool command used in this step")
    prerequisite: str = Field(
        default="", description="What must be true before this step"
    )


class AttackPath(BaseModel):
    """A complete attack path from initial access to Domain Admin."""

    path_id: str
    starting_user: str
    starting_host: str
    target: str = Field(default="Domain Admin", description="Goal of the path")
    steps: list[AttackStep]
    strategies_used: list[str] = Field(
        description="e.g. ['kerberoasting', 'acl_abuse']"
    )
    total_steps: int = Field(description="Length of the attack path")


# ---------------------------------------------------------------------------
# Configuration & Manifest (Top-Level Models)
# ---------------------------------------------------------------------------


class ManifestConfig(BaseModel):
    """User-configurable parameters for world generation."""

    # Scale
    num_hosts: int = Field(default=20, ge=5, le=200, description="Total hosts")
    num_subnets: int = Field(default=2, ge=1, le=10, description="Network subnets")
    num_users: int = Field(default=50, ge=10, le=1000, description="Total users")
    num_groups: int = Field(default=15, ge=5, le=100, description="Total groups")
    num_ous: int = Field(default=8, ge=3, le=50, description="Organizational units")

    # Attack strategies to include (at least 1 required)
    include_kerberoasting: bool = Field(default=True)
    include_asrep_roasting: bool = Field(default=True)
    include_acl_abuse: bool = Field(default=True)
    include_adcs_abuse: bool = Field(default=True)
    include_credential_in_shares: bool = Field(default=True)

    # Difficulty
    min_attack_path_length: int = Field(default=3, ge=2, le=20)
    max_attack_path_length: int = Field(default=8, ge=3, le=30)
    password_crack_difficulty: PasswordStrength = Field(default=PasswordStrength.WEAK)

    # Starting point
    starting_user: str | None = Field(
        default=None, description="Specific starting user or random"
    )
    starting_host: str | None = Field(
        default=None, description="Specific starting host or random"
    )

    # Reproducibility
    seed: int | None = Field(default=None, description="Random seed for reproducibility")


class Domain(BaseModel):
    """The AD domain — top-level container for the entire simulated network."""

    name: str = Field(description="FQDN, e.g. 'NORTH.local'")
    netbios_name: str = Field(description="NetBIOS name, e.g. 'NORTH'")
    functional_level: str = Field(
        default="2016", description="'2016', '2019', or '2022'"
    )
    domain_sid: str = Field(description="Domain SID, e.g. 'S-1-5-21-...'")
    subnets: list[Subnet] = Field(default_factory=list)
    forest_root: bool = Field(default=True)


class Manifest(BaseModel):
    """The single source of truth for the entire simulated network.

    Everything — tool handlers, trajectory generators, evaluators — queries
    this model. It is serializable to JSON for storage and reproducibility.
    """

    domain: Domain
    hosts: list[Host]
    users: list[User]
    groups: list[Group]
    ous: list[OrganizationalUnit]
    acls: list[ACLEntry]
    cert_templates: list[CertificateTemplate] = Field(default_factory=list)
    gpos: list[GPO] = Field(default_factory=list)

    # Computed attack paths (generated by path_validator)
    attack_paths: list[AttackPath] = Field(default_factory=list)

    # Metadata
    generated_at: datetime = Field(default_factory=datetime.now)
    seed: int = Field(description="Seed used for reproducibility")
    config: ManifestConfig


# ---------------------------------------------------------------------------
# CVE Database (Curated Real CVEs)
# ---------------------------------------------------------------------------

CVE_DATABASE: list[CVE] = [
    CVE(
        cve_id="CVE-2021-34527",
        name="PrintNightmare",
        cvss=8.8,
        affected_service="spoolss",
        exploitable=True,
        exploit_tool="printnightmare-exploit",
    ),
    CVE(
        cve_id="CVE-2021-1675",
        name="PrintNightmare LPE",
        cvss=7.8,
        affected_service="spoolss",
        exploitable=True,
        exploit_tool="printnightmare-exploit",
    ),
    CVE(
        cve_id="CVE-2020-1472",
        name="ZeroLogon",
        cvss=10.0,
        affected_service="netlogon",
        exploitable=True,
        exploit_tool="impacket-zerologon",
    ),
    CVE(
        cve_id="CVE-2022-26923",
        name="Certifried",
        cvss=8.8,
        affected_service="adcs",
        exploitable=True,
        exploit_tool="certipy",
    ),
    CVE(
        cve_id="CVE-2021-42278",
        name="sAMAccountName Spoofing",
        cvss=7.5,
        affected_service="ldap",
        exploitable=True,
        exploit_tool="impacket-noPac",
    ),
    CVE(
        cve_id="CVE-2021-42287",
        name="noPac",
        cvss=7.5,
        affected_service="kerberos",
        exploitable=True,
        exploit_tool="impacket-noPac",
    ),
    CVE(
        cve_id="CVE-2022-33679",
        name="Kerberos RC4 Downgrade",
        cvss=8.1,
        affected_service="kerberos",
        exploitable=True,
    ),
    CVE(
        cve_id="CVE-2019-1040",
        name="NTLM MIC Bypass",
        cvss=7.5,
        affected_service="smb",
        exploitable=True,
        exploit_tool="impacket-ntlmrelayx",
    ),
    CVE(
        cve_id="CVE-2020-17049",
        name="Kerberos Bronze Bit",
        cvss=6.6,
        affected_service="kerberos",
        exploitable=True,
    ),
    CVE(
        cve_id="CVE-2023-23397",
        name="Outlook NTLM Leak",
        cvss=9.8,
        affected_service="smtp",
        exploitable=True,
    ),
    CVE(
        cve_id="CVE-2017-0144",
        name="EternalBlue",
        cvss=9.8,
        affected_service="smb",
        exploitable=True,
        exploit_tool="msfconsole",
    ),
    CVE(
        cve_id="CVE-2019-0708",
        name="BlueKeep",
        cvss=9.8,
        affected_service="rdp",
        exploitable=True,
        exploit_tool="msfconsole",
    ),
]


# ---------------------------------------------------------------------------
# Service Mappings (Host Type → Default Services)
# ---------------------------------------------------------------------------

SERVICE_TEMPLATES: dict[HostType, list[dict[str, Any]]] = {
    HostType.DOMAIN_CONTROLLER: [
        {"name": "ldap", "port": 389, "version": "Microsoft Windows Active Directory LDAP",
         "product": "Microsoft Windows Active Directory LDAP"},
        {"name": "kerberos-sec", "port": 88, "version": "Microsoft Windows Kerberos",
         "product": "Microsoft Windows Kerberos"},
        {"name": "dns", "port": 53, "version": "Microsoft DNS", "protocol": "udp",
         "product": "Microsoft DNS"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
        {"name": "msrpc", "port": 135, "version": "Microsoft Windows RPC",
         "product": "Microsoft Windows RPC"},
        {"name": "ldap", "port": 3268, "version": "Microsoft Windows Active Directory LDAP (Global Catalog)",
         "product": "Microsoft Windows Active Directory LDAP"},
        {"name": "ms-wbt-server", "port": 5985, "version": "Microsoft HTTPAPI httpd 2.0",
         "product": "Microsoft HTTPAPI httpd", "extra_info": "SSDP/UPnP"},
    ],
    HostType.CERTIFICATE_AUTHORITY: [
        {"name": "http", "port": 80, "version": "Microsoft IIS httpd 10.0",
         "product": "Microsoft IIS httpd", "extra_info": "10.0"},
        {"name": "ssl/http", "port": 443, "version": "Microsoft IIS httpd 10.0",
         "product": "Microsoft IIS httpd", "extra_info": "10.0"},
        {"name": "msrpc", "port": 135, "version": "Microsoft Windows RPC",
         "product": "Microsoft Windows RPC"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
    ],
    HostType.SQL_SERVER: [
        {"name": "ms-sql-s", "port": 1433, "version": "Microsoft SQL Server 2019",
         "product": "Microsoft SQL Server", "extra_info": "15.00.2000"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
    ],
    HostType.WEB_SERVER: [
        {"name": "http", "port": 80, "version": "Microsoft IIS httpd 10.0",
         "product": "Microsoft IIS httpd", "extra_info": "10.0"},
        {"name": "ssl/http", "port": 443, "version": "Microsoft IIS httpd 10.0",
         "product": "Microsoft IIS httpd", "extra_info": "10.0"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
    ],
    HostType.MAIL_SERVER: [
        {"name": "smtp", "port": 25, "version": "Microsoft Exchange smtpd",
         "product": "Microsoft Exchange smtpd"},
        {"name": "imap", "port": 143, "version": "Microsoft Exchange imapd",
         "product": "Microsoft Exchange imapd"},
        {"name": "ssl/http", "port": 443, "version": "Microsoft Exchange OWA",
         "product": "Microsoft IIS httpd", "extra_info": "10.0"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
    ],
    HostType.FILE_SERVER: [
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
        {"name": "msrpc", "port": 135, "version": "Microsoft Windows RPC",
         "product": "Microsoft Windows RPC"},
    ],
    HostType.CI_SERVER: [
        {"name": "http-proxy", "port": 8080, "version": "Jenkins 2.426",
         "product": "Jenkins", "extra_info": "Jetty 10.0"},
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
    ],
    HostType.VPN_ENDPOINT: [
        {"name": "ssl/http", "port": 443, "version": "Fortinet SSL VPN",
         "product": "Fortinet FortiGate"},
        {"name": "isakmp", "port": 500, "version": "IKE", "protocol": "udp",
         "product": "IKE"},
    ],
    HostType.WORKSTATION: [
        {"name": "microsoft-ds", "port": 445, "version": "Windows 10 Pro 19045 microsoft-ds",
         "product": "Microsoft Windows 10 Pro"},
        {"name": "ms-wbt-server", "port": 3389, "version": "Microsoft Terminal Services",
         "product": "Microsoft Terminal Services"},
    ],
    HostType.PRINT_SERVER: [
        {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2019 Standard 17763 microsoft-ds",
         "product": "Microsoft Windows Server 2019"},
        {"name": "msrpc", "port": 135, "version": "Microsoft Windows RPC",
         "product": "Microsoft Windows RPC"},
        {"name": "ipp", "port": 631, "version": "CUPS 2.3",
         "product": "CUPS"},
    ],
}


# ---------------------------------------------------------------------------
# Password Pools (for realistic password generation)
# ---------------------------------------------------------------------------

WEAK_PASSWORDS: list[str] = [
    "Password1", "Welcome1", "Summer2024", "Winter2023", "Company123",
    "P@ssw0rd", "Passw0rd!", "Admin123", "Qwerty123", "Letmein1",
    "Password!", "Changeme1", "Pass1234", "Secret123", "Hello123",
    "Iloveyou1", "Dragon123", "Master123", "Monkey123", "Shadow123",
    "Trust!No1", "Access14!", "Friday13!", "October23!", "Monday01!",
]

MEDIUM_PASSWORDS: list[str] = [
    "Th3Qu!ckFox#2024", "D@taCenter$vc01", "S3rver!Pass_789",
    "Kerberos$Realm42", "Exchange!M@il99", "MSSQL_Adm!n2023",
    "B@ckup_Srv!ce07", "N3twork-Adm!n22", "C0rporate#VPN44",
    "Pr!nt3r-Svc_501", "FileShare#Acc03", "Deploy_P!pe88",
]

STRONG_PASSWORDS: list[str] = [
    "xK9#mN2$vL5@pQ8&wR3",
    "aB7*cD4!eF1%gH6^jK9",
    "Z$3nQ!7kP@9xM#2vN5w",
    "Tr4&Ky8^Lm2$Qp6!Wn9",
    "Hj5@Nk8#Pq2$Rs6!Tv9",
]


# ---------------------------------------------------------------------------
# Name Generation Data
# ---------------------------------------------------------------------------

FIRST_NAMES: list[str] = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly",
    "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth",
    "Carol", "Kevin", "Amanda", "Brian", "Dorothy", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca",
    "Jason", "Sharon", "Jeffrey", "Laura", "Ryan", "Cynthia",
]

LAST_NAMES: list[str] = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts",
]

# Department-based OU names
DEPARTMENT_NAMES: list[str] = [
    "IT", "Finance", "HR", "Marketing", "Sales", "Engineering",
    "Legal", "Operations", "Executive", "Research", "Support",
    "Procurement", "Facilities", "Security", "Communications",
]

# Realistic service account naming patterns
SERVICE_ACCOUNT_PREFIXES: list[str] = [
    "svc_", "sa_", "app_", "sys_", "auto_",
]

SERVICE_ACCOUNT_PURPOSES: list[str] = [
    "backup", "sql", "web", "exchange", "sharepoint", "print", "scan",
    "deploy", "monitor", "alert", "reporting", "etl", "sync", "api",
    "scheduler", "archive", "proxy", "dns", "dhcp", "ftp",
]

# SPN patterns for Kerberoastable service accounts
SPN_PATTERNS: list[str] = [
    "HTTP/{fqdn}",
    "MSSQLSvc/{fqdn}:1433",
    "MSSQLSvc/{fqdn}",
    "FTP/{fqdn}",
    "CIFS/{fqdn}",
    "exchangeRFR/{fqdn}",
    "imap/{fqdn}",
    "smtp/{fqdn}",
    "ldap/{fqdn}",
    "HOST/{fqdn}",
]
