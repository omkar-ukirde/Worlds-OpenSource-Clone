"""State Tracker — tracks agent knowledge during a simulated pentest.

Maintains the agent's view of the world: discovered hosts, obtained
credentials, compromised hosts, and cracked hashes.  Used by the
trajectory generator to determine valid next actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CredentialType(str, Enum):
    """How a credential was obtained."""

    INITIAL = "initial"
    KERBEROAST = "kerberoast"
    ASREP_ROAST = "asrep_roast"
    HASH_CRACK = "hash_crack"
    SHARE_CREDENTIAL = "share_credential"
    DCSYNC = "dcsync"
    ADCS_ESC1 = "adcs_esc1"
    ACL_ABUSE = "acl_abuse"
    LOCAL_DUMP = "local_dump"


@dataclass
class ObtainedCredential:
    """A credential the agent has obtained."""

    username: str
    password: str = ""
    nt_hash: str = ""
    domain: str = ""
    method: CredentialType = CredentialType.INITIAL
    cracked: bool = False  # Has the hash been cracked to plaintext?

    @property
    def has_plaintext(self) -> bool:
        """Whether we have the plaintext password."""
        return bool(self.password)

    @property
    def has_hash(self) -> bool:
        """Whether we have the NT hash."""
        return bool(self.nt_hash)


@dataclass
class DiscoveredHost:
    """A host the agent has discovered."""

    hostname: str
    ip: str
    fqdn: str = ""
    os: str = ""
    services: list[dict[str, str]] = field(default_factory=list)
    is_dc: bool = False
    compromised: bool = False


class StateTracker:
    """Tracks agent knowledge during a simulated pentest session.

    Usage:
        state = StateTracker(domain="WEST.local", start_user="b.wright",
                             start_pass="Hello123", start_host="WS01",
                             start_ip="10.0.1.50")
        state.add_credential("svc_sql", nt_hash="aabbccdd...", method=CredentialType.KERBEROAST)
        state.crack_hash("svc_sql", "Summer2024!")
        state.compromise_host("DC01")
    """

    def __init__(
        self,
        domain: str,
        start_user: str,
        start_pass: str,
        start_host: str,
        start_ip: str,
    ) -> None:
        self.domain = domain
        self.current_user = start_user
        self.current_host = start_host
        self.current_ip = start_ip

        # Knowledge stores
        self.credentials: dict[str, ObtainedCredential] = {}
        self.discovered_hosts: dict[str, DiscoveredHost] = {}
        self.compromised_hosts: set[str] = set()
        self.obtained_hashes: dict[str, str] = {}  # username → hash
        self.cracked_hashes: dict[str, str] = {}  # username → plaintext

        # Initialize with starting credential
        self.add_credential(
            start_user,
            password=start_pass,
            method=CredentialType.INITIAL,
        )

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def add_credential(
        self,
        username: str,
        password: str = "",
        nt_hash: str = "",
        method: CredentialType = CredentialType.INITIAL,
    ) -> None:
        """Record a newly obtained credential."""
        existing = self.credentials.get(username)
        if existing:
            # Update with new info
            if password and not existing.password:
                existing.password = password
                existing.cracked = True
            if nt_hash and not existing.nt_hash:
                existing.nt_hash = nt_hash
            return

        cred = ObtainedCredential(
            username=username,
            password=password,
            nt_hash=nt_hash,
            domain=self.domain,
            method=method,
            cracked=bool(password),
        )
        self.credentials[username] = cred

        if nt_hash:
            self.obtained_hashes[username] = nt_hash
        if password:
            self.cracked_hashes[username] = password

    def crack_hash(self, username: str, plaintext: str) -> None:
        """Record that a hash has been cracked to plaintext."""
        if username in self.credentials:
            self.credentials[username].password = plaintext
            self.credentials[username].cracked = True
        self.cracked_hashes[username] = plaintext

    def has_credential(self, username: str) -> bool:
        """Check if we have any credential for a user."""
        return username in self.credentials

    def has_plaintext(self, username: str) -> bool:
        """Check if we have the plaintext password for a user."""
        cred = self.credentials.get(username)
        return bool(cred and cred.has_plaintext)

    def get_credential(self, username: str) -> ObtainedCredential | None:
        """Get a credential by username."""
        return self.credentials.get(username)

    # ------------------------------------------------------------------
    # Host tracking
    # ------------------------------------------------------------------

    def discover_host(
        self,
        hostname: str,
        ip: str,
        fqdn: str = "",
        os: str = "",
        is_dc: bool = False,
    ) -> None:
        """Record a discovered host."""
        if hostname not in self.discovered_hosts:
            self.discovered_hosts[hostname] = DiscoveredHost(
                hostname=hostname, ip=ip, fqdn=fqdn, os=os, is_dc=is_dc,
            )

    def compromise_host(self, hostname: str) -> None:
        """Mark a host as compromised."""
        self.compromised_hosts.add(hostname)
        if hostname in self.discovered_hosts:
            self.discovered_hosts[hostname].compromised = True

    def is_compromised(self, hostname: str) -> bool:
        """Check if a host is compromised."""
        return hostname in self.compromised_hosts

    # ------------------------------------------------------------------
    # Context for reasoning generation
    # ------------------------------------------------------------------

    def pivot_to(self, username: str, hostname: str, ip: str) -> None:
        """Switch the agent's current identity and location."""
        self.current_user = username
        self.current_host = hostname
        self.current_ip = ip

    def summary(self) -> str:
        """Human-readable summary of current agent knowledge."""
        lines = [
            f"Current identity: {self.current_user}@{self.current_host} ({self.current_ip})",
            f"Credentials obtained: {len(self.credentials)}",
            f"  Plaintext: {sum(1 for c in self.credentials.values() if c.has_plaintext)}",
            f"  Hash only: {sum(1 for c in self.credentials.values() if c.has_hash and not c.has_plaintext)}",
            f"Hosts discovered: {len(self.discovered_hosts)}",
            f"Hosts compromised: {len(self.compromised_hosts)}",
        ]
        return "\n".join(lines)
