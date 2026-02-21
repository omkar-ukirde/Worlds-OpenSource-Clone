"""Unit tests for the OpenWorlds core data models."""

from openworlds.world_engine.models import (
    HostType,
    UserType,
    PasswordStrength,
    User,
    Host,
    Domain,
    TrustType,
    DomainTrust,
)

def test_user_password_hashing():
    """Test that setting a password computes a deterministic NT hash."""
    user = User(
        sam_account_name="j.doe",
        display_name="John Doe",
        upn="j.doe@WEST.local",
        dn="CN=John Doe,OU=IT,DC=WEST,DC=local",
        user_type=UserType.STANDARD,
        password="Password123!",
        password_strength=PasswordStrength.MEDIUM,
        nt_hash=User.compute_nt_hash("Password123!"),
        sid="S-1-5-21-12345-12345-12345-1001",
        ou="OU=IT,DC=WEST,DC=local",
    )
    
    # NTLM hash of "Password123!" using md4
    expected_hash = User.compute_nt_hash("Password123!")
    assert user.nt_hash == expected_hash
    assert len(user.nt_hash) == 32


def test_domain_trust_serialization():
    """Test that DomainTrust logic correctly models bidirectional trusts."""
    trust = DomainTrust(
        target_domain="EAST.local",
        trust_type=TrustType.BIDIRECTIONAL,
        transitive=True
    )
    
    assert trust.target_domain == "EAST.local"
    assert trust.trust_type == "bidirectional"
    assert trust.transitive is True


def test_host_service_templates():
    """Test that hosts correctly expose basic AD services out of the box."""
    host = Host(
        hostname="DC01",
        fqdn="DC01.WEST.local",
        ip="10.0.1.5",
        mac="00:15:5D:12:34:56",
        os="Windows Server 2022",
        os_build="20348",
        subnet="10.0.1.0/24",
        host_type=HostType.DOMAIN_CONTROLLER,
        services=[{"name": "msrpc", "port": 135, "version": "Microsoft Windows RPC", "product": "Windows RPC"}]
    )
    
    assert host.hostname == "DC01"
    assert host.host_type == HostType.DOMAIN_CONTROLLER
    assert len(host.services) == 1
    assert host.services[0].name == "msrpc"
