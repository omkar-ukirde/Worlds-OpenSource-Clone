"""Unit tests for the ToolSimulator and individual Handlers."""

import pytest
from openworlds.tools.simulator import ToolSimulator
from openworlds.world_engine.models import Manifest, Domain, Host, User, HostType, UserType, PasswordStrength
from openworlds.world_engine.models import ManifestConfig


@pytest.fixture
def mock_manifest():
    """Provides a small, consistent Manifest for testing parsers."""
    config = ManifestConfig(num_hosts=5, num_users=10)
    
    domain = Domain(
        name="CORP.local",
        netbios_name="CORP",
        domain_sid="S-1-5-21-999-999-999"
    )
    
    host = Host(
        hostname="DC01",
        fqdn="DC01.CORP.local",
        ip="192.168.1.100",
        mac="00:15:5D:11:11:11",
        os="Windows Server 2022",
        os_build="20348",
        subnet="192.168.1.0/24",
        local_admins=["admin"],
        host_type=HostType.DOMAIN_CONTROLLER,
        services=[
            {"name": "ldap", "port": 389, "version": "Microsoft Windows Active Directory LDAP", "product": "Windows AD LDAP"},
            {"name": "microsoft-ds", "port": 445, "version": "Windows Server 2022 Standard 20348", "product": "Windows Server 2022"}
        ]
    )
    
    user = User(
        sam_account_name="admin",
        display_name="Admin",
        upn="admin@CORP.local",
        dn="CN=Admin,DC=CORP,DC=local",
        user_type=UserType.ADMIN,
        password="Password1",
        password_strength=PasswordStrength.WEAK,
        nt_hash="8846F7EAEE8FB117AD06BDD830B7586C",  # md4(Password1)
        sid="S-1-5-21-999-999-999-500",
        member_of=["Domain Admins"],
        ou="OU=IT,DC=CORP,DC=local",
    )
    
    return Manifest(
        domain=domain,
        hosts=[host],
        users=[user],
        groups=[],
        ous=[],
        acls=[],
        config=config,
        seed=42
    )


def test_nmap_handler(mock_manifest):
    """Test that NmapHandler identifies the open ports from the manifest."""
    sim = ToolSimulator(mock_manifest)
    
    output = sim.execute("nmap -sV -p 389,445 192.168.1.100")
    
    assert "Nmap scan report for DC01.CORP.local (192.168.1.100)" in output
    assert "389/tcp" in output
    assert "445/tcp" in output


def test_ssh_handler(mock_manifest):
    """Test that SSHHandler fails when connecting to a Windows host without SSH."""
    sim = ToolSimulator(mock_manifest)
    
    output = sim.execute("ssh 192.168.1.100 -l root")
    
    # DC01 does not have SSH running in mock_manifest
    assert "Connection refused" in output or "Could not resolve" in output


def test_secretsdump_handler(mock_manifest):
    """Test secretsdump retrieving hashes using valid credentials."""
    sim = ToolSimulator(mock_manifest)
    
    # User 'admin' has password 'Password1'
    output = sim.execute("secretsdump.py CORP.local/admin:Password1@192.168.1.100")
    
    assert "Dumping cached domain logon information (domain/uid:hash)" in output
    assert "CORP/admin:$DCC2$10240#admin#" in output
