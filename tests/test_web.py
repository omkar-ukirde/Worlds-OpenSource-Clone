"""Unit tests for Phase 11: Web Application Simulation Handlers."""

import pytest
from openworlds.tools.simulator import ToolSimulator
from openworlds.world_engine.models import (
    Domain, Host, User, HostType, UserType, PasswordStrength,
    ManifestConfig, Manifest, WebApp, WebRoute, WebVulnerability, WebVulnType,
)


@pytest.fixture
def web_manifest():
    """Manifest with a single host running a vulnerable WebApp."""
    domain = Domain(name="CORP.local", netbios_name="CORP", domain_sid="S-1-5-21-1")

    host = Host(
        hostname="WEB01", fqdn="WEB01.CORP.local", ip="10.0.1.20",
        mac="AA:BB:CC:DD:EE:FF", os="Ubuntu 22.04", os_build="5.15",
        subnet="10.0.1.0/24", host_type=HostType.WEB_SERVER,
        services=[{"name": "http", "port": 8080, "version": "nginx/1.24.0"}],
    )

    webapp = WebApp(
        name="TestApp",
        base_url="http://10.0.1.20:8080",
        framework="django",
        tech_stack=["Python 3.11", "PostgreSQL 15"],
        routes=[
            WebRoute(path="/", description="Home"),
            WebRoute(path="/login", methods=["GET", "POST"], parameters=["username", "password"]),
            WebRoute(path="/products", description="Product listing"),
            WebRoute(path="/product", parameters=["id"], description="Single product"),
            WebRoute(path="/search", parameters=["q"], description="Search"),
            WebRoute(path="/admin", auth_required=True, hidden=True, description="Admin"),
            WebRoute(path="/api/health", response_type="json", description="Health"),
        ],
        vulnerabilities=[
            WebVulnerability(
                vuln_type=WebVulnType.SQLI,
                route_path="/product",
                injection_point="id",
                trigger_payload="1 OR 1=1--",
                exploited_response="admin|admin@corp.local|$2b$12$hash1\nuser1|user1@corp.local|$2b$12$hash2",
            ),
            WebVulnerability(
                vuln_type=WebVulnType.XSS,
                route_path="/search",
                injection_point="q",
                trigger_payload="<script>",
                exploited_response="<h2>Results for: <script>alert(1)</script></h2>",
            ),
        ],
        server_header="nginx/1.24.0",
        db_name="test_db",
        db_users_table="users",
    )

    user = User(
        sam_account_name="webadmin", display_name="Web Admin",
        upn="webadmin@CORP.local", dn="CN=WebAdmin,DC=CORP,DC=local",
        user_type=UserType.ADMIN, password="Password1",
        password_strength=PasswordStrength.WEAK,
        nt_hash="aaaa", sid="S-1-5-21-1-500", ou="OU=IT",
    )

    return Manifest(
        domain=domain, hosts=[host], users=[user],
        groups=[], ous=[], acls=[],
        web_apps=[webapp],
        config=ManifestConfig(num_hosts=5, num_users=10), seed=42,
    )


def test_curl_normal_page(web_manifest):
    """Test curl returns a normal HTML response for a valid route."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("curl http://10.0.1.20:8080/products")
    assert "TestApp" in output
    assert "Product listing" in output


def test_curl_sqli_exploit(web_manifest):
    """Test curl triggers SQLi when payload matches."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("curl http://10.0.1.20:8080/product?id=1%20OR%201=1--")
    assert "admin@corp.local" in output
    assert "user1@corp.local" in output


def test_curl_xss_exploit(web_manifest):
    """Test curl triggers XSS when script tag is injected."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("curl http://10.0.1.20:8080/search?q=<script>alert(1)</script>")
    assert "<script>alert(1)</script>" in output


def test_curl_404(web_manifest):
    """Test curl returns 404 for unknown paths."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("curl http://10.0.1.20:8080/nonexistent")
    assert "404" in output
    assert "Not Found" in output


def test_curl_connection_refused(web_manifest):
    """Test curl reports connection refused for wrong port."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("curl http://10.0.1.20:9999/")
    assert "Connection refused" in output


def test_ffuf_discovers_routes(web_manifest):
    """Test ffuf discovers all routes on the web app."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("ffuf -u http://10.0.1.20:8080/FUZZ -w /usr/share/wordlists/common.txt")
    assert "login" in output
    assert "products" in output
    assert "admin" in output
    assert "Progress:" in output


def test_sqlmap_detects_sqli(web_manifest):
    """Test sqlmap identifies SQL injection on vulnerable endpoint."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("sqlmap -u http://10.0.1.20:8080/product?id=1 --batch")
    assert "injectable" in output
    assert "Parameter: id" in output


def test_sqlmap_dumps_database(web_manifest):
    """Test sqlmap --dump outputs the database table."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("sqlmap -u http://10.0.1.20:8080/product?id=1 --dump --batch")
    assert "admin" in output
    assert "admin@corp.local" in output
    assert "test_db" in output


def test_sqlmap_no_sqli(web_manifest):
    """Test sqlmap correctly reports no injection on safe endpoints."""
    sim = ToolSimulator(web_manifest)
    output = sim.execute("sqlmap -u http://10.0.1.20:8080/products --batch")
    assert "do not appear to be injectable" in output
