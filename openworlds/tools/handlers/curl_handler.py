"""Curl HTTP handler — simulates curl requests against the WebApp route tree.

Routes requests to the correct WebApp/WebRoute and evaluates payloads
against WebVulnerability triggers. Returns realistic HTTP responses.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import WebApp, WebRoute, WebVulnerability


class CurlHandler(BaseHandler):
    """Simulates curl HTTP client."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated curl.

        Supports:
            curl http://10.0.1.20:8080/path
            curl -X POST http://... -d 'key=value'
            curl -H 'Header: value' http://...
            curl -v http://...
        """
        url, method, data, headers, verbose = self._parse_args(args)
        if not url:
            return "curl: no URL specified"

        parsed = urlparse(url)
        host_str = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Find the web app on this host
        webapp = self._find_webapp(host_str, port)
        if not webapp:
            return (
                f"curl: (7) Failed to connect to {host_str} port {port} "
                f"after 0 ms: Connection refused"
            )

        path = parsed.path or "/"
        query_params = parse_qs(parsed.query)

        # Flatten query params for matching
        flat_params: dict[str, str] = {}
        for k, v_list in query_params.items():
            flat_params[k] = v_list[0] if v_list else ""

        # Add POST data params
        if data:
            for pair in data.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    flat_params[k] = v

        # Find matching route
        route = self._match_route(webapp, path)

        # Build response
        resp_lines: list[str] = []

        if verbose:
            resp_lines.extend([
                f"> {method} {parsed.path or '/'} HTTP/1.1",
                f"> Host: {host_str}:{port}",
                f"> User-Agent: curl/8.4.0",
                "> Accept: */*",
                ">",
            ])

        if route is None:
            status = "404 Not Found"
            body = f"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL {path} was not found on this server.</p></body></html>"
        else:
            # Check for vulnerability triggers
            vuln_hit = self._check_vulns(webapp, path, flat_params)
            if vuln_hit:
                status = "200 OK"
                body = vuln_hit.exploited_response
            elif route.auth_required and "Authorization" not in str(headers):
                status = "401 Unauthorized"
                body = '{"error": "Authentication required"}'
            else:
                status = "200 OK"
                body = self._generate_normal_response(webapp, route, flat_params)

        if verbose:
            resp_lines.extend([
                f"< HTTP/1.1 {status}",
                f"< Server: {webapp.server_header}",
                "< Content-Type: text/html; charset=utf-8",
                "<",
            ])

        resp_lines.append(body)
        return "\n".join(resp_lines)

    def _parse_args(self, args: list[str]) -> tuple[str, str, str, list[str], bool]:
        """Parse curl arguments into (url, method, data, headers, verbose)."""
        url = ""
        method = "GET"
        data = ""
        headers: list[str] = []
        verbose = False

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-X", "--request") and i + 1 < len(args):
                method = args[i + 1].upper()
                i += 2
            elif arg in ("-d", "--data", "--data-raw") and i + 1 < len(args):
                data = args[i + 1]
                method = "POST" if method == "GET" else method
                i += 2
            elif arg in ("-H", "--header") and i + 1 < len(args):
                headers.append(args[i + 1])
                i += 2
            elif arg in ("-v", "--verbose"):
                verbose = True
                i += 1
            elif arg in ("-s", "--silent", "-k", "--insecure", "-L", "--location"):
                i += 1
            elif arg in ("-o", "--output") and i + 1 < len(args):
                i += 2
            elif not arg.startswith("-"):
                url = arg
                i += 1
            else:
                i += 1

        return url, method, data, headers, verbose

    def _find_webapp(self, host: str, port: int) -> WebApp | None:
        """Find a WebApp matching the host IP and port."""
        for app in self.manifest.web_apps:
            parsed = urlparse(app.base_url)
            app_host = parsed.hostname or ""
            app_port = parsed.port or 80
            if app_host == host and app_port == port:
                return app
        return None

    def _match_route(self, webapp: WebApp, path: str) -> WebRoute | None:
        """Find a matching WebRoute for the given path."""
        path = path.rstrip("/") or "/"
        for route in webapp.routes:
            route_path = route.path.rstrip("/") or "/"
            if route_path == path:
                return route
        return None

    def _check_vulns(
        self, webapp: WebApp, path: str, params: dict[str, str]
    ) -> WebVulnerability | None:
        """Check if any vulnerability trigger matches the request."""
        path = path.rstrip("/") or "/"
        for vuln in webapp.vulnerabilities:
            vuln_path = vuln.route_path.rstrip("/") or "/"
            if vuln_path != path:
                continue
            param_value = params.get(vuln.injection_point, "")
            if vuln.trigger_payload.lower() in param_value.lower():
                return vuln
        return None

    def _generate_normal_response(
        self, webapp: WebApp, route: WebRoute, params: dict[str, str]
    ) -> str:
        """Generate a benign response for a normal (non-exploited) request."""
        if route.response_type == "json":
            return f'{{"status": "ok", "path": "{route.path}", "app": "{webapp.name}"}}'

        title = route.description or route.path
        return (
            f"<!DOCTYPE html>\n<html>\n<head><title>{webapp.name} - {title}</title></head>\n"
            f"<body>\n<h1>{title}</h1>\n"
            f"<p>Welcome to {webapp.name}.</p>\n"
            f"<footer>Powered by {webapp.framework}</footer>\n"
            f"</body>\n</html>"
        )
