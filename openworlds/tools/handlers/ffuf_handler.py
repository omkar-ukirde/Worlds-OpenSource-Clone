"""FFUF / Dirb handler — simulates directory brute-forcing against WebApp routes.

Matches wordlists against hidden and public routes to simulate path discovery.
"""

from __future__ import annotations

from urllib.parse import urlparse

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import WebApp


class FFUFHandler(BaseHandler):
    """Simulates ffuf / gobuster / dirb directory brute-forcing."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated ffuf.

        Supports:
            ffuf -u http://10.0.1.20:8080/FUZZ -w wordlist.txt
            gobuster dir -u http://... -w wordlist.txt
            dirb http://...
        """
        url, wordlist = self._parse_args(args)
        if not url:
            return "ffuf: error: -u flag is required"

        parsed = urlparse(url.replace("/FUZZ", "").replace("/fuzz", ""))
        host_str = parsed.hostname or ""
        port = parsed.port or 80

        webapp = self._find_webapp(host_str, port)
        if not webapp:
            return f"ffuf: error: connection refused to {host_str}:{port}"

        lines: list[str] = [
            f"        /'___\\  /'___\\           /'___\\       ",
            f"       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/       ",
            f"       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\      ",
            f"        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/      ",
            f"         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\       ",
            f"          \\/_/    \\/_/   \\/___/    \\/_/       ",
            "",
            f"      v2.1.0",
            "________________________________________________",
            "",
            f" :: Method           : GET",
            f" :: URL              : {url}",
            f" :: Wordlist         : FUZZ: {wordlist}",
            f" :: Follow redirects : false",
            f" :: Calibration      : false",
            f" :: Timeout          : 10",
            f" :: Threads          : 40",
            "________________________________________________",
            "",
        ]

        # Discover routes (simulate matching against wordlist)
        found = 0
        for route in webapp.routes:
            path = route.path.lstrip("/")
            if not path:
                continue

            # Simulate: the wordlist "contains" this path segment
            top_segment = path.split("/")[0]
            size = len(self._generate_placeholder(webapp, route))
            status = 200
            if route.auth_required:
                status = 401
                size = 42

            lines.append(
                f"{top_segment.ljust(25)} [Status: {status}, Size: {size}, Words: {size // 5}, Lines: {size // 40 + 1}]"
            )
            found += 1

        lines.extend([
            "",
            f":: Progress: [1000/1000] :: Job [1/1] :: {found} results :: Duration: [0:00:02] :: Errors: 0 ::",
        ])

        return "\n".join(lines)

    def _parse_args(self, args: list[str]) -> tuple[str, str]:
        """Parse ffuf arguments into (url, wordlist)."""
        url = ""
        wordlist = "/usr/share/wordlists/dirb/common.txt"

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-u", "--url") and i + 1 < len(args):
                url = args[i + 1]
                i += 2
            elif arg in ("-w", "--wordlist") and i + 1 < len(args):
                wordlist = args[i + 1]
                i += 2
            elif not arg.startswith("-") and not url:
                url = arg  # dirb-style: dirb http://...
                i += 1
            else:
                i += 1

        return url, wordlist

    def _find_webapp(self, host: str, port: int) -> WebApp | None:
        """Find a WebApp matching the host IP and port."""
        for app in self.manifest.web_apps:
            parsed = urlparse(app.base_url)
            app_host = parsed.hostname or ""
            app_port = parsed.port or 80
            if app_host == host and app_port == port:
                return app
        return None

    def _generate_placeholder(self, webapp: WebApp, route) -> str:
        """Generate a placeholder body for size estimation."""
        return f"<html><head><title>{webapp.name}</title></head><body><h1>{route.description}</h1></body></html>"
