"""SQLMap handler — simulates automated SQL injection testing.

If the target URL maps to a WebRoute with a SQLi WebVulnerability,
simulates the full sqlmap output including database enumeration and dump.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import WebApp, WebVulnType


class SQLMapHandler(BaseHandler):
    """Simulates sqlmap automated SQL injection tool."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated sqlmap.

        Supports:
            sqlmap -u 'http://10.0.1.20:8080/product?id=1' --dbs
            sqlmap -u '...' --dump -D db_name -T table
            sqlmap -u '...' --batch --risk=3 --level=5
        """
        url, dump, dbs_flag, db_name, table_name, batch = self._parse_args(args)
        if not url:
            return "[!] missing mandatory option '-u' (target URL)"

        parsed = urlparse(url)
        host_str = parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"

        webapp = self._find_webapp(host_str, port)
        if not webapp:
            return (
                f"[*] starting @ 14:30:00 /2024-01-15/\n"
                f"[CRITICAL] unable to connect to the target URL"
            )

        # Find SQLi vulnerability on this path
        sqli_vuln = None
        for vuln in webapp.vulnerabilities:
            if vuln.vuln_type == WebVulnType.SQLI and vuln.route_path.rstrip("/") == path.rstrip("/"):
                sqli_vuln = vuln
                break

        lines: list[str] = [
            "        ___",
            "       __H__",
            " ___ ___[']_____ ___ ___  {1.8.2#stable}",
            "|_ -| . [']     | .'| . |",
            "|___|_  [)]_|_|_|__,|  _|",
            "      |_|V...       |_|   https://sqlmap.org",
            "",
            f"[*] starting @ 14:30:00 /2024-01-15/",
            "",
            f"[*] testing connection to the target URL",
            f"[*] checking if the target is protected by a WAF/IPS",
        ]

        if sqli_vuln is None:
            lines.extend([
                f"[*] testing if the URL is stable",
                f"[*] testing '{path}' parameters",
                f"[WARNING] {path}: all tested parameters do not appear to be injectable",
                f"[*] ending @ 14:30:45 /2024-01-15/",
            ])
            return "\n".join(lines)

        param = sqli_vuln.injection_point
        lines.extend([
            f"[*] testing if GET parameter '{param}' is dynamic",
            f"[*] heuristic (basic) test shows that GET parameter '{param}' might be injectable (possible DBMS: 'MySQL')",
            f"[*] testing for SQL injection on GET parameter '{param}'",
            f"[*] testing 'AND boolean-based blind - WHERE or HAVING clause'",
            f"[14:30:10] [INFO] GET parameter '{param}' appears to be 'AND boolean-based blind' injectable",
            f"[14:30:12] [INFO] testing 'MySQL >= 5.0 AND error-based'",
            f"[14:30:14] [INFO] GET parameter '{param}' is 'MySQL >= 5.0 AND error-based' injectable",
            f"[14:30:16] [INFO] testing 'MySQL >= 5.0.12 time-based blind'",
            f"[14:30:20] [INFO] GET parameter '{param}' appears to be 'MySQL >= 5.0.12 time-based blind' injectable",
            "",
            f"sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:",
            f"---",
            f"Parameter: {param} (GET)",
            f"    Type: boolean-based blind",
            f"    Title: AND boolean-based blind - WHERE or HAVING clause",
            f"    Payload: {param}=1 AND 5731=5731",
            "",
            f"    Type: error-based",
            f"    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING clause",
            f"    Payload: {param}=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7162787a71,(SELECT (ELT(1,1))),0x716b707071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
            "",
            f"    Type: time-based blind",
            f"    Title: MySQL >= 5.0.12 time-based blind",
            f"    Payload: {param}=1 AND SLEEP(5)",
            f"---",
            f"[14:30:22] [INFO] the back-end DBMS is MySQL",
            f"web application technology: {webapp.framework}, {webapp.server_header}",
            f"back-end DBMS: MySQL >= 5.0",
        ])

        if dbs_flag:
            # --dbs: show databases
            lines.extend([
                "",
                f"[14:30:25] [INFO] fetching database names",
                f"available databases [{3}]:",
                f"[*] information_schema",
                f"[*] {webapp.db_name}",
                f"[*] mysql",
            ])
        elif dump:
            # --dump: dump table
            target_db = db_name or webapp.db_name
            target_table = table_name or webapp.db_users_table
            lines.extend([
                "",
                f"[14:30:28] [INFO] fetching columns for table '{target_table}' in database '{target_db}'",
                f"[14:30:30] [INFO] fetching entries for table '{target_table}' in database '{target_db}'",
                f"Database: {target_db}",
                f"Table: {target_table}",
                f"[3 entries]",
                f"+----+------------------------+---------------------------+----------------------------------+",
                f"| id | username               | email                     | password_hash                    |",
                f"+----+------------------------+---------------------------+----------------------------------+",
                f"| 1  | admin                  | admin@corp.local          | $2b$12$LJ3m4yK9v...(hashed)     |",
                f"| 2  | svc_backup             | backup@corp.local         | $2b$12$Xk9p2R1v...(hashed)      |",
                f"| 3  | j.developer            | dev@corp.local            | $2b$12$Qw8n3P5t...(hashed)      |",
                f"+----+------------------------+---------------------------+----------------------------------+",
            ])
        else:
            lines.extend([
                "",
                f"[14:30:25] [INFO] SQL injection vulnerability confirmed",
                f"[*] use '--dbs' to enumerate databases, '--dump' to dump table contents",
            ])

        lines.append(f"\n[*] ending @ 14:31:00 /2024-01-15/")
        return "\n".join(lines)

    def _parse_args(self, args: list[str]) -> tuple[str, bool, bool, str, str, bool]:
        """Parse sqlmap args -> (url, dump, dbs, db_name, table, batch)."""
        url = ""
        dump = False
        dbs = False
        db_name = ""
        table = ""
        batch = False

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-u", "--url") and i + 1 < len(args):
                url = args[i + 1]
                i += 2
            elif arg == "--dump":
                dump = True
                i += 1
            elif arg == "--dbs":
                dbs = True
                i += 1
            elif arg in ("-D",) and i + 1 < len(args):
                db_name = args[i + 1]
                i += 2
            elif arg in ("-T",) and i + 1 < len(args):
                table = args[i + 1]
                i += 2
            elif arg == "--batch":
                batch = True
                i += 1
            else:
                i += 1

        return url, dump, dbs, db_name, table, batch

    def _find_webapp(self, host: str, port: int) -> WebApp | None:
        """Find a WebApp matching the host IP and port."""
        for app in self.manifest.web_apps:
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(app.base_url)
            app_host = parsed.hostname or ""
            app_port = parsed.port or 80
            if app_host == host and app_port == port:
                return app
        return None
