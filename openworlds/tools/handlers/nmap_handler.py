"""Nmap handler — simulates port scanning and service detection.

Produces output matching real nmap format including:
    - Host discovery
    - Port table with service versions
    - OS detection hints
"""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler


class NmapHandler(BaseHandler):
    """Simulates nmap scan output."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated nmap scan.

        Supports:
            nmap <target>           Basic port scan
            nmap -sV <target>       Service version detection
            nmap -sV -p- <target>   Full port scan + version
            nmap -sC -sV <target>   Script + version scan
            nmap -Pn <target>       Skip host discovery
        """
        # Parse target (last non-flag argument)
        target = None
        scan_flags = set()
        ports_specified = None

        for arg in args:
            if arg.startswith("-"):
                scan_flags.add(arg)
                if arg.startswith("-p"):
                    ports_specified = arg[2:] if len(arg) > 2 else "1-65535"
            else:
                target = arg

        if not target:
            return "Usage: nmap [options] <target>"

        host = self.find_host(target)
        if not host:
            return (
                f"Starting Nmap 7.94SVN ( https://nmap.org )\n"
                f"Note: Host seems down. If it is really up, but blocking our ping probes, "
                f"try -Pn\n"
                f"Nmap done: 1 IP address (0 hosts up) scanned in 3.21 seconds"
            )

        # Build output
        lines = [
            f"Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-15 14:30 UTC",
            f"Nmap scan report for {host.fqdn} ({host.ip})",
            f"Host is up (0.0015s latency).",
        ]

        if host.mac:
            lines.append(f"MAC Address: {host.mac} (VMware)")

        # Port table
        if host.services:
            lines.append("")

            # Determine which ports to show
            services_to_show = host.services
            if ports_specified and ports_specified != "1-65535":
                try:
                    port_list = [int(p) for p in ports_specified.split(",")]
                    services_to_show = [
                        s for s in host.services if s.port in port_list
                    ]
                except ValueError:
                    pass

            if not services_to_show:
                lines.append(f"All {65535} scanned ports on {host.fqdn} ({host.ip}) are closed")
            else:
                # Header
                if "-sV" in scan_flags or "-sC" in scan_flags or "-A" in scan_flags:
                    lines.append(
                        f"PORT      STATE SERVICE          VERSION"
                    )
                else:
                    lines.append(f"PORT      STATE SERVICE")

                for svc in services_to_show:
                    port_str = f"{svc.port}/{svc.protocol}".ljust(9)
                    state = svc.state.ljust(5)
                    name = svc.name.ljust(16)

                    if "-sV" in scan_flags or "-sC" in scan_flags or "-A" in scan_flags:
                        version = svc.version
                        if svc.extra_info:
                            version += f" ({svc.extra_info})"
                        lines.append(f"{port_str} {state} {name} {version}")
                    else:
                        lines.append(f"{port_str} {state} {name}")

        # OS detection
        if "-O" in scan_flags or "-A" in scan_flags:
            lines.extend([
                "",
                f"OS details: {host.os}",
                f"Network Distance: 1 hop",
            ])

        # Script scan results
        if "-sC" in scan_flags or "-A" in scan_flags:
            for svc in host.services:
                if svc.name == "microsoft-ds" and svc.port == 445:
                    lines.extend([
                        "",
                        f"Host script results:",
                        f"|_smb2-security-mode:",
                        f"|   3:1:1:",
                        f"|_    Message signing enabled and required" if host.host_type.value == "domain_controller" else f"|_    Message signing enabled but not required",
                        f"|_smb2-time:",
                        f"|   date: 2024-01-15T14:30:00",
                    ])
                if svc.name == "ldap" and svc.port == 389:
                    lines.extend([
                        f"|_ldap-rootdse:",
                        f"|   domainFunctionality: {self.domain.functional_level}",
                        f"|   forestFunctionality: {self.domain.functional_level}",
                        f"|   domainControllerFunctionality: {self.domain.functional_level}",
                        f"|   rootDomainNamingContext: {''.join(f'DC={p},' for p in self.domain.name.split('.'))[:-1]}",
                        f"|   ldapServiceName: {self.domain.name}:{host.hostname.lower()}$@{self.domain.name.upper()}",
                    ])

        lines.extend([
            "",
            f"Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .",
            f"Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds",
        ])

        return "\n".join(lines)
