"""Certipy handler — simulates AD CS enumeration and exploitation."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import HostType


class CertipyHandler(BaseHandler):
    """Simulates certipy for AD CS attacks."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated certipy.

        Supports:
            certipy find -u user -p pass -dc-ip IP     Enumerate templates
            certipy req -u user -target CA -template T  Request certificate
        """
        if not args:
            return "Usage: certipy {find,req} [options]"

        subcommand = args[0]

        if subcommand == "find":
            return self._find_templates()
        elif subcommand == "req":
            return self._request_cert(args[1:])
        else:
            return f"Unknown certipy subcommand: {subcommand}"

    def _find_templates(self) -> str:
        """Enumerate certificate templates and flag vulnerable ones."""
        ca_hosts = [
            h for h in self.manifest.hosts
            if h.host_type == HostType.CERTIFICATE_AUTHORITY
        ]

        lines = [
            "Certipy v4.8.2 - by Oliver Lyak (ly4k)",
            "",
            "[*] Finding certificate templates",
        ]

        if not ca_hosts:
            lines.append("[-] No Certificate Authority found")
            return "\n".join(lines)

        ca = ca_hosts[0]
        lines.append(f"[*] Certificate Authority: {ca.hostname}.{self.domain.name}")

        for template in self.manifest.cert_templates:
            vuln_flags = []
            if template.enrollee_supplies_subject and not template.requires_manager_approval:
                vuln_flags.append("[!] VULNERABLE: ESC1 — Enrollee supplies subject")
            if template.any_purpose:
                vuln_flags.append("[!] VULNERABLE: ESC2 — Any Purpose EKU")
            if template.agent_template:
                vuln_flags.append("[!] VULNERABLE: ESC3 — Enrollment agent")

            lines.extend([
                "",
                f"  Template Name                : {template.name}",
                f"  Display Name                 : {template.display_name}",
                f"  Enrollee Supplies Subject    : {template.enrollee_supplies_subject}",
                f"  Any Purpose                  : {template.any_purpose}",
                f"  Requires Manager Approval    : {template.requires_manager_approval}",
                f"  Authorized Signatures Required: {template.authorized_signatures_required}",
                f"  Enrollment Principals        : {', '.join(template.enrollment_principals)}",
            ])
            for flag in vuln_flags:
                lines.append(f"  {flag}")

        return "\n".join(lines)

    def _request_cert(self, args: list[str]) -> str:
        """Simulate certificate request (ESC1 exploitation)."""
        template_name = ""
        target_upn = ""

        for i, arg in enumerate(args):
            if arg == "-template" and i + 1 < len(args):
                template_name = args[i + 1]
            if arg == "-upn" and i + 1 < len(args):
                target_upn = args[i + 1]

        template = next(
            (t for t in self.manifest.cert_templates if t.name == template_name),
            None,
        )

        if not template:
            return f"[-] Template '{template_name}' not found"

        if not template.enrollee_supplies_subject:
            return f"[-] Template '{template_name}' does not allow enrollee-supplied subject"

        if template.requires_manager_approval:
            return f"[-] Template '{template_name}' requires manager approval"

        lines = [
            "Certipy v4.8.2 - by Oliver Lyak (ly4k)",
            "",
            f"[*] Requesting certificate for '{target_upn}'",
            "[*] Successfully requested certificate",
            "[*] Request ID is 42",
            f"[*] Got certificate with UPN '{target_upn}'",
            "[*] Certificate has no object SID",
            f"[*] Saved certificate and private key to '{target_upn.split('@')[0]}.pfx'",
        ]
        return "\n".join(lines)
