"""Evil-WinRM handler — simulates WinRM sessions."""

from __future__ import annotations

from openworlds.tools.handlers.base import BaseHandler


class EvilWinRMHandler(BaseHandler):
    """Simulates evil-winrm session establishment."""

    def execute(self, args: list[str]) -> str:
        """Execute simulated evil-winrm.

        Usage: evil-winrm -i TARGET -u user -p password
        """
        target = ""
        username = ""
        password = ""
        nt_hash = ""

        for i, arg in enumerate(args):
            if arg == "-i" and i + 1 < len(args):
                target = args[i + 1]
            elif arg == "-u" and i + 1 < len(args):
                username = args[i + 1]
            elif arg == "-p" and i + 1 < len(args):
                password = args[i + 1]
            elif arg == "-H" and i + 1 < len(args):
                nt_hash = args[i + 1]

        if not target:
            return "Usage: evil-winrm -i TARGET -u USER -p PASSWORD"

        host = self.find_host(target)
        if not host:
            return f"Error: Cannot connect to {target}"

        # Check if WinRM is available (port 5985)
        has_winrm = any(
            s.port in (5985, 5986) for s in host.services
        )
        if not has_winrm:
            return f"Error: WinRM not available on {target}"

        # Verify credentials
        user = self.find_user(username)
        if not user:
            return f"Error: Authentication failed for {username}"

        auth_ok = False
        if password and user.password == password:
            auth_ok = True
        elif nt_hash and user.nt_hash == nt_hash:
            auth_ok = True

        if not auth_ok:
            return (
                f"Evil-WinRM shell v3.5\n\n"
                f"Error: An error of type WinRM::WinRMAuthorizationError happened, "
                f"message is WinRM::WinRMAuthorizationError"
            )

        # Check if user has access (local admin)
        if username not in host.local_admins:
            return (
                f"Evil-WinRM shell v3.5\n\n"
                f"Error: Access denied. {username} is not a local admin on {host.hostname}"
            )

        return (
            f"Evil-WinRM shell v3.5\n\n"
            f"Info: Establishing connection to remote endpoint\n"
            f"*Evil-WinRM* PS C:\\Users\\{username}\\Documents> whoami\n"
            f"{self.domain.netbios_name.lower()}\\{username}\n"
            f"*Evil-WinRM* PS C:\\Users\\{username}\\Documents>"
        )
