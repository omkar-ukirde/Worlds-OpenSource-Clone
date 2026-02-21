"""Tool Simulator — dispatches commands to the correct tool handler.

Takes a raw command string (like "nmap -sV 10.0.1.10") and routes it
to the appropriate handler, which queries the manifest and returns
realistic simulated output.
"""

from __future__ import annotations

from typing import Any

from openworlds.tools.handlers.bloodhound_handler import BloodHoundHandler
from openworlds.tools.handlers.certipy_handler import CertipyHandler
from openworlds.tools.handlers.crackmapexec_handler import CrackMapExecHandler
from openworlds.tools.handlers.evil_winrm_handler import EvilWinRMHandler
from openworlds.tools.handlers.getnpusers_handler import GetNPUsersHandler
from openworlds.tools.handlers.getuserspns_handler import GetUserSPNsHandler
from openworlds.tools.handlers.ldapsearch_handler import LdapsearchHandler
from openworlds.tools.handlers.nmap_handler import NmapHandler
from openworlds.tools.handlers.secretsdump_handler import SecretsdumpHandler
from openworlds.tools.handlers.smbclient_handler import SmbclientHandler
from openworlds.world_engine.models import Manifest


class ToolSimulator:
    """Routes commands to the correct tool handler.

    Usage:
        simulator = ToolSimulator(manifest)
        output = simulator.execute("nmap -sV -p- 10.0.1.10")
    """

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.handlers: dict[str, Any] = {
            "nmap": NmapHandler(manifest),
            "ldapsearch": LdapsearchHandler(manifest),
            "smbclient": SmbclientHandler(manifest),
            "impacket-secretsdump": SecretsdumpHandler(manifest),
            "secretsdump": SecretsdumpHandler(manifest),
            "secretsdump.py": SecretsdumpHandler(manifest),
            "impacket-GetUserSPNs": GetUserSPNsHandler(manifest),
            "GetUserSPNs": GetUserSPNsHandler(manifest),
            "GetUserSPNs.py": GetUserSPNsHandler(manifest),
            "impacket-GetNPUsers": GetNPUsersHandler(manifest),
            "GetNPUsers": GetNPUsersHandler(manifest),
            "GetNPUsers.py": GetNPUsersHandler(manifest),
            "certipy": CertipyHandler(manifest),
            "bloodhound-python": BloodHoundHandler(manifest),
            "bloodhound": BloodHoundHandler(manifest),
            "crackmapexec": CrackMapExecHandler(manifest),
            "cme": CrackMapExecHandler(manifest),
            "evil-winrm": EvilWinRMHandler(manifest),
        }

    def execute(self, command: str) -> str:
        """Execute a simulated tool command.

        Args:
            command: Raw command string, e.g. "nmap -sV 10.0.1.10"

        Returns:
            Simulated tool output as a string.
        """
        parts = command.strip().split()
        if not parts:
            return "Error: Empty command"

        tool_name = parts[0]

        handler = self.handlers.get(tool_name)
        if not handler:
            return f"Error: Unknown tool '{tool_name}'. Available: {', '.join(sorted(set(self.handlers.keys())))}"

        try:
            return handler.execute(parts[1:])
        except Exception as e:
            return f"Error executing {tool_name}: {e}"

    def get_available_tools(self) -> list[str]:
        """Return list of available tool names."""
        return sorted(set(self.handlers.keys()))
