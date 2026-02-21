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
from openworlds.world_engine.blue_team import BlueTeamAgent


class ToolSimulator:
    """Routes commands to the correct tool handler.

    Usage:
        simulator = ToolSimulator(manifest)
        output = simulator.execute("nmap -sV -p- 10.0.1.10")
    """

    def __init__(self, manifest: Manifest, dynamic_defense: bool = False) -> None:
        self.manifest = manifest
        self.dynamic_defense = dynamic_defense
        self.blue_team = BlueTeamAgent(manifest) if dynamic_defense else None
        
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
            output_prefix = ""
            if self.dynamic_defense and self.blue_team:
                # Basic heuristic base-noise estimation (simplified for now)
                noise_score = 5.0
                if "nmap" in command:
                    noise_score = 15.0 if "-p-" in command else 5.0
                elif "crackmapexec" in command or "kerberoast" in command:
                    noise_score = 25.0
                
                target = parts[-1] if len(parts) > 1 else "network"
                source_ip = "10.0.1.99" # Default attacker IP
                
                retaliation = self.blue_team.report_noise(source_ip, command, target, noise_score)
                if retaliation:
                    if "blocked" in retaliation.lower() or "disconnected" in retaliation.lower():
                        return retaliation
                    output_prefix = retaliation + "\n\n"

            result = handler.execute(parts[1:])
            # If blue team closed the port mid-scan, the handler output wouldn't know
            # A true integration would pass blue_team to the handler, but we simulate it by altering output
            if self.dynamic_defense and self.blue_team and "nmap" in command:
                target = parts[-1]
                if self.blue_team.is_port_blocked(target, 445):
                    result = result.replace("445/tcp open", "445/tcp filtered")
                    result = result.replace("135/tcp open", "135/tcp filtered")

            return output_prefix + result
        except Exception as e:
            return f"Error executing {tool_name}: {e}"

    def get_available_tools(self) -> list[str]:
        """Return list of available tool names."""
        return sorted(set(self.handlers.keys()))
