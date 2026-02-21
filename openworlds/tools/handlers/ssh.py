"""SSH command handler for simulated lateral movement."""

import argparse
import shlex
from typing import Any

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import HostType


class SSHHandler(BaseHandler):
    """Simulates an SSH client."""

    command = "ssh"
    description = "OpenSSH client for lateral movement to Linux/Cloud instances"

    def execute(self, args: list[str]) -> str:
        """Execute the ssh command.
        
        Usage: ssh user@10.0.1.55 -i id_rsa
        or     ssh 10.0.1.55 -l user
        """
        parser = argparse.ArgumentParser(prog="ssh", add_help=False)
        parser.add_argument("target", nargs="?")
        parser.add_argument("-l", "--login", dest="user")
        parser.add_argument("-i", "--identity_file", dest="key")
        
        # Best-effort parsing
        try:
            parsed_args, _ = parser.parse_known_args(args)
        except Exception:
            return "ssh: illegal option"

        target_str = parsed_args.target
        user = parsed_args.user
        
        if target_str and "@" in target_str:
            user, target_str = target_str.split("@", 1)
            
        if not target_str:
            return "usage: ssh [-i identity_file] [-l login_name] [user@]hostname [command]"

        host = self.find_host(target_str)
        if not host:
            return f"ssh: connect to host {target_str} port 22: Connection refused"
            
        ip = host.ip
        # Ensure it has SSH running
        ssh_svc = next((s for s in host.services if s.name == "ssh" or s.port == 22), None)
        if not ssh_svc:
            return f"ssh: connect to host {ip} port 22: Connection refused"

        # Check authentication (simulate key or password fallback)
        if parsed_args.key:
            return f"Linux {host.hostname} 5.15.0-generic x86_64\nWelcome to Ubuntu 22.04 LTS!\n\n{user}@{host.hostname.lower()}:~$"
            
        return f"{user}@{ip}'s password:\nPermission denied, please try again."
