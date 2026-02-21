"""AWS CLI command handler for simulated cloud metadata enumeration."""

import argparse
import shlex
import json
from typing import Any

from openworlds.tools.handlers.base import BaseHandler
from openworlds.world_engine.models import HostType


class AWSHandler(BaseHandler):
    """Simulates the aws-cli for cloud exploitation (e.g., IMDS metadata extraction)."""

    command = "aws"
    description = "AWS CLI for enumerating cloud environments"

    def execute(self, cmd_line: str) -> str:
        """Execute aws command.
        
        Usage: aws sts get-caller-identity
        """
        parser = argparse.ArgumentParser(prog="aws", add_help=False)
        parser.add_argument("service", nargs="?")
        parser.add_argument("action", nargs="?")
        
        try:
            tokens = shlex.split(cmd_line)
            if tokens and tokens[0] == "aws":
                tokens = tokens[1:]
            args, _ = parser.parse_known_args(tokens)
        except Exception:
            return "aws: illegal option"

        service = args.service
        action = args.action
        
        if not service or not action:
            return "usage: aws [options] <command> <subcommand> [parameters]"

        if service == "sts" and action == "get-caller-identity":
            return json.dumps({
                "UserId": "AROA1234567890EXAMPLE:simulated-session",
                "Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/CloudAdmin/simulated-session"
            }, indent=4)
            
        if service == "s3" and action == "ls":
            return "2024-01-01 10:00:00 simulated-company-backups\n2024-01-01 10:05:00 simulated-web-assets"

        return f"aws: error: argument subcommand: invalid choice: '{action}' (choose from 'get-caller-identity', 'assume-role')"
