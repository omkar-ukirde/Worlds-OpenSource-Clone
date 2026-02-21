"""Reinforcement Learning Environment for Agentic Pentesting.

This module provides an OpenAI Gym-like interface wrapping the OpenWorlds
simulation engine. It is designed to be used with RL algorithms (PPO, GRPO)
via libraries like `trl` or `stable-baselines3`.
"""

from __future__ import annotations

import re
from typing import Any

from openworlds.world_engine.ad_graph import ManifestGenerator
from openworlds.world_engine.models import HostType, ManifestConfig
from openworlds.world_engine.path_validator import PathValidator
from openworlds.world_engine.vuln_injector import VulnerabilityInjector
from openworlds.tools.simulator import ToolSimulator
from openworlds.trajectory.state_tracker import StateTracker

# Extract tool call
CMD_PATTERN = re.compile(r"<tool_call>\s*(.+?)\s*</tool_call>", re.DOTALL)
SHELL_PATTERN = re.compile(
    r"^\s*(?:sudo\s+)?(?:nmap|ldapsearch|impacket-\S+|GetUserSPNs\.py|GetNPUsers\.py|"
    r"secretsdump\.py|hashcat|crackmapexec|cme|evil-winrm|smbclient|"
    r"certipy|bloodhound|python3?)(?:\s+.*)$",
    re.MULTILINE | re.IGNORECASE,
)


class OpenWorldsRLEnv:
    """An environment wrapper for RL training.
    
    Provides standard reset() and step() methods. The action space is text
    (the LLM generates a string), and the observation space is text (simulator output).
    """

    def __init__(
        self,
        max_steps: int = 15,
        dynamic_defense: bool = True,
        seed: int = 42,
    ) -> None:
        self.max_steps = max_steps
        self.dynamic_defense = dynamic_defense
        self.seed = seed
        
        self.current_step = 0
        self.manifest = None
        self.simulator = None
        self.state_tracker = None
        self.target_domain = ""
        self.episode_seed = self.seed

    def reset(self, seed: int | None = None) -> tuple[str, dict[str, Any]]:
        """Reset the environment to a new fresh AD network episode.
        
        Returns:
            observation (str): The initial system prompt and context.
            info (dict): Additional scenario metadata.
        """
        if seed is not None:
            self.episode_seed = seed
        else:
            self.episode_seed += 1

        # 1. Generate fresh network
        config = ManifestConfig(num_hosts=10, num_users=25, seed=self.episode_seed)
        self.manifest = ManifestGenerator(config).generate()
        VulnerabilityInjector(self.manifest).inject_all()
        self.manifest.attack_paths = PathValidator(self.manifest).find_attack_paths()
        
        # 2. Initialize simulation components
        self.simulator = ToolSimulator(self.manifest, dynamic_defense=self.dynamic_defense)
        # We defer StateTracker initialization until after we pick the starting user
        
        # 3. Choose starting user and context
        start_user = None
        if self.manifest.attack_paths:
            for path in self.manifest.attack_paths:
                for user in self.manifest.users:
                    if user.sam_account_name == path.starting_user:
                        start_user = user
                        break
                if start_user:
                    break
        
        if not start_user:
            # Fallback if no specific path
            start_user = self.manifest.users[0]

        dc = next(
            (h for h in self.manifest.hosts if h.host_type == HostType.DOMAIN_CONTROLLER),
            self.manifest.hosts[0],
        )

        self.target_domain = self.manifest.domain.name
        self.current_step = 0
        
        # Initialize the state tracker appropriately
        self.state_tracker = StateTracker(
            domain=self.target_domain,
            start_user=start_user.sam_account_name,
            start_pass=start_user.password,
            start_host=self.manifest.hosts[1].hostname if len(self.manifest.hosts) > 1 else dc.hostname,
            start_ip=self.manifest.hosts[1].ip if len(self.manifest.hosts) > 1 else dc.ip,
        )

        # Construct initial observation (System Prompt)
        observation = (
            "You are an expert penetration tester conducting an authorized Active "
            "Directory security assessment.\n\n"
            "Your objective is to achieve Domain Admin privileges.\n\n"
            f"Target Domain: {self.target_domain}\n"
            f"Starting Credentials:\n"
            f"  Username: {start_user.sam_account_name}\n"
            f"  Password: {start_user.password}\n"
            f"  Domain: {self.target_domain}\n"
            f"DC IP: {dc.ip}\n\n"
            "Instructions:\n"
            "- Think step by step. Use <think> tags for reasoning.\n"
            "- Use <tool_call> tags to execute commands.\n"
            "- If a command fails, try a different approach."
        )

        info = {
            "domain": self.target_domain,
            "starting_user": start_user.sam_account_name,
            "ideal_steps": min(len(p.steps) for p in self.manifest.attack_paths) if self.manifest.attack_paths else 10
        }

        return observation, info

    def step(self, action_text: str) -> tuple[str, float, bool, bool, dict[str, Any]]:
        """Take a step in the environment.
        
        Args:
            action_text: The full string generated by the LLM (including <think> and <tool_call>).
            
        Returns:
            observation (str): The output of the executed command.
            reward (float): Reward signal for RL.
            terminated (bool): True if Domain Admin is reached.
            truncated (bool): True if max_steps is hit.
            info (dict): Metadata including step breakdown.
        """
        self.current_step += 1
        reward = 0.0
        terminated = False
        truncated = self.current_step >= self.max_steps
        
        # Extract command
        cmd = self._extract_command(action_text)
        if not cmd:
            reward -= 1.0  # Penalty for entirely invalid formatting
            observation = "Error: Could not extract a tool command. Please use <tool_call> tags."
            return observation, reward, terminated, truncated, {"is_valid": False}

        # Execute
        try:
            observation = self.simulator.execute(cmd)
            # Small penalty for every valid step to encourage efficiency
            reward -= 0.1 
            is_valid = True
        except Exception:
            observation = f"Error: Command execution failed for '{cmd}'."
            reward -= 0.5 # Penalty for malformed tool args
            is_valid = False

        # Apply massive penalty if Blue Team blocked us
        if "disconnected" in observation.lower() or "blocked by firewall" in observation.lower():
            reward -= 10.0
            terminated = True # Episode ends abruptly

        # Detect Domain Admin
        if self._check_da_achieved(observation, cmd):
            reward += 100.0
            terminated = True

        info = {
            "is_valid": is_valid,
            "command": cmd,
            "step": self.current_step
        }

        return observation, reward, terminated, truncated, info

    def _extract_command(self, text: str) -> str:
        """Extract a tool command from model output."""
        match = CMD_PATTERN.search(text)
        if match:
            return match.group(1).strip()
        match = SHELL_PATTERN.search(text)
        if match:
            return match.group(0).strip()
        return ""

    def _check_da_achieved(self, observation: str, cmd: str) -> bool:
        indicators = [
            "Pwn3d!", 
            "krbtgt", 
            "STATUS: Cracked", 
            "Domain Admin",
            "DOMAIN ADMINS",
            "PS >", 
            "Administrator:500:",
        ]
        obs_lower = observation.lower()
        return any(ind.lower() in obs_lower for ind in indicators)
