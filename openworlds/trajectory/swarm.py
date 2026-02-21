"""Multi-Agent Swarm Orchestrator for Advanced Pentesting Operations.

This module implements the "Swarm" architecture where a Coordinator
delegates tasks to specialized agents (Recon, Exploit) sharing a global state.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from openworlds.trajectory.state_tracker import StateTracker
from openworlds.tools.simulator import ToolSimulator

logger = logging.getLogger(__name__)

DELEGATE_PATTERN = re.compile(r"<delegate\s+to=[\"']?(Recon|Exploit)[\"']?>\s*(.+?)\s*</delegate>", re.DOTALL | re.IGNORECASE)
TOOL_PATTERN = re.compile(r"<tool_call>\s*(.+?)\s*</tool_call>", re.DOTALL)


class SpecialistAgent:
    """A specialized AI agent that executes tools in a specific domain."""

    def __init__(self, name: str, system_prompt: str, llm_pipeline: Any = None) -> None:
        self.name = name
        self.system_prompt = system_prompt
        self.llm_pipeline = llm_pipeline

    def act(self, task: str, state_summary: str, simulator: ToolSimulator) -> tuple[str, str]:
        """Generate a tool call, execute it, and return the result."""
        # Note: In a real run, the LLM pipeline generates the tool call
        # For demonstration of the scaffold, if no LLM provided, we return empty
        if not self.llm_pipeline:
            return "Mock Tool Call", f"({self.name} acting on: {task}) - LLM pipeline omitted for placeholder"
            
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Task: {task}\n\nCurrent State: {state_summary}"}
        ]
        response = self.llm_pipeline(messages)
        return self._execute_response(response, simulator)
        
    def _execute_response(self, response: str, simulator: ToolSimulator) -> tuple[str, str]:
        match = TOOL_PATTERN.search(response)
        if match:
            cmd = match.group(1).strip()
            try:
                out = simulator.execute(cmd)
                return cmd, out
            except Exception as e:
                return cmd, f"Error: {e}"
        return "", "Could not parse tool call."


class SwarmOrchestrator:
    """Coordinates specialized agents to compromise a network."""

    def __init__(
        self,
        manifest: Any,
        llm_pipeline: Any = None,
        max_turns: int = 20,
        dynamic_defense: bool = True
    ) -> None:
        self.manifest = manifest
        self.llm_pipeline = llm_pipeline
        self.max_turns = max_turns
        self.simulator = ToolSimulator(manifest, dynamic_defense=dynamic_defense)
        self.state_tracker = StateTracker()
        
        # Initialize specialists
        self.specialists = {
            "Recon": SpecialistAgent(
                "Recon", 
                "You are the Recon Agent. Your job is to run nmap and ldapsearch to find targets and output strictly what you find.",
                llm_pipeline
            ),
            "Exploit": SpecialistAgent(
                "Exploit",
                "You are the Exploit Agent. Your job is to use secretsdump, GetUserSPNs, or cme to extract hashes and passwords.",
                llm_pipeline
            )
        }
        
    def _get_coordinator_prompt(self) -> str:
        return (
            "You are the Swarm Coordinator for a red team operation.\n"
            "Your job is to read the current network state, decide the next step, "
            "and DELEGATE the task to a specialist. Do not run tools yourself.\n\n"
            "Available Specialists:\n"
            "- Recon: Good for host discovery and ldap mapping.\n"
            "- Exploit: Good for cracking hashes, lateral movement, and dumping creds.\n\n"
            "To assign a task, use this exact XML format:\n"
            "<delegate to=\"Recon\">Run a port sweep on 10.0.1.0/24</delegate>\n"
            "or <delegate to=\"Exploit\">Attempt Kerberoasting on the domain</delegate>"
        )

    def run_episode(self, start_user: Any) -> dict[str, Any]:
        """Run the swarm until Domain Admin or max turns reached."""
        context = f"Starting User: {start_user.sam_account_name}, Target: {self.manifest.domain.name}"
        trajectory = []
        messages = [
            {"role": "system", "content": self._get_coordinator_prompt()},
            {"role": "user", "content": context}
        ]
        
        for turn in range(self.max_turns):
            if not self.llm_pipeline:
                logger.warning("Swarm ran without LLM pipeline; returning mock trace.")
                break
                
            coordinator_response = self.llm_pipeline(messages)
            messages.append({"role": "assistant", "content": coordinator_response})
            
            # Parse delegation
            delegate_match = DELEGATE_PATTERN.search(coordinator_response)
            if not delegate_match:
                messages.append({"role": "user", "content": "Error: You must use <delegate to=\"...\"> tags."})
                continue
                
            agent_name = delegate_match.group(1).capitalize()
            task_desc = delegate_match.group(2).strip()
            
            if agent_name not in self.specialists:
                messages.append({"role": "user", "content": f"Error: Agent '{agent_name}' not found. Use Recon or Exploit."})
                continue
                
            # Delegate to specialist
            agent = self.specialists[agent_name]
            state_str = self.state_tracker.get_context()
            
            cmd, output = agent.act(task_desc, state_str, self.simulator)
            
            # Optional: update state tracker based on output parsing
            # (In production, the state tracker parses outputs internally or the agent does it)
            
            trajectory.append({
                "turn": turn,
                "coordinator_directive": task_desc,
                "agent": agent_name,
                "command_run": cmd,
                "output": output
            })
            
            # Report back to coordinator
            report = f"[{agent_name} executed '{cmd}']\nResult:\n{output}"
            messages.append({"role": "user", "content": report})
            
            # Win condition
            if "krbtgt" in output.lower() or "Domain Admin" in output:
                break
                
        return {
            "success": turn < self.max_turns - 1,
            "turns_taken": turn,
            "trajectory": trajectory
        }
