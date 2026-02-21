"""Breach and Attack Simulation (BAS) Automation Engine.

This module allows running a deterministic, pre-scripted set of
tool commands (YAML/JSON) against the ToolSimulator to evaluate
if the BlueTeamAgent successfully detects and mitigates the threat.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from openworlds.tools.simulator import ToolSimulator
from openworlds.world_engine.models import Manifest


class BASStepResult(BaseModel):
    """Result of a single step in a BAS script."""

    step_number: int
    command: str
    output: str
    noise_generated: int
    blue_team_blocked: bool
    mitigation_reason: str | None


class BASReport(BaseModel):
    """The aggregate report from running a BAS script."""

    script_name: str
    total_steps: int
    steps_completed: int
    success: bool = Field(description="False if blocked by Blue Team")
    step_results: list[BASStepResult]
    final_noise_level: int
    blocked_at_step: int | None = None


class BASEngine:
    """Runs a hardcoded YAML playbook against the simulated network."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        # We always enforce dynamic defense for BAS runs
        self.simulator = ToolSimulator(manifest, dynamic_defense=True)
        self.blue_team = self.simulator.blue_team

    def run_script(self, script_path: Path) -> BASReport:
        """Parse and execute a YAML/JSON BAS script."""
        with open(script_path, "r") as f:
            if script_path.suffix == ".json":
                data = json.load(f)
            else:
                data = yaml.safe_load(f)

        script_name = data.get("name", "Untitled BAS Script")
        steps = data.get("steps", [])

        results = []
        blocked = False
        blocked_at = None

        for idx, cmd in enumerate(steps, 1):
            if blocked:
                # Can't proceed if already blocked by Blue Team
                break

            prev_noise = self.blue_team.network_alert_level if self.blue_team else 0
            
            # Execute command
            output = self.simulator.execute(cmd)
            
            # Check noise delta
            new_noise = self.blue_team.network_alert_level if self.blue_team else 0
            delta_noise = new_noise - prev_noise

            # Check if Blue Team triggered a block during this step
            was_blocked = False
            mitigation_reason = None
            
            if "has been blocked" in output or "has been isolated" in output:
                was_blocked = True
                blocked = True
                blocked_at = idx
                mitigation_reason = output.split("\n")[0]  # EDR alert is usually at the top
            elif "Simulation Terminated" in output:
                was_blocked = True
                blocked = True
                blocked_at = idx
                mitigation_reason = "Max noise threshold exceeded"

            result = BASStepResult(
                step_number=idx,
                command=cmd,
                output=output[:500] + ("..." if len(output) > 500 else ""),
                noise_generated=delta_noise,
                blue_team_blocked=was_blocked,
                mitigation_reason=mitigation_reason,
            )
            results.append(result)

        return BASReport(
            script_name=script_name,
            total_steps=len(steps),
            steps_completed=len(results),
            success=not blocked,
            step_results=results,
            final_noise_level=self.blue_team.network_alert_level if self.blue_team else 0,
            blocked_at_step=blocked_at,
        )
