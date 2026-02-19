"""Evaluation data models — Pydantic models for eval results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class EvalStep(BaseModel):
    """A single step in an evaluation scenario."""

    step_number: int
    action: str = Field(description="Command the model generated")
    observation: str = Field(description="Simulator output")
    reasoning: str = Field(default="", description="Model's <think> block")
    is_valid_command: bool = Field(default=True, description="Recognized by simulator")
    is_failure: bool = Field(default=False, description="Command failed")
    recovered: bool = Field(default=False, description="Recovered after failure")
    technique: str = Field(default="", description="Detected technique")


class ScenarioResult(BaseModel):
    """Raw result of running one evaluation scenario."""

    scenario_id: int
    domain: str
    starting_user: str
    steps: list[EvalStep] = Field(default_factory=list)
    reached_da: bool = False
    total_steps: int = 0
    ideal_steps: int = 0  # Length of shortest attack path
    strategies_available: list[str] = Field(default_factory=list)
    techniques_used: list[str] = Field(default_factory=list)
    error: str = ""  # If scenario errored


class ScenarioScore(BaseModel):
    """Scored metrics for one scenario."""

    scenario_id: int
    success: bool = False  # Reached DA
    step_efficiency: float = 0.0  # ideal/actual (1.0 = perfect, capped at 1.0)
    technique_coverage: float = 0.0  # unique used / available
    valid_command_rate: float = 0.0  # valid commands / total
    recovery_rate: float = 0.0  # recoveries / failures (1.0 if no failures)
    total_steps: int = 0


class EvalReport(BaseModel):
    """Aggregate evaluation report."""

    model_config = {"protected_namespaces": ()}

    model_path: str
    num_scenarios: int = 0
    max_steps_per_scenario: int = 0

    # Aggregate metrics
    success_rate: float = 0.0
    avg_step_efficiency: float = 0.0
    avg_technique_coverage: float = 0.0
    avg_valid_command_rate: float = 0.0
    avg_recovery_rate: float = 0.0
    avg_steps_to_da: float = 0.0

    # Per-scenario breakdown
    scenarios: list[ScenarioScore] = Field(default_factory=list)
