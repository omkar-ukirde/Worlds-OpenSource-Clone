"""Layer 4: Evaluation — Simulated evaluation harness.

Public API:
    EvalHarness  — runs a model against fresh AD networks
    EvalScorer   — computes per-scenario and aggregate metrics
    EvalReport   — aggregate evaluation results
"""

from openworlds.eval.models import EvalReport, EvalStep, ScenarioResult, ScenarioScore

__all__ = ["EvalReport", "EvalStep", "ScenarioResult", "ScenarioScore"]
