"""Evaluation Scorer — computes metrics from scenario results.

Metrics:
    1. Success Rate       — % scenarios reaching Domain Admin
    2. Step Efficiency    — ideal_steps / actual_steps (1.0 = perfect)
    3. Technique Coverage — unique techniques / available techniques
    4. Valid Command Rate  — commands recognized by simulator / total
    5. Recovery Rate      — successful corrections after failures / total failures
"""

from __future__ import annotations

from openworlds.eval.models import EvalReport, ScenarioResult, ScenarioScore


class EvalScorer:
    """Scores evaluation scenarios and aggregates results."""

    def score_scenario(self, result: ScenarioResult) -> ScenarioScore:
        """Score a single scenario result."""
        total = result.total_steps or len(result.steps)
        if total == 0:
            return ScenarioScore(scenario_id=result.scenario_id)

        # Valid command rate
        valid = sum(1 for s in result.steps if s.is_valid_command)
        valid_rate = valid / total

        # Step efficiency (ideal / actual, capped at 1.0)
        efficiency = 0.0
        if result.reached_da and result.ideal_steps > 0:
            efficiency = min(result.ideal_steps / total, 1.0)

        # Technique coverage
        available = len(result.strategies_available) if result.strategies_available else 1
        used = len(set(result.techniques_used))
        coverage = min(used / available, 1.0) if available > 0 else 0.0

        # Recovery rate
        failures = sum(1 for s in result.steps if s.is_failure)
        recoveries = sum(1 for s in result.steps if s.recovered)
        recovery = recoveries / failures if failures > 0 else 1.0

        return ScenarioScore(
            scenario_id=result.scenario_id,
            success=result.reached_da,
            step_efficiency=round(efficiency, 3),
            technique_coverage=round(coverage, 3),
            valid_command_rate=round(valid_rate, 3),
            recovery_rate=round(recovery, 3),
            total_steps=total,
        )

    def aggregate(
        self,
        scores: list[ScenarioScore],
        model_path: str,
        max_steps: int,
    ) -> EvalReport:
        """Aggregate per-scenario scores into a final report."""
        n = len(scores)
        if n == 0:
            return EvalReport(
                model_path=model_path,
                num_scenarios=0,
                max_steps_per_scenario=max_steps,
            )

        successes = [s for s in scores if s.success]

        return EvalReport(
            model_path=model_path,
            num_scenarios=n,
            max_steps_per_scenario=max_steps,
            success_rate=round(len(successes) / n, 3),
            avg_step_efficiency=round(
                sum(s.step_efficiency for s in scores) / n, 3,
            ),
            avg_technique_coverage=round(
                sum(s.technique_coverage for s in scores) / n, 3,
            ),
            avg_valid_command_rate=round(
                sum(s.valid_command_rate for s in scores) / n, 3,
            ),
            avg_recovery_rate=round(
                sum(s.recovery_rate for s in scores) / n, 3,
            ),
            avg_steps_to_da=round(
                sum(s.total_steps for s in successes) / len(successes), 1,
            ) if successes else 0.0,
            scenarios=scores,
        )
