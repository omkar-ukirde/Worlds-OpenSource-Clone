"""Dataset Formatter — converts Trajectories into training-ready JSONL.

Supported formats:
    - messages: List of {role, content} dicts (OpenAI / generic).
    - chatml: ChatML token format (<|im_start|>role\n...<|im_end|>).

Each trajectory becomes one training sample with:
    system → mission briefing (domain, credentials, goal)
    assistant → <think>reasoning</think>\n<tool_call>command</tool_call>
    tool → simulated output
    ... (repeating for each step)
"""

from __future__ import annotations

import json
from pathlib import Path

from openworlds.trajectory.generator import Trajectory, TrajectoryStep

# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------


def _system_prompt(trajectory: Trajectory) -> str:
    """Build the system prompt for a trajectory."""
    return (
        "You are an expert penetration tester conducting an authorized Active "
        "Directory security assessment. You have access to a Kali Linux "
        "command line with standard pentesting tools.\n\n"
        "Your objective is to achieve Domain Admin privileges in the target "
        "Active Directory network.\n\n"
        f"Target Domain: {trajectory.domain}\n"
        f"Starting Credentials:\n"
        f"  Username: {trajectory.starting_user}\n"
        f"  Domain: {trajectory.domain}\n"
        f"Starting Host: {trajectory.starting_host} ({trajectory.starting_ip})\n\n"
        "Instructions:\n"
        "- Think step by step. Use <think> tags for reasoning before each command.\n"
        "- Use <tool_call> tags to execute commands.\n"
        "- Analyze tool output carefully before deciding the next step.\n"
        "- If a command fails, analyze the error and try a different approach."
    )


def _format_assistant_turn(step: TrajectoryStep) -> str:
    """Format an assistant turn with reasoning + tool call."""
    parts = []
    if step.reasoning:
        parts.append(f"<think>\n{step.reasoning}\n</think>")
    parts.append(f"\n<tool_call>\n{step.action}\n</tool_call>")
    return "\n".join(parts)


def _trajectory_to_messages(trajectory: Trajectory) -> list[dict[str, str]]:
    """Convert a trajectory into a list of chat messages."""
    messages: list[dict[str, str]] = [
        {"role": "system", "content": _system_prompt(trajectory)},
    ]

    for step in trajectory.steps:
        # Assistant turn: reasoning + tool call
        messages.append({
            "role": "assistant",
            "content": _format_assistant_turn(step),
        })
        # Tool turn: observation
        messages.append({
            "role": "tool",
            "content": step.observation,
        })

    return messages


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


def format_messages(trajectory: Trajectory) -> dict:
    """Convert trajectory to messages format (generic / OpenAI).

    Returns:
        Dict with 'messages' key containing list of role/content dicts.
    """
    return {
        "id": trajectory.trajectory_id,
        "messages": _trajectory_to_messages(trajectory),
        "metadata": {
            "domain": trajectory.domain,
            "starting_user": trajectory.starting_user,
            "strategies": trajectory.strategies_used,
            "total_steps": trajectory.total_steps,
            "success": trajectory.success,
        },
    }


def format_chatml(trajectory: Trajectory) -> str:
    """Convert trajectory to ChatML string format.

    Returns:
        Full ChatML-formatted string.
    """
    messages = _trajectory_to_messages(trajectory)
    parts = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Batch export
# ---------------------------------------------------------------------------


def export_dataset(
    trajectories: list[Trajectory],
    output_path: str | Path,
    fmt: str = "messages",
) -> None:
    """Export trajectories to a JSONL file.

    Args:
        trajectories: List of Trajectory objects to export.
        output_path: Path to write the JSONL file.
        fmt: Format — 'messages' or 'chatml'.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w") as f:
        for traj in trajectories:
            if fmt == "chatml":
                record = {
                    "id": traj.trajectory_id,
                    "text": format_chatml(traj),
                    "metadata": {
                        "domain": traj.domain,
                        "strategies": traj.strategies_used,
                        "total_steps": traj.total_steps,
                        "success": traj.success,
                    },
                }
            else:
                record = format_messages(traj)

            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def dataset_stats(trajectories: list[Trajectory]) -> dict:
    """Compute summary statistics about a trajectory dataset.

    Returns:
        Dict with counts, averages, and strategy breakdown.
    """
    if not trajectories:
        return {"total": 0}

    total_steps = [t.total_steps for t in trajectories]
    strategies: dict[str, int] = {}
    for t in trajectories:
        for s in t.strategies_used:
            strategies[s] = strategies.get(s, 0) + 1

    failure_counts = [
        sum(1 for s in t.steps if s.is_failure) for t in trajectories
    ]

    return {
        "total_trajectories": len(trajectories),
        "successful": sum(1 for t in trajectories if t.success),
        "avg_steps": sum(total_steps) / len(total_steps),
        "min_steps": min(total_steps),
        "max_steps": max(total_steps),
        "avg_failures_per_trajectory": (
            sum(failure_counts) / len(failure_counts) if failure_counts else 0
        ),
        "strategies": strategies,
    }
