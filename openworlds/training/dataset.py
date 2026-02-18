"""Dataset loader — converts trajectory JSONL to HuggingFace Dataset.

Supports model-aware chat template formatting:
  - auto-detects what roles the model's template supports
  - applies the minimal necessary transformation per model family
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openworlds.training.config import TrainingConfig

# ---------------------------------------------------------------------------
# Chat format detection
# ---------------------------------------------------------------------------

VALID_CHAT_FORMATS = ("auto", "full", "no_tool", "strict_alternation", "chatml")


def detect_chat_format(tokenizer: Any) -> str:
    """Probe the tokenizer's chat template to determine supported roles.

    Tests whether the template can handle 'system' and 'tool' roles,
    and whether it requires strict user/assistant alternation.

    Returns one of: 'full', 'no_tool', 'strict_alternation', 'chatml'.
    """
    if not hasattr(tokenizer, "apply_chat_template"):
        return "chatml"

    # Check if chat_template attribute exists and is non-empty
    template = getattr(tokenizer, "chat_template", None)
    if not template:
        return "chatml"

    # --- Probe 1: Does it support 'system' role? ---
    has_system = _probe_role(tokenizer, [
        {"role": "system", "content": "Test."},
        {"role": "user", "content": "Hi."},
        {"role": "assistant", "content": "Hello."},
    ])

    # --- Probe 2: Does it support 'tool' role? ---
    has_tool = _probe_role(tokenizer, [
        {"role": "user", "content": "Use the tool."},
        {"role": "assistant", "content": "Calling tool."},
        {"role": "tool", "content": "Result."},
        {"role": "assistant", "content": "Done."},
    ])

    # --- Probe 3: Does it require strict alternation? ---
    # If it fails with two consecutive user messages, it's strict
    requires_alternation = not _probe_role(tokenizer, [
        {"role": "user", "content": "First."},
        {"role": "user", "content": "Second."},
        {"role": "assistant", "content": "Reply."},
    ])

    if requires_alternation:
        return "strict_alternation"
    if has_system and has_tool:
        return "full"
    if has_system:
        return "no_tool"
    return "strict_alternation"


def _probe_role(tokenizer: Any, messages: list[dict[str, str]]) -> bool:
    """Test if a tokenizer's template accepts a given message sequence."""
    try:
        tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False,
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def load_trajectory_dataset(
    config: TrainingConfig,
) -> tuple[Any, Any]:
    """Load trajectory JSONL and prepare for SFT training.

    Reads JSONL files produced by the trajectory formatter,
    applies the model's chat template, and returns train/val splits.

    Args:
        config: Training configuration.

    Returns:
        Tuple of (train_dataset, val_dataset) as HuggingFace Datasets.
    """
    from datasets import Dataset

    # Read JSONL
    records = _read_jsonl(config.dataset_path)
    if not records:
        raise ValueError(f"No records found in {config.dataset_path}")

    # Extract conversations
    conversations = []
    for record in records:
        messages = record.get("messages", [])
        if not messages:
            continue
        conversations.append({"messages": messages})

    if not conversations:
        raise ValueError("No valid conversations found in dataset")

    # Create HuggingFace Dataset
    dataset = Dataset.from_list(conversations)

    # Train/val split
    if config.val_split > 0 and len(conversations) > 1:
        split = dataset.train_test_split(
            test_size=config.val_split,
            seed=config.seed,
        )
        return split["train"], split["test"]

    return dataset, None


# ---------------------------------------------------------------------------
# Formatting strategies
# ---------------------------------------------------------------------------


def format_for_training(
    example: dict[str, Any],
    tokenizer: Any,
    max_seq_len: int = 2048,
    chat_format: str = "auto",
) -> dict[str, Any]:
    """Format a single example using the appropriate chat template strategy.

    The chat_format parameter controls how roles are remapped:
      - 'full':  Keep system + tool roles (Llama 3, Qwen 2.5)
      - 'no_tool':  Keep system, remap tool→user (Mistral)
      - 'strict_alternation':  Merge to user/assistant only (Gemma 3)
      - 'chatml':  Raw <|im_start|> fallback (base models)
      - 'auto':  Auto-detect (should be resolved before calling this)

    Args:
        example: Dict with 'messages' key (list of role/content dicts).
        tokenizer: HuggingFace tokenizer.
        max_seq_len: Max sequence length.
        chat_format: Which formatting strategy to use.

    Returns:
        Dict with 'text' key containing formatted string.
    """
    messages = example["messages"]

    if chat_format == "auto":
        chat_format = detect_chat_format(tokenizer)

    if chat_format == "full":
        final = _format_full(messages)
    elif chat_format == "no_tool":
        final = _format_no_tool(messages)
    elif chat_format == "strict_alternation":
        final = _format_strict_alternation(messages)
    elif chat_format == "chatml":
        return {"text": _format_chatml(messages)}
    else:
        raise ValueError(
            f"Unknown chat_format: {chat_format!r}. "
            f"Valid: {VALID_CHAT_FORMATS}"
        )

    # Apply the model's chat template
    try:
        text = tokenizer.apply_chat_template(
            final,
            tokenize=False,
            add_generation_prompt=False,
        )
    except Exception:
        # If template still fails, fall back to ChatML
        text = _format_chatml(final)

    return {"text": text}


# --- Strategy: full (Llama 3, Qwen 2.5) ---

def _format_full(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep system and tool roles as-is. Only remap unknown roles."""
    result = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role not in ("system", "user", "assistant", "tool"):
            role = "user"
        result.append({"role": role, "content": content})
    return result


# --- Strategy: no_tool (Mistral) ---

def _format_no_tool(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep system role, remap tool→user with prefix."""
    result = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role == "tool":
            role = "user"
            content = f"[Tool Output]\n{content}"
        result.append({"role": role, "content": content})

    # Merge consecutive same-role messages
    return _merge_consecutive(result)


# --- Strategy: strict_alternation (Gemma 3) ---

def _format_strict_alternation(
    messages: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Remap everything to user/assistant with strict alternation."""
    # Step 1: Remap system/tool → user
    remapped: list[dict[str, str]] = []
    system_prefix = ""
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role == "system":
            system_prefix += content + "\n\n"
            continue
        if role == "tool":
            role = "user"
            content = f"[Tool Output]\n{content}"
        if system_prefix and role == "user":
            content = system_prefix + content
            system_prefix = ""
        elif system_prefix and role == "assistant":
            remapped.append({"role": "user", "content": system_prefix.strip()})
            system_prefix = ""
        remapped.append({"role": role, "content": content})

    # Step 2: Merge consecutive same-role
    merged = _merge_consecutive(remapped)

    # Step 3: Ensure starts with user
    if merged and merged[0]["role"] != "user":
        merged.insert(0, {"role": "user", "content": "Begin the penetration test."})

    # Step 4: Insert fillers for any remaining same-role pairs
    final: list[dict[str, str]] = []
    for msg in merged:
        if final and final[-1]["role"] == msg["role"]:
            filler_role = "assistant" if msg["role"] == "user" else "user"
            filler_text = "Continue." if filler_role == "user" else "Understood."
            final.append({"role": filler_role, "content": filler_text})
        final.append(msg)

    return final


# --- Strategy: chatml (base models / fallback) ---

def _format_chatml(messages: list[dict[str, str]]) -> str:
    """Raw ChatML format for models without a chat template."""
    parts = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _merge_consecutive(
    messages: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Merge consecutive messages with the same role."""
    merged: list[dict[str, str]] = []
    for msg in messages:
        if merged and merged[-1]["role"] == msg["role"]:
            merged[-1]["content"] += "\n\n" + msg["content"]
        else:
            merged.append(dict(msg))
    return merged


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL file into a list of dicts."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    records = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
