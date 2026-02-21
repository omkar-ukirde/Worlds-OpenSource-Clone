"""Training configuration — all hyperparameters in one place."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TrainingConfig(BaseModel):
    """Configuration for LoRA SFT training.

    Usage:
        config = TrainingConfig(
            model_name="google/gemma-3-270m-it",
            dataset_path="data/datasets/trajectories.jsonl",
        )
    """

    model_config = {"protected_namespaces": ()}

    # Model
    model_name: str = Field(
        default="google/gemma-3-270m-it",
        description="HuggingFace model name or local path",
    )
    trust_remote_code: bool = Field(
        default=False,
        description="Whether to trust remote code from HuggingFace",
    )

    # Dataset
    dataset_path: str = Field(
        default="data/datasets/trajectories.jsonl",
        description="Path to JSONL trajectory file",
    )
    val_split: float = Field(
        default=0.1,
        description="Fraction of data for validation (0.0–1.0)",
    )
    max_seq_len: int = Field(
        default=2048,
        description="Maximum sequence length for tokenization",
    )
    chat_format: str = Field(
        default="auto",
        description=(
            "Chat template format: 'auto' (detect from tokenizer), "
            "'full' (Llama 3/Qwen), 'no_tool' (Mistral), "
            "'strict_alternation' (Gemma 3), 'chatml' (base models)"
        ),
    )

    # LoRA
    lora_r: int = Field(default=16, description="LoRA rank")
    lora_alpha: int = Field(default=32, description="LoRA alpha scaling")
    lora_dropout: float = Field(default=0.05, description="LoRA dropout")
    lora_target_modules: list[str] = Field(
        default_factory=lambda: ["q_proj", "v_proj", "k_proj", "o_proj"],
        description="Modules to apply LoRA to",
    )

    # Training
    epochs: int = Field(default=3, description="Number of training epochs")
    batch_size: int = Field(default=1, description="Per-device batch size")
    gradient_accumulation_steps: int = Field(
        default=4,
        description="Gradient accumulation steps (effective batch = batch_size × this)",
    )
    learning_rate: float = Field(default=2e-4, description="Learning rate")
    weight_decay: float = Field(default=0.01, description="Weight decay")
    warmup_ratio: float = Field(default=0.03, description="Warmup as fraction of total steps")
    lr_scheduler: str = Field(default="cosine", description="LR scheduler type")
    fp16: bool = Field(default=False, description="Use fp16 (CUDA only)")
    bf16: bool = Field(default=False, description="Use bf16 (Ampere+ / Apple Silicon)")
    use_cpu: bool = Field(
        default=False,
        description="Force CPU training (avoids MPS OOM on small Macs)",
    )
    seed: int = Field(default=42, description="Random seed")

    # Output
    output_dir: str = Field(
        default="data/models/openworlds-agent",
        description="Directory to save the LoRA adapter",
    )
    logging_steps: int = Field(default=5, description="Log every N steps")
    save_strategy: str = Field(default="epoch", description="Checkpoint save strategy")

    # HuggingFace Hub
    push_to_hub: bool = Field(default=False, description="Push to HuggingFace Hub")
    hub_model_id: str | None = Field(
        default=None,
        description="HuggingFace Hub model ID (e.g. 'username/model-name')",
    )
    hub_token: str | None = Field(
        default=None,
        description="HuggingFace API token (or set HF_TOKEN env var)",
    )

    def effective_batch_size(self) -> int:
        """Compute effective batch size."""
        return self.batch_size * self.gradient_accumulation_steps
