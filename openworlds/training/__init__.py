"""Agent Training — LoRA SFT fine-tuning on trajectory data."""

from openworlds.training.config import TrainingConfig

__all__ = [
    "TrainingConfig",
]

# Heavy imports (trainer, dataset) are deferred to avoid loading
# torch/transformers when only config is needed.
