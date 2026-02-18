"""SFT Trainer — LoRA fine-tuning with HuggingFace Hub support."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from openworlds.training.config import TrainingConfig
from openworlds.training.dataset import format_for_training, load_trajectory_dataset


class OpenWorldsTrainer:
    """Fine-tune a language model on OpenWorlds trajectories.

    Uses LoRA (Low-Rank Adaptation) for parameter-efficient training
    and optionally pushes the result to HuggingFace Hub.

    Usage:
        from openworlds.training.config import TrainingConfig
        from openworlds.training.trainer import OpenWorldsTrainer

        config = TrainingConfig(
            model_name="google/gemma-3-270m-it",
            dataset_path="data/datasets/trajectories.jsonl",
            epochs=3,
        )
        trainer = OpenWorldsTrainer(config)
        trainer.train()
        trainer.save()
    """

    def __init__(self, config: TrainingConfig) -> None:
        self.config = config
        self.model: Any = None
        self.tokenizer: Any = None
        self.trainer: Any = None
        self._adapter_path: str = ""

    def train(self) -> dict[str, float]:
        """Run the full training pipeline.

        Returns:
            Dict with training metrics (loss, etc.)
        """
        import torch
        from peft import LoraConfig, TaskType, get_peft_model
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
        )
        from trl import SFTTrainer

        config = self.config

        # --- 1. Load tokenizer ---
        print(f"📦 Loading tokenizer: {config.model_name}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            config.model_name,
            trust_remote_code=config.trust_remote_code,
        )
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # --- 2. Load model ---
        print(f"🧠 Loading model: {config.model_name}")

        # Determine dtype
        if config.bf16:
            dtype = torch.bfloat16
        elif config.fp16:
            dtype = torch.float16
        else:
            dtype = torch.float32

        load_kwargs: dict[str, Any] = {
            "torch_dtype": dtype,
            "trust_remote_code": config.trust_remote_code,
        }
        if config.use_cpu:
            load_kwargs["device_map"] = "cpu"

        self.model = AutoModelForCausalLM.from_pretrained(
            config.model_name,
            **load_kwargs,
        )
        self.model.config.use_cache = False  # Required for gradient checkpointing

        # --- 3. Apply LoRA ---
        print(f"🔧 Applying LoRA (r={config.lora_r}, alpha={config.lora_alpha})")
        lora_config = LoraConfig(
            r=config.lora_r,
            lora_alpha=config.lora_alpha,
            lora_dropout=config.lora_dropout,
            target_modules=config.lora_target_modules,
            task_type=TaskType.CAUSAL_LM,
            bias="none",
        )
        self.model = get_peft_model(self.model, lora_config)
        self.model.print_trainable_parameters()

        # --- 4. Load dataset ---
        print(f"📂 Loading dataset: {config.dataset_path}")
        train_dataset, val_dataset = load_trajectory_dataset(config)
        print(f"   Train: {len(train_dataset)} examples")
        if val_dataset:
            print(f"   Val:   {len(val_dataset)} examples")

        # Apply chat template formatting
        tokenizer = self.tokenizer

        # Resolve chat format: auto-detect or use explicit override
        from openworlds.training.dataset import detect_chat_format
        resolved_fmt = config.chat_format
        if resolved_fmt == "auto":
            resolved_fmt = detect_chat_format(tokenizer)
        print(f"📋 Chat format: {resolved_fmt} (config={config.chat_format})")

        def _format(example: dict) -> dict:
            return format_for_training(
                example, tokenizer, config.max_seq_len,
                chat_format=resolved_fmt,
            )

        train_dataset = train_dataset.map(_format)
        if val_dataset:
            val_dataset = val_dataset.map(_format)

        # Remove 'messages' column — SFTTrainer would re-apply the chat
        # template if it sees it, causing errors with strict-alternation models.
        if "messages" in train_dataset.column_names:
            train_dataset = train_dataset.remove_columns(["messages"])
        if val_dataset and "messages" in val_dataset.column_names:
            val_dataset = val_dataset.remove_columns(["messages"])

        # --- 5. Training arguments ---
        output_dir = config.output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=config.epochs,
            per_device_train_batch_size=config.batch_size,
            gradient_accumulation_steps=config.gradient_accumulation_steps,
            learning_rate=config.learning_rate,
            weight_decay=config.weight_decay,
            warmup_ratio=config.warmup_ratio,
            lr_scheduler_type=config.lr_scheduler,
            logging_steps=config.logging_steps,
            save_strategy=config.save_strategy,
            fp16=config.fp16 and not config.use_cpu,
            bf16=config.bf16 and not config.use_cpu,
            use_cpu=config.use_cpu,
            seed=config.seed,
            report_to="none",  # No wandb/tensorboard by default
            remove_unused_columns=False,
        )

        # --- 6. Train ---
        print("🚀 Starting training...")
        self.trainer = SFTTrainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
        )

        result = self.trainer.train()
        metrics = result.metrics
        print(f"✅ Training complete! Loss: {metrics.get('train_loss', 'N/A'):.4f}")

        return metrics

    def save(self, merge: bool = False) -> str:
        """Save the trained LoRA adapter.

        Args:
            merge: If True, merge LoRA weights into base model and save full model.

        Returns:
            Path where the model/adapter was saved.
        """
        if not self.model or not self.tokenizer:
            raise RuntimeError("No trained model to save. Call train() first.")

        output_dir = self.config.output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if merge:
            print("🔀 Merging LoRA weights into base model...")
            merged_model = self.model.merge_and_unload()
            merged_model.save_pretrained(output_dir)
            self.tokenizer.save_pretrained(output_dir)
            print(f"💾 Merged model saved to: {output_dir}")
        else:
            self.model.save_pretrained(output_dir)
            self.tokenizer.save_pretrained(output_dir)
            print(f"💾 LoRA adapter saved to: {output_dir}")

        self._adapter_path = output_dir

        # Push to Hub if configured
        if self.config.push_to_hub:
            self._push_to_hub()

        return output_dir

    def _push_to_hub(self) -> None:
        """Push model to HuggingFace Hub."""
        hub_id = self.config.hub_model_id
        if not hub_id:
            print("⚠️  hub_model_id not set, skipping Hub push.")
            return

        token = self.config.hub_token or os.environ.get("HF_TOKEN")
        if not token:
            print("⚠️  No HF_TOKEN found. Set hub_token or HF_TOKEN env var.")
            return

        print(f"☁️  Pushing to HuggingFace Hub: {hub_id}")
        self.model.push_to_hub(hub_id, token=token)
        self.tokenizer.push_to_hub(hub_id, token=token)
        print(f"✅ Pushed to https://huggingface.co/{hub_id}")

    def test_inference(self, prompt: str = "", max_new_tokens: int = 200) -> str:
        """Run a quick inference test with the fine-tuned model.

        Args:
            prompt: Test prompt. If empty, uses a default pentest prompt.
            max_new_tokens: Max tokens to generate.

        Returns:
            Generated text.
        """
        if not self.model or not self.tokenizer:
            raise RuntimeError("No model loaded. Call train() first.")

        if not prompt:
            prompt = (
                "You are a penetration tester. You have access to a Kali Linux "
                "terminal. Your target domain is WEST.local. You have credentials "
                "b.wright:Hello123. The DC is at 10.0.1.247. What is your first step?"
            )

        messages = [
            {"role": "user", "content": prompt},
        ]

        try:
            text = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True,
            )
        except Exception:
            text = prompt

        inputs = self.tokenizer(text, return_tensors="pt")

        # Move to same device as model
        device = next(self.model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        import torch

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
            )

        result = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True,
        )
        return result
