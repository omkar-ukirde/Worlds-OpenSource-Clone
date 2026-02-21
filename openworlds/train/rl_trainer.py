"""Reinforcement Learning Trainer using PPO and Optional Teacher Distillation.

This module sets up a TRPO/PPO training loop using HuggingFace `trl` to
fine-tune a base model against the `OpenWorldsRLEnv`. It includes logic for
calling a larger "Teacher" model when the Student gets stuck.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import torch
from pathlib import Path
from tqdm import tqdm

from openworlds.train.rl_env import OpenWorldsRLEnv

logger = logging.getLogger(__name__)


class RLTrainer:
    """Trains an LLM on OpenWorlds using PPO + Teacher Distillation."""

    def __init__(
        self,
        model_path: str,
        output_dir: str = "data/models/openworlds-rl",
        learning_rate: float = 1.41e-5,
        batch_size: int = 1,
        max_episodes: int = 100,
        max_steps_per_episode: int = 15,
        device: str = "auto",
        teacher_api_base: str | None = None,
        teacher_model: str = "gpt-4o",
    ) -> None:
        self.model_path = model_path
        self.output_dir = Path(output_dir)
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.max_episodes = max_episodes
        self.max_steps_per_episode = max_steps_per_episode
        self.device = "cuda" if torch.cuda.is_available() and device == "auto" else "cpu"
        
        self.teacher_api_base = teacher_api_base
        self.teacher_model = teacher_model
        
        self.env = OpenWorldsRLEnv(max_steps=self.max_steps_per_episode)
        
        # Will be initialized in .train()
        self.ppo_trainer = None
        self.model = None
        self.tokenizer = None

    def train(self) -> None:
        """Run the RL training loop."""
        try:
            from trl import AutoModelForCausalLMWithValueHead, PPOConfig, PPOTrainer
            from transformers import AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "RL Training requires `trl` and `peft`. Run `pip install -e '.[training]'`"
            ) from e

        logger.info(f"Loading Base Model for PPO: {self.model_path}")
        
        config = PPOConfig(
            model_name=self.model_path,
            learning_rate=self.learning_rate,
            batch_size=self.batch_size,
            mini_batch_size=self.batch_size,
            gradient_accumulation_steps=4,
            accelerator_kwargs={"device_placement": True}
        )

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self.tokenizer.pad_token = self.tokenizer.eos_token
        
        self.model = AutoModelForCausalLMWithValueHead.from_pretrained(
            self.model_path, 
            device_map=self.device, 
            torch_dtype=torch.float16 if self.device == "cuda" else torch.float32
        )
        
        # PPO requires a reference model that doesn't update, to compute KL penalties
        from trl import create_reference_model
        ref_model = create_reference_model(self.model)

        self.ppo_trainer = PPOTrainer(config, self.model, ref_model, self.tokenizer)

        for episode in tqdm(range(self.max_episodes), desc="RL Episodes"):
            self._run_episode()
            
        logger.info(f"Saving final RL-tuned model to {self.output_dir}")
        self.ppo_trainer.save_pretrained(self.output_dir)
        self.tokenizer.save_pretrained(self.output_dir)

    def _run_episode(self) -> None:
        """Execute one complete episode through the environment."""
        obs_str, info = self.env.reset()
        
        terminated = False
        truncated = False
        
        messages = [{"role": "system", "content": obs_str}]
        consecutive_failures = 0

        while not (terminated or truncated):
            # 1. Format prompt for model
            prompt_str = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            input_tensor = self.tokenizer(prompt_str, return_tensors="pt").input_ids.to(self.device)

            # 2. Student generates action
            generation_kwargs = {
                "max_new_tokens": 256,
                "top_k": 0.0,
                "top_p": 1.0,
                "do_sample": True,
                "pad_token_id": self.tokenizer.eos_token_id,
            }
            
            with torch.no_grad():
                response_tensor = self.ppo_trainer.generate(input_tensor, **generation_kwargs)
            
            # Extract just the response part (remove prompt)
            response_slice = response_tensor[0][input_tensor.shape[1]:]
            action_text = self.tokenizer.decode(response_slice, skip_special_tokens=True)
            
            messages.append({"role": "assistant", "content": action_text})

            # Teacher Distillation Fallback
            if consecutive_failures >= 3 and self.teacher_api_base:
                logger.info(f"Student stuck ({consecutive_failures} fails). Invoking Teacher {self.teacher_model}...")
                action_text = self._query_teacher(messages)
                messages[-1]["content"] = action_text # Force student to use teacher's output
                reward_override = 50.0  # Teacher distillation reward
                
                # Step env with teacher's action
                obs_str, reward, terminated, truncated, step_info = self.env.step(action_text)
                reward = reward_override
                consecutive_failures = 0
            else:
                # 3. Environment Step (Normal Student)
                obs_str, reward, terminated, truncated, step_info = self.env.step(action_text)
                if not step_info.get("is_valid", False):
                    consecutive_failures += 1
                else:
                    consecutive_failures = 0
            
            # Format and step PPO
            reward_tensor = torch.tensor([reward], dtype=torch.float32, device=self.device)
            # PPO expects a list of query tensors, response tensors, and rewards
            self.ppo_trainer.step([input_tensor[0]], [response_slice], [reward_tensor[0]])
            
            messages.append({"role": "user", "content": f"```\n{obs_str}\n```"})

    def _query_teacher(self, messages: list[dict[str, str]]) -> str:
        """Call a frontier model via an OpenAI API-compatible endpoint to un-stick the student."""
        import requests
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer optional_token"
        }
        
        # Inject standard instruction for teacher
        payload = {
            "model": self.teacher_model,
            "messages": messages[:-1] + [{"role": "user", "content": "You are the Teacher. The junior pentester is stuck. Output the exact <think> reasoning block and <tool_call> command they should execute next to proceed."}],
            "temperature": 0.2
        }

        try:
            response = requests.post(
                f"{self.teacher_api_base.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
                timeout=15
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"Teacher API failed: {e}. Falling back to empty command.")
            return "<think>Teacher failed.</think>\n<tool_call>exit</tool_call>"
