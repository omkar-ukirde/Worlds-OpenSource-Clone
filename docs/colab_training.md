# Training on Google Colab (Free GPU)

Use this guide to fine-tune larger models (1B–7B) with a free T4 GPU on Google Colab.

## 1. Setup

```python
# Install OpenWorlds with training deps
!pip install -q git+https://github.com/omkar-ukirde/Worlds-OpenSource-Clone.git[training]

# Login to HuggingFace (for model downloads and Hub push)
from huggingface_hub import login
login()  # Paste your HF token
```

## 2. Generate Training Data

```python
from openworlds.world_engine.models import ManifestConfig
from openworlds.world_engine.ad_graph import ManifestGenerator
from openworlds.world_engine.vuln_injector import VulnerabilityInjector
from openworlds.world_engine.path_validator import PathValidator
from openworlds.trajectory.generator import TrajectoryGenerator
from openworlds.trajectory.failure_injector import FailureInjector
from openworlds.trajectory.formatter import export_dataset

# Generate 5 different networks with different seeds
all_trajectories = []
for seed in range(5):
    config = ManifestConfig(num_hosts=20, num_users=50, seed=seed)
    manifest = ManifestGenerator(config).generate()
    VulnerabilityInjector(manifest).inject_all()
    manifest.attack_paths = PathValidator(manifest).find_attack_paths()

    gen = TrajectoryGenerator(manifest, seed=seed)
    trajs = gen.generate_all()

    injector = FailureInjector(failure_rate=0.15, seed=seed)
    trajs = [injector.inject(t) for t in trajs]
    all_trajectories.extend(trajs)

print(f"Total trajectories: {len(all_trajectories)}")
export_dataset(all_trajectories, "trajectories.jsonl")
```

## 3. Train with a Larger Model

```python
from openworlds.training.config import TrainingConfig
from openworlds.training.trainer import OpenWorldsTrainer

config = TrainingConfig(
    # Use Gemma 3 1B for a good balance of quality and speed
    model_name="google/gemma-3-1b-it",
    dataset_path="trajectories.jsonl",
    
    # LoRA
    lora_r=32,
    lora_alpha=64,
    
    # Training
    epochs=3,
    batch_size=2,
    gradient_accumulation_steps=4,
    learning_rate=2e-4,
    max_seq_len=4096,
    
    # Use bf16 on T4
    bf16=True,
    
    # Output
    output_dir="openworlds-agent",
    
    # HuggingFace Hub push
    push_to_hub=True,
    hub_model_id="YOUR_USERNAME/openworlds-agent-1b",
)

trainer = OpenWorldsTrainer(config)
metrics = trainer.train()
trainer.save(merge=True)  # Merge LoRA into base for easy deployment
```

## 4. Test the Model

```python
response = trainer.test_inference(
    "You are a pentester. Target domain: CORP.local, DC at 10.0.1.1. "
    "You have credentials jsmith:Welcome1. What's your first move?"
)
print(response)
```

## 5. Recommended Models by GPU

| GPU | VRAM | Recommended Model | Training Time (100 trajs) |
|-----|------|-------------------|--------------------------|
| T4 (Colab Free) | 16GB | `google/gemma-3-1b-it` | ~15 min |
| A100 (Colab Pro) | 40GB | `Qwen/Qwen2.5-7B-Instruct` | ~30 min |
| L4 (Colab Pro) | 24GB | `google/gemma-3-4b-it` | ~20 min |
| CPU / M2 Mac | 8GB | `google/gemma-3-270m-it` | ~10 min |

## Tips

- **More data = better**: Generate 5–10 different networks with different seeds
- **Failure rate**: Use `0.15`–`0.25` for realistic error recovery learning
- **LoRA rank**: Higher rank (32–64) captures more detail but uses more memory
- **Epochs**: 3 epochs is usually enough; watch for overfitting on small datasets
- **Evaluation**: After training, use `openworlds eval` (Phase 5) to test against unseen networks
