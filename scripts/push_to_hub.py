#!/usr/bin/env python3
"""Push dataset + model adapter to HuggingFace Hub."""

from huggingface_hub import HfApi

api = HfApi()

# ---------------------------------------------------------------
# Step 1: Push Dataset
# ---------------------------------------------------------------
print("=== Step 1: Push Dataset ===", flush=True)
ds_repo = "omkar6699/openworlds-ad-trajectories"

api.create_repo(ds_repo, repo_type="dataset", exist_ok=True)
print(f"  Created repo: {ds_repo}", flush=True)

api.upload_file(
    path_or_fileobj="data/datasets/trajectories.jsonl",
    path_in_repo="trajectories.jsonl",
    repo_id=ds_repo,
    repo_type="dataset",
)
print("  Uploaded trajectories.jsonl", flush=True)

DS_README = """---
dataset_info:
  features:
    - name: messages
      list:
        - name: role
          dtype: string
        - name: content
          dtype: string
    - name: id
      dtype: string
license: apache-2.0
task_categories:
  - text-generation
tags:
  - cybersecurity
  - pentesting
  - active-directory
  - synthetic-data
  - openworlds
pretty_name: OpenWorlds AD Penetration Testing Trajectories
---

# OpenWorlds AD Penetration Testing Trajectories

Synthetic training trajectories for fine-tuning AI agents on Active Directory penetration testing.

## Dataset Description

Each trajectory is a complete attack path from **initial access** to **Domain Admin**, formatted as multi-turn chat conversations with:

- **System prompt** with target domain context
- **<think> reasoning** traces (expert thought process)
- **Tool calls** (nmap, ldapsearch, GetUserSPNs, hashcat, secretsdump, etc.)
- **Tool outputs** (realistic simulated responses)
- **Failure recovery** (typos, wrong creds, with correction steps)

## Attack Strategies Covered

| Strategy | Description |
|----------|-------------|
| Kerberoasting | Service accounts with SPNs -> crack TGS tickets |
| AS-REP Roasting | Users without pre-auth -> crack AS-REP hashes |
| ACL Abuse Chains | GenericAll -> WriteDACL -> ForceChangePassword -> DCSync |
| AD CS Abuse (ESC1) | Vulnerable cert templates -> impersonate Domain Admin |
| Credential Pivoting | Passwords in shares, GPPs, config files |

## Usage

```python
from datasets import load_dataset
ds = load_dataset("omkar6699/openworlds-ad-trajectories")
```

## Generation

Generated using [OpenWorlds](https://github.com/omkar-ukirde/Worlds-OpenSource-Clone):

```bash
openworlds manifest generate --hosts 10 --users 25 --seed 42
openworlds trajectory generate --failure-rate 0.15
```

## License

Apache 2.0
"""

api.upload_file(
    path_or_fileobj=DS_README.encode(),
    path_in_repo="README.md",
    repo_id=ds_repo,
    repo_type="dataset",
)
print("  Uploaded dataset README", flush=True)
print(f"\n  Dataset: https://huggingface.co/datasets/{ds_repo}", flush=True)

# ---------------------------------------------------------------
# Step 2: Push Model Adapter
# ---------------------------------------------------------------
print("\n=== Step 2: Push Model Adapter ===", flush=True)
model_repo = "omkar6699/openworlds-pentest-agent"

api.create_repo(model_repo, exist_ok=True)
print(f"  Created repo: {model_repo}", flush=True)

api.upload_folder(
    folder_path="data/models/gemma3-auto",
    repo_id=model_repo,
    ignore_patterns=["checkpoint-*"],
)
print("  Uploaded adapter files", flush=True)

MODEL_README = """---
base_model: google/gemma-3-270m-it
library_name: peft
license: apache-2.0
tags:
  - cybersecurity
  - pentesting
  - active-directory
  - lora
  - openworlds
  - gemma-3
pipeline_tag: text-generation
datasets:
  - omkar6699/openworlds-ad-trajectories
---

# OpenWorlds Pentest Agent (Gemma 3 270M + LoRA)

A LoRA adapter fine-tuned on synthetic Active Directory penetration testing trajectories.

## Model Description

- **Base model:** google/gemma-3-270m-it
- **Fine-tuning:** LoRA (r=16, alpha=32)
- **Training data:** 20 trajectories from OpenWorlds
- **Objective:** Teach small LLMs to perform structured AD penetration testing

## Capabilities

The model learns to:
1. **Reason** about attack paths (<think> traces)
2. **Select** appropriate pentesting tools (nmap, GetUserSPNs, hashcat, etc.)
3. **Recover** from failures (wrong commands, typos, permission denied)
4. **Escalate** privileges from low-priv user to Domain Admin

## Usage

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

base = AutoModelForCausalLM.from_pretrained("google/gemma-3-270m-it")
model = PeftModel.from_pretrained(base, "omkar6699/openworlds-pentest-agent")
tokenizer = AutoTokenizer.from_pretrained("omkar6699/openworlds-pentest-agent")

prompt = "You are a penetration tester. Target domain: corp.local."
inputs = tokenizer(prompt, return_tensors="pt")
output = model.generate(**inputs, max_new_tokens=200)
print(tokenizer.decode(output[0]))
```

## Training

```bash
pip install openworlds[training]
openworlds manifest generate --hosts 10 --users 25 --seed 42
openworlds trajectory generate
openworlds train run --model google/gemma-3-270m-it --cpu --chat-format auto
```

## Limitations

- Trained on synthetic data (simulated tool outputs, not real networks)
- Small base model (270M) -- use as a starting point, scale up for production
- For authorized security testing and research only

## License

Apache 2.0
"""

api.upload_file(
    path_or_fileobj=MODEL_README.encode(),
    path_in_repo="README.md",
    repo_id=model_repo,
)
print("  Uploaded model card", flush=True)
print(f"\n  Model: https://huggingface.co/{model_repo}", flush=True)

print("\n=== DONE ===", flush=True)
print(f"  Dataset: https://huggingface.co/datasets/{ds_repo}", flush=True)
print(f"  Model:   https://huggingface.co/{model_repo}", flush=True)
