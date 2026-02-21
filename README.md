# 🌐 OpenWorlds

**An open-source simulation engine for agentic pentesting** — generate realistic Active Directory networks, simulate real pentesting tools, and produce training data to fine-tune small AI models. Zero infrastructure needed.

Inspired by [Dreadnode's Worlds](https://dreadnode.io/blog/worlds-a-simulation-engine-for-agentic-pentesting).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 What Is This?

OpenWorlds lets you:

1. **Generate** realistic Active Directory networks (hosts, users, groups, ACLs, vulnerabilities) — entirely synthetic
2. **Simulate** pentesting tools (nmap, ldapsearch, Impacket, certipy, etc.) against these networks — realistic output, zero infrastructure
3. **Explore** networks interactively via a rich CLI shell
4. **Create** training trajectories with `<think>` reasoning traces and failure recovery examples
5. **Export** datasets in ChatML/Messages JSONL format, ready for fine-tuning any LLM
6. **Fine-tune** any small LLM with LoRA to autonomously perform penetration tests

> The goal: an 8B model fine-tuned on synthetic data that can achieve **full Domain Admin compromise** on real AD networks. No real infrastructure needed for training.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     OpenWorlds Pipeline                       │
│                                                              │
│  ┌──────────────┐   ┌───────────────┐   ┌───────────────┐   │
│  │ World Engine  │──▶│ Tool Simulator│──▶│  Trajectory   │   │
│  │   ✅ Done    │   │   ✅ Done     │   │   Pipeline    │   │
│  │ • Manifest   │   │ • nmap        │   │   ✅ Done     │   │
│  │   Generator  │   │ • ldapsearch  │   │              │   │
│  │ • Vuln       │   │ • Impacket    │   │ • Reasoning  │   │
│  │   Injector   │   │ • certipy     │   │   Traces     │   │
│  │ • Path       │   │ • smbclient   │   │ • Failure    │   │
│  │   Validator  │   │ • 10+ tools   │   │   Injection  │   │
│  └──────────────┘   └───────────────┘   └──────┬───────┘   │
│                                                 │           │
│                                         ┌───────▼───────┐   │
│                                         │   Training    │   │
│                                         │   ✅ Done     │   │
│                                         │ • LoRA SFT    │   │
│                                         │ • HF Hub Push │   │
│                                         └───────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.11+
- No GPU or real infrastructure needed for data generation

### Installation

```bash
# Clone the repository
git clone https://github.com/omkar-ukirde/Worlds-OpenSource-Clone.git
cd Worlds-OpenSource-Clone

# Install core package
pip install -e .

# Install with training support (torch, transformers, peft, trl)
pip install -e ".[training]"

# Install with dev tools
pip install -e ".[dev]"
```

### Generate Your First Network

```bash
# Generate a 20-host AD network with all attack strategies
openworlds manifest generate \
    --hosts 20 \
    --users 50 \
    --seed 42 \
    -o data/manifests/my_network.json
```

This creates a complete Active Directory network with:
- **Domain Controllers**, SQL servers, web servers, file servers, workstations
- **Users** with realistic names, group memberships, and ACL permissions
- **Kerberoastable** service accounts with SPNs and crackable hashes
- **AS-REP Roastable** users without Kerberos pre-authentication
- **ACL abuse chains** (GenericAll → WriteDACL → DCSync)
- **AD CS** vulnerable certificate templates (ESC1, ESC2)
- **Credentials in SMB shares** (SYSVOL GPPs, scripts, config files)
- At least one valid multi-step path from low-privilege user to Domain Admin

**Example output:**

```
╭──────────────────── 🌐 OpenWorlds Manifest ────────────────────╮
│ Domain: WEST.local                                             │
│ Hosts: 15 | Users: 30 | Groups: 15                            │
│ OUs: 17 | ACLs: 7 | Cert Templates: 3                         │
│ Attack Paths: 20                                               │
│ Seed: 42                                                       │
╰────────────────────────────────────────────────────────────────╯
         Vulnerability Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Category                  ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Kerberoastable accounts   │     2 │
│ AS-REP Roastable accounts │     3 │
│ ACL abuse entries         │     7 │
│ Vulnerable cert templates │     2 │
│ Sensitive files in shares │     3 │
└───────────────────────────┴───────┘
```

### Explore Interactively

```bash
# Launch an interactive shell
openworlds shell --manifest data/manifests/my_network.json
```

```
╭────────────── OpenWorlds Interactive Shell v0.1.0 ──────────────╮
│ Domain: WEST.local | Hosts: 15 | Users: 30                     │
╰─────────────────────────────────────────────────────────────────╯
Type help for commands, exit to quit.

openworlds> hosts
                        Hosts
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Hostname  ┃ IP         ┃ OS                  ┃ Type    ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ DC01      │ 10.0.1.247 │ Windows Server 2019 │ DC      │
│ SQL01     │ 10.0.1.112 │ Windows Server 2019 │ SQL     │
│ WEB01     │ 10.0.2.54  │ Windows Server 2019 │ Web     │
│ ...       │            │                     │         │
└───────────┴────────────┴─────────────────────┴─────────┘

openworlds> paths
Attack Path 1 (4 steps)
├── Start: b.wright @ WORKSTATION01
├── Strategies: kerberoasting, dcsync, acl_abuse, group_membership
├── Step 1: kerberoasting → app_sync
├── Step 2: acl_abuse → l.admin
├── Step 3: group_membership → DomainAdmins
├── Step 4: dcsync → Domain Admin
└── 🎯 Target: Domain Admin
```

### Use Simulated Tools Directly

```python
from openworlds.world_engine.models import Manifest, ManifestConfig
from openworlds.world_engine.ad_graph import ManifestGenerator
from openworlds.world_engine.vuln_injector import VulnerabilityInjector
from openworlds.world_engine.path_validator import PathValidator
from openworlds.tools.simulator import ToolSimulator

# Generate a network
config = ManifestConfig(num_hosts=20, num_users=50, seed=42)
manifest = ManifestGenerator(config).generate()
VulnerabilityInjector(manifest).inject_all()
manifest.attack_paths = PathValidator(manifest).find_attack_paths()

# Simulate tools against it
sim = ToolSimulator(manifest)

# Port scan the domain controller
print(sim.execute("nmap -sV 10.0.1.247"))

# Kerberoast service accounts
print(sim.execute("GetUserSPNs WEST.local/b.wright:Hello123 -dc-ip 10.0.1.247 -request"))

# Check credentials with CrackMapExec
print(sim.execute("cme smb 10.0.1.247 -u b.wright -p Hello123"))

# Enumerate AD CS templates
print(sim.execute("certipy find -u b.wright -p Hello123 -dc-ip 10.0.1.247"))
```

---

## 🔧 Simulated Tools

OpenWorlds simulates **10 real pentesting tools** with high-fidelity output:

| Tool | What It Simulates |
|------|-------------------|
| `nmap` | Port scanning, service version detection, NSE scripts |
| `ldapsearch` | LDAP user/group/SPN/computer enumeration (LDIF format) |
| `smbclient` | SMB share listing, file browsing, file download |
| `impacket-GetUserSPNs` | Kerberoasting — extracts `$krb5tgs$` hashcat hashes |
| `impacket-GetNPUsers` | AS-REP Roasting — extracts `$krb5asrep$` hashes |
| `impacket-secretsdump` | DCSync and local SAM/LSA credential dumping |
| `certipy` | AD Certificate Services enumeration + ESC1 exploitation |
| `bloodhound-python` | AD relationship collection statistics |
| `crackmapexec` / `cme` | SMB credential spraying with Pwn3d! detection |
| `evil-winrm` | WinRM shell (auth + local admin verification) |

Each tool handler validates credentials, checks permissions, and returns output that matches the real tool's format.

---

## 🎓 Generate Training Data

Transform attack paths into fine-tuning datasets. Two reasoning modes:

### Mode 1: Template Reasoning (default, offline)

```bash
openworlds trajectory generate \
    --manifest data/manifests/my_network.json \
    --failure-rate 0.15 \
    --format messages \
    -o data/datasets/trajectories.jsonl
```

### Mode 2: LLM-Powered Reasoning (🧠 Intelligent)

Uses Ollama, vLLM, or any OpenAI-compatible API for richer, contextual `<think>` traces:

```bash
# With Ollama (local)
openworlds trajectory generate \
    --llm \
    --llm-model qwen2.5:32b \
    --api-base http://localhost:11434/v1

# With vLLM (remote)
openworlds trajectory generate \
    --llm \
    --llm-model meta-llama/Llama-3.2-3B-Instruct \
    --api-base http://your-server:8000/v1

# With OpenAI API
OPENAI_API_KEY=sk-xxx openworlds trajectory generate \
    --llm \
    --llm-model gpt-4o \
    --api-base https://api.openai.com/v1
```

> **Fallback:** If the LLM server is unreachable, it automatically falls back to template reasoning.

**Output:**
```
  ✅ Generated 20 raw trajectories
  ✅ Injected 8 failure(s) across trajectories
  ✅ Exported to data/datasets/trajectories.jsonl (messages format)
    📊 Dataset Statistics
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric            ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Trajectories      │    20 │
│ Avg Steps         │   8.4 │
│ Avg Failures/Traj │   0.4 │
└───────────────────┴───────┘
```

Each trajectory is a complete attack path from initial access to Domain Admin, formatted as a multi-turn chat conversation:

```json
{"role": "assistant", "content": "<think>\nI identified svc_sql as a service account with an SPN.\nKerberoasting allows me to request a service ticket and\ncrack the hash offline.\n</think>\n\n<tool_call>\nimpacket-GetUserSPNs WEST.local/b.wright:Hello123 -dc-ip 10.0.1.247 -request\n</tool_call>"}

{"role": "tool", "content": "$krb5tgs$23$*svc_sql$WEST.local*$a1b2c3..."}
```

**Failure injection** teaches the model to recover from mistakes:
| Failure Type | Example | What Happens |
|-------------|---------|--------------|
| Typo in command | `nmpa -sV 10.0.1.10` | `bash: nmpa: command not found` → corrects to `nmap` |
| Wrong credentials | `evil-winrm -u admin -p Password1` | `STATUS_LOGON_FAILURE` → uses correct password |
| Non-existent target | `nmap 10.0.2.250` | `Host seems down` → corrects IP from scan results |
| Wrong tool | `msfconsole` | `command not found` → falls back to Impacket |
| Missing flags | `ldapsearch -x 10.0.1.10` | `Missing required argument` → adds correct flags |

---

## 🧠 Fine-Tune a Model

Train a small LLM on your generated trajectories using LoRA:

> **🚀 Quick Start:** Skip generation and use our pre-built artifacts:
> - **Dataset:** [omkar6699/openworlds-ad-trajectories](https://huggingface.co/datasets/omkar6699/openworlds-ad-trajectories)
> - **Model Adapter:** [omkar6699/openworlds-pentest-agent](https://huggingface.co/omkar6699/openworlds-pentest-agent)

### 1. Setup (one-time)

```bash
# Install training dependencies
pip install -e ".[training]"
```

**HuggingFace Login:**
Many models (like Gemma 3) are gated. You need to log in to download them and to push your adapters later.
1. Create a token at [hf.co/settings/tokens](https://huggingface.co/settings/tokens) (make sure it has `Write` access if you plan to push).
2. Login via CLI:
```bash
huggingface-cli login
# Paste your token when prompted
```

### 2. Train

```bash
# Fine-tune Gemma 3 270M on your trajectories
openworlds train run \
    --model google/gemma-3-270m-it \
    --dataset data/datasets/trajectories.jsonl \
    --epochs 3 --lora-r 16 \
    --chat-format auto \
    --cpu \
    -o data/models/my-pentest-agent
```

Works with **any model** — auto-detects chat template format:
```bash
# Llama 3 → auto-detects 'full' format
openworlds train run --model meta-llama/Llama-3.2-1B-Instruct --cpu

# Qwen 2.5 → auto-detects 'full' format  
openworlds train run --model Qwen/Qwen2.5-0.5B-Instruct --cpu

# Gemma 3 → auto-detects 'strict_alternation'
openworlds train run --model google/gemma-3-270m-it --cpu
```

**Output:**
```
🧠 OpenWorlds Training
  Model: google/gemma-3-270m-it
  LoRA: r=16, alpha=32
  
trainable params: 368,640 || all params: 268,466,816 || trainable%: 0.14

🚀 Starting training...
{'loss': 3.771, 'epoch': 0.2}
{'loss': 3.683, 'epoch': 0.6}
{'loss': 3.565, 'epoch': 1.0}
✅ Training complete! Loss: 3.5654
💾 LoRA adapter saved to: data/models/my-pentest-agent/

🧪 Model says: "I'm ready to start. I'll begin by running nmap to discover
services on the domain controller at 10.0.1.247..."
```

### 3. Push to HuggingFace Hub (optional)

```bash
openworlds train run \
    --model google/gemma-3-270m-it \
    --dataset data/datasets/trajectories.jsonl \
    --push-to-hub --hub-id yourname/openworlds-agent
```

> **Mac Mini M2 (8GB)?** Use `--cpu` flag. For larger models, see [`docs/colab_training.md`](docs/colab_training.md).

---

## 🎮 Attack Strategies

Generated networks include these attack vectors:

| Strategy | Description |
|----------|-------------|
| **Kerberoasting** | Service accounts with SPNs and weak passwords → crack TGS tickets offline |
| **AS-REP Roasting** | Users without Kerberos pre-auth → crack AS-REP hashes offline |
| **ACL Abuse Chains** | GenericAll → WriteDACL → ForceChangePassword → DCSync escalation |
| **AD CS Abuse (ESC1/ESC2)** | Vulnerable certificate templates → impersonate Domain Admin |
| **Credential Pivoting** | Passwords in SYSVOL GPPs, department share scripts, config files |

Attack paths are validated using **NetworkX graph analysis** with 8 edge types, ensuring every generated network has at least one solvable path to Domain Admin.

---

## 📁 Project Structure

```
Worlds-OpenSource-Clone/
├── openworlds/                    # Main Python package
│   ├── __init__.py                # Package version
│   ├── cli.py                     # Typer CLI (manifest, trajectory, shell)
│   ├── world_engine/              # Layer 1: AD network generation
│   │   ├── models.py              # 40+ Pydantic models, CVE DB, service templates
│   │   ├── ad_graph.py            # ManifestGenerator pipeline
│   │   ├── vuln_injector.py       # 5 vulnerability injectors
│   │   └── path_validator.py      # NetworkX attack graph + BFS path discovery
│   ├── tools/                     # Layer 2: Tool simulation
│   │   ├── simulator.py           # ToolSimulator dispatcher
│   │   └── handlers/              # 10 tool handlers
│   │       ├── base.py            # BaseHandler ABC
│   │       ├── nmap_handler.py
│   │       ├── ldapsearch_handler.py
│   │       ├── smbclient_handler.py
│   │       ├── secretsdump_handler.py
│   │       ├── getuserspns_handler.py
│   │       ├── getnpusers_handler.py
│   │       ├── certipy_handler.py
│   │       ├── bloodhound_handler.py
│   │       ├── crackmapexec_handler.py
│   │       └── evil_winrm_handler.py
│   ├── trajectory/                # Layer 3: Training data pipeline
│   │   ├── state_tracker.py       # Agent knowledge tracking
│   │   ├── reasoning.py           # <think> trace generation (15+ templates)
│   │   ├── generator.py           # Attack path → trajectory walker
│   │   ├── failure_injector.py    # Realistic mistake injection
│   │   └── formatter.py           # Messages/ChatML JSONL exporter
│   ├── training/                  # Layer 4: LoRA SFT fine-tuning
│   │   ├── config.py              # Pydantic training configuration
│   │   ├── dataset.py             # JSONL → HuggingFace Dataset loader
│   │   └── trainer.py             # LoRA SFT + merge + HF Hub push
│   └── eval/                      # Layer 5: Evaluation harness (coming soon)
├── data/
│   ├── manifests/                 # Generated network JSON files
│   ├── datasets/                  # Training-ready JSONL datasets
│   └── models/                    # Saved LoRA adapters
├── tests/                         # Test suite (pytest)
├── docs/
│   └── colab_training.md          # Google Colab GPU training guide
├── pyproject.toml                 # Build config, deps, ruff, mypy
├── Makefile                       # Dev commands
├── LICENSE                        # Apache 2.0
└── README.md
```

---

## 📋 CLI Reference

Every command and flag at a glance:

### Global Flags
| Flag | Description |
|------|-------------|
| `--version`, `-v` | Show OpenWorlds version and exit |

### `openworlds manifest generate`
| Flag | Default | Description |
|------|---------|-------------|
| `--hosts` | 10 | Number of hosts to generate |
| `--users` | 25 | Number of users to generate |
| `--seed` | random | Seed for reproducible generation |
| `-o`, `--output` | `data/manifests/default.json` | Output file path |

### `openworlds manifest show`
| Flag | Default | Description |
|------|---------|-------------|
| `--manifest` | `data/manifests/default.json` | Manifest file to display |

### `openworlds shell`
| Flag | Default | Description |
|------|---------|-------------|
| `--manifest` | `data/manifests/default.json` | Network to explore interactively |

### `openworlds trajectory generate`
| Flag | Default | Description |
|------|---------|-------------|
| `-m`, `--manifest` | `data/manifests/default.json` | Source manifest |
| `-n`, `--count` | 0 (= all paths) | Max trajectories to generate |
| `-f`, `--failure-rate` | 0.15 | Failure injection probability |
| `--format` | `messages` | Output format: `messages` or `chatml` |
| `-o`, `--output` | `data/datasets/trajectories.jsonl` | Output file |
| `--seed` | 42 | Random seed |
| `--no-recon` | false | Skip recon steps |
| `--llm` | false | **Enable LLM reasoning** (Ollama/vLLM/OpenAI) |
| `--api-base` | `http://localhost:11434/v1` | OpenAI-compatible API URL |
| `--llm-model` | `qwen2.5:32b` | LLM model for reasoning |

### `openworlds train run`
| Flag | Default | Description |
|------|---------|-------------|
| `--model` | `google/gemma-3-270m-it` | Any HuggingFace model |
| `--dataset` | `data/datasets/trajectories.jsonl` | Training data |
| `--epochs` | 3 | Training epochs |
| `--lr` | 2e-4 | Learning rate |
| `--batch-size` | 1 | Per-device batch size |
| `--lora-r` | 16 | LoRA rank |
| `-o`, `--output` | `data/models/openworlds-agent` | Output directory |
| `--cpu` | false | Force CPU training |
| `--chat-format` | `auto` | `auto`, `full`, `no_tool`, `strict_alternation`, `chatml` |
| `--push-to-hub` | false | Push to HuggingFace Hub |
| `--hub-id` | none | Hub model ID |
| `--test/--no-test` | true | Run inference test after training |
| `--seed` | 42 | Random seed |

### `openworlds eval run`
| Flag | Default | Description |
|------|---------|-------------|
| `-m`, `--model` | `data/models/gemma3-auto` | Trained model or LoRA adapter |
| `-n`, `--scenarios` | 5 | Number of fresh networks |
| `--max-steps` | 15 | Max steps per scenario |
| `--cpu` | false | Force CPU inference |
| `--seed` | 42 | Random seed |
| `-o`, `--output` | `data/eval/report.json` | Output JSON report |

### Complete Workflow

```bash
# 1. Generate a network
openworlds manifest generate --hosts 20 --users 50 --seed 42

# 2. Explore interactively (optional)
openworlds shell

# 3. Generate training data (template mode)
openworlds trajectory generate

# 3b. Or with LLM reasoning (requires Ollama/vLLM)
openworlds trajectory generate --llm --llm-model qwen2.5:32b

# 4. Install training deps + login
pip install -e ".[training]"
huggingface-cli login

# 5. Fine-tune any model
openworlds train run --model google/gemma-3-270m-it --cpu

# 6. Push to Hub (optional)
openworlds train run --model google/gemma-3-270m-it --push-to-hub --hub-id you/agent

# 7. Evaluate your model
openworlds eval run --model data/models/my-pentest-agent --scenarios 5 --cpu
```

---

## 🧪 Evaluate Your Model

Measure how well your fine-tuned model performs on **fresh, unseen** AD networks:

```bash
openworlds eval run \
    --model data/models/gemma3-auto \
    --scenarios 5 \
    --max-steps 15 \
    --cpu
```

The harness:
1. Generates fresh AD networks (never seen during training)
2. Runs the model in an **agent loop** (generate → execute via simulator → observe → repeat)
3. Scores across **5 metrics**:

| Metric | Description |
|--------|-------------|
| **Success Rate** | % scenarios reaching Domain Admin |
| **Step Efficiency** | ideal_steps / actual_steps (1.0 = perfect) |
| **Technique Coverage** | unique techniques used / available |
| **Valid Command Rate** | commands recognized by simulator / total |
| **Recovery Rate** | successful corrections after failures |

---

## 🛠️ Development

```bash
# Install dev dependencies
make install-dev

# Run linter
make lint

# Format code
make format

# Type check
make typecheck

# Run tests
make test
```

---

## 🤝 Contributing

Contributions are welcome! Key areas:

- **Add new tool handlers** — [see CONTRIBUTING.md](CONTRIBUTING.md)
- **Add attack strategies** — expand the vulnerability injector
- **Improve output fidelity** — make tool output even more realistic
- **Add CVEs** — expand the CVE database in `models.py`
- **Write tests** — increase coverage for generators and handlers

---

## 🗺️ Roadmap

**v0.1.0 — Foundation (✅ Done)**
- [x] Active Directory network generation (40+ Pydantic models)
- [x] 5 vulnerability injectors (Kerberoast, AS-REP, ACL abuse, AD CS, share creds)
- [x] Attack path validation via NetworkX graph analysis
- [x] 10 simulated pentesting tools with realistic output
- [x] CLI with `manifest generate/show` and interactive shell
- [x] Reproducible generation via seeds

**v0.2.0 — Trajectory Pipeline (✅ Done)**
- [x] Trajectory generation (walk attack paths → tool call sequences)
- [x] `<think>` reasoning traces (15+ technique templates + **LLM-powered** via Ollama/vLLM)
- [x] Failure injection (5 types: typos, wrong creds, wrong target, malformed args, wrong tool)
- [x] Dataset formatter (Messages/ChatML JSONL)
- [x] CLI: `openworlds trajectory generate` with `--llm`, `--api-base`, `--llm-model`

**v0.3.0 — Agent Training (✅ Done)**
- [x] LoRA SFT fine-tuning pipeline (`peft` + `trl`)
- [x] Gemma 3 270M IT tested end-to-end on 8GB Mac Mini M2 (CPU)
- [x] HuggingFace Hub integration for model pushing
- [x] CLI: `openworlds train run` with `--cpu`, `--push-to-hub`, `--lora-r`, `--chat-format`
- [x] Model-aware chat template auto-detection (Gemma 3, Llama 3, Qwen, Mistral)
- [x] Google Colab GPU training guide (`docs/colab_training.md`)

**v0.4.0 — Evaluation (✅ Done)**
- [x] Simulated evaluation harness with agent loop
- [x] 5-metric scoring (success rate, efficiency, coverage, validity, recovery)
- [x] CLI: `openworlds eval run` with rich table output
- [ ] Optional GOAD integration for sim-to-real validation

**v0.5.0 — CLI & Deployment (✅ Done)**
- [x] Package versioning and CLI `--version` flag
- [x] Global exception handling via Rich Console
- [x] PyPI packaging automation (`make build`, `make publish`)

**v1.0 — Production Ready**
- [ ] PentestJudge (LLM-as-judge for evaluating agent quality)
- [ ] Pre-built datasets on Hugging Face Hub
- [ ] Import manifests from real BloodHound/ldapsearch data
- [ ] Plugin system for community tools

**Beyond v1.0**
- [ ] Web application pentesting support
- [ ] Multi-agent architecture (Coordinator + Specialists)
- [ ] Reinforcement learning (PPO/GRPO)
- [ ] Multi-domain AD forests with trust relationships
- [ ] Cloud environment simulation (AWS/Azure/GCP)
- [ ] Web UI dashboard

---

## 📚 References

- [Dreadnode: Worlds Blog Post](https://dreadnode.io/blog/worlds-a-simulation-engine-for-agentic-pentesting) — the research that inspired this project
- [GOAD: Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) — real AD lab for evaluation
- [ADSynth](https://github.com/AUCyberLab/ADSynth) — synthetic AD graph generation
- [LoRA Paper](https://arxiv.org/abs/2106.09685) — Low-Rank Adaptation for fine-tuning

---

## ⚖️ License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

OpenWorlds is designed for **authorized security testing and research only**. Generated models and trajectories should only be used against systems you have explicit permission to test. The authors are not responsible for misuse.
