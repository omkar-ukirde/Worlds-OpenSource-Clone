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
6. **Fine-tune** any small LLM (8B params) to autonomously perform penetration tests *(coming soon)*

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
│                                         │  Training &   │   │
│                                         │  Evaluation   │   │
│                                         │ (coming soon) │   │
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

Transform attack paths into fine-tuning datasets with a single command:

```bash
# Generate trajectories from all attack paths
openworlds trajectory generate \
    --manifest data/manifests/my_network.json \
    --failure-rate 0.15 \
    --format messages \
    -o data/datasets/trajectories.jsonl
```

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
│   ├── training/                  # Layer 4: LoRA fine-tuning (coming soon)
│   └── eval/                      # Layer 4: Evaluation harness (coming soon)
├── data/
│   ├── manifests/                 # Generated network JSON files
│   └── datasets/                  # Training-ready JSONL datasets
├── tests/                         # Test suite (pytest)
├── docs/                          # Documentation
├── pyproject.toml                 # Build config, deps, ruff, mypy
├── Makefile                       # Dev commands
├── LICENSE                        # Apache 2.0
└── README.md
```

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
- [x] `<think>` reasoning traces (15+ technique templates + optional LLM augmentation)
- [x] Failure injection (5 types: typos, wrong creds, wrong target, malformed args, wrong tool)
- [x] Dataset formatter (Messages/ChatML JSONL)
- [x] CLI: `openworlds trajectory generate`

**v0.3.0 — Agent Training (🔜 Next)**
- [ ] Model-agnostic LoRA/QLoRA fine-tuning pipeline
- [ ] HuggingFace Hub integration for model + dataset publishing

**v0.4.0 — Evaluation**
- [ ] Simulated evaluation harness with scoring
- [ ] Optional GOAD integration for sim-to-real validation

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
