# 🛡️ Cyber-Sentinel: Autonomous SOC Agent Environment

> An OpenEnv-compliant environment simulating **real-world cybersecurity operations** for training and evaluating AI agents as autonomous Security Operations Center (SOC) analysts.

[![OpenEnv](https://img.shields.io/badge/OpenEnv-compliant-blue)](https://github.com/meta-pytorch/OpenEnv)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Motivation

Security Operations Centers process **thousands of alerts per day**. Analysts face alert fatigue, sophisticated adversaries, and sprawling cloud infrastructure. The average time to identify and contain a breach is **277 days** (IBM, 2023).

**Cyber-Sentinel** simulates the three core SOC workflows where AI agents can have the most impact:

1. **Alert Triage** — Can the agent distinguish real attacks from noise?
2. **Threat Hunting** — Can it trace an attacker across a network and contain the breach?
3. **Cloud Hardening** — Can it fix infrastructure misconfigurations without causing downtime?

These are high-stakes, real-world tasks where mistakes have severe consequences: a missed ransomware alert costs millions; isolating the wrong server disrupts the business.

---

## 📋 Tasks

| # | Task | Difficulty | Objective | Max Steps |
|---|------|-----------|-----------|-----------|
| 1 | **SIEM Alert Triage** | 🟢 Easy | Classify 8 security alerts as benign/suspicious/malicious | 20 |
| 2 | **Forensic Threat Hunting** | 🟡 Medium | Investigate 6 hosts to find, kill, and isolate a compromised machine | 20 |
| 3 | **Cloud Perimeter Hardening** | 🔴 Hard | Fix 5 cloud misconfigurations without causing service outages | 25 |

### Scoring (0.0 – 1.0)

All graders are **deterministic and programmatic** — no LLM-as-judge.

#### Task 1: Alert Triage
| Outcome | Reward |
|---------|--------|
| Correct classification | `+1/total_alerts` (~0.125) |
| False negative (malicious → benign) | `-0.15` |
| False positive (benign → malicious) | `-0.05` |

#### Task 2: Threat Hunting
| Outcome | Reward |
|---------|--------|
| Query compromised host logs | `+0.10` |
| Query clean host (elimination) | `+0.02` |
| Kill correct malicious process | `+0.25` |
| Kill wrong process | `-0.10` |
| Isolate correct host | `+0.40` |
| Isolate wrong host | `-0.20` |

#### Task 3: Cloud Hardening
| Outcome | Reward |
|---------|--------|
| Correct remediation | `+0.15` |
| Severity-order bonus (CRITICAL first) | `+0.05` |
| Block critical port (outage) | `-0.30` |
| Wrong action/policy | `-0.05` |

---

## 🔌 Action Space

All actions use a single `CyberSentinelAction` model with an `action_type` discriminator:

```python
# Alert Triage
{"action_type": "triage_alert", "alert_id": "alert_001", "classification": "malicious", "metadata": {}}

# Forensic Hunting
{"action_type": "query_logs", "host_id": "host_003", "indicator": "198.51.100.23", "metadata": {}}
{"action_type": "kill_process", "host_id": "host_003", "process_id": "6666", "metadata": {}}
{"action_type": "isolate_host", "host_id": "host_003", "metadata": {}}

# Cloud Hardening
{"action_type": "restrict_access", "asset_id": "customer-data-bucket", "policy": "deny_public", "metadata": {}}
{"action_type": "enable_protection", "asset_id": "root-account", "policy": "enable_mfa", "metadata": {}}
{"action_type": "apply_policy", "asset_id": "prod-web-server", "policy": "least_privilege", "metadata": {}}
```

---

## 👁️ Observation Space

The `CyberSentinelObservation` includes:

| Field | Type | Description |
|-------|------|-------------|
| `task_name` | str | Active task identifier |
| `task_description` | str | Human-readable objective with constraints |
| `step_count` / `max_steps` | int | Progress tracking |
| `done` | bool | Whether the episode has ended |
| `reward` | float | Per-step reward delta |
| `current_score` | float | Cumulative score [0.0, 1.0] |
| `last_action_success` | bool | Whether the last action was valid |
| `last_action_error` | str? | Error message if invalid |
| `siem_alerts` | list? | SIEM alert feed (alert_triage only) |
| `network_hosts` | list? | Network hosts (threat_hunting only) |
| `threat_intel` | dict? | IoC details (threat_hunting only) |
| `investigation_log` | list? | Query results history (threat_hunting only) |
| `cloud_assets` | list? | Cloud infrastructure (cloud_hardening only) |
| `vulnerabilities` | list? | Active misconfigurations (cloud_hardening only) |
| `service_status` | dict? | Critical service uptime (cloud_hardening only) |

---

## 🚀 Setup & Usage

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Local Development

```bash
# Clone the repo
git clone <your-repo-url>
cd corp-ops-env

# Install dependencies with uv
uv sync

# Start the environment server (Terminal 1)
uv run uvicorn server.app:app --host 0.0.0.0 --port 7860

# Run inference (Terminal 2)
HF_TOKEN=your_token uv run python inference.py
```

### Docker

```bash
# Build
docker build -t cyber-sentinel .

# Run
docker run -p 7860:7860 cyber-sentinel

# Run inference against the container
HF_TOKEN=your_token python inference.py
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HF_TOKEN` | ✅ Yes | — | Hugging Face API token |
| `API_BASE_URL` | No | `https://api-inference.huggingface.co/v1/` | LLM API endpoint |
| `MODEL_NAME` | No | `meta-llama/Llama-3.1-8B-Instruct` | Model for inference |
| `ENV_BASE_URL` | No | `http://localhost:7860` | Environment server URL |
| `CYBER_SENTINEL_TASK` | No | `alert_triage` | Default task on startup |
| `CYBER_SENTINEL_SEED` | No | `42` | Random seed |

---

## 📊 Baseline Scores

| Task | Model | Score | Steps |
|------|-------|-------|-------|
| Alert Triage | Llama-3.1-8B | ~0.75 | 8 |
| Threat Hunting | Llama-3.1-8B | ~0.50 | 12 |
| Cloud Hardening | Llama-3.1-8B | ~0.35 | 15 |

> Scores are approximate and depend on the model's ability to parse security observations and produce valid JSON actions.

---

## 🏗️ Project Structure

```
cyber-sentinel/
├── openenv.yaml         # OpenEnv manifest
├── Dockerfile           # Container for HF Spaces
├── pyproject.toml       # Dependencies (uv)
├── requirements.txt     # Dependencies (Docker/pip)
├── models.py            # Pydantic: Action, Observation, State
├── inference.py         # Baseline evaluation script
├── README.md            # This file
├── .env                 # Local env vars (git-ignored)
├── .gitignore           # Git ignore rules
└── server/
    ├── __init__.py
    ├── app.py           # FastAPI entry point
    ├── environment.py   # Core OpenEnv Environment class
    └── tasks.py         # Task definitions + graders
```

---

## 🔍 OpenEnv Spec Compliance

- ✅ Typed `Action`, `Observation`, `State` models (Pydantic)
- ✅ `step(action)` → observation with reward + done
- ✅ `reset()` → initial observation
- ✅ `state()` → full internal state
- ✅ `openenv.yaml` manifest
- ✅ Programmatic graders (0.0–1.0)
- ✅ Incremental rewards with partial progress signals
- ✅ Penalties for undesirable behaviors (false negatives, outages)
- ✅ Deterministic and reproducible (seeded RNG)
- ✅ Baseline `inference.py` with strict output format

---

## 📜 License

MIT
