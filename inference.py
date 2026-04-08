#!/usr/bin/env python3
"""
Baseline inference script for the Cyber-Sentinel Environment.

Runs an LLM agent against each of the three tasks and logs results
in the strict OpenEnv hackathon format:
    [START] task=<task> env=cyber_sentinel model=<model>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<bool> error=<msg|null>
    [END]   success=<bool> steps=<n> rewards=<r1,...,rn>

Environment variables:
    API_BASE_URL  – LLM endpoint (default: https://api-inference.huggingface.co/v1/)
    MODEL_NAME    – Model identifier (default: meta-llama/Llama-3.1-8B-Instruct)
    HF_TOKEN      – Hugging Face API token (required)
    ENV_BASE_URL  – Cyber-Sentinel environment URL (default: http://localhost:7860)
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any, Dict, List, Optional

import httpx
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.1-8B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

if HF_TOKEN is None:
    raise ValueError("HF_TOKEN environment variable is required")

ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN, timeout=180.0)


# ═══════════════════════════════════════════════════════════════════════════
# Environment HTTP Client (uses stateful /env/* endpoints)
# ═══════════════════════════════════════════════════════════════════════════

class EnvClient:
    """HTTP client for the Cyber-Sentinel environment's stateful endpoints."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(timeout=60.0)
        self.session_id: Optional[str] = None

    def reset(self, task_name: str, seed: int = 42) -> Dict[str, Any]:
        resp = self._http.post(
            f"{self.base_url}/env/reset",
            json={"seed": seed, "task_name": task_name},
        )
        resp.raise_for_status()
        data = resp.json()
        self.session_id = data["session_id"]
        return data

    def step(self, action: Dict[str, Any]) -> Dict[str, Any]:
        if self.session_id is None:
            raise RuntimeError("Call reset() before step()")

        resp = self._http.post(
            f"{self.base_url}/env/step",
            json={"session_id": self.session_id, "action": action},
        )
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self._http.close()


# ═══════════════════════════════════════════════════════════════════════════
# LLM Agent
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are an autonomous SOC (Security Operations Center) agent. You are interacting with a cybersecurity simulation environment.

You will receive an observation (JSON) describing the current state of a security task.
You must respond with a single valid JSON action object.

RULES:
- The action object MUST have an "action_type" field and relevant parameters.
- Return ONLY valid JSON. No markdown fences, no explanation, no extra text.
- Include "metadata": {} in your response.

TASK-SPECIFIC ACTION TYPES:

== SIEM ALERT TRIAGE (action_type: "triage_alert") ==
Classify security alerts from the SIEM system.
  - alert_id: string (e.g. "alert_001")
  - classification: one of "benign", "suspicious", "malicious"
Guidance:
  - Routine internal traffic, VPN logins, backups → benign
  - Failed auth attempts, TOR connections, privilege escalation → suspicious
  - Data exfiltration, ransomware, C2 beacons, lateral movement → malicious
  - CRITICAL: Classifying a real attack as "benign" is the worst mistake.

== FORENSIC THREAT HUNTING ==
Investigate a network breach to find and contain a compromised host.
  Action 1: "query_logs" → Search a host's logs for an indicator
    - host_id: string, indicator: string (the malicious IP or hash)
  Action 2: "kill_process" → Terminate a suspicious process
    - host_id: string, process_id: string
  Action 3: "isolate_host" → Quarantine a host from the network
    - host_id: string
Guidance:
  - First query each host's logs to find the compromised one
  - Look for connections to the malicious IP or the malicious hash in logs
  - Once found, inspect processes and kill the malware process
  - Finally isolate the infected host
  - WARNING: Isolating the wrong host causes business disruption

== CLOUD PERIMETER HARDENING ==
Fix cloud security misconfigurations without breaking production.
  Action 1: "restrict_access" → Tighten firewall/ACL rules
    - asset_id: string, policy: string (e.g. "deny_public", "restrict_ssh")
  Action 2: "apply_policy" → Change IAM/resource policies
    - asset_id: string, policy: string (e.g. "least_privilege")
  Action 3: "enable_protection" → Turn on MFA/encryption/logging
    - asset_id: string, policy: string (e.g. "enable_mfa", "enable_encryption", "enable_logging")
Guidance:
  - Match each vulnerability to the correct (action_type, asset_id, policy) triple
  - Fix CRITICAL severity vulnerabilities first
  - NEVER block ports 80/443 on the web server or port 5432 on the database
  - Use the exact policy string from the vulnerability's recommended remediation

Analyze the observation carefully, then output the single best action as a JSON object.
"""


def get_agent_action(
    observation: Dict[str, Any], history: List[Dict[str, str]]
) -> Dict[str, Any]:
    """Ask the LLM for the next action given the current observation."""
    obs_text = json.dumps(observation, indent=2)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *history,
        {
            "role": "user",
            "content": (
                f"Current observation:\n```json\n{obs_text}\n```\n\n"
                "Respond with ONLY a single JSON action object."
            ),
        },
    ]

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0.0,
        max_tokens=512,
    )

    content = response.choices[0].message.content.strip()

    # Strip markdown fences if present
    if content.startswith("```"):
        lines = content.split("\n")
        lines = [l for l in lines if not l.startswith("```")]
        content = "\n".join(lines).strip()

    action = json.loads(content)

    if "metadata" not in action:
        action["metadata"] = {}

    return action


# ═══════════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════════

TASKS = ["alert_triage", "threat_hunting", "cloud_hardening"]
MAX_STEPS = {"alert_triage": 20, "threat_hunting": 20, "cloud_hardening": 25}


def run_task(env: EnvClient, task_name: str) -> bool:
    """Run a single task episode. Returns True if agent succeeded."""
    print(f"[START] task={task_name} env=cyber_sentinel model={MODEL_NAME}")

    rewards: List[float] = []
    success = False
    score = 0.0
    steps = 0
    history: List[Dict[str, str]] = []

    try:
        reset_resp = env.reset(task_name=task_name, seed=42)
        observation = reset_resp.get("observation", reset_resp)
        done = reset_resp.get("done", False)
        max_steps = MAX_STEPS.get(task_name, 20)

        while not done and steps < max_steps:
            steps += 1

            try:
                action = get_agent_action(observation, history)
            except Exception as e:
                print(f"Exception during get_agent_action: {e}", file=sys.stderr)
                action = {"action_type": "noop", "metadata": {}}

            action_str = json.dumps(action, separators=(",", ":"))

            step_resp = env.step(action)
            observation = step_resp.get("observation", step_resp)
            reward = step_resp.get("reward_delta", step_resp.get("reward", 0.0))
            if reward is None:
                reward = 0.0
            done = step_resp.get("done", False)

            rewards.append(reward)

            error = (
                observation.get("last_action_error")
                if isinstance(observation, dict)
                else None
            )
            error_str = str(error) if error else "null"

            print(
                f"[STEP] step={steps} "
                f"action={action_str} "
                f"reward={reward:.2f} "
                f"done={'true' if done else 'false'} "
                f"error={error_str}"
            )

            # Build conversation history for LLM context
            history.append({"role": "assistant", "content": json.dumps(action)})
            if isinstance(observation, dict):
                history.append({
                    "role": "user",
                    "content": (
                        f"Result: reward={reward:.2f}, done={done}. "
                        + (f"Error: {error}" if error else "Action succeeded.")
                        + f"\nUpdated observation:\n{json.dumps(observation, indent=2)}"
                    ),
                })

            # Keep history manageable
            if len(history) > 20:
                history = history[-16:]

        if isinstance(observation, dict):
            score = observation.get("current_score", 0.01)
        else:
            score = getattr(observation, "current_score", 0.01)

        success = done and score > 0.01

    except Exception:
        traceback.print_exc(file=sys.stderr)
        success = False

    rewards_str = ",".join(f"{r:.2f}" for r in rewards) if rewards else "0.00"
    print(
        f"[END] success={'true' if success else 'false'} "
        f"steps={steps} "
        f"score={score:.3f} "
        f"rewards={rewards_str}",
        flush=True
    )

    return success


def main():
    """Run the baseline agent across all three tasks."""
    env = EnvClient(ENV_BASE_URL)
    try:
        for task in TASKS:
            run_task(env, task)
            print()  # blank line between tasks
    finally:
        env.close()


if __name__ == "__main__":
    main()
