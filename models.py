"""
Pydantic data models for the Cyber-Sentinel Environment.

Defines Action, Observation, and State types used across all three tasks:
  1. SIEM Alert Triage
  2. Forensic Threat Hunting
  3. Cloud Perimeter Hardening
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from openenv.core.env_server.types import Action, Observation, State


# ---------------------------------------------------------------------------
# Action model
# ---------------------------------------------------------------------------

class CyberSentinelAction(Action):
    """
    Action model for the Cyber-Sentinel environment.

    The `action_type` field selects which sub-fields are relevant.

    Action types per task:
      SIEM Alert Triage:
        - triage_alert: classify an alert as benign/suspicious/malicious

      Forensic Threat Hunting:
        - query_logs: search a host's logs for an indicator
        - isolate_host: quarantine a compromised machine
        - kill_process: terminate a suspicious process on a host

      Cloud Perimeter Hardening:
        - restrict_access: tighten a security group / firewall rule
        - apply_policy: apply an IAM or bucket policy change
        - enable_protection: turn on MFA, encryption, logging, etc.
    """

    action_type: Literal[
        "triage_alert",
        "query_logs",
        "isolate_host",
        "kill_process",
        "restrict_access",
        "apply_policy",
        "enable_protection",
        "noop",
    ] = Field(..., description="Type of security action to perform")

    # --- SIEM Alert Triage fields ---
    alert_id: Optional[str] = Field(
        None, description="ID of the alert to triage"
    )
    classification: Optional[Literal[
        "benign", "suspicious", "malicious"
    ]] = Field(None, description="Classification for the alert")

    # --- Forensic Threat Hunting fields ---
    host_id: Optional[str] = Field(
        None, description="ID of the host to investigate or isolate"
    )
    indicator: Optional[str] = Field(
        None, description="IoC to search for (IP, hash, domain)"
    )
    process_id: Optional[str] = Field(
        None, description="PID of the process to kill"
    )

    # --- Cloud Perimeter Hardening fields ---
    asset_id: Optional[str] = Field(
        None, description="ID of the cloud asset to remediate"
    )
    rule_id: Optional[str] = Field(
        None, description="ID of the security rule to modify"
    )
    policy: Optional[str] = Field(
        None,
        description="Policy to apply (e.g. 'deny_public', 'enable_mfa', 'restrict_ssh')",
    )


# ---------------------------------------------------------------------------
# Observation model
# ---------------------------------------------------------------------------

class CyberSentinelObservation(Observation):
    """
    Observation returned by the environment after each step.

    Only the fields relevant to the active task will be populated.
    """

    task_name: str = Field(..., description="Name of the active task")
    task_description: str = Field(
        "", description="Human-readable description of the task objective"
    )
    step_count: int = Field(0, description="Current step number")
    max_steps: int = Field(0, description="Maximum allowed steps for this task")

    # Shared feedback
    last_action_success: bool = Field(
        True, description="Whether the last action was valid"
    )
    last_action_error: Optional[str] = Field(
        None, description="Error message if the last action was invalid"
    )
    current_score: float = Field(
        0.1, description="Current cumulative score in (0.0, 1.0)"
    )

    # --- SIEM Alert Triage ---
    siem_alerts: Optional[List[Dict[str, Any]]] = Field(
        None, description="List of security alerts from the SIEM"
    )
    valid_classifications: Optional[List[str]] = Field(
        None, description="Valid classification labels"
    )

    # --- Forensic Threat Hunting ---
    network_hosts: Optional[List[Dict[str, Any]]] = Field(
        None, description="Hosts on the network with status info"
    )
    threat_intel: Optional[Dict[str, Any]] = Field(
        None, description="Known threat indicators (IoCs)"
    )
    investigation_log: Optional[List[str]] = Field(
        None, description="Results from previous queries"
    )
    process_list: Optional[List[Dict[str, Any]]] = Field(
        None, description="Running processes on queried hosts"
    )

    # --- Cloud Perimeter Hardening ---
    cloud_assets: Optional[List[Dict[str, Any]]] = Field(
        None, description="Cloud infrastructure assets and their configs"
    )
    vulnerabilities: Optional[List[Dict[str, Any]]] = Field(
        None, description="Active vulnerabilities / misconfigurations"
    )
    service_status: Optional[Dict[str, Any]] = Field(
        None, description="Status of critical services (must stay online)"
    )


# ---------------------------------------------------------------------------
# State model
# ---------------------------------------------------------------------------

class CyberSentinelState(State):
    """
    Internal environment state (superset of what the agent observes).
    """

    task_name: str = Field("", description="Active task name")
    task_data: Dict[str, Any] = Field(
        default_factory=dict, description="Full internal task state"
    )
    score: float = Field(0.1, description="Current score (0.0, 1.0)")
    done: bool = Field(False, description="Whether the episode is finished")


__all__ = [
    "CyberSentinelAction",
    "CyberSentinelObservation",
    "CyberSentinelState",
]
