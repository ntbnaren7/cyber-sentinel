"""
Task definitions and deterministic graders for the Cyber-Sentinel Environment.

Each task is a self-contained class that:
  - Generates deterministic data from a seed
  - Processes actions and updates internal state
  - Computes incremental rewards via a programmatic grader

Tasks:
  1. SIEM Alert Triage (Easy)     – classify security alerts
  2. Forensic Threat Hunting (Medium) – find & isolate compromised hosts
  3. Cloud Perimeter Hardening (Hard) – fix cloud misconfigs without downtime
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Base Task
# ═══════════════════════════════════════════════════════════════════════════

class BaseTask(ABC):
    """Abstract base for all Cyber-Sentinel tasks."""

    name: str = ""
    description: str = ""
    max_steps: int = 20

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._step_count = 0
        self._score = 0.1
        self._done = False
        self._last_action_error: Optional[str] = None
        self._last_action_success = True
        self._setup()

    @abstractmethod
    def _setup(self) -> None:
        ...

    @abstractmethod
    def process_action(self, action_type: str, params: Dict[str, Any]) -> float:
        ...

    @abstractmethod
    def get_observation_fields(self) -> Dict[str, Any]:
        ...

    @abstractmethod
    def get_task_data(self) -> Dict[str, Any]:
        ...

    def step(self, action_type: str, params: Dict[str, Any]) -> Tuple[float, bool]:
        self._step_count += 1
        self._last_action_error = None
        self._last_action_success = True

        if self._done:
            self._last_action_error = "Episode already finished"
            self._last_action_success = False
            return 0.0, True

        try:
            raw_delta = self.process_action(action_type, params)
        except InvalidActionError as e:
            self._last_action_error = str(e)
            self._last_action_success = False
            raw_delta = -0.02  # small penalty for invalid actions

        proposed_score = self._score + raw_delta
        clamped_score = max(0.1, min(0.9, proposed_score))
        
        if self._step_count == 1:
            actual_delta = clamped_score
        else:
            actual_delta = clamped_score - self._score

        self._score = clamped_score

        if self._step_count >= self.max_steps:
            self._done = True

        return actual_delta, self._done

    @property
    def score(self) -> float:
        return self._score

    @property
    def done(self) -> bool:
        return self._done


class InvalidActionError(Exception):
    pass


# ═══════════════════════════════════════════════════════════════════════════
# Task 1: SIEM Alert Triage (Easy)
# ═══════════════════════════════════════════════════════════════════════════

_SIEM_ALERT_POOL = [
    # --- Benign ---
    {
        "source_ip": "10.0.1.15",
        "dest_ip": "10.0.1.1",
        "event_type": "DNS_QUERY",
        "description": "Routine DNS lookup for internal service registry.",
        "severity_raw": "LOW",
        "payload_snippet": "A? svc-registry.internal.corp",
        "correct_classification": "benign",
    },
    {
        "source_ip": "10.0.2.30",
        "dest_ip": "10.0.2.1",
        "event_type": "AUTH_SUCCESS",
        "description": "Successful VPN login from employee workstation during business hours.",
        "severity_raw": "INFO",
        "payload_snippet": "user=jsmith auth=MFA_OK src_geo=US",
        "correct_classification": "benign",
    },
    {
        "source_ip": "10.0.3.50",
        "dest_ip": "10.0.3.1",
        "event_type": "FILE_ACCESS",
        "description": "Scheduled backup process reading files from /data/reports.",
        "severity_raw": "INFO",
        "payload_snippet": "process=backup_agent.exe path=/data/reports/* action=READ",
        "correct_classification": "benign",
    },
    {
        "source_ip": "10.0.1.22",
        "dest_ip": "8.8.8.8",
        "event_type": "HTTPS_CONN",
        "description": "Software update check to vendor CDN.",
        "severity_raw": "INFO",
        "payload_snippet": "GET /updates/manifest.json Host: cdn.vendor.com",
        "correct_classification": "benign",
    },
    # --- Suspicious ---
    {
        "source_ip": "10.0.4.99",
        "dest_ip": "10.0.4.1",
        "event_type": "AUTH_FAILURE",
        "description": "15 failed SSH login attempts in 60 seconds from a single internal host.",
        "severity_raw": "MEDIUM",
        "payload_snippet": "user=root attempts=15 window=60s src=10.0.4.99",
        "correct_classification": "suspicious",
    },
    {
        "source_ip": "10.0.5.12",
        "dest_ip": "185.220.101.34",
        "event_type": "OUTBOUND_CONN",
        "description": "Outbound connection to IP on threat intel watchlist (TOR exit node).",
        "severity_raw": "HIGH",
        "payload_snippet": "dst=185.220.101.34:443 geo=NL label=TOR_EXIT",
        "correct_classification": "suspicious",
    },
    {
        "source_ip": "10.0.2.88",
        "dest_ip": "10.0.2.1",
        "event_type": "PRIV_ESCALATION",
        "description": "User account added to local administrators group outside of change window.",
        "severity_raw": "MEDIUM",
        "payload_snippet": "user=contractor3 group=Administrators by=contractor3",
        "correct_classification": "suspicious",
    },
    # --- Malicious ---
    {
        "source_ip": "10.0.6.77",
        "dest_ip": "198.51.100.23",
        "event_type": "DATA_EXFIL",
        "description": "Large encrypted data transfer (4.2 GB) to unknown external IP at 03:00 AM.",
        "severity_raw": "CRITICAL",
        "payload_snippet": "bytes_out=4509715456 dst=198.51.100.23:8443 proto=TLS duration=847s",
        "correct_classification": "malicious",
    },
    {
        "source_ip": "10.0.1.45",
        "dest_ip": "10.0.1.0/24",
        "event_type": "LATERAL_MOVEMENT",
        "description": "Host scanning all ports on /24 subnet using SYN sweep, followed by SMB exploitation attempt.",
        "severity_raw": "CRITICAL",
        "payload_snippet": "scan_type=SYN targets=254 ports=445,3389,22 exploit=MS17-010",
        "correct_classification": "malicious",
    },
    {
        "source_ip": "10.0.3.91",
        "dest_ip": "10.0.3.10",
        "event_type": "RANSOMWARE",
        "description": "File system encryption detected: 1,247 files renamed with .lockbit extension in 90 seconds.",
        "severity_raw": "CRITICAL",
        "payload_snippet": "process=svchost_update.exe files_encrypted=1247 ext=.lockbit ransom_note=README_RESTORE.txt",
        "correct_classification": "malicious",
    },
    {
        "source_ip": "10.0.7.33",
        "dest_ip": "10.0.7.1",
        "event_type": "C2_BEACON",
        "description": "Periodic HTTPS beaconing every 60s (+/- 5s jitter) to known Cobalt Strike C2 domain.",
        "severity_raw": "CRITICAL",
        "payload_snippet": "dst=update-check.malware-c2.xyz interval=60s jitter=5s beacon_size=256b",
        "correct_classification": "malicious",
    },
    {
        "source_ip": "10.0.8.14",
        "dest_ip": "10.0.8.1",
        "event_type": "CREDENTIAL_DUMP",
        "description": "Mimikatz-like tool detected accessing LSASS process memory.",
        "severity_raw": "CRITICAL",
        "payload_snippet": "process=taskhost_svc.exe target=lsass.exe access=PROCESS_VM_READ hash=a1b2c3d4e5",
        "correct_classification": "malicious",
    },
]


class AlertTriageTask(BaseTask):
    """
    Easy task: classify incoming SIEM alerts.

    Scoring:
      Correct classification: +1.0 / total_alerts
      Incorrect (benign when malicious): -0.15 (false negative – dangerous)
      Incorrect (malicious when benign): -0.05 (false positive – wastes time)
      Incorrect (other mismatches):       0.0
    """

    name = "alert_triage"
    description = (
        "You are a Tier-1 SOC analyst. Your SIEM has generated a batch of security "
        "alerts. Analyze each alert's source_ip, dest_ip, event_type, description, "
        "and payload_snippet to classify it as 'benign', 'suspicious', or 'malicious'. "
        "Use the 'triage_alert' action with 'alert_id' and 'classification'. "
        "CRITICAL: Missing a real attack (classifying malicious as benign) is the "
        "worst outcome. False positives are acceptable but wasteful."
    )
    max_steps = 20

    def _setup(self) -> None:
        selected = self._rng.sample(
            _SIEM_ALERT_POOL, k=min(8, len(_SIEM_ALERT_POOL))
        )
        self._alerts: List[Dict[str, Any]] = []
        self._ground_truth: Dict[str, str] = {}

        for i, alert in enumerate(selected):
            aid = f"alert_{i+1:03d}"
            self._alerts.append({
                "alert_id": aid,
                "source_ip": alert["source_ip"],
                "dest_ip": alert["dest_ip"],
                "event_type": alert["event_type"],
                "description": alert["description"],
                "severity_raw": alert["severity_raw"],
                "payload_snippet": alert["payload_snippet"],
                "classification": None,
            })
            self._ground_truth[aid] = alert["correct_classification"]

        self._classified: Dict[str, str] = {}
        self._total = len(self._alerts)

    def process_action(self, action_type: str, params: Dict[str, Any]) -> float:
        if action_type != "triage_alert":
            raise InvalidActionError(
                f"Invalid action_type '{action_type}' for alert_triage. "
                f"Use 'triage_alert'."
            )

        alert_id = params.get("alert_id")
        classification = params.get("classification")

        if not alert_id or not classification:
            raise InvalidActionError("Both 'alert_id' and 'classification' are required.")

        if alert_id not in self._ground_truth:
            raise InvalidActionError(f"Unknown alert_id: {alert_id}")

        if alert_id in self._classified:
            raise InvalidActionError(f"Alert {alert_id} already classified.")

        valid = ["benign", "suspicious", "malicious"]
        if classification not in valid:
            raise InvalidActionError(
                f"Invalid classification '{classification}'. Must be one of: {valid}"
            )

        self._classified[alert_id] = classification
        for a in self._alerts:
            if a["alert_id"] == alert_id:
                a["classification"] = classification
                break

        correct = self._ground_truth[alert_id]

        if classification == correct:
            reward = 0.80 / self._total
        elif correct == "malicious" and classification == "benign":
            reward = -0.15  # false negative - DANGEROUS
        elif correct == "benign" and classification == "malicious":
            reward = -0.05  # false positive - wasteful
        else:
            reward = 0.0  # partial mismatch

        if len(self._classified) >= self._total:
            self._done = True

        return reward

    def get_observation_fields(self) -> Dict[str, Any]:
        return {
            "siem_alerts": deepcopy(self._alerts),
            "valid_classifications": ["benign", "suspicious", "malicious"],
        }

    def get_task_data(self) -> Dict[str, Any]:
        return {
            "alerts": deepcopy(self._alerts),
            "ground_truth": dict(self._ground_truth),
            "classified": dict(self._classified),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Task 2: Forensic Threat Hunting (Medium)
# ═══════════════════════════════════════════════════════════════════════════

_NETWORK_HOSTS = [
    {"hostname": "web-prod-01", "ip": "10.0.1.10", "os": "Ubuntu 22.04", "role": "Web Server", "criticality": "high"},
    {"hostname": "db-prod-01", "ip": "10.0.1.20", "os": "RHEL 9", "role": "Database", "criticality": "critical"},
    {"hostname": "dev-ws-03", "ip": "10.0.2.33", "os": "Windows 11", "role": "Developer Workstation", "criticality": "medium"},
    {"hostname": "hr-ws-07", "ip": "10.0.2.77", "os": "Windows 11", "role": "HR Workstation", "criticality": "medium"},
    {"hostname": "ci-runner-02", "ip": "10.0.3.12", "os": "Ubuntu 22.04", "role": "CI/CD Runner", "criticality": "high"},
    {"hostname": "vpn-gw-01", "ip": "10.0.0.1", "os": "pfSense", "role": "VPN Gateway", "criticality": "critical"},
    {"hostname": "mail-srv-01", "ip": "10.0.1.50", "os": "Ubuntu 22.04", "role": "Mail Server", "criticality": "high"},
    {"hostname": "jump-box-01", "ip": "10.0.0.5", "os": "Ubuntu 22.04", "role": "Jump Box / Bastion", "criticality": "critical"},
]

_PROCESS_TEMPLATES = {
    "clean": [
        {"pid": "1001", "name": "nginx", "user": "www-data", "cpu": "2.1%", "mem": "128MB", "status": "running"},
        {"pid": "1002", "name": "postgres", "user": "postgres", "cpu": "4.3%", "mem": "512MB", "status": "running"},
        {"pid": "1003", "name": "sshd", "user": "root", "cpu": "0.1%", "mem": "12MB", "status": "running"},
        {"pid": "1004", "name": "cron", "user": "root", "cpu": "0.0%", "mem": "4MB", "status": "sleeping"},
    ],
    "infected": [
        {"pid": "1001", "name": "nginx", "user": "www-data", "cpu": "2.1%", "mem": "128MB", "status": "running"},
        {"pid": "1002", "name": "postgres", "user": "postgres", "cpu": "4.3%", "mem": "512MB", "status": "running"},
        {"pid": "1003", "name": "sshd", "user": "root", "cpu": "0.1%", "mem": "12MB", "status": "running"},
        {"pid": "6666", "name": "kworker_update", "user": "root", "cpu": "18.7%", "mem": "340MB", "status": "running"},
        {"pid": "6667", "name": "systemd-resolved-helper", "user": "root", "cpu": "5.2%", "mem": "89MB", "status": "running"},
    ],
}


class ForensicHuntingTask(BaseTask):
    """
    Medium task: investigate a breach by following IoCs across hosts.

    The agent receives threat intelligence (a malicious IP/hash) and must:
      1. Query hosts' logs to find which one communicated with the IoC
      2. Inspect the process list of the infected host
      3. Kill the malicious process
      4. Isolate the compromised host

    Scoring:
      query_logs on correct host: +0.10
      query_logs on wrong host: +0.02 (eliminates a candidate)
      kill_process (correct PID): +0.25
      kill_process (wrong PID): -0.10
      isolate_host (correct host): +0.40
      isolate_host (wrong host): -0.20
    """

    name = "threat_hunting"
    description = (
        "You are a Tier-2 SOC analyst. Threat intelligence has flagged a known "
        "malicious IP communicating with your network. Your mission: "
        "(1) Query host logs using 'query_logs' with 'host_id' and 'indicator' to "
        "find which host is compromised. "
        "(2) Once found, review the process list and use 'kill_process' with "
        "'host_id' and 'process_id' to terminate the malware. "
        "(3) Finally, use 'isolate_host' with 'host_id' to quarantine the machine. "
        "Investigate methodically — isolating the wrong host disrupts business."
    )
    max_steps = 20

    def _setup(self) -> None:
        # Select hosts
        selected = self._rng.sample(_NETWORK_HOSTS, k=min(6, len(_NETWORK_HOSTS)))
        self._hosts: List[Dict[str, Any]] = []

        for i, h in enumerate(selected):
            hid = f"host_{i+1:03d}"
            self._hosts.append({
                "host_id": hid,
                **h,
                "status": "online",
                "investigated": False,
            })

        # Pick one host as the compromised one
        infected_idx = self._rng.randint(0, len(self._hosts) - 1)
        self._infected_host_id = self._hosts[infected_idx]["host_id"]

        # The malicious IoC
        self._malicious_ip = "198.51.100.23"
        self._malicious_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        self._malicious_pid = "6666"

        # Build process lists per host
        self._host_processes: Dict[str, List[Dict[str, Any]]] = {}
        for h in self._hosts:
            if h["host_id"] == self._infected_host_id:
                self._host_processes[h["host_id"]] = deepcopy(
                    _PROCESS_TEMPLATES["infected"]
                )
            else:
                self._host_processes[h["host_id"]] = deepcopy(
                    _PROCESS_TEMPLATES["clean"]
                )

        # Build log evidence per host
        self._host_logs: Dict[str, List[str]] = {}
        for h in self._hosts:
            if h["host_id"] == self._infected_host_id:
                self._host_logs[h["host_id"]] = [
                    f"[03:01:22] OUTBOUND connection to {self._malicious_ip}:8443 (TLS)",
                    f"[03:01:23] Process kworker_update (PID 6666) opened socket to {self._malicious_ip}",
                    f"[03:02:10] File hash {self._malicious_hash} written to /tmp/.cache/update.bin",
                    f"[03:05:44] Unusual DNS query: beacon-c2.malware.xyz",
                    f"[03:10:01] 340MB memory allocation by PID 6666",
                ]
            else:
                self._host_logs[h["host_id"]] = [
                    "[08:00:01] Normal cron job executed: /etc/cron.daily/logrotate",
                    "[08:15:30] SSHD: Accepted publickey for deploy_user from 10.0.0.5",
                    "[09:00:00] Scheduled backup completed successfully",
                ]

        self._investigation_log: List[str] = []
        self._queried_hosts: set = set()
        self._process_killed = False
        self._host_isolated = False

    def process_action(self, action_type: str, params: Dict[str, Any]) -> float:
        if action_type == "query_logs":
            return self._handle_query(params)
        elif action_type == "kill_process":
            return self._handle_kill(params)
        elif action_type == "isolate_host":
            return self._handle_isolate(params)
        else:
            raise InvalidActionError(
                f"Invalid action_type '{action_type}' for threat_hunting. "
                f"Use 'query_logs', 'kill_process', or 'isolate_host'."
            )

    def _handle_query(self, params: Dict[str, Any]) -> float:
        host_id = params.get("host_id")
        indicator = params.get("indicator")

        if not host_id:
            raise InvalidActionError("'host_id' is required.")

        host = None
        for h in self._hosts:
            if h["host_id"] == host_id:
                host = h
                break
        if not host:
            raise InvalidActionError(f"Unknown host_id: {host_id}")

        if host["status"] == "isolated":
            raise InvalidActionError(f"Host {host_id} is isolated and cannot be queried.")

        logs = self._host_logs.get(host_id, [])
        host["investigated"] = True
        self._queried_hosts.add(host_id)

        # Build report
        log_text = "\n".join(logs)
        self._investigation_log.append(
            f"== Query results for {host_id} ({host['hostname']}) ==\n{log_text}"
        )

        if host_id == self._infected_host_id:
            self._investigation_log.append(
                f"⚠ MATCH: Host {host_id} shows communication with IoC {self._malicious_ip}"
            )
            return 0.10  # found the infected host
        else:
            self._investigation_log.append(
                f"✓ CLEAR: No indicators found on {host_id}"
            )
            return 0.02  # eliminated a candidate

    def _handle_kill(self, params: Dict[str, Any]) -> float:
        host_id = params.get("host_id")
        process_id = params.get("process_id")

        if not host_id or not process_id:
            raise InvalidActionError("'host_id' and 'process_id' are required.")

        host = None
        for h in self._hosts:
            if h["host_id"] == host_id:
                host = h
                break
        if not host:
            raise InvalidActionError(f"Unknown host_id: {host_id}")

        if host["status"] == "isolated":
            raise InvalidActionError(f"Host {host_id} is isolated.")

        procs = self._host_processes.get(host_id, [])
        proc = None
        for p in procs:
            if p["pid"] == process_id:
                proc = p
                break
        if not proc:
            raise InvalidActionError(f"No process with PID {process_id} on {host_id}.")

        # Remove process
        self._host_processes[host_id] = [
            p for p in procs if p["pid"] != process_id
        ]

        if host_id == self._infected_host_id and process_id == self._malicious_pid:
            self._process_killed = True
            self._investigation_log.append(
                f"☠ KILLED: Malicious process PID {process_id} on {host_id}"
            )
            return 0.80 / 3.0  # About 0.266 per correct kill
        else:
            self._investigation_log.append(
                f"❌ KILLED: Legitimate process PID {process_id} on {host_id} — WRONG TARGET"
            )
            return -0.10

    def _handle_isolate(self, params: Dict[str, Any]) -> float:
        host_id = params.get("host_id")
        if not host_id:
            raise InvalidActionError("'host_id' is required.")

        host = None
        for h in self._hosts:
            if h["host_id"] == host_id:
                host = h
                break
        if not host:
            raise InvalidActionError(f"Unknown host_id: {host_id}")

        if host["status"] == "isolated":
            raise InvalidActionError(f"Host {host_id} is already isolated.")

        host["status"] = "isolated"

        if host_id == self._infected_host_id:
            self._host_isolated = True
            self._investigation_log.append(
                f"🔒 ISOLATED: Compromised host {host_id} quarantined from network"
            )
            # Check if fully remediated
            if self._process_killed:
                self._done = True
            return 0.80 / 3.0  # About 0.266 per correct isolation
        else:
            self._investigation_log.append(
                f"⚠ ISOLATED: Clean host {host_id} — BUSINESS DISRUPTION"
            )
            return -0.20

    def get_observation_fields(self) -> Dict[str, Any]:
        return {
            "network_hosts": deepcopy(self._hosts),
            "threat_intel": {
                "type": "active_threat",
                "malicious_ip": self._malicious_ip,
                "malicious_hash": self._malicious_hash,
                "description": (
                    f"Threat feed detected outbound C2 communication to "
                    f"{self._malicious_ip}. File hash {self._malicious_hash} "
                    f"associated with known APT group. Identify and contain "
                    f"the compromised host immediately."
                ),
            },
            "investigation_log": list(self._investigation_log),
            "process_list": None,  # only populated on query
        }

    def get_task_data(self) -> Dict[str, Any]:
        return {
            "hosts": deepcopy(self._hosts),
            "infected_host_id": self._infected_host_id,
            "malicious_ip": self._malicious_ip,
            "malicious_pid": self._malicious_pid,
            "queried_hosts": list(self._queried_hosts),
            "process_killed": self._process_killed,
            "host_isolated": self._host_isolated,
            "investigation_log": list(self._investigation_log),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Task 3: Cloud Perimeter Hardening (Hard)
# ═══════════════════════════════════════════════════════════════════════════

_CLOUD_ASSETS = [
    {
        "name": "prod-web-server",
        "type": "EC2",
        "ip": "54.23.12.100",
        "ports": [80, 443, 22],
        "role": "Production Web Server",
        "critical_ports": [80, 443],  # must remain open
    },
    {
        "name": "customer-data-bucket",
        "type": "S3",
        "ip": None,
        "ports": [],
        "role": "Customer PII Storage",
        "critical_ports": [],
    },
    {
        "name": "internal-api-gateway",
        "type": "EC2",
        "ip": "10.0.5.50",
        "ports": [8080, 8443, 22],
        "role": "Internal API Gateway",
        "critical_ports": [8080, 8443],
    },
    {
        "name": "root-account",
        "type": "IAM",
        "ip": None,
        "ports": [],
        "role": "AWS Root Account",
        "critical_ports": [],
    },
    {
        "name": "staging-database",
        "type": "RDS",
        "ip": "10.0.6.20",
        "ports": [5432],
        "role": "Staging PostgreSQL Database",
        "critical_ports": [5432],
    },
    {
        "name": "log-archive-bucket",
        "type": "S3",
        "ip": None,
        "ports": [],
        "role": "Security Log Archive",
        "critical_ports": [],
    },
]

_VULNERABILITY_POOL = [
    {
        "vuln_id": "VULN-001",
        "asset": "customer-data-bucket",
        "severity": "CRITICAL",
        "title": "S3 Bucket Publicly Accessible",
        "description": "Bucket has ACL set to 'public-read'. Customer PII is exposed to the internet.",
        "remediation_action": "restrict_access",
        "remediation_policy": "deny_public",
    },
    {
        "vuln_id": "VULN-002",
        "asset": "root-account",
        "severity": "CRITICAL",
        "title": "Root Account Without MFA",
        "description": "AWS root account has no multi-factor authentication enabled. Full account takeover risk.",
        "remediation_action": "enable_protection",
        "remediation_policy": "enable_mfa",
    },
    {
        "vuln_id": "VULN-003",
        "asset": "prod-web-server",
        "severity": "HIGH",
        "title": "SSH Open to 0.0.0.0/0",
        "description": "Security group allows SSH (port 22) from any IP. Brute-force attack surface.",
        "remediation_action": "restrict_access",
        "remediation_policy": "restrict_ssh",
    },
    {
        "vuln_id": "VULN-004",
        "asset": "staging-database",
        "severity": "HIGH",
        "title": "Database Publicly Accessible",
        "description": "RDS instance has 'publicly accessible' flag set to True. Port 5432 reachable from internet.",
        "remediation_action": "restrict_access",
        "remediation_policy": "deny_public",
    },
    {
        "vuln_id": "VULN-005",
        "asset": "log-archive-bucket",
        "severity": "MEDIUM",
        "title": "No Encryption at Rest",
        "description": "Security log archive bucket has no server-side encryption. Compliance violation.",
        "remediation_action": "enable_protection",
        "remediation_policy": "enable_encryption",
    },
    {
        "vuln_id": "VULN-006",
        "asset": "internal-api-gateway",
        "severity": "MEDIUM",
        "title": "No Access Logging Enabled",
        "description": "API gateway has no CloudWatch or access logging. Cannot audit API calls.",
        "remediation_action": "enable_protection",
        "remediation_policy": "enable_logging",
    },
    {
        "vuln_id": "VULN-007",
        "asset": "prod-web-server",
        "severity": "CRITICAL",
        "title": "Overly Permissive IAM Role",
        "description": "IAM role attached to web server has AdministratorAccess policy. Violation of least-privilege.",
        "remediation_action": "apply_policy",
        "remediation_policy": "least_privilege",
    },
]


class CloudHardeningTask(BaseTask):
    """
    Hard task: fix cloud misconfigurations without breaking production.

    The agent must remediate vulnerabilities while keeping critical services online.
    If a remediation accidentally blocks a critical port (e.g., 80/443 on the web
    server), it incurs a massive penalty.

    Scoring:
      Correct remediation: +0.15 per vuln fixed
      Bonus for CRITICAL first: +0.05 if severity order respected
      Blocking critical port: -0.30 (service outage)
      Wrong action/policy combo: -0.05
    """

    name = "cloud_hardening"
    description = (
        "You are a Cloud Security Engineer. A vulnerability scan has found multiple "
        "misconfigurations in your AWS environment. Remediate each vulnerability using "
        "the appropriate action:\n"
        "- 'restrict_access': Tighten firewall/ACL rules (use with 'asset_id' and 'policy')\n"
        "- 'apply_policy': Change IAM/resource policies (use with 'asset_id' and 'policy')\n"
        "- 'enable_protection': Turn on MFA/encryption/logging (use with 'asset_id' and 'policy')\n\n"
        "CRITICAL CONSTRAINT: The production web server (ports 80, 443) and database "
        "(port 5432) MUST remain accessible. Blocking critical ports causes an outage "
        "and a severe penalty. Fix vulnerabilities in order of severity (CRITICAL first)."
    )
    max_steps = 25

    def _setup(self) -> None:
        # Select 5-6 vulns
        selected_vulns = self._rng.sample(
            _VULNERABILITY_POOL, k=min(5, len(_VULNERABILITY_POOL))
        )

        self._cloud_assets: List[Dict[str, Any]] = deepcopy(_CLOUD_ASSETS)
        self._vulnerabilities: List[Dict[str, Any]] = []
        self._vuln_map: Dict[str, Dict[str, Any]] = {}  # vuln_id -> vuln data

        for vuln in selected_vulns:
            v = deepcopy(vuln)
            v["status"] = "open"
            self._vulnerabilities.append(v)
            self._vuln_map[v["vuln_id"]] = v

        self._fixed_vulns: set = set()
        self._blocked_critical_ports = False
        self._fix_order: List[str] = []  # track severity ordering
        self._total_vulns = len(self._vulnerabilities)

        # Service status tracking
        self._service_status = {
            "prod-web-server": {"online": True, "ports_blocked": []},
            "internal-api-gateway": {"online": True, "ports_blocked": []},
            "staging-database": {"online": True, "ports_blocked": []},
        }

    def process_action(self, action_type: str, params: Dict[str, Any]) -> float:
        valid_actions = ["restrict_access", "apply_policy", "enable_protection"]
        if action_type not in valid_actions:
            raise InvalidActionError(
                f"Invalid action_type '{action_type}' for cloud_hardening. "
                f"Use one of: {valid_actions}"
            )

        asset_id = params.get("asset_id")
        policy = params.get("policy")

        if not asset_id or not policy:
            raise InvalidActionError("Both 'asset_id' and 'policy' are required.")

        # Find matching vulnerability
        matching_vuln = None
        for vid, v in self._vuln_map.items():
            if (
                v["asset"] == asset_id
                and v["remediation_action"] == action_type
                and v["remediation_policy"] == policy
                and v["status"] == "open"
            ):
                matching_vuln = v
                break

        if matching_vuln is None:
            # Check if it accidentally blocks critical ports
            reward = self._check_collateral_damage(asset_id, action_type, policy)
            if reward < 0:
                return reward
            raise InvalidActionError(
                f"No open vulnerability matches asset='{asset_id}', "
                f"action='{action_type}', policy='{policy}'."
            )

        # Apply fix
        matching_vuln["status"] = "fixed"
        self._fixed_vulns.add(matching_vuln["vuln_id"])
        self._fix_order.append(matching_vuln["severity"])

        reward = (0.80 - 0.05) / self._total_vulns  # base per-fix reward (leaving 0.05 for order bonus)

        # Priority bonus: check if fixing in severity order
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ranks = [severity_rank.get(s, 99) for s in self._fix_order]
        if ranks == sorted(ranks):
            reward += 0.05  # order bonus

        # Check completion
        if len(self._fixed_vulns) >= self._total_vulns:
            self._done = True

        return reward

    def _check_collateral_damage(
        self, asset_id: str, action_type: str, policy: str
    ) -> float:
        """Check if the action accidentally blocks critical ports."""
        # Dangerous: restrict_access with block_all or deny_all on production
        asset = None
        for a in self._cloud_assets:
            if a["name"] == asset_id:
                asset = a
                break

        if asset and action_type == "restrict_access":
            if policy in ("block_all", "deny_all", "block_http", "block_https"):
                critical = asset.get("critical_ports", [])
                if critical:
                    self._blocked_critical_ports = True
                    svc = self._service_status.get(asset_id)
                    if svc:
                        svc["online"] = False
                        svc["ports_blocked"] = critical
                    return -0.30  # service outage penalty

        return -0.05  # generic wrong action penalty

    def get_observation_fields(self) -> Dict[str, Any]:
        return {
            "cloud_assets": deepcopy(self._cloud_assets),
            "vulnerabilities": deepcopy(self._vulnerabilities),
            "service_status": deepcopy(self._service_status),
        }

    def get_task_data(self) -> Dict[str, Any]:
        return {
            "cloud_assets": deepcopy(self._cloud_assets),
            "vulnerabilities": deepcopy(self._vulnerabilities),
            "fixed_vulns": list(self._fixed_vulns),
            "fix_order": list(self._fix_order),
            "blocked_critical_ports": self._blocked_critical_ports,
            "service_status": deepcopy(self._service_status),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════════════════

TASK_REGISTRY: Dict[str, type] = {
    "alert_triage": AlertTriageTask,
    "threat_hunting": ForensicHuntingTask,
    "cloud_hardening": CloudHardeningTask,
}

TASK_DIFFICULTIES: Dict[str, str] = {
    "alert_triage": "easy",
    "threat_hunting": "medium",
    "cloud_hardening": "hard",
}
