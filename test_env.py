#!/usr/bin/env python3
"""Quick test script for Cyber-Sentinel environment endpoints."""

import httpx
import json

BASE = "http://localhost:7860"
http = httpx.Client(timeout=30)

print("=== Health Check ===")
r = http.get(f"{BASE}/health")
print(r.json())

print("\n=== Task 1: Alert Triage ===")
r = http.post(f"{BASE}/env/reset", json={"seed": 42, "task_name": "alert_triage"})
data = r.json()
sid = data["session_id"]
obs = data["observation"]
print(f"Session: {sid}")
print(f"Alerts: {len(obs['siem_alerts'])}")
for a in obs["siem_alerts"]:
    print(f"  {a['alert_id']}: [{a['severity_raw']}] {a['event_type']}")

# Step: classify C2 beacon as malicious (correct)
r = http.post(f"{BASE}/env/step", json={
    "session_id": sid,
    "action": {"action_type": "triage_alert", "alert_id": "alert_001", "classification": "malicious", "metadata": {}}
})
step1 = r.json()
print(f"\nStep 1 (C2 as malicious): reward={step1['reward']:.2f} score={step1['observation']['current_score']:.2f}")

# Step: classify ransomware as benign (FALSE NEGATIVE - should penalize)
r = http.post(f"{BASE}/env/step", json={
    "session_id": sid,
    "action": {"action_type": "triage_alert", "alert_id": "alert_008", "classification": "benign", "metadata": {}}
})
step2 = r.json()
print(f"Step 2 (Ransomware as benign): reward={step2['reward']:.2f} score={step2['observation']['current_score']:.2f}")

print("\n=== Task 2: Threat Hunting ===")
r = http.post(f"{BASE}/env/reset", json={"seed": 42, "task_name": "threat_hunting"})
data = r.json()
sid2 = data["session_id"]
obs2 = data["observation"]
print(f"Session: {sid2}")
print(f"Hosts: {len(obs2['network_hosts'])}")
print(f"IoC IP: {obs2['threat_intel']['malicious_ip']}")

# Query first host
first_host = obs2["network_hosts"][0]["host_id"]
r = http.post(f"{BASE}/env/step", json={
    "session_id": sid2,
    "action": {"action_type": "query_logs", "host_id": first_host, "indicator": "198.51.100.23", "metadata": {}}
})
q1 = r.json()
print(f"\nQuery {first_host}: reward={q1['reward']:.2f}")
inv_log = q1["observation"].get("investigation_log", [])
for line in inv_log:
    print(f"  {line}")

print("\n=== Task 3: Cloud Hardening ===")
r = http.post(f"{BASE}/env/reset", json={"seed": 42, "task_name": "cloud_hardening"})
data = r.json()
sid3 = data["session_id"]
obs3 = data["observation"]
print(f"Session: {sid3}")
print(f"Vulnerabilities: {len(obs3['vulnerabilities'])}")
for v in obs3["vulnerabilities"]:
    print(f"  {v['vuln_id']}: [{v['severity']}] {v['title']} -> {v['remediation_action']}({v['remediation_policy']})")

# Fix the CRITICAL S3 bucket vuln
r = http.post(f"{BASE}/env/step", json={
    "session_id": sid3,
    "action": {"action_type": "restrict_access", "asset_id": "customer-data-bucket", "policy": "deny_public", "metadata": {}}
})
fix1 = r.json()
print(f"\nFix S3 bucket (restrict_access+deny_public): reward={fix1['reward']:.2f} score={fix1['observation']['current_score']:.2f}")

print("\n✅ All tasks functional!")
http.close()
