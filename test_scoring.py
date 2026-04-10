import sys
import os

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.tasks import TASK_REGISTRY

def test_perfect_agent(task_name):
    print(f"\n--- Testing Perfect Agent: {task_name} ---")
    task_cls = TASK_REGISTRY[task_name]
    task = task_cls(seed=42)
    
    # Simulate making observation
    # First Reset emits 0.1
    all_rewards = [0.1]
    
    if task_name == "alert_triage":
        gt = task._ground_truth
        for a in task._alerts:
            aid = a["alert_id"]
            correct = gt[aid]
            reward, done = task.step("triage_alert", {"alert_id": aid, "classification": correct})
            all_rewards.append(reward)
            print(f"Step {aid}: reward={reward:.4f}, done={done}")
    
    elif task_name == "threat_hunting":
        # Compromised host
        ihost = task._infected_host_id
        ipid = task._malicious_pid
        
        r1, d1 = task.step("kill_process", {"host_id": ihost, "process_id": ipid})
        all_rewards.append(r1)
        print(f"Step kill {ipid}: reward={r1:.4f}, done={d1}")
        
        r2, d2 = task.step("isolate_host", {"host_id": ihost})
        all_rewards.append(r2)
        print(f"Step isolate {ihost}: reward={r2:.4f}, done={d2}")
        
    elif task_name == "cloud_hardening":
        for v in task._vulnerabilities:
            ast = v["asset"]
            ra = v["remediation_action"]
            rp = v["remediation_policy"]
            # To get bonus, must fix in order of severity, but this test just loops array 
            # (Bonus requires ordered fixing)
            # Find the actual vulns and sort them
            pass
            
        vulns = sorted(task._vulnerabilities, key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v["severity"], 99))
        for v in vulns:
            ast = v["asset"]
            ra = v["remediation_action"]
            rp = v["remediation_policy"]
            reward, done = task.step(ra, {"asset_id": ast, "policy": rp})
            all_rewards.append(reward)
            print(f"Step fix {v['vuln_id']}: reward={reward:.4f}, done={done}")

    s = sum(all_rewards)
    print(f"Total accumulated rewards: {s:.6f}")
    assert 0 < s < 1.0, f"Score {s} out of bounds!"
    for r in all_rewards:
        assert r > 0.0, f"Individual reward {r} is <= 0! This breaks SPM."
    
def test_worst_agent(task_name):
    print(f"\n--- Testing Worst Agent: {task_name} ---")
    task_cls = TASK_REGISTRY[task_name]
    task = task_cls(seed=42)
    
    all_rewards = [0.1]
    
    if task_name == "alert_triage":
        gt = task._ground_truth
        for a in task._alerts:
            aid = a["alert_id"]
            correct = gt[aid]
            wrong = "benign" if correct == "malicious" else "malicious"
            reward, done = task.step("triage_alert", {"alert_id": aid, "classification": wrong})
            all_rewards.append(reward)
            print(f"Step {aid}: reward={reward:.4f}, done={done}")
    
    elif task_name == "threat_hunting":
        hosts = [h["host_id"] for h in task._hosts if h["host_id"] != task._infected_host_id]
        
        for h in hosts[:3]:
            r1, d1 = task.step("isolate_host", {"host_id": h})
            all_rewards.append(r1)
            print(f"Step isolate {h}: reward={r1:.4f}, done={d1}")

    elif task_name == "cloud_hardening":
        # Wrong action
        reward, done = task.step("restrict_access", {"asset_id": "prod-web-server", "policy": "block_all"})
        all_rewards.append(reward)
        print(f"Step wrong: reward={reward:.4f}, done={done}")

        for i in range(5):
             r, d = task.step("noop", {})
             all_rewards.append(r)
             print(f"Step noop: reward={r:.4f}, done={d}")

    s = sum(all_rewards)
    print(f"Total accumulated rewards: {s:.6f}")
    assert 0 < s < 1.0, f"Score {s} out of bounds!"
    for r in all_rewards:
        assert r > 0.0, f"Individual reward {r} is <= 0! This breaks SPM."

if __name__ == "__main__":
    for t in TASK_REGISTRY.keys():
        test_perfect_agent(t)
        test_worst_agent(t)
