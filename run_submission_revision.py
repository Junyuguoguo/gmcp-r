#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMCP-R Submission Experiment Revision Orchestrator

Runs the full submission experiment suite in order:
1. Protocol tests
2. Baseline comparison
3. Adaptive hash chain attack
4. Recovery window experiment
5. Ticket rejection experiment
6. Checkpoint cost comparison
7. Concurrent experiment
8. Validation
9. Plots
10. Manifest
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def run(cmd, cwd, env=None, timeout=1800):
    """Run a command and return (success, stdout, stderr, elapsed)."""
    merged_env = {**os.environ, **(env or {})}
    start = time.time()
    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=merged_env,
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.time() - start
        return result.returncode == 0, result.stdout, result.stderr, elapsed
    except subprocess.TimeoutExpired:
        return False, "", f"Timeout after {timeout}s", time.time() - start
    except Exception as e:
        return False, "", str(e), time.time() - start


def main():
    parser = argparse.ArgumentParser(description="GMCP-R Submission Revision Orchestrator")
    parser.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--spawn-server", action="store_true", default=True)
    args = parser.parse_args()

    project = Path(__file__).parent
    venv_python = str(project / ".venv" / "bin" / "python")
    
    if args.output_root:
        output_root = args.output_root
    elif args.mode == "smoke":
        output_root = str(project / "results" / "submission_revision" / "smoke")
    else:
        output_root = str(project / "results" / "submission_revision")
    
    os.makedirs(output_root, exist_ok=True)
    
    repeats = 1 if args.mode == "smoke" else 30
    env = {
        "GMCP_REPEATS": str(repeats),
        "GMCP_OUTPUT_ROOT": output_root,
    }
    
    if args.mode == "smoke":
        env["GMCP_SESSION_LENGTHS"] = "1000"
        env["GMCP_CHECKPOINT_INTERVALS"] = "10,50"
        env["GMCP_MESSAGE_COUNTS"] = "20"
        env["GMCP_PAYLOAD_SIZES"] = "128"
        env["GMCP_RACE_REPEATS"] = "1"
        env["GMCP_BENCH_REPEATS"] = "3"
    
    steps = [
        ("Protocol tests", [venv_python, "-m", "unittest", "discover", "-s", "tests", "-p", "test*.py", "-v"]),
        ("Baseline comparison", [venv_python, "run_real_baseline_comparison.py", "--spawn-server"]),
        ("Adaptive hash chain", [venv_python, "run_hash_chain_adaptive_attack.py", "--spawn-server"]),
        ("Recovery window", [venv_python, "run_recovery_window_experiment.py", "--spawn-server"]),
        ("Ticket rejection", [venv_python, "run_real_ticket_recovery_experiment.py", "--spawn-server"]),
        ("Checkpoint cost", [venv_python, "run_checkpoint_cost_comparison.py"]),
        ("Concurrent", [venv_python, "run_concurrent_experiment.py", "--spawn-server"]),
        ("Validation", [
            venv_python, "validate_submission_revision.py",
            "--mode", "smoke" if args.mode == "smoke" else "release",
            "--output-root", output_root,
            "--expected-repeats", str(repeats),
        ]),
        ("Plots", [venv_python, "plot_submission_revision.py", "--output-root", output_root]),
    ]
    
    print("=" * 80)
    print(f"GMCP-R Submission Revision ({args.mode} mode)")
    print(f"Output: {output_root}")
    print(f"Repeats: {repeats}")
    print("=" * 80)
    
    failed = False
    for i, (name, cmd) in enumerate(steps, 1):
        print(f"\n[{i}/{len(steps)}] {name}...")
        ok, stdout, stderr, elapsed = run(cmd, project, env=env)
        
        if ok:
            print(f"  ✅ PASSED ({elapsed:.1f}s)")
        else:
            print(f"  ❌ FAILED ({elapsed:.1f}s)")
            if stderr:
                for line in stderr.strip().split("\n")[-5:]:
                    print(f"  {line}")
            failed = True
            break
    
    if not failed:
        print("\n" + "=" * 80)
        print("✅ ALL STEPS PASSED!")
        print("=" * 80)
    else:
        print("\n" + "=" * 80)
        print("❌ SOME STEPS FAILED")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
