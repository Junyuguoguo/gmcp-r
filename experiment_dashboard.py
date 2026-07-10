#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMCP-R Protocol: Experiment Dashboard

Real-time monitoring dashboard for all experiments.
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime
from typing import Dict, List, Any

# Add project path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def get_experiment_status() -> Dict[str, Any]:
    """Get status of all experiments"""
    status = {}
    
    # Check baseline experiment
    baseline_log = "/tmp/baseline_experiment.log"
    if os.path.exists(baseline_log):
        with open(baseline_log, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                if "[" in last_line and "/" in last_line:
                    try:
                        progress = last_line.split("]")[0].split("[")[1]
                        current, total = progress.split("/")
                        percentage = int(current) / int(total) * 100
                        status["baseline"] = {
                            "current": int(current),
                            "total": int(total),
                            "percentage": round(percentage, 1),
                            "status": "running" if percentage < 100 else "completed"
                        }
                    except:
                        status["baseline"] = {"status": "error"}
    
    # Check if baseline process is running
    try:
        result = subprocess.run(
            ["pgrep", "-f", "run_real_baseline_comparison.py"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            status["baseline"]["pid"] = result.stdout.strip()
        else:
            status["baseline"]["status"] = "not_running"
    except:
        pass
    
    return status

def get_system_resources() -> Dict[str, Any]:
    """Get system resource usage"""
    resources = {}
    
    try:
        # CPU usage
        result = subprocess.run(["top", "-l", "1"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "CPU usage" in line:
                resources["cpu"] = line.split(":")[-1].strip()
                break
        
        # Memory usage
        result = subprocess.run(["vm_stat"], capture_output=True, text=True)
        resources["memory"] = "Available"
        
    except:
        resources["error"] = "Could not get system resources"
    
    return resources

def get_csv_status() -> Dict[str, Any]:
    """Get status of CSV files"""
    csv_status = {}
    
    csv_files = [
        ("baseline", "results/real_baseline_comparison/real_baseline_comparison_results.csv"),
        ("ticket_recovery", "results/real_ticket_recovery/real_ticket_recovery_results.csv"),
        ("checkpoint", "results/checkpoint_recovery/checkpoint_recovery_results.csv"),
    ]
    
    for name, path in csv_files:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    lines = f.readlines()
                    csv_status[name] = {
                        "rows": len(lines) - 1,  # Exclude header
                        "size_kb": os.path.getsize(path) / 1024,
                        "last_modified": datetime.fromtimestamp(
                            os.path.getmtime(path)
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    }
            except:
                csv_status[name] = {"status": "error"}
        else:
            csv_status[name] = {"status": "not_found"}
    
    return csv_status

def print_dashboard():
    """Print experiment dashboard"""
    print("=" * 80)
    print("GMCP-R Protocol: Experiment Dashboard")
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Experiment Status
    print("📊 Experiment Status:")
    print("-" * 40)
    
    status = get_experiment_status()
    if "baseline" in status:
        baseline = status["baseline"]
        if "percentage" in baseline:
            print(f"  Baseline Comparison: {baseline['percentage']}%")
            print(f"    Progress: {baseline['current']}/{baseline['total']}")
            print(f"    Status: {baseline['status']}")
        else:
            print(f"  Baseline Comparison: {baseline.get('status', 'unknown')}")
    else:
        print("  Baseline Comparison: not started")
    
    print()
    
    # System Resources
    print("💻 System Resources:")
    print("-" * 40)
    
    resources = get_system_resources()
    if "cpu" in resources:
        print(f"  CPU: {resources['cpu']}")
    if "memory" in resources:
        print(f"  Memory: {resources['memory']}")
    
    print()
    
    # CSV Status
    print("📁 Data Files:")
    print("-" * 40)
    
    csv_status = get_csv_status()
    for name, info in csv_status.items():
        if "rows" in info:
            print(f"  {name}: {info['rows']} rows, {info['size_kb']:.1f} KB")
        else:
            print(f"  {name}: {info.get('status', 'unknown')}")
    
    print()
    
    # Next Steps
    print("🎯 Next Steps:")
    print("-" * 40)
    
    if "baseline" in status and status["baseline"].get("percentage", 0) >= 100:
        print("  ✅ Baseline experiment completed")
        print("  → Generate charts: python3 plot_real_baseline_comparison.py")
        print("  → Start weak network experiment")
    else:
        print("  → Wait for baseline experiment to complete")
        print("  → Prepare weak network experiment")
    
    print()
    print("=" * 80)

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--watch":
        # Watch mode: refresh every 10 seconds
        while True:
            os.system("clear")
            print_dashboard()
            time.sleep(10)
    else:
        # Single print
        print_dashboard()

if __name__ == "__main__":
    main()
