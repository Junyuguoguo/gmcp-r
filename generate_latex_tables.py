#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMCP-R Protocol: Generate LaTeX Tables

Generate publication-ready LaTeX tables from experiment results.
"""

import csv
import os
import sys
from typing import Dict, List, Any
from collections import defaultdict

# Add project path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def load_csv(filepath: str) -> List[Dict[str, Any]]:
    """Load CSV file"""
    results = []
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(row)
    return results

def generate_detection_rate_table():
    """Generate attack detection rate table"""
    filepath = "results/real_baseline_comparison/real_baseline_comparison_results.csv"
    results = load_csv(filepath)
    
    if not results:
        return "% No data available\n"
    
    # Calculate detection rates
    protocols = sorted(set(r.get("protocol", "") for r in results))
    attack_types = sorted(set(r.get("attack_type", "") for r in results 
                            if r.get("attack_type") != "none"))
    
    detection_data = defaultdict(lambda: defaultdict(list))
    for r in results:
        protocol = r.get("protocol", "")
        attack = r.get("attack_type", "")
        if attack != "none":
            detected = r.get("attack_detected", "False") == "True"
            detection_data[protocol][attack].append(detected)
    
    # Generate LaTeX
    latex = []
    latex.append("\\begin{table}[t]")
    latex.append("\\centering")
    latex.append("\\caption{Attack Detection Rates}")
    latex.append("\\begin{tabular}{l" + "c" * len(attack_types) + "}")
    latex.append("\\toprule")
    latex.append("Protocol & " + " & ".join(attack_types) + " \\\\")
    latex.append("\\midrule")
    
    for protocol in protocols:
        row = [protocol]
        for attack in attack_types:
            if detection_data[protocol][attack]:
                rate = sum(detection_data[protocol][attack]) / len(detection_data[protocol][attack]) * 100
                row.append(f"{rate:.0f}\\%")
            else:
                row.append("N/A")
        latex.append(" & ".join(row) + " \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\label{tab:detection_rates}")
    latex.append("\\end{table}")
    
    return "\n".join(latex)

def generate_performance_table():
    """Generate performance comparison table"""
    filepath = "results/real_baseline_comparison/summary_real_baseline_comparison.csv"
    results = load_csv(filepath)
    
    if not results:
        return "% No data available\n"
    
    # Generate LaTeX
    latex = []
    latex.append("\\begin{table}[t]")
    latex.append("\\centering")
    latex.append("\\caption{Performance Comparison}")
    latex.append("\\begin{tabular}{lcccc}")
    latex.append("\\toprule")
    latex.append("Protocol & Success (\\%) & Throughput (msg/s) & RTT (ms) & Detection (\\%) \\\\")
    latex.append("\\midrule")
    
    for r in results:
        protocol = r.get("protocol", "")
        success = float(r.get("success_rate_mean", 0))
        throughput = float(r.get("throughput_mean", 0))
        rtt = float(r.get("rtt_mean", 0))
        detection = float(r.get("detection_rate", 0))
        
        latex.append(f"{protocol} & {success:.1f} & {throughput:.0f} & {rtt:.2f} & {detection:.0f} \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\label{tab:performance}")
    latex.append("\\end{table}")
    
    return "\n".join(latex)

def generate_confidence_interval_table():
    """Generate confidence interval table"""
    filepath = "results/real_baseline_comparison/summary_real_baseline_comparison.csv"
    results = load_csv(filepath)
    
    if not results:
        return "% No data available\n"
    
    # Generate LaTeX
    latex = []
    latex.append("\\begin{table}[t]")
    latex.append("\\centering")
    latex.append("\\caption{Performance Metrics with 95\\% Confidence Intervals}")
    latex.append("\\begin{tabular}{lccc}")
    latex.append("\\toprule")
    latex.append("Protocol & Throughput (msg/s) & RTT (ms) & Success (\\%) \\\\")
    latex.append("\\midrule")
    
    for r in results:
        protocol = r.get("protocol", "")
        
        # Throughput
        t_mean = float(r.get("throughput_mean", 0))
        t_std = float(r.get("throughput_std", 0))
        t_ci = 1.96 * t_std / 30  # 95% CI with n=30
        
        # RTT
        r_mean = float(r.get("rtt_mean", 0))
        r_std = float(r.get("rtt_std", 0))
        r_ci = 1.96 * r_std / 30
        
        # Success
        s_mean = float(r.get("success_rate_mean", 0))
        s_std = float(r.get("success_rate_std", 0))
        s_ci = 1.96 * s_std / 30
        
        latex.append(f"{protocol} & {t_mean:.0f} $\\pm$ {t_ci:.0f} & "
                    f"{r_mean:.2f} $\\pm$ {r_ci:.2f} & "
                    f"{s_mean:.1f} $\\pm$ {s_ci:.1f} \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\label{tab:confidence_intervals}")
    latex.append("\\end{table}")
    
    return "\n".join(latex)

def main():
    """Main function"""
    output_dir = "paper/tables"
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate tables
    tables = {
        "detection_rates": generate_detection_rate_table(),
        "performance": generate_performance_table(),
        "confidence_intervals": generate_confidence_interval_table(),
    }
    
    # Save to files
    for name, latex in tables.items():
        filepath = os.path.join(output_dir, f"{name}.tex")
        with open(filepath, "w") as f:
            f.write(latex)
        print(f"[TABLE] Saved {filepath}")
    
    # Print combined output
    print("\n" + "=" * 80)
    print("Generated LaTeX Tables")
    print("=" * 80)
    
    for name, latex in tables.items():
        print(f"\n--- {name} ---")
        print(latex)
        print()

if __name__ == "__main__":
    main()
