# -*- coding: utf-8 -*-
# plot_ticket_recovery_results.py
#
# 绘制MemoryTicket恢复实验结果图表

import csv
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

OUTPUT_DIR = "results/real_ticket_recovery"
CSV_FILE = os.path.join(OUTPUT_DIR, "real_ticket_recovery_results.csv")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")


def ensure_figures_dir():
    os.makedirs(FIGURES_DIR, exist_ok=True)


def load_results():
    results = []
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 转换数值字段
            for key in ["message_count", "payload_size", "repeat_id", "sent_count", 
                        "accepted_count", "rejected_count", "timeout_count",
                        "recovery_extra_messages", "recovery_extra_bytes",
                        "final_server_last_seq"]:
                if key in row:
                    row[key] = int(row[key])
            for key in ["recovery_latency_ms", "elapsed_seconds"]:
                if key in row:
                    row[key] = float(row[key])
            for key in ["attack_detected", "recovery_requested", "recovery_success",
                        "memory_match_after_recovery", "ticket_verified", 
                        "ticket_expired", "ticket_replay_detected"]:
                if key in row:
                    row[key] = row[key] == "True"
            results.append(row)
    return results


def plot_recovery_success_by_attack(results):
    """绘制不同攻击类型的恢复成功率"""
    attack_types = sorted(set(r["attack_type"] for r in results))
    success_counts = defaultdict(int)
    total_counts = defaultdict(int)
    
    for r in results:
        attack = r["attack_type"]
        total_counts[attack] += 1
        if r["recovery_success"]:
            success_counts[attack] += 1
    
    success_rates = [success_counts[a] / total_counts[a] * 100 for a in attack_types]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(attack_types, success_rates, color=['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#3498db'])
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Recovery Success Rate (%)', fontsize=12)
    ax.set_title('MemoryTicket Recovery Success Rate by Attack Type', fontsize=14)
    ax.set_ylim(0, 110)
    
    # 添加数值标签
    for bar, rate in zip(bars, success_rates):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{rate:.1f}%', ha='center', va='bottom', fontsize=10)
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "ticket_fig1_recovery_success_by_attack.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved ticket_fig1_recovery_success_by_attack.png")


def plot_ticket_verification_results(results):
    """绘制ticket验证结果"""
    attack_types = sorted(set(r["attack_type"] for r in results))
    
    verified_counts = defaultdict(int)
    expired_counts = defaultdict(int)
    replay_counts = defaultdict(int)
    total_counts = defaultdict(int)
    
    for r in results:
        attack = r["attack_type"]
        total_counts[attack] += 1
        if r["ticket_verified"]:
            verified_counts[attack] += 1
        if r["ticket_expired"]:
            expired_counts[attack] += 1
        if r["ticket_replay_detected"]:
            replay_counts[attack] += 1
    
    x = np.arange(len(attack_types))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    verified_rates = [verified_counts[a] / total_counts[a] * 100 for a in attack_types]
    expired_rates = [expired_counts[a] / total_counts[a] * 100 for a in attack_types]
    replay_rates = [replay_counts[a] / total_counts[a] * 100 for a in attack_types]
    
    bars1 = ax.bar(x - width, verified_rates, width, label='Verified', color='#2ecc71')
    bars2 = ax.bar(x, expired_rates, width, label='Expired', color='#e74c3c')
    bars3 = ax.bar(x + width, replay_rates, width, label='Replay Detected', color='#f39c12')
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Rate (%)', fontsize=12)
    ax.set_title('MemoryTicket Verification Results', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(attack_types, rotation=45, ha='right')
    ax.legend()
    ax.set_ylim(0, 110)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "ticket_fig2_verification_results.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved ticket_fig2_verification_results.png")


def plot_recovery_latency(results):
    """绘制恢复延迟"""
    attack_types = sorted(set(r["attack_type"] for r in results))
    
    latencies = defaultdict(list)
    for r in results:
        if r["recovery_success"]:
            latencies[r["attack_type"]].append(r["recovery_latency_ms"])
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    data = [latencies[a] for a in attack_types]
    bp = ax.boxplot(data, patch_artist=True)
    
    colors = ['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#3498db']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Recovery Latency (ms)', fontsize=12)
    ax.set_title('Recovery Latency Distribution by Attack Type', fontsize=14)
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "ticket_fig3_recovery_latency.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved ticket_fig3_recovery_latency.png")


def plot_memory_match_after_recovery(results):
    """绘制恢复后记忆一致性"""
    attack_types = sorted(set(r["attack_type"] for r in results))
    
    match_counts = defaultdict(int)
    total_counts = defaultdict(int)
    
    for r in results:
        attack = r["attack_type"]
        total_counts[attack] += 1
        if r["memory_match_after_recovery"]:
            match_counts[attack] += 1
    
    match_rates = [match_counts[a] / total_counts[a] * 100 for a in attack_types]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(attack_types, match_rates, color=['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#3498db'])
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Memory Match Rate (%)', fontsize=12)
    ax.set_title('Memory Consistency After Recovery', fontsize=14)
    ax.set_ylim(0, 110)
    
    for bar, rate in zip(bars, match_rates):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{rate:.1f}%', ha='center', va='bottom', fontsize=10)
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "ticket_fig4_memory_match_after_recovery.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved ticket_fig4_memory_match_after_recovery.png")


def main():
    ensure_figures_dir()
    results = load_results()
    
    print(f"[INFO] Loaded {len(results)} experiment results")
    
    plot_recovery_success_by_attack(results)
    plot_ticket_verification_results(results)
    plot_recovery_latency(results)
    plot_memory_match_after_recovery(results)
    
    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
