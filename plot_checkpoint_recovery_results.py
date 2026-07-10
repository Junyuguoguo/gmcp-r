# -*- coding: utf-8 -*-
# plot_checkpoint_recovery_results.py
#
# 绘制Checkpoint恢复实验结果图表

import csv
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

OUTPUT_DIR = "results/checkpoint_recovery"
CSV_FILE = os.path.join(OUTPUT_DIR, "checkpoint_recovery_results.csv")
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
                        "checkpoint_count", "replay_count", "checkpoint_seq",
                        "final_server_last_seq"]:
                if key in row:
                    try:
                        row[key] = int(row[key])
                    except:
                        row[key] = 0
            for key in ["recovery_latency_ms", "elapsed_seconds"]:
                if key in row:
                    try:
                        row[key] = float(row[key])
                    except:
                        row[key] = 0.0
            for key in ["attack_detected", "recovery_requested", "recovery_success",
                        "memory_match_after_recovery"]:
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
    bars = ax.bar(attack_types, success_rates, color=['#2ecc71', '#e74c3c', '#f39c12'])
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Recovery Success Rate (%)', fontsize=12)
    ax.set_title('Checkpoint Recovery Success Rate by Attack Type', fontsize=14)
    ax.set_ylim(0, 110)
    
    for bar, rate in zip(bars, success_rates):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{rate:.1f}%', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "checkpoint_fig1_recovery_success.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved checkpoint_fig1_recovery_success.png")


def plot_checkpoint_count_by_message_count(results):
    """绘制不同消息数量下的checkpoint数量"""
    message_counts = sorted(set(r["message_count"] for r in results))
    
    checkpoint_counts = defaultdict(list)
    for r in results:
        checkpoint_counts[r["message_count"]].append(r["checkpoint_count"])
    
    avg_checkpoint_counts = [float(np.mean(checkpoint_counts[m])) for m in message_counts]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar([str(m) for m in message_counts], avg_checkpoint_counts, color='#3498db')
    
    ax.set_xlabel('Message Count', fontsize=12)
    ax.set_ylabel('Average Checkpoint Count', fontsize=12)
    ax.set_title('Checkpoint Count vs Message Count', fontsize=14)
    
    for bar, count in zip(bars, avg_checkpoint_counts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{count:.1f}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "checkpoint_fig2_checkpoint_count.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved checkpoint_fig2_checkpoint_count.png")


def plot_replay_count_by_attack(results):
    """绘制不同攻击类型下的重放消息数"""
    attack_types = sorted(set(r["attack_type"] for r in results))
    
    replay_counts = defaultdict(list)
    for r in results:
        if r["recovery_success"]:
            replay_counts[r["attack_type"]].append(r["replay_count"])
    
    avg_replay_counts = [np.mean(replay_counts[a]) if replay_counts[a] else 0 for a in attack_types]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(attack_types, avg_replay_counts, color=['#2ecc71', '#e74c3c', '#f39c12'])
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Average Replay Count', fontsize=12)
    ax.set_title('Replay Count by Attack Type', fontsize=14)
    
    for bar, count in zip(bars, avg_replay_counts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                f'{count:.1f}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "checkpoint_fig3_replay_count.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved checkpoint_fig3_replay_count.png")


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
    
    colors = ['#2ecc71', '#e74c3c', '#f39c12']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Recovery Latency (ms)', fontsize=12)
    ax.set_title('Recovery Latency Distribution by Attack Type', fontsize=14)
    
    # 添加x轴标签
    ax.set_xticks(range(1, len(attack_types) + 1))
    ax.set_xticklabels(attack_types)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "checkpoint_fig4_recovery_latency.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved checkpoint_fig4_recovery_latency.png")


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
    bars = ax.bar(attack_types, match_rates, color=['#2ecc71', '#e74c3c', '#f39c12'])
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Memory Match Rate (%)', fontsize=12)
    ax.set_title('Memory Consistency After Checkpoint Recovery', fontsize=14)
    ax.set_ylim(0, 110)
    
    for bar, rate in zip(bars, match_rates):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{rate:.1f}%', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "checkpoint_fig5_memory_match.png"), dpi=150)
    plt.close()
    print(f"[PLOT] Saved checkpoint_fig5_memory_match.png")


def main():
    ensure_figures_dir()
    results = load_results()
    
    print(f"[INFO] Loaded {len(results)} experiment results")
    
    plot_recovery_success_by_attack(results)
    plot_checkpoint_count_by_message_count(results)
    plot_replay_count_by_attack(results)
    plot_recovery_latency(results)
    plot_memory_match_after_recovery(results)
    
    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
