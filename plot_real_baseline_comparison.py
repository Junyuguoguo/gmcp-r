# -*- coding: utf-8 -*-
# plot_real_baseline_comparison.py
#
# 绘制真实Baseline对比实验图表
# 分开统计：正常性能 vs 攻击检测

import csv
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

OUTPUT_DIR = "results/real_baseline_comparison"
CSV_FILE = os.path.join(OUTPUT_DIR, "real_baseline_comparison_results.csv")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")

# 配色方案（Okabe-Ito色盲安全）
COLORS = {
    "gmcp_r": "#E69F00",
    "hash_chain": "#56B4E9",
    "seq_mac": "#009E73",
    "ticket_only": "#F0E442",
}


def ensure_figures_dir():
    os.makedirs(FIGURES_DIR, exist_ok=True)


def load_results():
    results = []
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key in ["message_count", "payload_size", "repeat_id", "sent_count", 
                        "accepted_count", "rejected_count", "timeout_count", "error_count"]:
                if key in row:
                    try:
                        row[key] = int(row[key])
                    except:
                        row[key] = 0
            for key in ["success_rate", "throughput_msg_per_sec", "rtt_mean_ms",
                        "rtt_std_ms", "rtt_min_ms", "rtt_max_ms", "rtt_median_ms",
                        "elapsed_seconds"]:
                if key in row:
                    try:
                        row[key] = float(row[key])
                    except:
                        row[key] = 0.0
            for key in ["attack_injected", "attack_detected_by_server"]:
                if key in row:
                    row[key] = row[key] == "True"
            results.append(row)
    return results


def plot_normal_performance(results):
    """绘制正常通信性能（只统计attack_type=none）"""
    normal_results = [r for r in results if r["attack_type"] == "none"]
    protocols = sorted(set(r["protocol"] for r in normal_results))
    
    # 计算每个协议的平均性能
    throughputs = {}
    rtts = {}
    for protocol in protocols:
        proto_results = [r for r in normal_results if r["protocol"] == protocol]
        throughputs[protocol] = [r["throughput_msg_per_sec"] for r in proto_results]
        rtts[protocol] = [r["rtt_mean_ms"] for r in proto_results]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # 吞吐量
    means = [np.mean(throughputs[p]) for p in protocols]
    stds = [np.std(throughputs[p]) for p in protocols]
    bars = ax1.bar(protocols, means, yerr=stds, capsize=5,
                   color=[COLORS.get(p, "#999999") for p in protocols],
                   edgecolor='black', linewidth=0.5)
    ax1.set_ylabel('Throughput (msg/s)', fontsize=12)
    ax1.set_title('Normal Communication: Throughput', fontsize=14, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    # RTT
    means = [np.mean(rtts[p]) for p in protocols]
    stds = [np.std(rtts[p]) for p in protocols]
    bars = ax2.bar(protocols, means, yerr=stds, capsize=5,
                   color=[COLORS.get(p, "#999999") for p in protocols],
                   edgecolor='black', linewidth=0.5)
    ax2.set_ylabel('RTT (ms)', fontsize=12)
    ax2.set_title('Normal Communication: RTT', fontsize=14, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "baseline_fig1_normal_performance.png"), dpi=600)
    plt.close()
    print("[PLOT] Saved baseline_fig1_normal_performance.png")


def plot_attack_detection_rate(results):
    """绘制攻击检测率（只统计attack_type!=none）"""
    attack_results = [r for r in results if r["attack_type"] != "none"]
    protocols = sorted(set(r["protocol"] for r in attack_results))
    attack_types = sorted(set(r["attack_type"] for r in attack_results))
    
    # 计算每个协议对每种攻击的检测率
    detection_data = defaultdict(lambda: defaultdict(list))
    for r in attack_results:
        protocol = r["protocol"]
        attack = r["attack_type"]
        detected = r.get("attack_detected_by_server", False)
        detection_data[protocol][attack].append(detected)
    
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(attack_types))
    width = 0.2
    
    for i, protocol in enumerate(protocols):
        detection_rates = []
        for attack in attack_types:
            if detection_data[protocol][attack]:
                rate = sum(detection_data[protocol][attack]) / len(detection_data[protocol][attack]) * 100
                detection_rates.append(rate)
            else:
                detection_rates.append(0)
        
        offset = (i - len(protocols)/2 + 0.5) * width
        bars = ax.bar(x + offset, detection_rates, width,
                      label=protocol, color=COLORS.get(protocol, "#999999"),
                      edgecolor='black', linewidth=0.5)
    
    ax.set_xlabel('Attack Type', fontsize=12)
    ax.set_ylabel('Detection Rate (%)', fontsize=12)
    ax.set_title('Attack Detection Rate by Protocol (Server-side)', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(attack_types)
    ax.legend(loc='best')
    ax.grid(axis='y', alpha=0.3)
    ax.set_ylim(0, 110)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "baseline_fig2_attack_detection.png"), dpi=600)
    plt.close()
    print("[PLOT] Saved baseline_fig2_attack_detection.png")


def plot_false_accept_reject(results):
    """绘制误接受率和误拒绝率"""
    attack_results = [r for r in results if r["attack_type"] != "none"]
    normal_results = [r for r in results if r["attack_type"] == "none"]
    protocols = sorted(set(r["protocol"] for r in results))
    
    # 计算误接受率（攻击被接受）和误拒绝率（正常被拒绝）
    false_accept = {}
    false_reject = {}
    
    for protocol in protocols:
        # 误接受率：攻击注入但服务端未检测到的比例
        proto_attack = [r for r in attack_results if r["protocol"] == protocol]
        if proto_attack:
            undetected = sum(1 for r in proto_attack if r.get("attack_injected", False) and not r.get("attack_detected_by_server", False))
            false_accept[protocol] = undetected / len(proto_attack) * 100
        else:
            false_accept[protocol] = 0
        
        # 误拒绝率：正常场景下被拒绝的比例
        proto_normal = [r for r in normal_results if r["protocol"] == protocol]
        if proto_normal:
            rejected_when_normal = sum(1 for r in proto_normal if r["rejected_count"] > 0)
            false_reject[protocol] = rejected_when_normal / len(proto_normal) * 100
        else:
            false_reject[protocol] = 0
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(protocols))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, [false_accept[p] for p in protocols], width,
                   label='False Accept Rate', color='#E74C3C', edgecolor='black', linewidth=0.5)
    bars2 = ax.bar(x + width/2, [false_reject[p] for p in protocols], width,
                   label='False Reject Rate', color='#3498DB', edgecolor='black', linewidth=0.5)
    
    ax.set_xlabel('Protocol', fontsize=12)
    ax.set_ylabel('Rate (%)', fontsize=12)
    ax.set_title('False Accept and False Reject Rates', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(protocols)
    ax.legend(loc='best')
    ax.grid(axis='y', alpha=0.3)
    ax.set_ylim(0, 110)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "baseline_fig3_false_rates.png"), dpi=600)
    plt.close()
    print("[PLOT] Saved baseline_fig3_false_rates.png")


def generate_summary_table(results):
    """生成分开统计的汇总表格"""
    protocols = sorted(set(r["protocol"] for r in results))
    
    normal_results = [r for r in results if r["attack_type"] == "none"]
    attack_results = [r for r in results if r["attack_type"] != "none"]
    
    summary = []
    for protocol in protocols:
        # 正常性能
        proto_normal = [r for r in normal_results if r["protocol"] == protocol]
        normal_throughput = np.mean([r["throughput_msg_per_sec"] for r in proto_normal]) if proto_normal else 0
        normal_rtt = np.mean([r["rtt_mean_ms"] for r in proto_normal]) if proto_normal else 0
        
        # 攻击检测
        proto_attack = [r for r in attack_results if r["protocol"] == protocol]
        if proto_attack:
            detected = sum(1 for r in proto_attack if r.get("attack_detected_by_server", False))
            detection_rate = detected / len(proto_attack) * 100
        else:
            detection_rate = 0
        
        # 误接受率：攻击注入但服务端未检测到的比例
        if proto_attack:
            undetected = sum(1 for r in proto_attack if r.get("attack_injected", False) and not r.get("attack_detected_by_server", False))
            false_accept = undetected / len(proto_attack) * 100
        else:
            false_accept = 0
        
        # 误拒绝率
        if proto_normal:
            false_reject = sum(1 for r in proto_normal if r["rejected_count"] > 0) / len(proto_normal) * 100
        else:
            false_reject = 0
        
        summary.append({
            "protocol": protocol,
            "normal_throughput": round(normal_throughput, 0),
            "normal_rtt": round(normal_rtt, 3),
            "attack_detection_rate": round(detection_rate, 1),
            "false_accept_rate": round(false_accept, 1),
            "false_reject_rate": round(false_reject, 1),
        })
    
    # 保存为CSV
    summary_file = os.path.join(OUTPUT_DIR, "summary_real_baseline_comparison_v2.csv")
    with open(summary_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["protocol", "normal_throughput", "normal_rtt",
                      "attack_detection_rate", "false_accept_rate", "false_reject_rate"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow(row)
    
    print(f"[SUMMARY] Saved to {summary_file}")
    
    # 打印表格
    print("\n" + "="*100)
    print("Summary Table (Separated Statistics)")
    print("="*100)
    print(f"{'Protocol':<15} {'Normal TP':<12} {'Normal RTT':<12} {'Detect%':<12} {'FalseAccept%':<14} {'FalseReject%':<14}")
    print("-"*100)
    for row in summary:
        print(f"{row['protocol']:<15} "
              f"{row['normal_throughput']:.0f} msg/s  "
              f"{row['normal_rtt']:.3f} ms    "
              f"{row['attack_detection_rate']:.1f}%      "
              f"{row['false_accept_rate']:.1f}%          "
              f"{row['false_reject_rate']:.1f}%")
    print("="*100)


def main():
    ensure_figures_dir()
    results = load_results()
    
    print(f"[INFO] Loaded {len(results)} experiment results")
    
    plot_normal_performance(results)
    plot_attack_detection_rate(results)
    plot_false_accept_reject(results)
    generate_summary_table(results)
    
    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
