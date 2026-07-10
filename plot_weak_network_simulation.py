# -*- coding: utf-8 -*-
# plot_weak_network_simulation.py
#
# 绘制弱网仿真实验结果图表

import csv
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

OUTPUT_DIR = "results/weak_network_simulation"
CSV_FILE = os.path.join(OUTPUT_DIR, "weak_network_simulation_results.csv")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")

# 配色方案
COLORS = {
    "gmcp_r": "#E69F00",
    "hash_chain": "#56B4E9",
    "seq_mac": "#009E73",
}

MARKERS = {
    "gmcp_r": "o",
    "hash_chain": "s",
    "seq_mac": "^",
}


def ensure_figures_dir():
    os.makedirs(FIGURES_DIR, exist_ok=True)


def load_results():
    results = []
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key in ["loss_rate", "delay_ms", "reorder_rate", "message_count", 
                        "payload_size", "repeat_id", "sent_count", "accepted_count",
                        "rejected_count", "timeout_count", "dropped_count"]:
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
            results.append(row)
    return results


def plot_success_rate_vs_loss_rate(results):
    """绘制成功率随丢包率变化"""
    protocols = sorted(set(r["protocol"] for r in results))
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for protocol in protocols:
        success_rates = []
        for loss in loss_rates:
            protocol_loss_results = [r for r in results 
                                    if r["protocol"] == protocol and r["loss_rate"] == loss]
            if protocol_loss_results:
                avg_success = np.mean([r["success_rate"] for r in protocol_loss_results])
                success_rates.append(avg_success)
            else:
                success_rates.append(0)
        
        ax.plot(loss_rates, success_rates, marker=MARKERS.get(protocol, "o"),
                label=protocol, color=COLORS.get(protocol, "#999999"),
                linewidth=2, markersize=8)
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12)
    ax.set_ylabel('Success Rate (%)', fontsize=12)
    ax.set_title('Success Rate vs Loss Rate', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 105)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "weaknet_fig1_success_vs_loss.png"), dpi=600)
    plt.close()
    print(f"[PLOT] Saved weaknet_fig1_success_vs_loss.png")


def plot_success_rate_vs_delay(results):
    """绘制成功率随延迟变化"""
    protocols = sorted(set(r["protocol"] for r in results))
    delays = sorted(set(r["delay_ms"] for r in results))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for protocol in protocols:
        success_rates = []
        for delay in delays:
            protocol_delay_results = [r for r in results 
                                     if r["protocol"] == protocol and r["delay_ms"] == delay]
            if protocol_delay_results:
                avg_success = np.mean([r["success_rate"] for r in protocol_delay_results])
                success_rates.append(avg_success)
            else:
                success_rates.append(0)
        
        ax.plot(delays, success_rates, marker=MARKERS.get(protocol, "o"),
                label=protocol, color=COLORS.get(protocol, "#999999"),
                linewidth=2, markersize=8)
    
    ax.set_xlabel('Delay (ms)', fontsize=12)
    ax.set_ylabel('Success Rate (%)', fontsize=12)
    ax.set_title('Success Rate vs Network Delay', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 105)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "weaknet_fig2_success_vs_delay.png"), dpi=600)
    plt.close()
    print(f"[PLOT] Saved weaknet_fig2_success_vs_delay.png")


def plot_throughput_vs_loss_rate(results):
    """绘制吞吐量随丢包率变化"""
    protocols = sorted(set(r["protocol"] for r in results))
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for protocol in protocols:
        throughputs = []
        for loss in loss_rates:
            protocol_loss_results = [r for r in results 
                                    if r["protocol"] == protocol and r["loss_rate"] == loss]
            if protocol_loss_results:
                avg_throughput = np.mean([r["throughput_msg_per_sec"] for r in protocol_loss_results])
                throughputs.append(avg_throughput)
            else:
                throughputs.append(0)
        
        ax.plot(loss_rates, throughputs, marker=MARKERS.get(protocol, "o"),
                label=protocol, color=COLORS.get(protocol, "#999999"),
                linewidth=2, markersize=8)
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12)
    ax.set_ylabel('Throughput (msg/s)', fontsize=12)
    ax.set_title('Throughput vs Loss Rate', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "weaknet_fig3_throughput_vs_loss.png"), dpi=600)
    plt.close()
    print(f"[PLOT] Saved weaknet_fig3_throughput_vs_loss.png")


def plot_throughput_vs_delay(results):
    """绘制吞吐量随延迟变化"""
    protocols = sorted(set(r["protocol"] for r in results))
    delays = sorted(set(r["delay_ms"] for r in results))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for protocol in protocols:
        throughputs = []
        for delay in delays:
            protocol_delay_results = [r for r in results 
                                     if r["protocol"] == protocol and r["delay_ms"] == delay]
            if protocol_delay_results:
                avg_throughput = np.mean([r["throughput_msg_per_sec"] for r in protocol_delay_results])
                throughputs.append(avg_throughput)
            else:
                throughputs.append(0)
        
        ax.plot(delays, throughputs, marker=MARKERS.get(protocol, "o"),
                label=protocol, color=COLORS.get(protocol, "#999999"),
                linewidth=2, markersize=8)
    
    ax.set_xlabel('Delay (ms)', fontsize=12)
    ax.set_ylabel('Throughput (msg/s)', fontsize=12)
    ax.set_title('Throughput vs Network Delay', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "weaknet_fig4_throughput_vs_delay.png"), dpi=600)
    plt.close()
    print(f"[PLOT] Saved weaknet_fig4_throughput_vs_delay.png")


def plot_rtt_vs_loss_rate(results):
    """绘制RTT随丢包率变化"""
    protocols = sorted(set(r["protocol"] for r in results))
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for protocol in protocols:
        rtts = []
        for loss in loss_rates:
            protocol_loss_results = [r for r in results 
                                    if r["protocol"] == protocol and r["loss_rate"] == loss]
            if protocol_loss_results:
                avg_rtt = np.mean([r["rtt_mean_ms"] for r in protocol_loss_results])
                rtts.append(avg_rtt)
            else:
                rtts.append(0)
        
        ax.plot(loss_rates, rtts, marker=MARKERS.get(protocol, "o"),
                label=protocol, color=COLORS.get(protocol, "#999999"),
                linewidth=2, markersize=8)
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12)
    ax.set_ylabel('RTT (ms)', fontsize=12)
    ax.set_title('RTT vs Loss Rate', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "weaknet_fig5_rtt_vs_loss.png"), dpi=600)
    plt.close()
    print(f"[PLOT] Saved weaknet_fig5_rtt_vs_loss.png")


def plot_success_rate_heatmap(results):
    """绘制成功率热力图（丢包率 vs 延迟）"""
    protocols = sorted(set(r["protocol"] for r in results))
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    delays = sorted(set(r["delay_ms"] for r in results))
    
    for protocol in protocols:
        # 构建数据矩阵
        data = np.zeros((len(loss_rates), len(delays)))
        count = np.zeros_like(data)
        
        for r in results:
            if r["protocol"] == protocol:
                i = loss_rates.index(r["loss_rate"])
                j = delays.index(r["delay_ms"])
                data[i][j] += r["success_rate"]
                count[i][j] += 1
        
        with np.errstate(divide='ignore', invalid='ignore'):
            avg_data = np.where(count > 0, data / count, 0)
        
        fig, ax = plt.subplots(figsize=(10, 8))
        im = ax.imshow(avg_data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
        
        ax.set_xticks(np.arange(len(delays)))
        ax.set_yticks(np.arange(len(loss_rates)))
        ax.set_xticklabels([f"{d}ms" for d in delays])
        ax.set_yticklabels([f"{l}%" for l in loss_rates])
        
        ax.set_xlabel('Delay', fontsize=12)
        ax.set_ylabel('Loss Rate', fontsize=12)
        ax.set_title(f'Success Rate Heatmap - {protocol}', fontsize=14, fontweight='bold')
        
        # 添加数值标签
        for i in range(len(loss_rates)):
            for j in range(len(delays)):
                text = ax.text(j, i, f'{avg_data[i][j]:.1f}%',
                              ha="center", va="center", color="black", fontsize=9)
        
        plt.colorbar(im, label='Success Rate (%)')
        plt.tight_layout()
        plt.savefig(os.path.join(FIGURES_DIR, f"weaknet_fig6_heatmap_{protocol}.png"), dpi=600)
        plt.close()
        print(f"[PLOT] Saved weaknet_fig6_heatmap_{protocol}.png")


def generate_summary_table(results):
    """生成汇总表格"""
    protocols = sorted(set(r["protocol"] for r in results))
    
    summary = []
    for protocol in protocols:
        protocol_results = [r for r in results if r["protocol"] == protocol]
        
        if not protocol_results:
            continue
        
        success_rates = [r["success_rate"] for r in protocol_results]
        throughputs = [r["throughput_msg_per_sec"] for r in protocol_results]
        rtts = [r["rtt_mean_ms"] for r in protocol_results if r["rtt_mean_ms"] > 0]
        
        summary.append({
            "protocol": protocol,
            "success_rate_mean": np.mean(success_rates),
            "success_rate_std": np.std(success_rates),
            "throughput_mean": np.mean(throughputs),
            "throughput_std": np.std(throughputs),
            "rtt_mean": np.mean(rtts) if rtts else 0,
            "rtt_std": np.std(rtts) if rtts else 0,
        })
    
    # 保存为CSV
    summary_file = os.path.join(OUTPUT_DIR, "summary_weak_network_simulation.csv")
    with open(summary_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["protocol", "success_rate_mean", "success_rate_std",
                      "throughput_mean", "throughput_std", "rtt_mean", "rtt_std"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow(row)
    
    print(f"[SUMMARY] Saved to {summary_file}")
    
    # 打印表格
    print("\n" + "="*80)
    print("Summary Table")
    print("="*80)
    print(f"{'Protocol':<15} {'Success%':<15} {'Throughput':<15} {'RTT(ms)':<15}")
    print("-"*80)
    for row in summary:
        print(f"{row['protocol']:<15} "
              f"{row['success_rate_mean']:.1f}±{row['success_rate_std']:.1f}  "
              f"{row['throughput_mean']:.0f}±{row['throughput_std']:.0f}  "
              f"{row['rtt_mean']:.1f}±{row['rtt_std']:.1f}")
    print("="*80)


def main():
    ensure_figures_dir()
    results = load_results()
    
    print(f"[INFO] Loaded {len(results)} experiment results")
    
    plot_success_rate_vs_loss_rate(results)
    plot_success_rate_vs_delay(results)
    plot_throughput_vs_loss_rate(results)
    plot_throughput_vs_delay(results)
    plot_rtt_vs_loss_rate(results)
    plot_success_rate_heatmap(results)
    generate_summary_table(results)
    
    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
