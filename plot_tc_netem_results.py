# -*- coding: utf-8 -*-
# plot_tc_netem_results.py
#
# 绘制 tc/netem 弱网实验结果图表
# 支持多种可视化：柱状图、热力图、箱线图、散点图

import csv
import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional
from scipy import stats

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

OUTPUT_DIR = "results/tc_netem"
CSV_FILE = os.path.join(OUTPUT_DIR, "tc_netem_results.csv")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")

# 颜色方案
COLORS = {
    'primary': '#3498db',
    'success': '#2ecc71',
    'danger': '#e74c3c',
    'warning': '#f39c12',
    'purple': '#9b59b6',
    'teal': '#1abc9c',
    'dark': '#34495e',
    'light': '#ecf0f1',
}

# 配色方案（用于多系列）
COLOR_PALETTE = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e']


def ensure_figures_dir():
    """确保图表目录存在"""
    os.makedirs(FIGURES_DIR, exist_ok=True)


def load_results() -> List[Dict[str, Any]]:
    """加载实验结果"""
    results = []
    
    if not os.path.exists(CSV_FILE):
        print(f"[ERROR] CSV file not found: {CSV_FILE}")
        print("[INFO] Please run run_real_tc_netem_experiment.py first")
        sys.exit(1)
    
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 转换数值字段
            int_fields = [
                "loss_rate", "delay_ms", "reorder_rate", "message_count", 
                "payload_size", "repeat_id", "sent_count", "accepted_count",
                "rejected_count", "timeout_count", "error_count"
            ]
            float_fields = [
                "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
                "avg_rtt_ms", "min_rtt_ms", "max_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms"
            ]
            
            for key in int_fields:
                if key in row:
                    try:
                        row[key] = int(row[key])
                    except:
                        row[key] = 0
            
            for key in float_fields:
                if key in row:
                    try:
                        row[key] = float(row[key])
                    except:
                        row[key] = 0.0
            
            results.append(row)
    
    return results


def calculate_ci95(values: List[float]) -> Tuple[Any, float, float]:
    """计算均值和95%置信区间"""
    if not values:
        return 0.0, 0.0, 0.0
    arr = np.array(values, dtype=float)
    n = len(arr)
    mean: float = float(np.mean(arr))
    if n < 2:
        return mean, 0.0, 0.0
    std: float = float(np.std(arr, ddof=1))
    ci: float = float(stats.t.ppf(0.975, n - 1) * std / np.sqrt(n))
    return mean, ci, std


def aggregate_by_param(results: List[Dict], param: str, metric: str) -> Dict[int, List[float]]:
    """按参数聚合指标"""
    data = defaultdict(list)
    for r in results:
        data[r[param]].append(r[metric])
    return data


# =========================
# 单因素分析图表
# =========================

def plot_success_rate_by_loss_rate(results: List[Dict]):
    """绘制不同丢包率下的成功率"""
    data = aggregate_by_param(results, "loss_rate", "success_rate")
    loss_rates = sorted(data.keys())
    
    means = []
    cis = []
    for l in loss_rates:
        mean, ci, _ = calculate_ci95(data[l])
        means.append(mean)
        cis.append(ci)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(l) + "%" for l in loss_rates], 
        means, 
        yerr=cis,
        color=COLORS['primary'],
        capsize=5,
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Success Rate vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean, ci in zip(bars, means, cis):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + ci + 2,
                f'{mean:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig1_success_rate_by_loss.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig1_success_rate_by_loss.png")


def plot_success_rate_by_delay(results: List[Dict]):
    """绘制不同延迟下的成功率"""
    data = aggregate_by_param(results, "delay_ms", "success_rate")
    delays = sorted(data.keys())
    
    means = []
    cis = []
    for d in delays:
        mean, ci, _ = calculate_ci95(data[d])
        means.append(mean)
        cis.append(ci)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(d) + "ms" for d in delays], 
        means, 
        yerr=cis,
        color=COLORS['success'],
        capsize=5,
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Network Delay (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Success Rate vs Network Delay', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean, ci in zip(bars, means, cis):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + ci + 2,
                f'{mean:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig2_success_rate_by_delay.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig2_success_rate_by_delay.png")


def plot_success_rate_by_reorder(results: List[Dict]):
    """绘制不同乱序率下的成功率"""
    data = aggregate_by_param(results, "reorder_rate", "success_rate")
    reorder_rates = sorted(data.keys())
    
    means = []
    cis = []
    for r in reorder_rates:
        mean, ci, _ = calculate_ci95(data[r])
        means.append(mean)
        cis.append(ci)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(r) + "%" for r in reorder_rates], 
        means, 
        yerr=cis,
        color=COLORS['warning'],
        capsize=5,
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Reorder Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Success Rate vs Packet Reorder Rate', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean, ci in zip(bars, means, cis):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + ci + 2,
                f'{mean:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig3_success_rate_by_reorder.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig3_success_rate_by_reorder.png")


# =========================
# 吞吐量分析图表
# =========================

def plot_throughput_by_loss_rate(results: List[Dict]):
    """绘制不同丢包率下的吞吐量"""
    data = aggregate_by_param(results, "loss_rate", "throughput_msg_per_sec")
    loss_rates = sorted(data.keys())
    
    means = []
    cis = []
    for l in loss_rates:
        mean, ci, _ = calculate_ci95(data[l])
        means.append(mean)
        cis.append(ci)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(l) + "%" for l in loss_rates], 
        means, 
        yerr=cis,
        color=COLORS['danger'],
        capsize=5,
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Throughput (msg/s)', fontsize=12, fontweight='bold')
    ax.set_title('Throughput vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean, ci in zip(bars, means, cis):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + ci + 0.5,
                f'{mean:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig4_throughput_by_loss.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig4_throughput_by_loss.png")


def plot_throughput_by_delay(results: List[Dict]):
    """绘制不同延迟下的吞吐量"""
    data = aggregate_by_param(results, "delay_ms", "throughput_msg_per_sec")
    delays = sorted(data.keys())
    
    means = []
    cis = []
    for d in delays:
        mean, ci, _ = calculate_ci95(data[d])
        means.append(mean)
        cis.append(ci)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(d) + "ms" for d in delays], 
        means, 
        yerr=cis,
        color=COLORS['warning'],
        capsize=5,
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Network Delay (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Throughput (msg/s)', fontsize=12, fontweight='bold')
    ax.set_title('Throughput vs Network Delay', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean, ci in zip(bars, means, cis):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + ci + 0.5,
                f'{mean:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig5_throughput_by_delay.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig5_throughput_by_delay.png")


# =========================
# RTT 分析图表
# =========================

def plot_rtt_by_loss_rate(results: List[Dict]):
    """绘制不同丢包率下的 RTT 分布（箱线图）"""
    data = aggregate_by_param(results, "loss_rate", "avg_rtt_ms")
    loss_rates = sorted(data.keys())
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    box_data = [data[l] for l in loss_rates]
    bp = ax.boxplot(
        box_data,
        tick_labels=[str(l) + "%" for l in loss_rates],
        patch_artist=True,
        boxprops=dict(facecolor=COLORS['primary'], alpha=0.7),
        whiskerprops=dict(color=COLORS['dark']),
        capprops=dict(color=COLORS['dark']),
        medianprops=dict(color=COLORS['danger'], linewidth=2),
        flierprops=dict(marker='o', markerfacecolor=COLORS['danger'], markersize=5, alpha=0.5)
    )
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Average RTT (ms)', fontsize=12, fontweight='bold')
    ax.set_title('RTT Distribution vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig6_rtt_by_loss.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig6_rtt_by_loss.png")


def plot_rtt_by_delay(results: List[Dict]):
    """绘制不同延迟下的 RTT 分布（箱线图）"""
    data = aggregate_by_param(results, "delay_ms", "avg_rtt_ms")
    delays = sorted(data.keys())
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    box_data = [data[d] for d in delays]
    bp = ax.boxplot(
        box_data,
        tick_labels=[str(d) + "ms" for d in delays],
        patch_artist=True,
        boxprops=dict(facecolor=COLORS['success'], alpha=0.7),
        whiskerprops=dict(color=COLORS['dark']),
        capprops=dict(color=COLORS['dark']),
        medianprops=dict(color=COLORS['danger'], linewidth=2),
        flierprops=dict(marker='o', markerfacecolor=COLORS['danger'], markersize=5, alpha=0.5)
    )
    
    ax.set_xlabel('Network Delay (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Average RTT (ms)', fontsize=12, fontweight='bold')
    ax.set_title('RTT Distribution vs Network Delay', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig7_rtt_by_delay.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig7_rtt_by_delay.png")


def plot_rtt_percentiles_by_loss(results: List[Dict]):
    """绘制不同丢包率下的 RTT 百分位数"""
    data = defaultdict(lambda: defaultdict(list))
    for r in results:
        data[r['loss_rate']]['p50'].append(r['p50_rtt_ms'])
        data[r['loss_rate']]['p95'].append(r['p95_rtt_ms'])
        data[r['loss_rate']]['p99'].append(r['p99_rtt_ms'])
    
    loss_rates = sorted(data.keys())
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(loss_rates))
    width = 0.25
    
    p50_means = [np.mean(data[l]['p50']) for l in loss_rates]
    p95_means = [np.mean(data[l]['p95']) for l in loss_rates]
    p99_means = [np.mean(data[l]['p99']) for l in loss_rates]
    
    ax.bar(x - width, p50_means, width, label='P50', color=COLORS['primary'], alpha=0.85)
    ax.bar(x, p95_means, width, label='P95', color=COLORS['warning'], alpha=0.85)
    ax.bar(x + width, p99_means, width, label='P99', color=COLORS['danger'], alpha=0.85)
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('RTT (ms)', fontsize=12, fontweight='bold')
    ax.set_title('RTT Percentiles vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([str(l) + "%" for l in loss_rates])
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig8_rtt_percentiles_by_loss.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig8_rtt_percentiles_by_loss.png")


# =========================
# 热力图
# =========================

def plot_success_rate_heatmap(results: List[Dict]):
    """绘制丢包率和延迟对成功率的热力图"""
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    delays = sorted(set(r["delay_ms"] for r in results))
    
    # 构建数据矩阵
    data = np.zeros((len(loss_rates), len(delays)))
    count = np.zeros((len(loss_rates), len(delays)))
    
    for r in results:
        i = loss_rates.index(r["loss_rate"])
        j = delays.index(r["delay_ms"])
        data[i][j] += r["success_rate"]
        count[i][j] += 1
    
    # 计算平均值
    with np.errstate(divide='ignore', invalid='ignore'):
        avg_data = np.where(count > 0, data / count, 0)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(avg_data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
    
    ax.set_xticks(np.arange(len(delays)))
    ax.set_yticks(np.arange(len(loss_rates)))
    ax.set_xticklabels([str(d) + "ms" for d in delays])
    ax.set_yticklabels([str(l) + "%" for l in loss_rates])
    
    ax.set_xlabel('Network Delay (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Success Rate Heatmap (Loss Rate vs Delay)', fontsize=14, fontweight='bold')
    
    # 添加数值标签
    for i in range(len(loss_rates)):
        for j in range(len(delays)):
            text = ax.text(j, i, f'{avg_data[i][j]:.1f}%',
                          ha="center", va="center", color="black", fontsize=9, fontweight='bold')
    
    plt.colorbar(im, label='Success Rate (%)')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig9_success_rate_heatmap.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig9_success_rate_heatmap.png")


def plot_throughput_heatmap(results: List[Dict]):
    """绘制丢包率和延迟对吞吐量的热力图"""
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    delays = sorted(set(r["delay_ms"] for r in results))
    
    # 构建数据矩阵
    data = np.zeros((len(loss_rates), len(delays)))
    count = np.zeros((len(loss_rates), len(delays)))
    
    for r in results:
        i = loss_rates.index(r["loss_rate"])
        j = delays.index(r["delay_ms"])
        data[i][j] += r["throughput_msg_per_sec"]
        count[i][j] += 1
    
    # 计算平均值
    with np.errstate(divide='ignore', invalid='ignore'):
        avg_data = np.where(count > 0, data / count, 0)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(avg_data, cmap='YlOrRd', aspect='auto')
    
    ax.set_xticks(np.arange(len(delays)))
    ax.set_yticks(np.arange(len(loss_rates)))
    ax.set_xticklabels([str(d) + "ms" for d in delays])
    ax.set_yticklabels([str(l) + "%" for l in loss_rates])
    
    ax.set_xlabel('Network Delay (ms)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Throughput Heatmap (Loss Rate vs Delay)', fontsize=14, fontweight='bold')
    
    # 添加数值标签
    for i in range(len(loss_rates)):
        for j in range(len(delays)):
            text = ax.text(j, i, f'{avg_data[i][j]:.1f}',
                          ha="center", va="center", color="black", fontsize=9, fontweight='bold')
    
    plt.colorbar(im, label='Throughput (msg/s)')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig10_throughput_heatmap.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig10_throughput_heatmap.png")


# =========================
# 综合分析图表
# =========================

def plot_comprehensive_summary(results: List[Dict]):
    """绘制综合分析摘要（2x2 子图）"""
    fig = plt.figure(figsize=(16, 12))
    gs = gridspec.GridSpec(2, 2, hspace=0.3, wspace=0.3)
    
    # 子图1：成功率 vs 丢包率
    ax1 = fig.add_subplot(gs[0, 0])
    data1 = aggregate_by_param(results, "loss_rate", "success_rate")
    loss_rates = sorted(data1.keys())
    means1 = [np.mean(data1[l]) for l in loss_rates]
    ax1.bar([str(l) + "%" for l in loss_rates], means1, color=COLORS['primary'], alpha=0.85)
    ax1.set_xlabel('Loss Rate (%)', fontsize=10)
    ax1.set_ylabel('Success Rate (%)', fontsize=10)
    ax1.set_title('(a) Success Rate vs Loss Rate', fontsize=11, fontweight='bold')
    ax1.set_ylim(0, 110)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    
    # 子图2：成功率 vs 延迟
    ax2 = fig.add_subplot(gs[0, 1])
    data2 = aggregate_by_param(results, "delay_ms", "success_rate")
    delays = sorted(data2.keys())
    means2 = [np.mean(data2[d]) for d in delays]
    ax2.bar([str(d) + "ms" for d in delays], means2, color=COLORS['success'], alpha=0.85)
    ax2.set_xlabel('Network Delay (ms)', fontsize=10)
    ax2.set_ylabel('Success Rate (%)', fontsize=10)
    ax2.set_title('(b) Success Rate vs Delay', fontsize=11, fontweight='bold')
    ax2.set_ylim(0, 110)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')
    
    # 子图3：吞吐量 vs 丢包率
    ax3 = fig.add_subplot(gs[1, 0])
    data3 = aggregate_by_param(results, "loss_rate", "throughput_msg_per_sec")
    means3 = [np.mean(data3[l]) for l in loss_rates]
    ax3.bar([str(l) + "%" for l in loss_rates], means3, color=COLORS['danger'], alpha=0.85)
    ax3.set_xlabel('Loss Rate (%)', fontsize=10)
    ax3.set_ylabel('Throughput (msg/s)', fontsize=10)
    ax3.set_title('(c) Throughput vs Loss Rate', fontsize=11, fontweight='bold')
    ax3.grid(axis='y', alpha=0.3, linestyle='--')
    
    # 子图4：RTT vs 丢包率
    ax4 = fig.add_subplot(gs[1, 1])
    data4 = aggregate_by_param(results, "loss_rate", "avg_rtt_ms")
    means4 = [np.mean(data4[l]) for l in loss_rates]
    ax4.bar([str(l) + "%" for l in loss_rates], means4, color=COLORS['purple'], alpha=0.85)
    ax4.set_xlabel('Loss Rate (%)', fontsize=10)
    ax4.set_ylabel('Average RTT (ms)', fontsize=10)
    ax4.set_title('(d) RTT vs Loss Rate', fontsize=11, fontweight='bold')
    ax4.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.suptitle('tc/netem Weak Network Experiment Summary', fontsize=16, fontweight='bold', y=1.02)
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig11_comprehensive_summary.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig11_comprehensive_summary.png")


def plot_timeout_analysis(results: List[Dict]):
    """绘制超时分析"""
    data = aggregate_by_param(results, "loss_rate", "timeout_count")
    loss_rates = sorted(data.keys())
    
    means = []
    for l in loss_rates:
        means.append(np.mean(data[l]))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        [str(l) + "%" for l in loss_rates], 
        means, 
        color=COLORS['purple'],
        alpha=0.85,
        edgecolor='white',
        linewidth=1.5
    )
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Average Timeout Count', fontsize=12, fontweight='bold')
    ax.set_title('Timeout Count vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    for bar, mean in zip(bars, means):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                f'{mean:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig12_timeout_analysis.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig12_timeout_analysis.png")


def plot_scatter_success_vs_throughput(results: List[Dict]):
    """绘制成功率 vs 吞吐量散点图"""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # 按丢包率着色
    loss_rates = sorted(set(r["loss_rate"] for r in results))
    colors = plt.cm.RdYlGn_r(np.linspace(0, 1, len(loss_rates)))
    
    for i, loss_rate in enumerate(loss_rates):
        subset = [r for r in results if r["loss_rate"] == loss_rate]
        x = [r["success_rate"] for r in subset]
        y = [r["throughput_msg_per_sec"] for r in subset]
        ax.scatter(x, y, c=[colors[i]], label=f'Loss {loss_rate}%', alpha=0.6, s=50, edgecolors='white', linewidth=0.5)
    
    ax.set_xlabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Throughput (msg/s)', fontsize=12, fontweight='bold')
    ax.set_title('Success Rate vs Throughput (colored by Loss Rate)', fontsize=14, fontweight='bold')
    ax.legend(fontsize=10, title='Loss Rate', title_fontsize=11)
    ax.grid(alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig13_scatter_success_vs_throughput.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig13_scatter_success_vs_throughput.png")


def plot_error_analysis(results: List[Dict]):
    """绘制错误分析（拒绝、超时、错误）"""
    data_reject = aggregate_by_param(results, "loss_rate", "rejected_count")
    data_timeout = aggregate_by_param(results, "loss_rate", "timeout_count")
    data_error = aggregate_by_param(results, "loss_rate", "error_count")
    
    loss_rates = sorted(data_reject.keys())
    
    means_reject = [np.mean(data_reject[l]) for l in loss_rates]
    means_timeout = [np.mean(data_timeout[l]) for l in loss_rates]
    means_error = [np.mean(data_error[l]) for l in loss_rates]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(loss_rates))
    width = 0.25
    
    ax.bar(x - width, means_reject, width, label='Rejected', color=COLORS['danger'], alpha=0.85)
    ax.bar(x, means_timeout, width, label='Timeout', color=COLORS['warning'], alpha=0.85)
    ax.bar(x + width, means_error, width, label='Error', color=COLORS['purple'], alpha=0.85)
    
    ax.set_xlabel('Loss Rate (%)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Average Count', fontsize=12, fontweight='bold')
    ax.set_title('Error Analysis vs Packet Loss Rate', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([str(l) + "%" for l in loss_rates])
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "tc_fig14_error_analysis.png"), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] Saved tc_fig14_error_analysis.png")


# =========================
# 主函数
# =========================

def generate_summary_table(results: List[Dict]) -> str:
    """生成汇总表格"""
    lines = []
    lines.append("=" * 80)
    lines.append("tc/netem Weak Network Experiment Summary")
    lines.append("=" * 80)
    lines.append("")
    
    # 按丢包率汇总
    lines.append("By Loss Rate:")
    lines.append("-" * 60)
    lines.append(f"{'Loss Rate':<12} {'Success%':<12} {'Throughput':<12} {'Avg RTT':<12} {'Timeouts':<12}")
    lines.append("-" * 60)
    
    data_success = aggregate_by_param(results, "loss_rate", "success_rate")
    data_throughput = aggregate_by_param(results, "loss_rate", "throughput_msg_per_sec")
    data_rtt = aggregate_by_param(results, "loss_rate", "avg_rtt_ms")
    data_timeout = aggregate_by_param(results, "loss_rate", "timeout_count")
    
    for loss_rate in sorted(data_success.keys()):
        mean_success = np.mean(data_success[loss_rate])
        mean_throughput = np.mean(data_throughput[loss_rate])
        mean_rtt = np.mean(data_rtt[loss_rate])
        mean_timeout = np.mean(data_timeout[loss_rate])
        lines.append(f"{loss_rate}%{'':<10} {mean_success:<12.2f} {mean_throughput:<12.2f} {mean_rtt:<12.2f} {mean_timeout:<12.2f}")
    
    lines.append("")
    
    # 按延迟汇总
    lines.append("By Delay:")
    lines.append("-" * 60)
    lines.append(f"{'Delay':<12} {'Success%':<12} {'Throughput':<12} {'Avg RTT':<12} {'Timeouts':<12}")
    lines.append("-" * 60)
    
    data_success_d = aggregate_by_param(results, "delay_ms", "success_rate")
    data_throughput_d = aggregate_by_param(results, "delay_ms", "throughput_msg_per_sec")
    data_rtt_d = aggregate_by_param(results, "delay_ms", "avg_rtt_ms")
    data_timeout_d = aggregate_by_param(results, "delay_ms", "timeout_count")
    
    for delay in sorted(data_success_d.keys()):
        mean_success = np.mean(data_success_d[delay])
        mean_throughput = np.mean(data_throughput_d[delay])
        mean_rtt = np.mean(data_rtt_d[delay])
        mean_timeout = np.mean(data_timeout_d[delay])
        lines.append(f"{delay}ms{'':<8} {mean_success:<12.2f} {mean_throughput:<12.2f} {mean_rtt:<12.2f} {mean_timeout:<12.2f}")
    
    lines.append("")
    lines.append(f"Total experiments: {len(results)}")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def main():
    """主函数"""
    ensure_figures_dir()
    results = load_results()
    
    print(f"[INFO] Loaded {len(results)} experiment results")
    print(f"[INFO] Output directory: {FIGURES_DIR}")
    print()
    
    # 生成汇总表格
    summary = generate_summary_table(results)
    print(summary)
    
    # 保存汇总到文件
    summary_file = os.path.join(OUTPUT_DIR, "summary.txt")
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(summary)
    print(f"\n[INFO] Summary saved to {summary_file}")
    
    # 生成图表
    print("\n[INFO] Generating plots...")
    
    # 单因素分析
    plot_success_rate_by_loss_rate(results)
    plot_success_rate_by_delay(results)
    plot_success_rate_by_reorder(results)
    
    # 吞吐量分析
    plot_throughput_by_loss_rate(results)
    plot_throughput_by_delay(results)
    
    # RTT 分析
    plot_rtt_by_loss_rate(results)
    plot_rtt_by_delay(results)
    plot_rtt_percentiles_by_loss(results)
    
    # 热力图
    plot_success_rate_heatmap(results)
    plot_throughput_heatmap(results)
    
    # 综合分析
    plot_comprehensive_summary(results)
    plot_timeout_analysis(results)
    plot_scatter_success_vs_throughput(results)
    plot_error_analysis(results)
    
    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")
    print(f"[INFO] Total plots generated: 14")


if __name__ == "__main__":
    main()
