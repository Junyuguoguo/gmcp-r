# -*- coding: utf-8 -*-
# plot_performance_results.py
#
# 绘制性能基准测试结果图表
# 使用 academic-figures 风格（Okabe-Ito 色盲安全配色）

import csv
import json
import os
import sys
from collections import defaultdict
from typing import Dict, Any, List

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.plot_style import (
    setup_chinese_academic_style,
    ACADEMIC_COLORS,
    PROTOCOL_LABELS,
    style_axes,
    localize_value,
)

# ─────────────────────────────────────────
# 路径
# ─────────────────────────────────────────

OUTPUT_DIR = "results/performance"
RESULTS_CSV = os.path.join(OUTPUT_DIR, "performance_benchmark_results.csv")
RTT_CSV = os.path.join(OUTPUT_DIR, "rtt_distribution.csv")
RESOURCE_JSON = os.path.join(OUTPUT_DIR, "resource_stats.json")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")

# 协议配色（Okabe-Ito 色盲安全）
PROTOCOL_COLORS = {
    "gmcp_r": "#E69F00",      # 橙色
    "hash_chain": "#56B4E9",   # 天蓝色
    "seq_mac": "#009E73",      # 绿色
    "ticket_only": "#CC79A7",  # 粉色
}

PROTOCOL_MARKERS = {
    "gmcp_r": "o",
    "hash_chain": "s",
    "seq_mac": "^",
    "ticket_only": "D",
}


# ─────────────────────────────────────────
# 数据加载
# ─────────────────────────────────────────

def load_results(csv_path: str = RESULTS_CSV) -> List[Dict[str, Any]]:
    """加载基准测试结果 CSV"""
    if not os.path.exists(csv_path):
        print(f"[WARN] CSV not found: {csv_path}")
        return []

    results = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 转换数值
            for key in ["msg_count", "payload_size", "repeat_id", "accepted",
                        "rejected", "errors", "window_size"]:
                if key in row:
                    try:
                        row[key] = int(row[key])
                    except (ValueError, KeyError):
                        row[key] = 0
            for key in row:
                if key not in ("mode", "protocol", "repeat_id"):
                    try:
                        row[key] = float(row[key])
                    except (ValueError, KeyError):
                        pass
            results.append(row)
    return results


def load_rtt_distribution(csv_path: str = RTT_CSV) -> List[Dict[str, Any]]:
    """加载 RTT 分布数据"""
    if not os.path.exists(csv_path):
        return []

    data = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                row["payload_size"] = int(row["payload_size"])
                row["repeat_id"] = int(row["repeat_id"])
                row["seq"] = int(row["seq"])
                row["rtt_ms"] = float(row["rtt_ms"])
            except (ValueError, KeyError):
                continue
            data.append(row)
    return data


def load_resource_stats(json_path: str = RESOURCE_JSON) -> Dict[str, Any]:
    """加载资源统计 JSON"""
    if not os.path.exists(json_path):
        return {}
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────
# 图 1: 吞吐量对比（本地模式）
# ─────────────────────────────────────────

def plot_throughput_local(results: List[Dict[str, Any]]):
    """本地模式下各协议吞吐量对比"""
    setup_chinese_academic_style()

    local_results = [r for r in results if r.get("mode") == "local"]
    if not local_results:
        print("[SKIP] No local results for throughput plot")
        return

    # 按 payload_size 分组，取 repeat_id=1 的数据
    payload_sizes = sorted(set(r["payload_size"] for r in local_results))
    protocols = sorted(set(r["protocol"] for r in local_results))

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(payload_sizes))
    width = 0.18
    offsets = np.arange(len(protocols)) - (len(protocols) - 1) / 2

    for i, protocol in enumerate(protocols):
        throughputs = []
        for ps in payload_sizes:
            vals = [r["throughput_msg_per_sec"]
                    for r in local_results
                    if r["protocol"] == protocol and r["payload_size"] == ps]
            throughputs.append(np.mean(vals) if vals else 0)

        color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
        label = PROTOCOL_LABELS.get(protocol, protocol)
        bars = ax.bar(x + offsets[i] * width, throughputs, width,
                      label=label, color=color, edgecolor="#2D3748",
                      linewidth=0.5, alpha=0.9)

    ax.set_xlabel("消息大小 (bytes)")
    ax.set_ylabel("吞吐量 (msg/s)")
    ax.set_title("本地基准：不同消息大小下的吞吐量")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(ps)) for ps in payload_sizes])
    ax.legend(frameon=False)
    style_axes(ax)

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "throughput_local.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 图 2: 吞吐量随消息大小变化趋势（折线图）
# ─────────────────────────────────────────

def plot_throughput_vs_size(results: List[Dict[str, Any]]):
    """吞吐量随消息大小变化趋势"""
    setup_chinese_academic_style()

    local_results = [r for r in results if r.get("mode") == "local"]
    if not local_results:
        print("[SKIP] No local results for throughput trend plot")
        return

    payload_sizes = sorted(set(r["payload_size"] for r in local_results))
    protocols = sorted(set(r["protocol"] for r in local_results))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 左图：构建耗时
    for i, protocol in enumerate(protocols):
        build_means = []
        build_stds = []
        for ps in payload_sizes:
            vals = [r["build_mean_us"]
                    for r in local_results
                    if r["protocol"] == protocol and r["payload_size"] == ps]
            build_means.append(np.mean(vals) if vals else 0)
            build_stds.append(np.std(vals) if len(vals) > 1 else 0)

        color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
        marker = PROTOCOL_MARKERS.get(protocol, "o")
        label = PROTOCOL_LABELS.get(protocol, protocol)
        ax1.errorbar(payload_sizes, build_means, yerr=build_stds,
                     label=label, color=color, marker=marker,
                     linewidth=2, markersize=6, capsize=3)

    ax1.set_xlabel("消息大小 (bytes)")
    ax1.set_ylabel("构建耗时 (μs)")
    ax1.set_title("构建耗时 vs 消息大小")
    ax1.legend(frameon=False)
    style_axes(ax1)

    # 右图：验证耗时
    for i, protocol in enumerate(protocols):
        verify_means = []
        verify_stds = []
        for ps in payload_sizes:
            vals = [r["verify_mean_us"]
                    for r in local_results
                    if r["protocol"] == protocol and r["payload_size"] == ps]
            verify_means.append(np.mean(vals) if vals else 0)
            verify_stds.append(np.std(vals) if len(vals) > 1 else 0)

        color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
        marker = PROTOCOL_MARKERS.get(protocol, "o")
        label = PROTOCOL_LABELS.get(protocol, protocol)
        ax2.errorbar(payload_sizes, verify_means, yerr=verify_stds,
                     label=label, color=color, marker=marker,
                     linewidth=2, markersize=6, capsize=3)

    ax2.set_xlabel("消息大小 (bytes)")
    ax2.set_ylabel("验证耗时 (μs)")
    ax2.set_title("验证耗时 vs 消息大小")
    ax2.legend(frameon=False)
    style_axes(ax2)

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "latency_vs_msg_size.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 图 3: RTT 分布（网络模式）
# ─────────────────────────────────────────

def plot_rtt_distribution(results: List[Dict[str, Any]]):
    """网络模式下 RTT 分布箱线图 + CDF"""
    setup_chinese_academic_style()

    net_results = [r for r in results if r.get("mode") == "network"]
    if not net_results:
        print("[SKIP] No network results for RTT plot")
        return

    protocols = sorted(set(r["protocol"] for r in net_results))

    # ── 箱线图 ──
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 百分位数对比
    percentiles = ["rtt_p50_ms", "rtt_p95_ms", "rtt_p99_ms"]
    percentile_labels = ["P50", "P95", "P99"]

    x = np.arange(len(percentiles))
    width = 0.18
    offsets = np.arange(len(protocols)) - (len(protocols) - 1) / 2

    for i, protocol in enumerate(protocols):
        pvals = []
        for pkey in percentiles:
            vals = [r[pkey] for r in net_results if r["protocol"] == protocol]
            pvals.append(np.mean(vals) if vals else 0)

        color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
        label = PROTOCOL_LABELS.get(protocol, protocol)
        ax1.bar(x + offsets[i] * width, pvals, width,
                label=label, color=color, edgecolor="#2D3748",
                linewidth=0.5, alpha=0.9)

    ax1.set_xlabel("百分位数")
    ax1.set_ylabel("RTT (ms)")
    ax1.set_title("网络延迟百分位数对比")
    ax1.set_xticks(x)
    ax1.set_xticklabels(percentile_labels)
    ax1.legend(frameon=False)
    style_axes(ax1)

    # ── CDF 图 ──
    rtt_data = load_rtt_distribution()
    if rtt_data:
        # 按协议分组
        rtt_by_protocol = defaultdict(list)
        for row in rtt_data:
            rtt_by_protocol[row["protocol"]].append(row["rtt_ms"])

        for i, protocol in enumerate(protocols):
            values = sorted(rtt_by_protocol.get(protocol, []))
            if not values:
                continue
            cdf = np.arange(1, len(values) + 1) / len(values)
            color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
            label = PROTOCOL_LABELS.get(protocol, protocol)
            ax2.plot(values, cdf, label=label, color=color, linewidth=2)

        ax2.set_xlabel("RTT (ms)")
        ax2.set_ylabel("CDF")
        ax2.set_title("RTT 累积分布函数 (CDF)")
        ax2.legend(frameon=False)
        ax2.set_xlim(left=0)
        ax2.set_ylim(0, 1.02)
        style_axes(ax2)
    else:
        # 用汇总统计画近似 CDF
        for i, protocol in enumerate(protocols):
            mean_vals = [r["rtt_mean_ms"] for r in net_results if r["protocol"] == protocol]
            if mean_vals:
                color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
                label = PROTOCOL_LABELS.get(protocol, protocol)
                ax2.axvline(np.mean(mean_vals), color=color, linestyle="--",
                            linewidth=2, label=f"{label} mean={np.mean(mean_vals):.2f}ms")

        ax2.set_xlabel("RTT (ms)")
        ax2.set_ylabel("")
        ax2.set_title("RTT 均值对比")
        ax2.legend(frameon=False)
        style_axes(ax2)

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "rtt_distribution.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 图 4: 端到端延迟百分位数对比（本地模式）
# ─────────────────────────────────────────

def plot_e2e_latency_percentiles(results: List[Dict[str, Any]]):
    """本地模式下端到端延迟百分位数热力图"""
    setup_chinese_academic_style()

    local_results = [r for r in results if r.get("mode") == "local"]
    if not local_results:
        return

    protocols = sorted(set(r["protocol"] for r in local_results))
    payload_sizes = sorted(set(r["payload_size"] for r in local_results))

    fig, axes = plt.subplots(1, 3, figsize=(16, 5), sharey=True)
    metrics = [
        ("e2e_p50_us", "P50 端到端延迟 (μs)"),
        ("e2e_p95_us", "P95 端到端延迟 (μs)"),
        ("e2e_p99_us", "P99 端到端延迟 (μs)"),
    ]

    for ax_idx, (metric_key, title) in enumerate(metrics):
        ax = axes[ax_idx]
        x = np.arange(len(payload_sizes))
        width = 0.18
        offsets = np.arange(len(protocols)) - (len(protocols) - 1) / 2

        for i, protocol in enumerate(protocols):
            vals = []
            for ps in payload_sizes:
                metric_vals = [r[metric_key]
                               for r in local_results
                               if r["protocol"] == protocol and r["payload_size"] == ps]
                vals.append(np.mean(metric_vals) if metric_vals else 0)

            color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
            label = PROTOCOL_LABELS.get(protocol, protocol)
            ax.bar(x + offsets[i] * width, vals, width,
                   label=label, color=color, edgecolor="#2D3748",
                   linewidth=0.5, alpha=0.9)

        ax.set_xlabel("消息大小 (bytes)")
        ax.set_ylabel("延迟 (μs)")
        ax.set_title(title)
        ax.set_xticks(x)
        ax.set_xticklabels([str(int(ps)) for ps in payload_sizes])
        if ax_idx == 0:
            ax.legend(frameon=False, fontsize=8)
        style_axes(ax)

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "e2e_latency_percentiles.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 图 5: 资源消耗概览
# ─────────────────────────────────────────

def plot_resource_usage(stats: Dict[str, Any]):
    """资源消耗概览图"""
    setup_chinese_academic_style()

    if not stats:
        print("[SKIP] No resource stats for resource plot")
        return

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # CPU
    cpu_keys = ["proc_cpu_pct_p50", "proc_cpu_pct_p95", "proc_cpu_pct_p99"]
    cpu_labels = ["P50", "P95", "P99"]
    cpu_vals = [stats.get(k, 0) for k in cpu_keys]

    axes[0].bar(cpu_labels, cpu_vals, color=ACADEMIC_COLORS[:3],
                edgecolor="#2D3748", linewidth=0.5)
    axes[0].set_ylabel("CPU 使用率 (%)")
    axes[0].set_title("进程 CPU 使用率百分位数")
    for i, v in enumerate(cpu_vals):
        axes[0].text(i, v + 0.5, f"{v:.1f}%", ha="center", fontsize=9)
    style_axes(axes[0])

    # Memory
    mem_keys = ["rss_mb_p50", "rss_mb_p95", "rss_mb_p99"]
    mem_labels = ["P50", "P95", "P99"]
    mem_vals = [stats.get(k, 0) for k in mem_keys]

    axes[1].bar(mem_labels, mem_vals, color=ACADEMIC_COLORS[:3],
                edgecolor="#2D3748", linewidth=0.5)
    axes[1].set_ylabel("RSS 内存 (MB)")
    axes[1].set_title("驻留内存百分位数")
    for i, v in enumerate(mem_vals):
        axes[1].text(i, v + 0.2, f"{v:.1f}MB", ha="center", fontsize=9)
    style_axes(axes[1])

    # Network
    net_labels = ["发送", "接收"]
    net_vals = [stats.get("total_mb_sent", 0), stats.get("total_mb_recv", 0)]

    axes[2].bar(net_labels, net_vals, color=[ACADEMIC_COLORS[0], ACADEMIC_COLORS[1]],
                edgecolor="#2D3748", linewidth=0.5)
    axes[2].set_ylabel("数据量 (MB)")
    axes[2].set_title("网络流量")
    for i, v in enumerate(net_vals):
        axes[2].text(i, v + 0.05, f"{v:.2f}MB", ha="center", fontsize=9)
    style_axes(axes[2])

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "resource_usage.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 图 6: 综合性能雷达图
# ─────────────────────────────────────────

def plot_performance_radar(results: List[Dict[str, Any]]):
    """综合性能雷达图（仅本地模式）"""
    setup_chinese_academic_style()

    local_results = [r for r in results if r.get("mode") == "local"]
    if not local_results:
        return

    protocols = sorted(set(r["protocol"] for r in local_results))

    # 取 payload_size=256 的结果
    base_results = [r for r in local_results if r["payload_size"] == 256]
    if not base_results:
        return

    # 指标：吞吐量、构建P50、验证P50、e2e P99
    metrics = ["throughput_msg_per_sec", "build_p50_us", "verify_p50_us", "e2e_p99_us"]
    metric_labels = ["吞吐量\n(msg/s)", "构建P50\n(μs)", "验证P50\n(μs)", "e2e P99\n(μs)"]

    # 归一化到 [0, 1]
    raw = {}
    for protocol in protocols:
        vals = []
        for m in metrics:
            mvals = [r[m] for r in base_results if r["protocol"] == protocol]
            vals.append(np.mean(mvals) if mvals else 0)
        raw[protocol] = vals

    # 归一化：吞吐量越大越好，延迟越小越好
    normalized = {}
    for j, m in enumerate(metrics):
        all_vals = [raw[p][j] for p in protocols]
        min_v = min(all_vals) if all_vals else 0
        max_v = max(all_vals) if all_vals else 1
        rng = max_v - min_v if max_v != min_v else 1
        for p in protocols:
            if p not in normalized:
                normalized[p] = [0.0] * len(metrics)
            # 吞吐量是越大越好（正向），延迟是越小越好（反向）
            if j == 0:  # throughput: 正向
                normalized[p][j] = (raw[p][j] - min_v) / rng
            else:  # latency: 反向
                normalized[p][j] = 1 - (raw[p][j] - min_v) / rng

    # 绘制雷达图
    angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]  # 闭合

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    for i, protocol in enumerate(protocols):
        values = normalized[protocol] + [normalized[protocol][0]]  # 闭合
        color = PROTOCOL_COLORS.get(protocol, ACADEMIC_COLORS[i])
        label = PROTOCOL_LABELS.get(protocol, protocol)
        ax.plot(angles, values, "o-", label=label, color=color, linewidth=2, markersize=6)
        ax.fill(angles, values, alpha=0.1, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metric_labels, fontsize=10)
    ax.set_ylim(0, 1.1)
    ax.set_title("综合性能对比（归一化）", pad=20, fontsize=14, fontweight="bold")
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), frameon=False)

    fig.tight_layout()
    path = os.path.join(FIGURES_DIR, "performance_radar.png")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"[SAVED] {path}")


# ─────────────────────────────────────────
# 汇总报告
# ─────────────────────────────────────────

def generate_summary_report(results: List[Dict[str, Any]],
                            resource_stats: Dict[str, Any]):
    """生成文本汇总报告"""
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("  GMCP-R 性能基准测试报告")
    report_lines.append("=" * 70)

    local_results = [r for r in results if r.get("mode") == "local"]
    net_results = [r for r in results if r.get("mode") == "network"]

    if local_results:
        report_lines.append("\n── 本地基准（纯计算开销）──")
        report_lines.append(f"{'Protocol':<14} {'Size':>6} {'TP(msg/s)':>10} "
                            f"{'build_p50(μs)':>14} {'verify_p50(μs)':>15} {'e2e_p99(μs)':>12}")
        report_lines.append("-" * 75)
        for r in sorted(local_results, key=lambda x: (x["protocol"], x["payload_size"])):
            if r.get("repeat_id") == 1:
                report_lines.append(
                    f"{r['protocol']:<14} {int(r['payload_size']):>6} "
                    f"{r['throughput_msg_per_sec']:>10.0f} "
                    f"{r['build_p50_us']:>14.1f} {r['verify_p50_us']:>15.1f} "
                    f"{r['e2e_p99_us']:>12.1f}"
                )

    if net_results:
        report_lines.append("\n── 网络基准（端到端 RTT）──")
        report_lines.append(f"{'Protocol':<14} {'Size':>6} {'TP(msg/s)':>10} "
                            f"{'p50(ms)':>9} {'p95(ms)':>9} {'p99(ms)':>9}")
        report_lines.append("-" * 62)
        for r in sorted(net_results, key=lambda x: (x["protocol"], x["payload_size"])):
            if r.get("repeat_id") == 1:
                report_lines.append(
                    f"{r['protocol']:<14} {int(r['payload_size']):>6} "
                    f"{r['throughput_msg_per_sec']:>10.1f} "
                    f"{r['rtt_p50_ms']:>9.3f} {r['rtt_p95_ms']:>9.3f} "
                    f"{r['rtt_p99_ms']:>9.3f}"
                )

    if resource_stats:
        report_lines.append("\n── 资源消耗 ──")
        report_lines.append(f"  CPU  avg={resource_stats.get('proc_cpu_pct_mean', 0):.1f}%  "
                            f"max={resource_stats.get('proc_cpu_pct_max', 0):.1f}%")
        report_lines.append(f"  RSS  avg={resource_stats.get('rss_mb_mean', 0):.1f}MB  "
                            f"max={resource_stats.get('rss_mb_max', 0):.1f}MB")
        report_lines.append(f"  Net  sent={resource_stats.get('total_mb_sent', 0):.2f}MB  "
                            f"recv={resource_stats.get('total_mb_recv', 0):.2f}MB")

    report_lines.append("\n" + "=" * 70)

    report_text = "\n".join(report_lines)
    report_path = os.path.join(OUTPUT_DIR, "benchmark_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"[SAVED] {report_path}")

    return report_text


# ─────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────

def main():
    print("=" * 60)
    print("  GMCP-R Performance Benchmark Visualization")
    print("=" * 60)

    os.makedirs(FIGURES_DIR, exist_ok=True)

    results = load_results()
    resource_stats = load_resource_stats()

    if not results:
        print("[ERROR] No results found. Run run_performance_benchmark.py first.")
        print(f"        Expected: {RESULTS_CSV}")
        return

    print(f"\nLoaded {len(results)} result records")

    # 生成所有图表
    plot_throughput_local(results)
    plot_throughput_vs_size(results)
    plot_rtt_distribution(results)
    plot_e2e_latency_percentiles(results)
    plot_resource_usage(resource_stats)
    plot_performance_radar(results)

    # 生成汇总报告
    report = generate_summary_report(results, resource_stats)
    print("\n" + report)

    print(f"\n[DONE] All figures saved to {FIGURES_DIR}/")


if __name__ == "__main__":
    main()
