# -*- coding: utf-8 -*-
# plot_concurrent_results.py
#
# 绘制多客户端并发实验结果图表
# 展示并发度对吞吐量、延迟的影响

import csv
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from typing import Dict, Any, List

OUTPUT_DIR = "results/concurrent"
CSV_FILE = os.path.join(OUTPUT_DIR, "concurrent_results.csv")
DETAIL_CSV = os.path.join(OUTPUT_DIR, "concurrent_detail.csv")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")

# 配色
CONCURRENCY_COLORS = {
    1: "#2F5597",
    2: "#C55A11",
    5: "#548235",
    10: "#8064A2",
    20: "#1F7A8C",
}

MARKERS = {1: "o", 2: "s", 5: "^", 10: "D", 20: "v"}


def setup_style():
    """设置中文学术风格"""
    preferred_fonts = [
        "PingFang SC", "Hiragino Sans GB", "Heiti SC", "STHeiti",
        "Songti SC", "Microsoft YaHei", "SimHei",
        "Noto Sans CJK SC", "Source Han Sans SC",
        "WenQuanYi Micro Hei", "Arial Unicode MS",
    ]
    from matplotlib import font_manager
    available = set(f.name for f in font_manager.fontManager.ttflist)
    chosen = [n for n in preferred_fonts if n in available] or ["DejaVu Sans"]

    plt.rcParams.update({
        "font.sans-serif": chosen + ["DejaVu Sans"],
        "axes.unicode_minus": False,
        "figure.dpi": 160,
        "savefig.dpi": 600,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": "#333333",
        "axes.linewidth": 0.8,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
        "axes.labelsize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "lines.linewidth": 2.0,
        "lines.markersize": 7,
    })


def ensure_figures_dir():
    os.makedirs(FIGURES_DIR, exist_ok=True)


def load_summary():
    """加载汇总 CSV"""
    results = []
    if not os.path.exists(CSV_FILE):
        print(f"[ERROR] Summary CSV not found: {CSV_FILE}")
        return results
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 转换数值
            for k in ["concurrency", "repeat_id", "message_count_per_client", "payload_size",
                       "total_sent", "total_accepted", "total_rejected", "total_timeout",
                       "total_error", "successful_clients", "rtt_n"]:
                if k in row:
                    try:
                        row[k] = int(row[k])
                    except (ValueError, KeyError):
                        row[k] = 0
            for k in ["success_rate_pct", "overall_throughput_msg_per_sec", "test_elapsed_sec",
                       "rtt_mean_ms", "rtt_std_ms", "rtt_ci95_ms", "rtt_min_ms", "rtt_max_ms",
                       "rtt_median_ms", "per_client_rtt_mean_ms", "per_client_rtt_std_ms",
                       "per_client_rtt_ci95_ms", "per_client_tp_mean_msg_per_sec",
                       "per_client_tp_std_msg_per_sec", "per_client_tp_ci95_msg_per_sec"]:
                if k in row:
                    try:
                        row[k] = float(row[k])
                    except (ValueError, KeyError):
                        row[k] = 0.0
            results.append(row)
    return results


def load_detail():
    """加载详细 CSV"""
    results = []
    if not os.path.exists(DETAIL_CSV):
        print(f"[WARN] Detail CSV not found: {DETAIL_CSV}")
        return results
    with open(DETAIL_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for k in ["concurrency", "repeat_id", "sent_count", "accepted_count",
                       "rejected_count", "timeout_count", "error_count"]:
                if k in row:
                    try:
                        row[k] = int(row[k])
                    except (ValueError, KeyError):
                        row[k] = 0
            for k in ["rtt_mean_ms", "rtt_std_ms", "rtt_min_ms", "rtt_max_ms",
                       "rtt_median_ms", "elapsed_sec", "throughput_msg_per_sec"]:
                if k in row:
                    try:
                        row[k] = float(row[k])
                    except (ValueError, KeyError):
                        row[k] = 0.0
            results.append(row)
    return results


def style_axes(ax, rate_axis=False):
    """统一坐标轴风格"""
    ax.set_axisbelow(True)
    ax.grid(axis="y", color="#D9DEE7", linestyle="--", linewidth=0.7, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#555555")
    ax.spines["bottom"].set_color("#555555")


# =========================
# 图表1：吞吐量 vs 并发度（带误差棒）
# =========================

def plot_throughput_vs_concurrency(results):
    """绘制并发度对吞吐量的影响（带95% CI误差棒）"""
    conc_groups = defaultdict(list)
    for r in results:
        conc_groups[r["concurrency"]].append(r["overall_throughput_msg_per_sec"])

    concs = sorted(conc_groups.keys())
    means = [np.mean(conc_groups[c]) for c in concs]
    cis = []
    for c in concs:
        vals = np.array(conc_groups[c], dtype=float)
        n = len(vals)
        if n > 1:
            from scipy import stats as sp_stats
            se = np.std(vals, ddof=1) / np.sqrt(n)
            ci = sp_stats.t.ppf(0.975, n - 1) * se
        else:
            ci = 0.0
        cis.append(ci)

    colors = [CONCURRENCY_COLORS.get(c, "#999999") for c in concs]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(
        [str(c) for c in concs], means, yerr=cis, capsize=6,
        color=colors, edgecolor="#2D3748", linewidth=0.7, width=0.6,
        error_kw={"linewidth": 1.5, "ecolor": "#444444"},
    )

    # 数值标签
    for bar, mean, ci in zip(bars, means, cis):
        ax.text(
            bar.get_x() + bar.get_width() / 2, mean + ci + max(means) * 0.02,
            f"{mean:.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold",
        )

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("整体吞吐量 (msg/s)")
    ax.set_title("并发度对整体吞吐量的影响")
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig1_throughput.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig1_throughput.png")


# =========================
# 图表2：RTT vs 并发度
# =========================

def plot_rtt_vs_concurrency(results):
    """绘制并发度对 RTT 的影响"""
    conc_groups = defaultdict(list)
    for r in results:
        conc_groups[r["concurrency"]].append(r["rtt_mean_ms"])

    concs = sorted(conc_groups.keys())
    means = [np.mean(conc_groups[c]) for c in concs]
    cis = []
    for c in concs:
        vals = np.array(conc_groups[c], dtype=float)
        n = len(vals)
        if n > 1:
            from scipy import stats as sp_stats
            se = np.std(vals, ddof=1) / np.sqrt(n)
            ci = sp_stats.t.ppf(0.975, n - 1) * se
        else:
            ci = 0.0
        cis.append(ci)

    colors = [CONCURRENCY_COLORS.get(c, "#999999") for c in concs]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.errorbar(
        [str(c) for c in concs], means, yerr=cis,
        fmt="-o", color="#2F5597", capsize=6, capthick=1.5,
        linewidth=2.2, markersize=8, markerfacecolor="white",
        markeredgewidth=2, markeredgecolor="#2F5597",
    )

    for i, (conc, mean, ci) in enumerate(zip(concs, means, cis)):
        ax.annotate(
            f"{mean:.2f}ms", (str(conc), mean),
            textcoords="offset points", xytext=(0, 12),
            ha="center", fontsize=9,
        )

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("平均 RTT (ms)")
    ax.set_title("并发度对消息往返延迟的影响")
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig2_rtt.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig2_rtt.png")


# =========================
# 图表3：每客户端吞吐量箱线图
# =========================

def plot_per_client_throughput_boxplot(detail_results):
    """绘制每个客户端吞吐量的分布（按并发度分组）"""
    conc_data = defaultdict(list)
    for r in detail_results:
        if r.get("success", True):
            conc_data[r["concurrency"]].append(r["throughput_msg_per_sec"])

    if not conc_data:
        print("[WARN] No detail data for per-client boxplot")
        return

    concs = sorted(conc_data.keys())
    data = [conc_data[c] for c in concs]
    colors = [CONCURRENCY_COLORS.get(c, "#999999") for c in concs]

    fig, ax = plt.subplots(figsize=(8, 5))
    bp = ax.boxplot(data, patch_artist=True, labels=[str(c) for c in concs],
                    widths=0.55, showfliers=True, flierprops=dict(marker="o", markersize=3, alpha=0.4))

    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    for median in bp["medians"]:
        median.set_color("#D62728")
        median.set_linewidth(2)

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("单客户端吞吐量 (msg/s)")
    ax.set_title("不同并发度下各客户端吞吐量分布")
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig3_per_client_boxplot.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig3_per_client_boxplot.png")


# =========================
# 图表4：RTT 分布（按并发度分组的箱线图）
# =========================

def plot_rtt_distribution_boxplot(results):
    """绘制各并发度下的全局 RTT 分布"""
    conc_rtts = defaultdict(list)
    for r in results:
        conc_rtts[r["concurrency"]].append(r["rtt_mean_ms"])

    concs = sorted(conc_rtts.keys())
    data = [conc_rtts[c] for c in concs]
    colors = [CONCURRENCY_COLORS.get(c, "#999999") for c in concs]

    fig, ax = plt.subplots(figsize=(8, 5))
    bp = ax.boxplot(data, patch_artist=True, labels=[str(c) for c in concs],
                    widths=0.55)

    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    for median in bp["medians"]:
        median.set_color("#D62728")
        median.set_linewidth(2)

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("平均 RTT (ms)")
    ax.set_title("不同并发度下的 RTT 分布")
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig4_rtt_boxplot.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig4_rtt_boxplot.png")


# =========================
# 图表5：可扩展性曲线
# =========================

def plot_scalability_curve(results):
    """绘制可扩展性曲线：相对吞吐量 vs 并发度"""
    conc_groups = defaultdict(list)
    for r in results:
        conc_groups[r["concurrency"]].append(r["overall_throughput_msg_per_sec"])

    concs = sorted(conc_groups.keys())
    means = {c: np.mean(conc_groups[c]) for c in concs}

    if 1 not in means or means[1] == 0:
        print("[WARN] Cannot plot scalability: no baseline (concurrency=1) data")
        return

    baseline = means[1]

    fig, ax = plt.subplots(figsize=(8, 5))

    # 理想线性扩展
    ax.plot(
        [str(c) for c in concs], [c for c in concs],
        "--", color="#AAAAAA", linewidth=1.5, label="理想线性扩展", zorder=1,
    )

    # 实际吞吐量倍数
    actual = [means[c] / baseline for c in concs]
    ax.plot(
        [str(c) for c in concs], actual,
        "-o", color="#E69F00", linewidth=2.5, markersize=9,
        markerfacecolor="white", markeredgewidth=2.5, markeredgecolor="#E69F00",
        label="实测吞吐量倍数", zorder=2,
    )

    # 数值标注
    for conc, a in zip(concs, actual):
        ax.annotate(
            f"{a:.2f}x", (str(conc), a),
            textcoords="offset points", xytext=(0, 10),
            ha="center", fontsize=9, fontweight="bold",
        )

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("相对吞吐量（1客户端=1.0）")
    ax.set_title("多客户端并发可扩展性")
    ax.legend(loc="upper left", frameon=False)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig5_scalability.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig5_scalability.png")


# =========================
# 图表6：成功率 vs 并发度
# =========================

def plot_success_rate_vs_concurrency(results):
    """绘制并发度对成功率的影响"""
    conc_groups = defaultdict(list)
    for r in results:
        conc_groups[r["concurrency"]].append(r["success_rate_pct"])

    concs = sorted(conc_groups.keys())
    means = [np.mean(conc_groups[c]) for c in concs]
    stds = [np.std(conc_groups[c]) for c in concs]

    colors = [CONCURRENCY_COLORS.get(c, "#999999") for c in concs]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(
        [str(c) for c in concs], means, yerr=stds, capsize=5,
        color=colors, edgecolor="#2D3748", linewidth=0.7, width=0.6,
    )

    for bar, mean in zip(bars, means):
        ax.text(
            bar.get_x() + bar.get_width() / 2, mean + 1,
            f"{mean:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold",
        )

    ax.set_xlabel("并发客户端数")
    ax.set_ylabel("成功率 (%)")
    ax.set_title("并发度对消息验证成功率的影响")
    ax.set_ylim(0, 108)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGURES_DIR, "concurrent_fig6_success_rate.png"), bbox_inches="tight")
    plt.close(fig)
    print("[PLOT] Saved concurrent_fig6_success_rate.png")


# =========================
# 汇总表
# =========================

def generate_summary_table(results):
    """生成汇总表格"""
    conc_groups = defaultdict(list)
    for r in results:
        conc_groups[r["concurrency"]].append(r)

    concs = sorted(conc_groups.keys())

    summary = []
    for c in concs:
        group = conc_groups[c]
        throughputs = [r["overall_throughput_msg_per_sec"] for r in group]
        rtts = [r["rtt_mean_ms"] for r in group]
        successes = [r["success_rate_pct"] for r in group]

        summary.append({
            "concurrency": c,
            "throughput_mean": round(np.mean(throughputs), 2),
            "throughput_std": round(np.std(throughputs), 2),
            "rtt_mean": round(np.mean(rtts), 3),
            "rtt_std": round(np.std(rtts), 3),
            "success_rate_mean": round(np.mean(successes), 2),
            "success_rate_std": round(np.std(successes), 2),
            "n_repeats": len(group),
        })

    # 保存 CSV
    summary_file = os.path.join(OUTPUT_DIR, "concurrent_summary.csv")
    with open(summary_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "concurrency", "throughput_mean", "throughput_std",
            "rtt_mean", "rtt_std", "success_rate_mean", "success_rate_std", "n_repeats",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow(row)
    print(f"[SUMMARY] Saved to {summary_file}")

    # 打印表格
    print("\n" + "=" * 80)
    print("并发实验汇总表")
    print("=" * 80)
    print(f"{'并发数':<8} {'吞吐量(msg/s)':<20} {'RTT(ms)':<20} {'成功率(%)':<15} {'重复次数':<8}")
    print("-" * 80)
    for row in summary:
        print(
            f"{row['concurrency']:<8} "
            f"{row['throughput_mean']:.1f}±{row['throughput_std']:.1f}      "
            f"{row['rtt_mean']:.3f}±{row['rtt_std']:.3f}      "
            f"{row['success_rate_mean']:.1f}±{row['success_rate_std']:.1f}    "
            f"{row['n_repeats']}"
        )
    print("=" * 80)


# =========================
# Main
# =========================

def main():
    setup_style()
    ensure_figures_dir()

    results = load_summary()
    if not results:
        print("[ERROR] No summary results to plot. Run run_concurrent_experiment.py first.")
        return

    detail = load_detail()

    print(f"[INFO] Loaded {len(results)} summary rows, {len(detail)} detail rows")

    # 绘制图表
    plot_throughput_vs_concurrency(results)
    plot_rtt_vs_concurrency(results)
    plot_rtt_distribution_boxplot(results)
    plot_scalability_curve(results)
    plot_success_rate_vs_concurrency(results)

    if detail:
        plot_per_client_throughput_boxplot(detail)

    # 生成汇总表
    generate_summary_table(results)

    print(f"\n[COMPLETE] All plots saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()
