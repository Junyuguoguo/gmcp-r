# -*- coding: utf-8 -*-
# plot_submission_revision.py
#
# Generate nine publication-quality figures for the submission revision.
# Each function receives explicit CSV and output paths.

import argparse
import csv
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Add project path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.plot_style import (
    ACADEMIC_COLORS,
    PROTOCOL_LABELS,
    ATTACK_LABELS,
    setup_chinese_academic_style,
    style_axes,
    localize_value,
)


def read_csv(path: str) -> List[Dict[str, str]]:
    """Read CSV into list of row dicts."""
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def safe_float(v: str, default: float = 0.0) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def safe_int(v: str, default: int = 0) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Figure 1: Baseline Capability (attack detection rate)
# ---------------------------------------------------------------------------

def plot_baseline_capability(csv_path: str, output_path: str) -> str:
    """
    Bar chart of attack detection rate by protocol.
    Reads baseline_comparison.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Baseline comparison data not available")
        return output_path

    # Compute detection rate per protocol
    by_proto: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in rows:
        by_proto[r.get("protocol", "unknown")].append(r)

    protocols = []
    rates = []
    for proto in ["gmcp_r", "authenticated_hash_chain", "hash_chain", "seq_mac", "ticket_only"]:
        if proto not in by_proto:
            continue
        prows = by_proto[proto]
        attacks = [r for r in prows if r.get("attack_type") != "none"]
        if not attacks:
            continue
        detected = sum(
            1 for r in attacks
            if str(r.get("attack_detected_by_server", "")).lower() == "true"
        )
        rate = detected / len(attacks) * 100
        protocols.append(proto)
        rates.append(rate)

    if not protocols:
        _write_empty_notice(output_path, "No baseline data to plot")
        return output_path

    labels = [localize_value(p) for p in protocols]
    colors = [ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(protocols))]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, rates, color=colors, edgecolor="#2D3748", linewidth=0.7, width=0.68)
    for bar, rate in zip(bars, rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
            f"{rate:.1f}%", ha="center", va="bottom", fontsize=9,
        )
    ax.set_ylabel("Attack Detection Rate (%)")
    ax.set_title("Baseline Protocol Capability: Attack Detection Rate", pad=14)
    ax.set_ylim(0, 110)
    ax.tick_params(axis="x", rotation=30)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 2: Adaptive Tamper (hash chain vs authenticated)
# ---------------------------------------------------------------------------

def plot_adaptive_tamper(csv_path: str, output_path: str) -> str:
    """
    Grouped bar chart: plain hash chain accepts tamper, authenticated rejects.
    Reads hash_chain_adaptive_attack.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Adaptive attack data not available")
        return output_path

    protocols = [r.get("protocol", "") for r in rows]
    accepted = [1 if str(r.get("attack_accepted", "")).lower() == "true" else 0 for r in rows]
    labels = [localize_value(p) for p in protocols]
    colors = ["#C55A11" if a else "#548235" for a in accepted]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(labels, [100 if a else 0 for a in accepted],
                  color=colors, edgecolor="#2D3748", linewidth=0.7, width=0.5)
    for bar, a in zip(bars, accepted):
        status = "Accepted" if a else "Rejected"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                status, ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_ylabel("Tamper Acceptance (%)")
    ax.set_title("Adaptive Tamper Attack: Hash Chain vs Authenticated", pad=14)
    ax.set_ylim(0, 120)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 3: Recovery Window (success by scenario)
# ---------------------------------------------------------------------------

def plot_recovery_window(csv_path: str, output_path: str) -> str:
    """
    Bar chart of success rate by recovery scenario.
    Reads recovery_window_experiment.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Recovery window data not available")
        return output_path

    scenario_order = ["control", "ack_loss", "old_ticket", "below_floor", "nonce_race"]
    by_scenario: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in rows:
        by_scenario[r.get("scenario", "unknown")].append(r)

    scenarios = []
    success_rates = []
    counts = []
    for s in scenario_order:
        if s in by_scenario:
            srows = by_scenario[s]
            success = sum(1 for r in srows if str(r.get("success", "")).lower() == "true")
            scenarios.append(s)
            success_rates.append(success / len(srows) * 100)
            counts.append(len(srows))

    if not scenarios:
        _write_empty_notice(output_path, "No recovery window data")
        return output_path

    labels = [localize_value(s) if s in ("control", "disconnect") else s.replace("_", " ").title()
              for s in scenarios]
    colors = [ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(scenarios))]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, success_rates, color=colors, edgecolor="#2D3748",
                  linewidth=0.7, width=0.65)
    for bar, rate, cnt in zip(bars, success_rates, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f"{rate:.0f}%\n(n={cnt})", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Success Rate (%)")
    ax.set_title("Recovery Window Scenarios: Success Rate", pad=14)
    ax.set_ylim(0, 115)
    ax.tick_params(axis="x", rotation=20)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 4: Nonce Race (winner distribution)
# ---------------------------------------------------------------------------

def plot_nonce_race(csv_path: str, output_path: str) -> str:
    """
    Bar chart of nonce race results: exactly 1 winner count.
    Reads recovery_window_experiment.csv (nonce_race rows only).
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Nonce race data not available")
        return output_path

    race_rows = [r for r in rows if r.get("scenario") == "nonce_race"]
    if not race_rows:
        _write_empty_notice(output_path, "No nonce race rows found")
        return output_path

    winners = [safe_int(r.get("race_winner_count")) for r in race_rows]
    winner_dist = defaultdict(int)
    for w in winners:
        winner_dist[w] += 1

    x_labels = sorted(winner_dist.keys())
    y_values = [winner_dist[x] for x in x_labels]
    x_str = [str(x) for x in x_labels]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(x_str, y_values, color=ACADEMIC_COLORS[0], edgecolor="#2D3748",
                  linewidth=0.7, width=0.5)
    for bar, val in zip(bars, y_values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", fontsize=10)
    ax.set_xlabel("Number of Race Winners")
    ax.set_ylabel("Frequency")
    ax.set_title("Nonce Race: Winner Distribution", pad=14)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 5: Recovery Time (box plot by protocol)
# ---------------------------------------------------------------------------

def plot_recovery_time(csv_path: str, output_path: str) -> str:
    """
    Box plot of recovery time by protocol.
    Reads checkpoint_cost_comparison.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Checkpoint cost data not available")
        return output_path

    by_proto: Dict[str, List[float]] = defaultdict(list)
    for r in rows:
        proto = r.get("protocol", "unknown")
        t_ms = safe_float(r.get("recovery_time_ms", r.get("recovery_time_ns", "0")))
        if t_ms == 0:
            t_ns = safe_float(r.get("recovery_time_ns", "0"))
            t_ms = t_ns / 1e6
        by_proto[proto].append(t_ms)

    protocol_order = ["gmcp_r", "authenticated_hash_chain"]
    protocols = [p for p in protocol_order if p in by_proto]
    if not protocols:
        _write_empty_notice(output_path, "No recovery time data")
        return output_path

    labels = [localize_value(p) for p in protocols]
    data = [by_proto[p] for p in protocols]
    colors = [ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(protocols))]

    fig, ax = plt.subplots(figsize=(7, 5))
    positions = list(range(1, len(protocols) + 1))
    bp = ax.boxplot(data, positions=positions, patch_artist=True, widths=0.5,
                    medianprops=dict(color="#2D3748", linewidth=2))
    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_edgecolor("#2D3748")
        patch.set_alpha(0.7)
    ax.set_ylabel("Recovery Time (ms)")
    ax.set_title("Recovery Time Distribution by Protocol", pad=14)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 6: Replay Count (line chart by offset)
# ---------------------------------------------------------------------------

def plot_replay_count(csv_path: str, output_path: str) -> str:
    """
    Line chart of replay count vs offset for each protocol.
    Reads checkpoint_cost_comparison.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Checkpoint cost data not available")
        return output_path

    # Group by (protocol, offset), average replay_count
    data: Dict[Tuple[str, int], List[int]] = defaultdict(list)
    for r in rows:
        proto = r.get("protocol", "unknown")
        offset = safe_int(r.get("offset"))
        replay = safe_int(r.get("replay_count"))
        data[(proto, offset)].append(replay)

    protocol_order = ["gmcp_r", "authenticated_hash_chain"]
    offsets = sorted(set(o for _, o in data.keys()))

    fig, ax = plt.subplots(figsize=(8, 5))
    for i, proto in enumerate(protocol_order):
        means = []
        for o in offsets:
            vals = data.get((proto, o), [])
            means.append(np.mean(vals) if vals else 0)
        label = localize_value(proto)
        ax.plot(offsets, means, marker="o", label=label,
                color=ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)], linewidth=2.2)

    ax.set_xlabel("Offset from Checkpoint")
    ax.set_ylabel("Replay Count")
    ax.set_title("Replay Count vs Offset from Checkpoint", pad=14)
    legend = ax.get_legend()
    if legend:
        legend.set_frame_on(False)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 7: Byte Cost (recovery material bytes by protocol)
# ---------------------------------------------------------------------------

def plot_byte_cost(csv_path: str, output_path: str) -> str:
    """
    Grouped bar chart of recovery material bytes by protocol and n.
    Reads checkpoint_cost_comparison.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Checkpoint cost data not available")
        return output_path

    # Group by (protocol, n), average recovery_material_bytes
    data: Dict[Tuple[str, str], List[int]] = defaultdict(list)
    for r in rows:
        proto = r.get("protocol", "unknown")
        n = r.get("n", "0")
        nbytes = safe_int(r.get("recovery_material_bytes"))
        data[(proto, n)].append(nbytes)

    protocol_order = ["gmcp_r", "authenticated_hash_chain"]
    n_values = sorted(set(n for _, n in data.keys()), key=lambda x: int(x))

    if not n_values:
        _write_empty_notice(output_path, "No byte cost data")
        return output_path

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(n_values))
    width = 0.35
    for i, proto in enumerate(protocol_order):
        means = []
        for n in n_values:
            vals = data.get((proto, n), [])
            means.append(np.mean(vals) if vals else 0)
        offset = (i - 0.5) * width
        label = localize_value(proto)
        ax.bar(x + offset, means, width, label=label,
               color=ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)],
               edgecolor="#2D3748", linewidth=0.7)

    ax.set_xlabel("Session Length (n)")
    ax.set_ylabel("Recovery Material Bytes")
    ax.set_title("Recovery Byte Cost by Session Length", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(n):,}" for n in n_values])
    legend = ax.get_legend()
    if legend:
        legend.set_frame_on(False)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 8: Concurrency / CI (RTT by concurrency level)
# ---------------------------------------------------------------------------

def plot_concurrency_ci(csv_path: str, output_path: str) -> str:
    """
    Line chart of mean RTT with CI bars by concurrency level.
    Reads concurrent_results.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Concurrency data not available")
        return output_path

    # Group by concurrency, compute mean and CI of rtt_mean_ms
    by_conc: Dict[int, List[float]] = defaultdict(list)
    for r in rows:
        conc = safe_int(r.get("concurrency"))
        rtt = safe_float(r.get("rtt_mean_ms"))
        by_conc[conc].append(rtt)

    conc_levels = sorted(by_conc.keys())
    if not conc_levels:
        _write_empty_notice(output_path, "No concurrency data")
        return output_path

    means = []
    ci_halfs = []
    for c in conc_levels:
        vals = by_conc[c]
        m = np.mean(vals)
        if len(vals) > 1:
            try:
                from scipy.stats import t as t_dist
                t_crit = t_dist.ppf(0.975, len(vals) - 1)
            except ModuleNotFoundError:
                t_crit = 1.96
            ci = t_crit * np.std(vals, ddof=1) / np.sqrt(len(vals))
        else:
            ci = 0
        means.append(m)
        ci_halfs.append(ci)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.errorbar(conc_levels, means, yerr=ci_halfs, marker="o", capsize=4,
                color=ACADEMIC_COLORS[0], linewidth=2.2, markersize=6)
    ax.set_xlabel("Concurrent Clients")
    ax.set_ylabel("Mean RTT (ms)")
    ax.set_title("Concurrency vs Latency with 95% CI", pad=14)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Figure 9: Observed Rate / Confidence (attack detection with exact bounds)
# ---------------------------------------------------------------------------

def plot_observed_rate_confidence(csv_path: str, output_path: str) -> str:
    """
    Bar chart of attack detection rate with Clopper-Pearson lower bounds
    for 100% observed rates.
    Reads baseline_comparison.csv.
    """
    setup_chinese_academic_style()
    rows = read_csv(csv_path)
    if not rows:
        _write_empty_notice(output_path, "Baseline data not available")
        return output_path

    # Compute detection rate + CI per protocol
    by_proto: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in rows:
        by_proto[r.get("protocol", "unknown")].append(r)

    protocol_order = ["gmcp_r", "authenticated_hash_chain", "hash_chain", "seq_mac", "ticket_only"]
    protocols = []
    rates = []
    lower_bounds = []
    totals = []

    for proto in protocol_order:
        if proto not in by_proto:
            continue
        prows = by_proto[proto]
        attacks = [r for r in prows if r.get("attack_type") != "none"]
        if not attacks:
            continue
        detected = sum(
            1 for r in attacks
            if str(r.get("attack_detected_by_server", "")).lower() == "true"
        )
        total = len(attacks)
        rate = detected / total

        # Clopper-Pearson exact lower bound for 100% observed
        if rate == 1.0:
            lower = 0.025 ** (1.0 / total) if total > 0 else 0
        elif rate == 0.0:
            lower = 0.0
        else:
            # Wilson score for intermediate
            z = 1.96
            denom = 1 + z**2 / total
            center = (rate + z**2 / (2 * total)) / denom
            se = np.sqrt((rate * (1 - rate) + z**2 / (4 * total)) / total) / denom
            lower = max(0, center - z * se)

        protocols.append(proto)
        rates.append(rate * 100)
        lower_bounds.append(lower * 100)
        totals.append(total)

    if not protocols:
        _write_empty_notice(output_path, "No observed rate data")
        return output_path

    labels = [localize_value(p) for p in protocols]
    colors = [ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(protocols))]

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(protocols))
    bars = ax.bar(x, rates, color=colors, edgecolor="#2D3748", linewidth=0.7, width=0.6)

    # Error bars: lower bound is the error below
    errors_below = [r - lb for r, lb in zip(rates, lower_bounds)]
    errors_above = [0] * len(rates)  # upper bound is 100%
    ax.errorbar(x, rates, yerr=[errors_below, errors_above],
                fmt="none", ecolor="#2D3748", capsize=5, linewidth=1.5)

    for i, (bar, rate, lb, total) in enumerate(zip(bars, rates, lower_bounds, totals)):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                f"{rate:.0f}%\nLB: {lb:.0f}%\n(n={total})",
                ha="center", va="bottom", fontsize=7)

    ax.set_ylabel("Attack Detection Rate (%)")
    ax.set_title("Observed Detection Rate with Exact Confidence Bounds", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylim(0, 120)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_empty_notice(output_path: str, message: str):
    """Write a placeholder PNG with a notice message."""
    setup_chinese_academic_style()
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.text(0.5, 0.5, message, ha="center", va="center",
            fontsize=12, color="#888888", transform=ax.transAxes)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[PLOT] {output_path} (placeholder: {message})")


# ---------------------------------------------------------------------------
# Main: generate all nine figures
# ---------------------------------------------------------------------------

def generate_all_plots(output_root: str) -> Dict[str, str]:
    """
    Generate all nine figures from CSV data in output_root.
    Returns dict of plot_name -> output_path.
    """
    os.makedirs(output_root, exist_ok=True)

    plots: Dict[str, str] = {}

    # Figure 1: Baseline capability
    bl_path = os.path.join(output_root, "baseline_comparison.csv")
    if not os.path.isfile(bl_path):
        bl_path = os.path.join(output_root, "real_baseline_comparison_results.csv")
    p = os.path.join(output_root, "fig_baseline_capability.png")
    plot_baseline_capability(bl_path, p)
    plots["baseline_capability"] = p

    # Figure 2: Adaptive tamper
    aa_path = os.path.join(output_root, "hash_chain_adaptive_attack.csv")
    p = os.path.join(output_root, "fig_adaptive_tamper.png")
    plot_adaptive_tamper(aa_path, p)
    plots["adaptive_tamper"] = p

    # Figure 3: Recovery window
    rw_path = os.path.join(output_root, "recovery_window_experiment.csv")
    p = os.path.join(output_root, "fig_recovery_window.png")
    plot_recovery_window(rw_path, p)
    plots["recovery_window"] = p

    # Figure 4: Nonce race
    p = os.path.join(output_root, "fig_nonce_race.png")
    plot_nonce_race(rw_path, p)
    plots["nonce_race"] = p

    # Figure 5: Recovery time
    cc_path = os.path.join(output_root, "checkpoint_cost_comparison.csv")
    p = os.path.join(output_root, "fig_recovery_time.png")
    plot_recovery_time(cc_path, p)
    plots["recovery_time"] = p

    # Figure 6: Replay count
    p = os.path.join(output_root, "fig_replay_count.png")
    plot_replay_count(cc_path, p)
    plots["replay_count"] = p

    # Figure 7: Byte cost
    p = os.path.join(output_root, "fig_byte_cost.png")
    plot_byte_cost(cc_path, p)
    plots["byte_cost"] = p

    # Figure 8: Concurrency / CI
    conc_path = os.path.join(output_root, "concurrent_results.csv")
    if not os.path.isfile(conc_path):
        conc_path = "results/concurrent/concurrent_results.csv"
    p = os.path.join(output_root, "fig_concurrency_ci.png")
    plot_concurrency_ci(conc_path, p)
    plots["concurrency_ci"] = p

    # Figure 9: Observed rate / confidence
    p = os.path.join(output_root, "fig_observed_rate_confidence.png")
    plot_observed_rate_confidence(bl_path, p)
    plots["observed_rate_confidence"] = p

    print(f"\n[PLOTS] Generated {len(plots)} figures in {output_root}")
    return plots


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate submission revision plots")
    parser.add_argument(
        "--output-root",
        default="results/submission_revision",
        help="Directory containing CSVs and where PNGs will be saved",
    )
    args = parser.parse_args()

    plots = generate_all_plots(args.output_root)

    # Verify all PNGs are nonempty
    all_ok = True
    for name, path in plots.items():
        if not os.path.isfile(path):
            print(f"  MISSING: {name} → {path}")
            all_ok = False
        elif os.path.getsize(path) == 0:
            print(f"  EMPTY: {name} → {path}")
            all_ok = False
        else:
            size = os.path.getsize(path)
            print(f"  OK: {name} → {path} ({size:,} bytes)")

    if all_ok:
        print("\n✅ All plots generated successfully")
        return 0
    else:
        print("\n❌ Some plots failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
