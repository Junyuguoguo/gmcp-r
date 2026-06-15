# -*- coding: utf-8 -*-
# plot_baseline_comparison_results.py
#
# Figures are based on protocol-level simulation output from
# run_baseline_comparison_experiment.py.

import glob
import os

import matplotlib.pyplot as plt
import pandas as pd


INPUT_CSV = "results/baseline/baseline_comparison_results.csv"
OUTPUT_DIR = "results/baseline/figures"
SUMMARY_CSV = "results/baseline/summary_baseline_comparison.csv"


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_old_figures() -> None:
    for path in glob.glob(os.path.join(OUTPUT_DIR, "*.png")):
        os.remove(path)


def bool_series(series):
    return (series.astype(str).str.lower() == "true").astype(int)


def save_bar(series, xlabel, ylabel, title, output_path, rotation=45) -> None:
    plt.figure(figsize=(8, 5))
    series.plot(kind="bar")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=rotation)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def save_line(table, xlabel, ylabel, title, output_path) -> None:
    plt.figure(figsize=(8, 5))
    table.plot(kind="line", marker="o")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def main() -> None:
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)
    for col in [
        "memory_supported",
        "memory_recovered",
        "memory_match",
        "attack_detected",
        "normal_recovery_success",
        "secure_memory_recovery_success",
        "fast_secure_memory_recovery_success",
    ]:
        df[col + "_bool"] = bool_series(df[col])

    save_bar(
        df.groupby("protocol")["recovery_latency_ms"].mean(),
        "Protocol",
        "Recovery latency (ms)",
        "Protocol-level Simulation Recovery Latency by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig1_recovery_latency_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["memory_recovered_bool"].mean(),
        "Protocol",
        "Memory recovery rate",
        "Protocol-level Simulation Memory Recovery Rate by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig2_memory_recovery_rate_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["attack_detected_bool"].mean(),
        "Protocol",
        "Attack detection rate",
        "Protocol-level Simulation Attack Detection Rate by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig3_attack_detection_rate_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["secure_memory_recovery_success_bool"].mean(),
        "Protocol",
        "Secure memory recovery rate",
        "Protocol-level Simulation Secure Memory Recovery by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig4_secure_memory_recovery_success_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["recovery_extra_bytes"].mean(),
        "Protocol",
        "Extra bytes",
        "Protocol-level Simulation Recovery Extra Bytes by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig5_recovery_extra_bytes_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["throughput_score"].mean(),
        "Protocol",
        "Relative throughput score",
        "Protocol-level Simulation Throughput Score by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig6_throughput_score_by_protocol.png"),
    )

    checkpoint_table = df[df["protocol"].isin(["hash_chain", "gmcp_r"])].pivot_table(
        index="checkpoint_interval",
        columns="protocol",
        values="recovery_latency_ms",
        aggfunc="mean",
    )
    save_line(
        checkpoint_table,
        "Checkpoint interval",
        "Recovery latency (ms)",
        "Protocol-level Simulation Checkpoint Interval Impact on Latency",
        os.path.join(OUTPUT_DIR, "baseline_fig7_checkpoint_interval_latency.png"),
    )

    prev_mem = df[df["attack_type"] == "prev_mem"].groupby("protocol")["attack_detected_bool"].mean()
    save_bar(
        prev_mem,
        "Protocol",
        "prev_mem detection rate",
        "Protocol-level Simulation prev_mem Detection by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig8_prev_mem_detection_by_protocol.png"),
    )

    rollback = df[df["attack_type"] == "rollback_ticket"].groupby("protocol")[
        "attack_detected_bool"
    ].mean()
    save_bar(
        rollback,
        "Protocol",
        "Rollback ticket detection rate",
        "Protocol-level Simulation Rollback Ticket Detection by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig9_rollback_ticket_detection_by_protocol.png"),
    )

    summary = df.groupby("protocol").agg(
        recovery_latency_ms_mean=("recovery_latency_ms", "mean"),
        recovery_latency_ms_std=("recovery_latency_ms", "std"),
        recovery_latency_ms_min=("recovery_latency_ms", "min"),
        recovery_latency_ms_max=("recovery_latency_ms", "max"),
        memory_recovery_rate=("memory_recovered_bool", "mean"),
        attack_detection_rate=("attack_detected_bool", "mean"),
        secure_memory_recovery_rate=("secure_memory_recovery_success_bool", "mean"),
        fast_secure_memory_recovery_rate=("fast_secure_memory_recovery_success_bool", "mean"),
        recovery_extra_bytes_mean=("recovery_extra_bytes", "mean"),
        throughput_score_mean=("throughput_score", "mean"),
        replay_count_mean=("replay_count", "mean"),
    )
    summary.to_csv(SUMMARY_CSV, encoding="utf-8")

    print("[BASELINE_PLOT] figures saved to", OUTPUT_DIR)
    print("[BASELINE_PLOT] summary saved to", SUMMARY_CSV)


if __name__ == "__main__":
    main()
