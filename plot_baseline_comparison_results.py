# -*- coding: utf-8 -*-
# plot_baseline_comparison_results.py

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


INPUT_CSV = "results/baseline/baseline_comparison_results.csv"
OUTPUT_DIR = "results/baseline/figures"


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_old_figures():
    for path in glob.glob(os.path.join(OUTPUT_DIR, "*.png")):
        os.remove(path)


def save_bar(series, xlabel, ylabel, title, output_path, rotation=45):
    plt.figure(figsize=(8, 5))
    series.plot(kind="bar")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=rotation)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def save_line(table, xlabel, ylabel, title, output_path):
    plt.figure(figsize=(8, 5))
    table.plot(kind="line", marker="o")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def main():
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
    ]:
        df[col + "_bool"] = df[col].astype(str).str.lower() == "true"

    detection_df = df[df["detection_result"] != "not_applicable"]

    fig1 = df.groupby("protocol")["recovery_latency_ms"].mean()
    save_bar(
        fig1,
        "Protocol",
        "Recovery latency (ms)",
        "Baseline Recovery Latency by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig1_recovery_latency.png"),
    )

    fig2 = df.groupby("protocol")["memory_recovered_bool"].mean()
    save_bar(
        fig2,
        "Protocol",
        "Memory recovery rate",
        "Memory Recovery Capability by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig2_memory_recovery_rate.png"),
    )

    fig3 = detection_df.groupby("protocol")["attack_detected_bool"].mean()
    save_bar(
        fig3,
        "Protocol",
        "Detection rate",
        "Attack Detection Rate by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig3_attack_detection_rate.png"),
    )

    fig4 = df.groupby("protocol")["secure_memory_recovery_success_bool"].mean()
    save_bar(
        fig4,
        "Protocol",
        "Secure memory recovery rate",
        "Secure Memory Recovery Success by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig4_secure_memory_recovery.png"),
    )

    fig5 = df.groupby("protocol")["recovery_extra_bytes"].mean()
    save_bar(
        fig5,
        "Protocol",
        "Extra bytes",
        "Recovery Extra Communication Overhead by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig5_recovery_overhead.png"),
    )

    fig6 = df.groupby("protocol")["throughput_score"].mean()
    save_bar(
        fig6,
        "Protocol",
        "Relative throughput score",
        "Relative Throughput Score by Protocol",
        os.path.join(OUTPUT_DIR, "baseline_fig6_throughput_score.png"),
    )

    gmcp_hash = df[df["protocol"].isin(["hash_chain", "gmcp_r"])]
    fig7 = gmcp_hash.pivot_table(
        index="checkpoint_interval",
        columns="protocol",
        values="recovery_latency_ms",
        aggfunc="mean",
    )
    save_line(
        fig7,
        "Checkpoint interval",
        "Recovery latency (ms)",
        "Checkpoint Interval Impact on Recovery Latency",
        os.path.join(OUTPUT_DIR, "baseline_fig7_checkpoint_latency.png"),
    )

    summary = df.groupby("protocol").agg(
        recovery_latency_ms=("recovery_latency_ms", "mean"),
        memory_recovery_rate=("memory_recovered_bool", "mean"),
        secure_memory_recovery_rate=("secure_memory_recovery_success_bool", "mean"),
        recovery_extra_bytes=("recovery_extra_bytes", "mean"),
        throughput_score=("throughput_score", "mean"),
    )

    detection_summary = detection_df.groupby("protocol").agg(
        attack_detection_rate=("attack_detected_bool", "mean")
    )

    summary = summary.join(detection_summary, how="left")
    summary.to_csv("results/baseline/summary_baseline_comparison.csv", encoding="utf-8")

    print("[BASELINE_PLOT] figures saved to", OUTPUT_DIR)
    print("[BASELINE_PLOT] summary saved to results/baseline/summary_baseline_comparison.csv")


if __name__ == "__main__":
    main()