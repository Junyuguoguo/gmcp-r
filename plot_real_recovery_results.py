# -*- coding: utf-8 -*-
# plot_real_recovery_results.py

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


INPUT_CSV = "results/real_recovery/real_recovery_results.csv"
OUTPUT_DIR = "results/real_recovery/figures"


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


def main():
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)

    for col in [
        "attack_detected",
        "recovery_requested",
        "recovery_success",
        "full_recovery_success",
        "memory_match_after_recovery",
        "final_seq_consistent",
    ]:
        df[col + "_bool"] = df[col].astype(str).str.lower() == "true"
    if "recovery_extra_messages" not in df.columns:
        df["recovery_extra_messages"] = 0
    if "recovery_extra_bytes" not in df.columns:
        df["recovery_extra_bytes"] = 0

    fig1 = df.groupby("attack_type")["full_recovery_success_bool"].mean()
    save_bar(
        fig1,
        "Attack type",
        "Success rate",
        "Recovery Success Rate after Attack",
        os.path.join(OUTPUT_DIR, "recovery_fig1_success_rate_by_attack.png"),
    )

    fig2 = df.groupby("attack_type")["recovery_latency_ms"].mean()
    save_bar(
        fig2,
        "Attack type",
        "Recovery latency (ms)",
        "Recovery Latency by Attack Type",
        os.path.join(OUTPUT_DIR, "recovery_fig2_latency_by_attack.png"),
    )

    fig3 = df.groupby("attack_type")["memory_match_after_recovery_bool"].mean()
    save_bar(
        fig3,
        "Attack type",
        "Memory match rate",
        "Memory Match Rate after Recovery",
        os.path.join(OUTPUT_DIR, "recovery_fig3_memory_match_after_recovery.png"),
    )

    fig4 = df.groupby("attack_type")["post_recovery_accepted"].mean()
    save_bar(
        fig4,
        "Attack type",
        "Accepted messages",
        "Post-Recovery Accepted Messages by Attack Type",
        os.path.join(OUTPUT_DIR, "recovery_fig4_post_recovery_accepted.png"),
    )

    fig5 = df.groupby("attack_type")["final_seq_consistent_bool"].mean()
    save_bar(
        fig5,
        "Attack type",
        "Final seq consistency rate",
        "Final Sequence Consistency after Recovery",
        os.path.join(OUTPUT_DIR, "recovery_fig5_final_seq_consistency.png"),
    )

    fig6 = df.groupby("attack_type")["recovery_extra_bytes"].mean()
    save_bar(
        fig6,
        "Attack type",
        "Recovery extra bytes",
        "Recovery Overhead by Attack Type",
        os.path.join(OUTPUT_DIR, "recovery_fig6_recovery_overhead_by_attack.png"),
    )

    summary = df.groupby("attack_type").agg(
        attack_detection_rate=("attack_detected_bool", "mean"),
        recovery_success_rate=("full_recovery_success_bool", "mean"),
        memory_match_after_recovery=("memory_match_after_recovery_bool", "mean"),
        final_seq_consistency=("final_seq_consistent_bool", "mean"),
        recovery_latency_ms=("recovery_latency_ms", "mean"),
        recovery_extra_messages=("recovery_extra_messages", "mean"),
        recovery_extra_bytes=("recovery_extra_bytes", "mean"),
        post_recovery_accepted=("post_recovery_accepted", "mean"),
    )

    summary.to_csv("results/real_recovery/summary_real_recovery.csv", encoding="utf-8")

    print("[REAL_RECOVERY_PLOT] figures saved to", OUTPUT_DIR)
    print("[REAL_RECOVERY_PLOT] summary saved to results/real_recovery/summary_real_recovery.csv")


if __name__ == "__main__":
    main()
