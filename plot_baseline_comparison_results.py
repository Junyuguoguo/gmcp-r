# -*- coding: utf-8 -*-
# plot_baseline_comparison_results.py
#
# Figures are based on protocol-level simulation output from
# run_baseline_comparison_experiment.py.

import glob
import os

import pandas as pd

from gmcp.plot_style import save_bar_chart, save_line_chart


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
    save_bar_chart(series, xlabel, ylabel, title, output_path, rotation=rotation)


def save_line(table, xlabel, ylabel, title, output_path) -> None:
    save_line_chart(table, xlabel, ylabel, title, output_path)


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
        "协议类型",
        "恢复时延（ms）",
        "协议级模拟：不同协议的恢复时延",
        os.path.join(OUTPUT_DIR, "baseline_fig1_recovery_latency_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["memory_recovered_bool"].mean(),
        "协议类型",
        "记忆恢复率",
        "协议级模拟：不同协议的记忆恢复能力",
        os.path.join(OUTPUT_DIR, "baseline_fig2_memory_recovery_rate_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["attack_detected_bool"].mean(),
        "协议类型",
        "攻击检测率",
        "协议级模拟：不同协议的攻击检测能力",
        os.path.join(OUTPUT_DIR, "baseline_fig3_attack_detection_rate_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["secure_memory_recovery_success_bool"].mean(),
        "协议类型",
        "安全记忆恢复率",
        "协议级模拟：安全记忆恢复成功率",
        os.path.join(OUTPUT_DIR, "baseline_fig4_secure_memory_recovery_success_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["recovery_extra_bytes"].mean(),
        "协议类型",
        "额外通信开销（字节）",
        "协议级模拟：恢复阶段额外通信开销",
        os.path.join(OUTPUT_DIR, "baseline_fig5_recovery_extra_bytes_by_protocol.png"),
    )

    save_bar(
        df.groupby("protocol")["throughput_score"].mean(),
        "协议类型",
        "相对吞吐评分",
        "协议级模拟：不同协议的相对吞吐表现",
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
        "检查点间隔",
        "恢复时延（ms）",
        "协议级模拟：检查点间隔对恢复时延的影响",
        os.path.join(OUTPUT_DIR, "baseline_fig7_checkpoint_interval_latency.png"),
    )

    prev_mem = df[df["attack_type"] == "prev_mem"].groupby("protocol")["attack_detected_bool"].mean()
    save_bar(
        prev_mem,
        "协议类型",
        "记忆断裂检测率",
        "协议级模拟：记忆断裂攻击检测率",
        os.path.join(OUTPUT_DIR, "baseline_fig8_prev_mem_detection_by_protocol.png"),
    )

    rollback = df[df["attack_type"] == "rollback_ticket"].groupby("protocol")[
        "attack_detected_bool"
    ].mean()
    save_bar(
        rollback,
        "协议类型",
        "票据回滚检测率",
        "协议级模拟：票据回滚攻击检测率",
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
