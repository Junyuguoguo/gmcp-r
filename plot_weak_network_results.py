# -*- coding: utf-8 -*-
# plot_weak_network_results.py
#
# Figures are generated from a controlled weak-network simulation.

import glob
import os

import pandas as pd

from gmcp.plot_style import save_line_chart


INPUT_CSV = "results/weak_network/weak_network_results.csv"
OUTPUT_DIR = "results/weak_network/figures"
SUMMARY_CSV = "results/weak_network/summary_weak_network.csv"


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_old_figures() -> None:
    for path in glob.glob(os.path.join(OUTPUT_DIR, "*.png")):
        os.remove(path)


def save_line(table, xlabel, ylabel, title, output_path) -> None:
    save_line_chart(table, xlabel, ylabel, title, output_path)


def main() -> None:
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)

    loss_success = df.pivot_table(
        index="loss_rate",
        columns="protocol",
        values="recovery_success_rate",
        aggfunc="mean",
    )
    save_line(
        loss_success,
        "丢包率",
        "恢复成功率",
        "弱网模拟：不同丢包率下的恢复成功率",
        os.path.join(OUTPUT_DIR, "weak_fig1_loss_rate_recovery_success.png"),
    )

    loss_memory = df.pivot_table(
        index="loss_rate",
        columns="protocol",
        values="memory_match_rate",
        aggfunc="mean",
    )
    save_line(
        loss_memory,
        "丢包率",
        "记忆一致率",
        "弱网模拟：不同丢包率下的记忆一致性",
        os.path.join(OUTPUT_DIR, "weak_fig2_loss_rate_memory_match.png"),
    )

    delay_latency = df.pivot_table(
        index="delay_ms",
        columns="protocol",
        values="avg_recovery_latency_ms",
        aggfunc="mean",
    )
    save_line(
        delay_latency,
        "网络时延（ms）",
        "平均恢复时延（ms）",
        "弱网模拟：网络时延对恢复时延的影响",
        os.path.join(OUTPUT_DIR, "weak_fig3_delay_recovery_latency.png"),
    )

    reorder_detection = df.pivot_table(
        index="reorder_rate",
        columns="protocol",
        values="attack_detection_rate",
        aggfunc="mean",
    )
    save_line(
        reorder_detection,
        "乱序率",
        "攻击检测率",
        "弱网模拟：乱序条件下的攻击检测率",
        os.path.join(OUTPUT_DIR, "weak_fig4_reorder_attack_detection.png"),
    )

    extra_bytes = df.pivot_table(
        index="loss_rate",
        columns="protocol",
        values="extra_bytes",
        aggfunc="mean",
    )
    save_line(
        extra_bytes,
        "丢包率",
        "额外通信开销（字节）",
        "弱网模拟：丢包条件下的额外通信开销",
        os.path.join(OUTPUT_DIR, "weak_fig5_extra_bytes_under_loss.png"),
    )

    throughput = df.pivot_table(
        index="loss_rate",
        columns="protocol",
        values="throughput_score",
        aggfunc="mean",
    )
    save_line(
        throughput,
        "丢包率",
        "相对吞吐评分",
        "弱网模拟：不同丢包率下的吞吐表现",
        os.path.join(OUTPUT_DIR, "weak_fig6_throughput_under_weak_network.png"),
    )

    summary = df.groupby("protocol").agg(
        delivery_success_rate_mean=("delivery_success_rate", "mean"),
        recovery_success_rate_mean=("recovery_success_rate", "mean"),
        recovery_success_rate_std=("recovery_success_rate", "std"),
        memory_match_rate_mean=("memory_match_rate", "mean"),
        attack_detection_rate_mean=("attack_detection_rate", "mean"),
        avg_recovery_latency_ms_mean=("avg_recovery_latency_ms", "mean"),
        avg_recovery_latency_ms_std=("avg_recovery_latency_ms", "std"),
        extra_messages_mean=("extra_messages", "mean"),
        extra_bytes_mean=("extra_bytes", "mean"),
        throughput_score_mean=("throughput_score", "mean"),
    )
    summary.to_csv(SUMMARY_CSV, encoding="utf-8")

    print("[WEAK_NETWORK_PLOT] figures saved to", OUTPUT_DIR)
    print("[WEAK_NETWORK_PLOT] summary saved to", SUMMARY_CSV)


if __name__ == "__main__":
    main()
