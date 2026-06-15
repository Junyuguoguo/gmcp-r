# -*- coding: utf-8 -*-
# plot_real_memory_results.py

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt

from gmcp.plot_style import ACADEMIC_COLORS, save_bar_chart, save_line_chart, setup_chinese_academic_style


INPUT_CSV = "results/real_network/real_network_results.csv"
OUTPUT_DIR = "results/real_network/memory_figures"


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_old_figures():
    for path in glob.glob(os.path.join(OUTPUT_DIR, "*.png")):
        os.remove(path)


def save_bar(series, xlabel, ylabel, title, output_path, rotation=45):
    save_bar_chart(series, xlabel, ylabel, title, output_path, rotation=rotation)


def save_line(table, xlabel, ylabel, title, output_path):
    save_line_chart(table, xlabel, ylabel, title, output_path)


def save_window_tradeoff(table, output_path):
    setup_chinese_academic_style()
    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax1.plot(
        table.index,
        table["throughput_msg_per_s"],
        marker="o",
        color=ACADEMIC_COLORS[0],
        linewidth=2.4,
        label="吞吐量",
    )
    ax1.set_xlabel("滑动窗口大小")
    ax1.set_ylabel("吞吐量（条/秒）", color=ACADEMIC_COLORS[0])
    ax1.tick_params(axis="y", labelcolor=ACADEMIC_COLORS[0])
    ax1.grid(axis="y", color="#D9DEE7", linestyle="--", linewidth=0.7, alpha=0.8)
    ax1.spines["top"].set_visible(False)

    ax2 = ax1.twinx()
    ax2.plot(
        table.index,
        table["avg_rtt_ms"],
        marker="s",
        color=ACADEMIC_COLORS[1],
        linewidth=2.4,
        label="应用层 RTT",
    )
    ax2.set_ylabel("应用层 RTT（ms）", color=ACADEMIC_COLORS[1])
    ax2.tick_params(axis="y", labelcolor=ACADEMIC_COLORS[1])
    ax2.spines["top"].set_visible(False)

    lines = ax1.get_lines() + ax2.get_lines()
    labels = [line.get_label() for line in lines]
    ax1.legend(lines, labels, loc="best", frameon=False)
    plt.title("滑动窗口：时延与吞吐量权衡", pad=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)


def main():
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)

    df["memory_match_bool"] = (df["memory_match"].astype(str).str.lower() == "true").astype(int)
    df["memory_verified_bool"] = (df["memory_verified"].astype(str).str.lower() == "true").astype(int)
    df["attack_detected_bool"] = (df["attack_detected"].astype(str).str.lower() == "true").astype(int)
    df["seq_consistent_bool"] = (df["seq_consistent"].astype(str).str.lower() == "true").astype(int)

    normal_df = df[df["attack_type"] == "none"]
    attack_df = df[df["attack_type"] != "none"]
    prev_mem_df = df[df["attack_type"] == "prev_mem"]

    # 图1：正常通信下 memory state 是否一致
    fig1 = normal_df.groupby("message_count")["memory_match_bool"].mean()
    save_bar(
        fig1,
        "消息数量",
        "记忆一致率",
        "真实网络：正常通信下的记忆状态一致率",
        os.path.join(OUTPUT_DIR, "memory_fig1_memory_match_rate.png"),
        rotation=0,
    )

    # 图2：正常通信下 memory verified rate
    fig2 = normal_df.groupby("message_count")["memory_verified_bool"].mean()
    save_bar(
        fig2,
        "消息数量",
        "记忆验证率",
        "真实网络：正常通信下的记忆验证率",
        os.path.join(OUTPUT_DIR, "memory_fig2_memory_verified_rate.png"),
        rotation=0,
    )

    # 图3：prev_mem 记忆断裂攻击检测率
    fig3 = prev_mem_df.groupby("message_count")["attack_detected_bool"].mean()
    save_bar(
        fig3,
        "消息数量",
        "检测率",
        "真实网络：记忆断裂攻击检测率",
        os.path.join(OUTPUT_DIR, "memory_fig3_prev_mem_detection_rate.png"),
        rotation=0,
    )

    # 图4：不同滑动窗口下吞吐量
    fig4 = normal_df.groupby("window_size")["throughput_msg_per_s"].mean()
    save_bar(
        fig4,
        "滑动窗口大小",
        "吞吐量（条/秒）",
        "真实网络：不同滑动窗口下的吞吐量",
        os.path.join(OUTPUT_DIR, "memory_fig4_window_throughput.png"),
        rotation=0,
    )

    # 图5：不同滑动窗口下 RTT
    fig5 = normal_df.groupby("window_size")["avg_rtt_ms"].mean()
    save_bar(
        fig5,
        "滑动窗口大小",
        "应用层 RTT（ms）",
        "真实网络：不同滑动窗口下的应用层 RTT",
        os.path.join(OUTPUT_DIR, "memory_fig5_window_rtt.png"),
        rotation=0,
    )

    # 图6：不同窗口下 memory match rate
    fig6 = normal_df.groupby("window_size")["memory_match_bool"].mean()
    save_bar(
        fig6,
        "滑动窗口大小",
        "记忆一致率",
        "真实网络：滑动窗口传输下的记忆一致率",
        os.path.join(OUTPUT_DIR, "memory_fig6_window_memory_match.png"),
        rotation=0,
    )

    # 图7：最终序号一致性
    fig7 = normal_df.groupby("message_count")["seq_consistent_bool"].mean()
    save_bar(
        fig7,
        "消息数量",
        "最终序号一致率",
        "真实网络：有记忆通信下的最终序号一致性",
        os.path.join(OUTPUT_DIR, "memory_fig7_final_seq_consistency.png"),
        rotation=0,
    )

    # 图8：不同攻击类型检测率
    fig8 = attack_df.groupby("attack_type")["attack_detected_bool"].mean()
    save_bar(
        fig8,
        "攻击类型",
        "检测率",
        "真实网络：面向记忆状态的攻击检测率",
        os.path.join(OUTPUT_DIR, "memory_fig8_attack_detection_rate.png"),
        rotation=45,
    )

    tradeoff = normal_df.groupby("window_size").agg(
        throughput_msg_per_s=("throughput_msg_per_s", "mean"),
        avg_rtt_ms=("avg_rtt_ms", "mean"),
    )
    save_window_tradeoff(
        tradeoff,
        os.path.join(OUTPUT_DIR, "memory_fig9_window_latency_throughput_tradeoff.png"),
    )

    summary = {
        "normal_memory_match_rate": normal_df["memory_match_bool"].mean(),
        "normal_memory_verified_rate": normal_df["memory_verified_bool"].mean(),
        "prev_mem_detection_rate": prev_mem_df["attack_detected_bool"].mean(),
        "all_attack_detection_rate": attack_df["attack_detected_bool"].mean(),
        "seq_consistency_rate": normal_df["seq_consistent_bool"].mean(),
        "avg_throughput": normal_df["throughput_msg_per_s"].mean(),
        "avg_rtt_ms": normal_df["avg_rtt_ms"].mean(),
        "std_throughput": normal_df["throughput_msg_per_s"].std(),
        "min_throughput": normal_df["throughput_msg_per_s"].min(),
        "max_throughput": normal_df["throughput_msg_per_s"].max(),
        "std_rtt_ms": normal_df["avg_rtt_ms"].std(),
        "min_rtt_ms": normal_df["avg_rtt_ms"].min(),
        "max_rtt_ms": normal_df["avg_rtt_ms"].max(),
    }

    pd.DataFrame([summary]).to_csv(
        "results/real_network/summary_real_memory.csv",
        index=False,
        encoding="utf-8",
    )

    print("[REAL_MEMORY_PLOT] figures saved to", OUTPUT_DIR)
    print("[REAL_MEMORY_PLOT] summary saved to results/real_network/summary_real_memory.csv")


if __name__ == "__main__":
    main()
