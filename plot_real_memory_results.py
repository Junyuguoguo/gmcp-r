# -*- coding: utf-8 -*-
# plot_real_memory_results.py

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


INPUT_CSV = "results/real_network/real_network_results.csv"
OUTPUT_DIR = "results/real_network/memory_figures"


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


def save_window_tradeoff(table, output_path):
    plt.figure(figsize=(8, 5))
    ax1 = plt.gca()
    ax1.plot(
        table.index,
        table["throughput_msg_per_s"],
        marker="o",
        color="tab:blue",
        label="Throughput",
    )
    ax1.set_xlabel("Window size")
    ax1.set_ylabel("Throughput (msg/s)", color="tab:blue")
    ax1.tick_params(axis="y", labelcolor="tab:blue")
    ax1.grid(True, linestyle="--", alpha=0.4)

    ax2 = ax1.twinx()
    ax2.plot(
        table.index,
        table["avg_rtt_ms"],
        marker="s",
        color="tab:red",
        label="Application-level RTT",
    )
    ax2.set_ylabel("Application RTT (ms)", color="tab:red")
    ax2.tick_params(axis="y", labelcolor="tab:red")

    plt.title("Sliding Window Latency-Throughput Tradeoff")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


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
        "Message count",
        "Memory match rate",
        "Memory State Match Rate under Normal Communication",
        os.path.join(OUTPUT_DIR, "memory_fig1_memory_match_rate.png"),
        rotation=0,
    )

    # 图2：正常通信下 memory verified rate
    fig2 = normal_df.groupby("message_count")["memory_verified_bool"].mean()
    save_bar(
        fig2,
        "Message count",
        "Memory verified rate",
        "Memory Verification Rate under Normal Communication",
        os.path.join(OUTPUT_DIR, "memory_fig2_memory_verified_rate.png"),
        rotation=0,
    )

    # 图3：prev_mem 记忆断裂攻击检测率
    fig3 = prev_mem_df.groupby("message_count")["attack_detected_bool"].mean()
    save_bar(
        fig3,
        "Message count",
        "Detection rate",
        "Memory Break Detection Rate under prev_mem Attack",
        os.path.join(OUTPUT_DIR, "memory_fig3_prev_mem_detection_rate.png"),
        rotation=0,
    )

    # 图4：不同滑动窗口下吞吐量
    fig4 = normal_df.groupby("window_size")["throughput_msg_per_s"].mean()
    save_bar(
        fig4,
        "Window size",
        "Throughput (msg/s)",
        "Throughput under Different Sliding Window Sizes",
        os.path.join(OUTPUT_DIR, "memory_fig4_window_throughput.png"),
        rotation=0,
    )

    # 图5：不同滑动窗口下 RTT
    fig5 = normal_df.groupby("window_size")["avg_rtt_ms"].mean()
    save_bar(
        fig5,
        "Window size",
        "Application RTT (ms)",
        "Application-level RTT under Different Sliding Window Sizes",
        os.path.join(OUTPUT_DIR, "memory_fig5_window_rtt.png"),
        rotation=0,
    )

    # 图6：不同窗口下 memory match rate
    fig6 = normal_df.groupby("window_size")["memory_match_bool"].mean()
    save_bar(
        fig6,
        "Window size",
        "Memory match rate",
        "Memory Match Rate under Sliding Window Transmission",
        os.path.join(OUTPUT_DIR, "memory_fig6_window_memory_match.png"),
        rotation=0,
    )

    # 图7：最终序号一致性
    fig7 = normal_df.groupby("message_count")["seq_consistent_bool"].mean()
    save_bar(
        fig7,
        "Message count",
        "Final seq consistency rate",
        "Final Sequence Consistency under Memory Communication",
        os.path.join(OUTPUT_DIR, "memory_fig7_final_seq_consistency.png"),
        rotation=0,
    )

    # 图8：不同攻击类型检测率
    fig8 = attack_df.groupby("attack_type")["attack_detected_bool"].mean()
    save_bar(
        fig8,
        "Attack type",
        "Detection rate",
        "Memory-Aware Attack Detection Rate by Attack Type",
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
