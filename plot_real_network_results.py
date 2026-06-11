# -*- coding: utf-8 -*-
# plot_real_network_results.py

import os
import glob

import pandas as pd
import matplotlib.pyplot as plt


INPUT_CSV = "results/real_network/real_network_results.csv"
OUTPUT_DIR = "results/real_network/figures"


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

    # 兼容 bool / str
    df["attack_detected_bool"] = df["attack_detected"].astype(str).str.lower() == "true"
    df["recovery_success_bool"] = df["recovery_success"].astype(str).str.lower() == "true"
    df["server_reachable_bool"] = df["server_reachable"].astype(str).str.lower() == "true"

    normal_df = df[df["attack_type"] == "none"]
    attack_df = df[df["attack_type"] != "none"]

    # 图 1：不同消息规模下真实网络平均 RTT
    fig1 = normal_df.groupby("message_count")["avg_rtt_ms"].mean()
    save_bar(
        fig1,
        "Message count",
        "Average RTT (ms)",
        "Real Network Average RTT by Message Count",
        os.path.join(OUTPUT_DIR, "real_fig1_avg_rtt_by_message_count.png"),
        rotation=0,
    )

    # 图 2：不同 payload 大小下真实网络吞吐量
    fig2 = normal_df.groupby("payload_size")["throughput_msg_per_s"].mean()
    save_bar(
        fig2,
        "Payload size",
        "Throughput (msg/s)",
        "Real Network Throughput by Payload Size",
        os.path.join(OUTPUT_DIR, "real_fig2_throughput_by_payload_size.png"),
        rotation=0,
    )

    # 图 3：不同攻击类型检测率
    fig3 = attack_df.groupby("attack_type")["attack_detected_bool"].mean()
    save_bar(
        fig3,
        "Attack type",
        "Detection rate",
        "Real Network Attack Detection Rate by Attack Type",
        os.path.join(OUTPUT_DIR, "real_fig3_detection_rate_by_attack_type.png"),
    )

    # 图 4：不同攻击类型下服务端拒绝数量
    fig4 = attack_df.groupby("attack_type")["rejected_count"].mean()
    save_bar(
        fig4,
        "Attack type",
        "Average rejected count",
        "Real Network Rejected Count by Attack Type",
        os.path.join(OUTPUT_DIR, "real_fig4_rejected_count_by_attack_type.png"),
    )

    # 图 5：不同消息规模下真实网络吞吐量趋势
    fig5 = normal_df.pivot_table(
        index="message_count",
        columns="payload_size",
        values="throughput_msg_per_s",
        aggfunc="mean",
    )
    save_line(
        fig5,
        "Message count",
        "Throughput (msg/s)",
        "Real Network Throughput under Different Payload Sizes",
        os.path.join(OUTPUT_DIR, "real_fig5_throughput_trend.png"),
    )

    # 图 6：正常通信成功率
    fig6 = normal_df.groupby("message_count")["recovery_success_bool"].mean()
    save_bar(
        fig6,
        "Message count",
        "Success rate",
        "Real Network Normal Communication Success Rate",
        os.path.join(OUTPUT_DIR, "real_fig6_normal_success_rate.png"),
        rotation=0,
    )

    summary = df.groupby("attack_type").agg(
        avg_rtt_ms=("avg_rtt_ms", "mean"),
        throughput_msg_per_s=("throughput_msg_per_s", "mean"),
        accepted_count=("accepted_count", "mean"),
        rejected_count=("rejected_count", "mean"),
        timeout_count=("timeout_count", "mean"),
        detection_rate=("attack_detected_bool", "mean"),
    )

    summary.to_csv("results/real_network/summary_real_network.csv", encoding="utf-8")

    print("[REAL_PLOT] figures saved to", OUTPUT_DIR)
    print("[REAL_PLOT] summary saved to results/real_network/summary_real_network.csv")


if __name__ == "__main__":
    main()