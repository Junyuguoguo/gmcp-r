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


def flatten_columns(columns):
    return [
        "_".join([str(part) for part in col if str(part)])
        if isinstance(col, tuple)
        else str(col)
        for col in columns
    ]


def main():
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)

    # 兼容 bool / str
    df["attack_detected_bool"] = (df["attack_detected"].astype(str).str.lower() == "true").astype(int)
    df["recovery_success_bool"] = (df["recovery_success"].astype(str).str.lower() == "true").astype(int)
    df["server_reachable_bool"] = (df["server_reachable"].astype(str).str.lower() == "true").astype(int)
    if "p50_rtt_ms" not in df.columns:
        df["p50_rtt_ms"] = df["avg_rtt_ms"]
    if "p95_rtt_ms" not in df.columns:
        df["p95_rtt_ms"] = df["max_rtt_ms"]

    normal_df = df[df["attack_type"] == "none"]
    attack_df = df[df["attack_type"] != "none"]

    # avg_rtt_ms is Application-level RTT measured by DATA request/response.
    fig1 = normal_df.groupby("message_count")["avg_rtt_ms"].mean()
    save_bar(
        fig1,
        "Message count",
        "Application RTT (ms)",
        "Real Network Application-level RTT by Message Count",
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
        avg_rtt_ms_mean=("avg_rtt_ms", "mean"),
        avg_rtt_ms_std=("avg_rtt_ms", "std"),
        avg_rtt_ms_min=("avg_rtt_ms", "min"),
        avg_rtt_ms_max=("avg_rtt_ms", "max"),
        p50_rtt_ms_mean=("p50_rtt_ms", "mean"),
        p95_rtt_ms_mean=("p95_rtt_ms", "mean"),
        throughput_msg_per_s_mean=("throughput_msg_per_s", "mean"),
        throughput_msg_per_s_std=("throughput_msg_per_s", "std"),
        throughput_msg_per_s_min=("throughput_msg_per_s", "min"),
        throughput_msg_per_s_max=("throughput_msg_per_s", "max"),
        accepted_count_mean=("accepted_count", "mean"),
        rejected_count_mean=("rejected_count", "mean"),
        timeout_count_mean=("timeout_count", "mean"),
        detection_rate=("attack_detected_bool", "mean"),
    )

    summary.to_csv("results/real_network/summary_real_network.csv", encoding="utf-8")

    print("[REAL_PLOT] figures saved to", OUTPUT_DIR)
    print("[REAL_PLOT] summary saved to results/real_network/summary_real_network.csv")


if __name__ == "__main__":
    main()
