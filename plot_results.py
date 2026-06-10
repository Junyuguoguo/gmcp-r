# -*- coding: utf-8 -*-
# plot_results.py

import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


def ensure_output_dir(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)


def clean_old_figures(output_dir: str):
    for path in glob.glob(os.path.join(output_dir, "*.png")):
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


def save_line_table(table, xlabel, ylabel, title, output_path):
    plt.figure(figsize=(8, 5))
    table.plot(kind="line", marker="o")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def save_grouped_bar(table, xlabel, ylabel, title, output_path, rotation=45):
    plt.figure(figsize=(9, 5))
    table.plot(kind="bar")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=rotation)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def bool_mean(series):
    return series.astype(int).mean()


def main():
    input_path = "results/experiment_results.csv"
    output_dir = "results/figures"

    ensure_output_dir(output_dir)
    clean_old_figures(output_dir)

    df = pd.read_csv(input_path)

    # 兼容 True/False 被读成 bool 或 str 的情况
    if df["recovery_success"].dtype == object:
        df["recovery_success_bool"] = df["recovery_success"].astype(str).str.lower() == "true"
    else:
        df["recovery_success_bool"] = df["recovery_success"].astype(bool)

    if df["memory_recovered"].dtype == object:
        df["memory_recovered_bool"] = df["memory_recovered"].astype(str).str.lower() == "true"
    else:
        df["memory_recovered_bool"] = df["memory_recovered"].astype(bool)

    formal_df = df[df["scenario"] == "formal_v2"]
    weak_df = df[df["scenario"] == "weak_net"]

    normal_df = formal_df[formal_df["attack_type"] == "none"]

    attack_df = formal_df[
        (formal_df["attack_type"] != "none")
        & (formal_df["detection_result"] != "not_applicable")
    ]

    # 图 1：不同协议恢复时延
    fig1 = normal_df.groupby("protocol")["recovery_latency_ms"].mean()
    save_bar(
        fig1,
        "Protocol",
        "Recovery latency (ms)",
        "Fig.1 Average Recovery Latency by Protocol",
        os.path.join(output_dir, "fig1_recovery_latency_by_protocol.png"),
    )

    # 图 2：GMCP-R checkpoint 间隔对恢复时延影响
    gmcp_normal = normal_df[normal_df["protocol"] == "gmcp_r"]
    fig2 = gmcp_normal.groupby("checkpoint_interval")["recovery_latency_ms"].mean()
    save_bar(
        fig2,
        "Checkpoint interval",
        "Recovery latency (ms)",
        "Fig.2 GMCP-R Recovery Latency under Different Checkpoint Intervals",
        os.path.join(output_dir, "fig2_checkpoint_interval_latency.png"),
        rotation=0,
    )

    # 图 3：不同协议攻击检测率
    fig3 = attack_df.groupby("protocol")["detection_result"].apply(
        lambda x: (x == "detected").sum() / len(x) if len(x) > 0 else 0
    )
    save_bar(
        fig3,
        "Protocol",
        "Detection rate",
        "Fig.3 Attack Detection Rate by Protocol",
        os.path.join(output_dir, "fig3_detection_rate_by_protocol.png"),
    )

    # 图 4：GMCP-R 对不同攻击类型的检测率
    gmcp_attack = attack_df[attack_df["protocol"] == "gmcp_r"]
    fig4 = gmcp_attack.groupby("attack_type")["detection_result"].apply(
        lambda x: (x == "detected").sum() / len(x) if len(x) > 0 else 0
    )
    save_bar(
        fig4,
        "Attack type",
        "Detection rate",
        "Fig.4 GMCP-R Detection Rate by Attack Type",
        os.path.join(output_dir, "fig4_gmcp_detection_rate_by_attack.png"),
    )

    # 图 5：不同协议平均额外通信开销
    fig5 = formal_df.groupby("protocol")["extra_bytes"].mean()
    save_bar(
        fig5,
        "Protocol",
        "Extra bytes",
        "Fig.5 Average Extra Communication Overhead by Protocol",
        os.path.join(output_dir, "fig5_extra_bytes_by_protocol.png"),
    )

    # 图 6：不同协议吞吐量
    fig6 = normal_df.groupby("protocol")["throughput_msg_per_s"].mean()
    save_bar(
        fig6,
        "Protocol",
        "Throughput (msg/s)",
        "Fig.6 Average Throughput by Protocol",
        os.path.join(output_dir, "fig6_throughput_by_protocol.png"),
    )

    # 图 7：不同协议是否能恢复历史记忆状态
    fig7 = formal_df.groupby("protocol")["memory_recovered_bool"].mean()
    save_bar(
        fig7,
        "Protocol",
        "Memory recovery rate",
        "Fig.7 Memory State Recovery Capability by Protocol",
        os.path.join(output_dir, "fig7_memory_recovery_rate_by_protocol.png"),
    )

    # 图 8：弱网丢包率对恢复成功率影响
    if not weak_df.empty:
        fig8 = weak_df.pivot_table(
            index="loss_rate",
            columns="protocol",
            values="recovery_success_bool",
            aggfunc=lambda x: x.astype(int).mean(),
        )
        save_line_table(
            fig8,
            "Loss rate",
            "Recovery success rate",
            "Fig.8 Recovery Success Rate under Different Loss Rates",
            os.path.join(output_dir, "fig8_loss_rate_recovery_success.png"),
        )

    # 图 9：checkpoint 间隔对 replay_count 的影响
    fig9 = gmcp_normal.groupby("checkpoint_interval")["recovery_replay_count"].mean()
    save_bar(
        fig9,
        "Checkpoint interval",
        "Replay count",
        "Fig.9 GMCP-R Replay Count under Different Checkpoint Intervals",
        os.path.join(output_dir, "fig9_checkpoint_interval_replay_count.png"),
        rotation=0,
    )

    # 额外生成 summary 表
    summary = formal_df.groupby("protocol").agg(
        recovery_latency_ms=("recovery_latency_ms", "mean"),
        detection_security_score=("security_score", "mean"),
        extra_bytes=("extra_bytes", "mean"),
        throughput_msg_per_s=("throughput_msg_per_s", "mean"),
        memory_recovery_rate=("memory_recovered_bool", "mean"),
    )

    summary.to_csv("results/summary_by_protocol.csv", encoding="utf-8")

    print("[PLOT] figures saved to", output_dir)
    print("[PLOT] summary saved to results/summary_by_protocol.csv")


if __name__ == "__main__":
    main()