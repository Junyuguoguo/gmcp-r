# -*- coding: utf-8 -*-
# plot_results.py

import os
import glob
import pandas as pd

from gmcp.plot_style import save_bar_chart, save_line_chart


def ensure_output_dir(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)


def clean_old_figures(output_dir: str):
    for path in glob.glob(os.path.join(output_dir, "*.png")):
        os.remove(path)


def save_bar(series, xlabel, ylabel, title, output_path, rotation=45):
    save_bar_chart(series, xlabel, ylabel, title, output_path, rotation=rotation)


def save_line_table(table, xlabel, ylabel, title, output_path):
    save_line_chart(table, xlabel, ylabel, title, output_path)


def save_grouped_bar(table, xlabel, ylabel, title, output_path, rotation=45):
    save_line_chart(table, xlabel, ylabel, title, output_path, figsize=(9, 5))


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
        df["recovery_success_bool"] = (
            df["recovery_success"].astype(str).str.lower() == "true"
        ).astype(int)
    else:
        df["recovery_success_bool"] = df["recovery_success"].astype(bool).astype(int)

    if df["memory_recovered"].dtype == object:
        df["memory_recovered_bool"] = (
            df["memory_recovered"].astype(str).str.lower() == "true"
        ).astype(int)
    else:
        df["memory_recovered_bool"] = df["memory_recovered"].astype(bool).astype(int)

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
        "协议类型",
        "恢复时延（ms）",
        "图1 不同协议的平均恢复时延",
        os.path.join(output_dir, "fig1_recovery_latency_by_protocol.png"),
    )

    # 图 2：GMCP-R checkpoint 间隔对恢复时延影响
    gmcp_normal = normal_df[normal_df["protocol"] == "gmcp_r"]
    fig2 = gmcp_normal.groupby("checkpoint_interval")["recovery_latency_ms"].mean()
    save_bar(
        fig2,
        "检查点间隔",
        "恢复时延（ms）",
        "图2 GMCP-R 在不同检查点间隔下的恢复时延",
        os.path.join(output_dir, "fig2_checkpoint_interval_latency.png"),
        rotation=0,
    )

    # 图 3：不同协议攻击检测率
    fig3 = attack_df.groupby("protocol")["detection_result"].apply(
        lambda x: (x == "detected").sum() / len(x) if len(x) > 0 else 0
    )
    save_bar(
        fig3,
        "协议类型",
        "检测率",
        "图3 不同协议的攻击检测率",
        os.path.join(output_dir, "fig3_detection_rate_by_protocol.png"),
    )

    # 图 4：GMCP-R 对不同攻击类型的检测率
    gmcp_attack = attack_df[attack_df["protocol"] == "gmcp_r"]
    fig4 = gmcp_attack.groupby("attack_type")["detection_result"].apply(
        lambda x: (x == "detected").sum() / len(x) if len(x) > 0 else 0
    )
    save_bar(
        fig4,
        "攻击类型",
        "检测率",
        "图4 GMCP-R 对不同攻击类型的检测率",
        os.path.join(output_dir, "fig4_gmcp_detection_rate_by_attack.png"),
    )

    # 图 5：不同协议平均额外通信开销
    fig5 = formal_df.groupby("protocol")["extra_bytes"].mean()
    save_bar(
        fig5,
        "协议类型",
        "额外通信开销（字节）",
        "图5 不同协议的平均额外通信开销",
        os.path.join(output_dir, "fig5_extra_bytes_by_protocol.png"),
    )

    # 图 6：不同协议吞吐量
    fig6 = normal_df.groupby("protocol")["throughput_msg_per_s"].mean()
    save_bar(
        fig6,
        "协议类型",
        "吞吐量（条/秒）",
        "图6 不同协议的平均吞吐量",
        os.path.join(output_dir, "fig6_throughput_by_protocol.png"),
    )

    # 图 7：不同协议是否能恢复历史记忆状态
    fig7 = formal_df.groupby("protocol")["memory_recovered_bool"].mean()
    save_bar(
        fig7,
        "协议类型",
        "记忆恢复率",
        "图7 不同协议的记忆状态恢复能力",
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
            "丢包率",
            "恢复成功率",
            "图8 不同丢包率下的恢复成功率",
            os.path.join(output_dir, "fig8_loss_rate_recovery_success.png"),
        )

    # 图 9：checkpoint 间隔对 replay_count 的影响
    fig9 = gmcp_normal.groupby("checkpoint_interval")["recovery_replay_count"].mean()
    save_bar(
        fig9,
        "检查点间隔",
        "回放消息数量",
        "图9 GMCP-R 在不同检查点间隔下的回放数量",
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
