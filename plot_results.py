# plot_results.py

import os
import pandas as pd
import matplotlib.pyplot as plt


def save_bar(series, xlabel, ylabel, title, output_path):
    plt.figure()
    series.plot(kind="bar")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def main():
    input_path = "results/experiment_results.csv"
    output_dir = "results/figures"
    os.makedirs(output_dir, exist_ok=True)

    df = pd.read_csv(input_path)

    # 图 1：不同协议平均恢复时延
    normal_df = df[df["attack_type"] == "none"]
    latency_by_protocol = normal_df.groupby("protocol")["recovery_latency_ms"].mean()
    save_bar(
        latency_by_protocol,
        "Protocol",
        "Recovery Latency (ms)",
        "Average Recovery Latency by Protocol",
        os.path.join(output_dir, "fig1_recovery_latency_by_protocol.png"),
    )

    # 图 2：GMCP-R 检查点间隔对恢复时延影响
    gmcp_df = normal_df[normal_df["protocol"] == "gmcp_r"]
    cp_latency = gmcp_df.groupby("checkpoint_interval")["recovery_latency_ms"].mean()
    save_bar(
        cp_latency,
        "Checkpoint Interval",
        "Recovery Latency (ms)",
        "GMCP-R Recovery Latency under Different Checkpoint Intervals",
        os.path.join(output_dir, "fig2_checkpoint_interval_latency.png"),
    )

    # 图 3：不同协议攻击检测率
    attack_df = df[df["attack_type"] != "none"]
    attack_df = attack_df[attack_df["detection_result"] != "not_applicable"]

    detection_rate = attack_df.groupby("protocol")["detection_result"].apply(
        lambda x: (x == "detected").sum() / len(x) if len(x) > 0 else 0
    )

    save_bar(
        detection_rate,
        "Protocol",
        "Detection Rate",
        "Attack Detection Rate by Protocol",
        os.path.join(output_dir, "fig3_detection_rate_by_protocol.png"),
    )

    # 图 4：不同协议平均额外通信开销
    extra_bytes = df.groupby("protocol")["extra_bytes"].mean()
    save_bar(
        extra_bytes,
        "Protocol",
        "Extra Bytes",
        "Average Extra Communication Overhead by Protocol",
        os.path.join(output_dir, "fig4_extra_bytes_by_protocol.png"),
    )

    # 图 5：不同协议吞吐量
    throughput = normal_df.groupby("protocol")["throughput_msg_per_s"].mean()
    save_bar(
        throughput,
        "Protocol",
        "Throughput (msg/s)",
        "Average Throughput by Protocol",
        os.path.join(output_dir, "fig5_throughput_by_protocol.png"),
    )

    print("[PLOT] figures saved to", output_dir)


if __name__ == "__main__":
    main()