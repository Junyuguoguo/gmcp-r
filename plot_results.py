# plot_results.py

import os
import pandas as pd
import matplotlib.pyplot as plt


def main():
    input_path = "results/experiment_results.csv"
    output_dir = "results/figures"
    os.makedirs(output_dir, exist_ok=True)

    df = pd.read_csv(input_path)

    # 图 1：不同协议恢复时延
    grouped = df.groupby("protocol")["recovery_latency_ms"].mean()

    plt.figure()
    grouped.plot(kind="bar")
    plt.xlabel("Protocol")
    plt.ylabel("Recovery Latency (ms)")
    plt.title("Average Recovery Latency by Protocol")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "recovery_latency_by_protocol.png"))
    plt.close()

    # 图 2：不同协议攻击检测情况
    attack_df = df[df["attack_type"] != "none"]
    detection_count = attack_df.groupby("protocol")["detection_result"].count()

    plt.figure()
    detection_count.plot(kind="bar")
    plt.xlabel("Protocol")
    plt.ylabel("Detection Count")
    plt.title("Attack Detection Count by Protocol")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "attack_detection_by_protocol.png"))
    plt.close()

    print(f"[PLOT] figures saved to {output_dir}")


if __name__ == "__main__":
    main()