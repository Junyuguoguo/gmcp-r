# run_experiment.py

from gmcp.metrics import MetricsRecorder


def run_single_experiment(
    protocol: str,
    scenario: str,
    message_count: int,
    checkpoint_interval: int,
    attack_type: str,
):
    """
    这里后续接入真正的 client/server 运行逻辑。
    第一版可以先返回模拟结果，保证 CSV 流程跑通。
    """

    result = {
        "protocol": protocol,
        "scenario": scenario,
        "message_count": message_count,
        "payload_size": 128,
        "loss_rate": 0,
        "reorder_rate": 0,
        "checkpoint_interval": checkpoint_interval,
        "attack_type": attack_type,
        "recovery_success": True,
        "recovery_latency_ms": 0,
        "accepted_count": message_count,
        "rejected_count": 0,
        "detection_result": "detected" if attack_type != "none" else "normal",
        "extra_messages": 0,
        "extra_bytes": 0,
        "throughput_msg_per_s": 0,
    }

    return result


def main():
    recorder = MetricsRecorder("results/experiment_results.csv")

    protocols = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]
    attacks = ["none", "drop", "modify", "replay", "rollback_ticket"]
    message_counts = [1000, 5000, 10000]
    checkpoint_intervals = [50, 100, 500, 1000]

    for protocol in protocols:
        for attack in attacks:
            for count in message_counts:
                for cp_interval in checkpoint_intervals:
                    row = run_single_experiment(
                        protocol=protocol,
                        scenario="basic",
                        message_count=count,
                        checkpoint_interval=cp_interval,
                        attack_type=attack,
                    )
                    recorder.add_row(row)

    recorder.save()
    print("[EXPERIMENT] results saved to results/experiment_results.csv")


if __name__ == "__main__":
    main()