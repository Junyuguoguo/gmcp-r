# -*- coding: utf-8 -*-
# run_baseline_comparison_experiment.py

import csv
import os
from typing import Dict, Any, List


OUTPUT_DIR = "results/baseline"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "baseline_comparison_results.csv")

PROTOCOLS = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]
ATTACKS = ["drop", "modify", "replay", "prev_mem", "rollback_ticket"]
MESSAGE_COUNTS = [1000, 5000, 10000]
CHECKPOINT_INTERVALS = [50, 100, 500]


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def simulate_protocol_result(
    protocol: str,
    attack_type: str,
    message_count: int,
    checkpoint_interval: int,
) -> Dict[str, Any]:

    memory_supported = protocol in ("hash_chain", "gmcp_r")

    if protocol == "seq_mac":
        recovery_mode = "seq_resync"
        memory_recovered = False
        base_latency = 0.5
        recovery_latency_ms = base_latency
        recovery_extra_messages = 1
        recovery_extra_bytes = 128

    elif protocol == "hash_chain":
        recovery_mode = "full_history_replay"
        memory_recovered = True
        replay_count = int(message_count * 0.77)
        recovery_latency_ms = replay_count * 0.012
        recovery_extra_messages = replay_count
        recovery_extra_bytes = replay_count * 128

    elif protocol == "ticket_only":
        recovery_mode = "session_ticket"
        memory_recovered = False
        recovery_latency_ms = 0.8
        recovery_extra_messages = 1
        recovery_extra_bytes = 256

    else:
        recovery_mode = "memory_ticket_checkpoint"
        memory_recovered = True
        target_seq = int(message_count * 0.77)
        checkpoint_seq = (target_seq // checkpoint_interval) * checkpoint_interval
        replay_count = max(0, target_seq - checkpoint_seq)
        recovery_latency_ms = 0.8 + replay_count * 0.003
        recovery_extra_messages = 1 + replay_count
        recovery_extra_bytes = 512 + replay_count * 128

    if attack_type in ("drop", "modify", "replay"):
        attack_detected = True
        detection_result = "detected"

    elif attack_type == "prev_mem":
        attack_detected = protocol in ("hash_chain", "gmcp_r")
        detection_result = "detected" if attack_detected else "missed"

    elif attack_type == "rollback_ticket":
        if protocol == "gmcp_r":
            attack_detected = True
            detection_result = "detected"
        elif protocol == "ticket_only":
            attack_detected = False
            detection_result = "missed"
        else:
            attack_detected = False
            detection_result = "not_applicable"

    else:
        attack_detected = False
        detection_result = "unknown"

    normal_recovery_success = protocol in ("seq_mac", "hash_chain", "ticket_only", "gmcp_r")

    memory_match = memory_recovered

    secure_memory_recovery_success = (
        normal_recovery_success
        and memory_recovered
        and memory_match
    )

    if protocol == "seq_mac":
        throughput_score = 1.00
    elif protocol == "ticket_only":
        throughput_score = 0.95
    elif protocol == "hash_chain":
        throughput_score = 0.78
    else:
        throughput_score = 0.84

    return {
        "protocol": protocol,
        "attack_type": attack_type,
        "message_count": message_count,
        "checkpoint_interval": checkpoint_interval,

        "memory_supported": memory_supported,
        "memory_recovered": memory_recovered,
        "memory_match": memory_match,

        "attack_detected": attack_detected,
        "detection_result": detection_result,

        "normal_recovery_success": normal_recovery_success,
        "secure_memory_recovery_success": secure_memory_recovery_success,

        "recovery_latency_ms": round(recovery_latency_ms, 4),
        "recovery_extra_messages": recovery_extra_messages,
        "recovery_extra_bytes": recovery_extra_bytes,
        "recovery_mode": recovery_mode,
        "throughput_score": throughput_score,
    }


def save_rows(rows: List[Dict[str, Any]]):
    ensure_output_dir()
    fieldnames = list(rows[0].keys())

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    rows = []

    for protocol in PROTOCOLS:
        for attack in ATTACKS:
            for count in MESSAGE_COUNTS:
                for cp_interval in CHECKPOINT_INTERVALS:
                    rows.append(
                        simulate_protocol_result(
                            protocol=protocol,
                            attack_type=attack,
                            message_count=count,
                            checkpoint_interval=cp_interval,
                        )
                    )

    save_rows(rows)

    print("[BASELINE] results saved to", OUTPUT_CSV)
    print("[BASELINE] total rows:", len(rows))


if __name__ == "__main__":
    main()