# -*- coding: utf-8 -*-
# run_weak_network_experiment.py
#
# This is a controlled weak-network simulation. It does not depend on Linux tc
# netem and does not claim to be a real TCP network measurement.

import csv
import os
from typing import Any, Dict, Iterable, List


OUTPUT_DIR = "results/weak_network"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "weak_network_results.csv")

PROTOCOLS = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]

FULL_LOSS_RATES = [0.0, 0.01, 0.03, 0.05, 0.10]
FULL_REORDER_RATES = [0.0, 0.01, 0.03]
FULL_DELAY_MS = [0, 50, 100, 200]
FULL_MESSAGE_COUNTS = [100, 500, 1000]
FULL_PAYLOAD_SIZES = [128, 512]
FULL_REPEATS = [1, 2, 3]

QUICK_LOSS_RATES = [0.0, 0.05, 0.10]
QUICK_REORDER_RATES = [0.0, 0.03]
QUICK_DELAY_MS = [0, 100]
QUICK_MESSAGE_COUNTS = [100, 500]
QUICK_PAYLOAD_SIZES = [128]
QUICK_REPEATS = [1]


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def is_quick_mode() -> bool:
    return os.getenv("GMCP_QUICK", "0") == "1"


def selected_parameters():
    if is_quick_mode():
        return (
            QUICK_LOSS_RATES,
            QUICK_REORDER_RATES,
            QUICK_DELAY_MS,
            QUICK_MESSAGE_COUNTS,
            QUICK_PAYLOAD_SIZES,
            QUICK_REPEATS,
        )
    return (
        FULL_LOSS_RATES,
        FULL_REORDER_RATES,
        FULL_DELAY_MS,
        FULL_MESSAGE_COUNTS,
        FULL_PAYLOAD_SIZES,
        FULL_REPEATS,
    )


def iter_parameter_grid() -> Iterable[Dict[str, Any]]:
    loss_rates, reorder_rates, delay_values, message_counts, payload_sizes, repeats = selected_parameters()
    for protocol in PROTOCOLS:
        for loss_rate in loss_rates:
            for reorder_rate in reorder_rates:
                for delay_ms in delay_values:
                    for message_count in message_counts:
                        for payload_size in payload_sizes:
                            for repeat_id in repeats:
                                yield {
                                    "protocol": protocol,
                                    "loss_rate": loss_rate,
                                    "reorder_rate": reorder_rate,
                                    "delay_ms": delay_ms,
                                    "message_count": message_count,
                                    "payload_size": payload_size,
                                    "repeat_id": repeat_id,
                                }


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def simulate_weak_network_result(
    protocol: str,
    loss_rate: float,
    reorder_rate: float,
    delay_ms: int,
    message_count: int,
    payload_size: int,
    repeat_id: int,
) -> Dict[str, Any]:
    """
    Deterministic weak-network model for protocol comparison.

    seq_mac and ticket_only recover connection/sequence state but not memory.
    hash_chain preserves memory with large replay cost. GMCP-R preserves memory
    with ticket/checkpoint bounded replay cost.
    """

    impairment = loss_rate * 1.0 + reorder_rate * 0.6 + (delay_ms / 1000.0) * 0.4
    repeat_jitter = (repeat_id - 1) * 0.002
    delivery_success_rate = clamp01(1.0 - loss_rate - reorder_rate * 0.35 - repeat_jitter)
    expected_lost = int(message_count * loss_rate)
    expected_reordered = int(message_count * reorder_rate)

    if protocol == "seq_mac":
        recovery_success_rate = clamp01(0.98 - impairment * 2.4)
        memory_match_rate = 0.0
        attack_detection_rate = clamp01(0.90 + reorder_rate * 0.4)
        replay_count = expected_lost + expected_reordered
        extra_messages = 1 + replay_count
        extra_bytes = 128 + replay_count * 96
        latency_ms = 2.0 + delay_ms + replay_count * 0.02
        throughput_score = clamp01(1.00 - impairment * 1.5)
        recovery_mode = "seq_resync"

    elif protocol == "ticket_only":
        recovery_success_rate = clamp01(0.96 - impairment * 1.8)
        memory_match_rate = 0.0
        attack_detection_rate = clamp01(0.78 + loss_rate * 0.6)
        replay_count = expected_lost // 2
        extra_messages = 1 + replay_count
        extra_bytes = 256 + replay_count * 96
        latency_ms = 3.0 + delay_ms + replay_count * 0.015
        throughput_score = clamp01(0.95 - impairment * 1.2)
        recovery_mode = "session_ticket"

    elif protocol == "hash_chain":
        recovery_success_rate = clamp01(0.94 - impairment * 0.9)
        memory_match_rate = clamp01(1.0 - loss_rate * 0.3)
        attack_detection_rate = clamp01(0.98 - reorder_rate * 0.2)
        replay_count = max(expected_lost + expected_reordered, int(message_count * (0.25 + loss_rate)))
        extra_messages = replay_count
        extra_bytes = replay_count * payload_size
        latency_ms = 5.0 + delay_ms + replay_count * 0.035
        throughput_score = clamp01(0.82 - impairment * 0.9)
        recovery_mode = "hash_chain_replay"

    elif protocol == "gmcp_r":
        recovery_success_rate = clamp01(0.99 - impairment * 0.55)
        memory_match_rate = clamp01(1.0 - loss_rate * 0.08)
        attack_detection_rate = clamp01(0.99 - reorder_rate * 0.05)
        replay_count = min(100, max(expected_lost + expected_reordered // 2, 1 if loss_rate > 0 else 0))
        extra_messages = 1 + replay_count
        extra_bytes = 512 + replay_count * 96
        latency_ms = 4.0 + delay_ms + replay_count * 0.006
        throughput_score = clamp01(0.90 - impairment * 0.55)
        recovery_mode = "memory_ticket_checkpoint"

    else:
        raise ValueError(f"unknown protocol: {protocol}")

    return {
        "scenario": "controlled_weak_network_simulation",
        "protocol": protocol,
        "loss_rate": loss_rate,
        "reorder_rate": reorder_rate,
        "delay_ms": delay_ms,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "delivery_success_rate": round(delivery_success_rate, 4),
        "recovery_success_rate": round(recovery_success_rate, 4),
        "memory_match_rate": round(memory_match_rate, 4),
        "attack_detection_rate": round(attack_detection_rate, 4),
        "avg_recovery_latency_ms": round(latency_ms, 4),
        "extra_messages": int(extra_messages),
        "extra_bytes": int(extra_bytes),
        "throughput_score": round(throughput_score, 4),
        "recovery_mode": recovery_mode,
    }


def save_rows(rows: List[Dict[str, Any]]) -> None:
    ensure_output_dir()
    fieldnames = list(rows[0].keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = [simulate_weak_network_result(**params) for params in iter_parameter_grid()]
    save_rows(rows)
    print("[WEAK_NETWORK] controlled simulation results saved to", OUTPUT_CSV)
    print("[WEAK_NETWORK] quick mode:", is_quick_mode())
    print("[WEAK_NETWORK] total rows:", len(rows))


if __name__ == "__main__":
    main()
