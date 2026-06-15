# -*- coding: utf-8 -*-
# run_baseline_comparison_experiment.py
#
# This is a protocol-level analytical/simulation comparison, not a real TCP
# network experiment. The latency and overhead values below are deterministic
# model outputs used to compare protocol behavior under identical assumptions.

import csv
import os
from typing import Any, Dict, Iterable, List


OUTPUT_DIR = "results/baseline"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "baseline_comparison_results.csv")

PROTOCOLS = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]
ATTACK_TYPES = ["drop", "modify", "replay", "prev_mem", "rollback_ticket", "disconnect"]

FULL_MESSAGE_COUNTS = [100, 500, 1000, 5000]
FULL_PAYLOAD_SIZES = [128, 512]
FULL_CHECKPOINT_INTERVALS = [50, 100, 500]
FULL_REPEATS = [1, 2, 3]

QUICK_MESSAGE_COUNTS = [100, 500]
QUICK_PAYLOAD_SIZES = [128]
QUICK_CHECKPOINT_INTERVALS = [100]
QUICK_REPEATS = [1]


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def is_quick_mode() -> bool:
    return os.getenv("GMCP_QUICK", "0") == "1"


def selected_parameters():
    if is_quick_mode():
        return (
            QUICK_MESSAGE_COUNTS,
            QUICK_PAYLOAD_SIZES,
            QUICK_CHECKPOINT_INTERVALS,
            QUICK_REPEATS,
        )
    return (
        FULL_MESSAGE_COUNTS,
        FULL_PAYLOAD_SIZES,
        FULL_CHECKPOINT_INTERVALS,
        FULL_REPEATS,
    )


def iter_parameter_grid() -> Iterable[Dict[str, Any]]:
    message_counts, payload_sizes, checkpoint_intervals, repeats = selected_parameters()
    for protocol in PROTOCOLS:
        for attack_type in ATTACK_TYPES:
            for message_count in message_counts:
                for payload_size in payload_sizes:
                    for checkpoint_interval in checkpoint_intervals:
                        for repeat_id in repeats:
                            yield {
                                "protocol": protocol,
                                "attack_type": attack_type,
                                "message_count": message_count,
                                "payload_size": payload_size,
                                "checkpoint_interval": checkpoint_interval,
                                "repeat_id": repeat_id,
                            }


def _target_seq(message_count: int) -> int:
    return max(1, int(message_count * 0.7))


def _attack_detected(protocol: str, attack_type: str) -> bool:
    if attack_type in ("drop", "modify", "replay", "disconnect"):
        return True
    if attack_type == "prev_mem":
        return protocol in ("hash_chain", "gmcp_r")
    if attack_type == "rollback_ticket":
        return protocol == "gmcp_r"
    return False


def _detection_reason(protocol: str, attack_type: str, attack_detected: bool) -> str:
    if attack_type == "prev_mem" and not attack_detected:
        return "protocol does not carry verifiable prev_mem"
    if attack_type == "rollback_ticket" and protocol == "ticket_only":
        return "session ticket lacks last_mem and anti-rollback binding"
    if attack_type == "rollback_ticket" and protocol in ("seq_mac", "hash_chain"):
        return "rollback ticket is not used by this baseline"
    if attack_detected:
        return f"{attack_type} detected by {protocol} model"
    return "attack was not detected"


def simulate_protocol_result(
    protocol: str,
    attack_type: str,
    message_count: int,
    payload_size: int,
    checkpoint_interval: int,
    repeat_id: int,
) -> Dict[str, Any]:
    """
    Deterministic protocol-level model for baseline comparison.

    It intentionally models relative recovery cost instead of measuring a real
    socket. Real TCP results are produced only by run_real_tcp_network_experiment.py
    and run_real_recovery_experiment.py.
    """

    target_seq = _target_seq(message_count)
    memory_supported = protocol in ("hash_chain", "gmcp_r")
    attack_detected = _attack_detected(protocol, attack_type)

    if protocol == "seq_mac":
        memory_recovered = False
        memory_match = False
        replay_count = 0
        recovery_latency_ms = 1.5 + repeat_id * 0.05
        recovery_extra_messages = 1
        recovery_extra_bytes = 128
        recovery_mode = "seq_resync"
        throughput_score = 1.00
        recovery_reason = "sequence state resynchronized without memory recovery"

    elif protocol == "ticket_only":
        memory_recovered = False
        memory_match = False
        replay_count = 0
        recovery_latency_ms = 3.0 + repeat_id * 0.05
        recovery_extra_messages = 1
        recovery_extra_bytes = 256
        recovery_mode = "session_ticket"
        throughput_score = 0.95
        recovery_reason = "session ticket restores connection state only"

    elif protocol == "hash_chain":
        memory_recovered = True
        memory_match = True
        checkpoint_seq = 0
        replay_count = max(0, target_seq - checkpoint_seq)
        recovery_latency_ms = 2.0 + replay_count * 0.025 + repeat_id * 0.05
        recovery_extra_messages = replay_count
        recovery_extra_bytes = replay_count * payload_size
        recovery_mode = "history_hash_chain_replay"
        throughput_score = max(0.75, 0.85 - replay_count / max(message_count, 1) * 0.1)
        recovery_reason = "memory recovered by replaying hash-chain history"

    elif protocol == "gmcp_r":
        memory_recovered = True
        memory_match = True
        checkpoint_seq = (target_seq // checkpoint_interval) * checkpoint_interval
        replay_count = max(0, target_seq - checkpoint_seq)
        metadata_size = 96
        recovery_latency_ms = 3.0 + replay_count * 0.004 + repeat_id * 0.05
        recovery_extra_messages = 1 + replay_count
        recovery_extra_bytes = 512 + replay_count * metadata_size
        recovery_mode = "memory_ticket_checkpoint"
        throughput_score = max(0.85, 0.90 - replay_count / max(checkpoint_interval, 1) * 0.05)
        recovery_reason = "MemoryTicket returns trusted last_seq and last_mem"

    else:
        raise ValueError(f"unknown protocol: {protocol}")

    normal_recovery_success = True
    secure_memory_recovery_success = memory_supported and memory_recovered and memory_match
    fast_secure_memory_recovery_success = protocol == "gmcp_r" and secure_memory_recovery_success

    return {
        "protocol": protocol,
        "attack_type": attack_type,
        "message_count": message_count,
        "payload_size": payload_size,
        "checkpoint_interval": checkpoint_interval,
        "repeat_id": repeat_id,
        "memory_supported": memory_supported,
        "memory_recovered": memory_recovered,
        "memory_match": memory_match,
        "attack_detected": attack_detected,
        "normal_recovery_success": normal_recovery_success,
        "secure_memory_recovery_success": secure_memory_recovery_success,
        "fast_secure_memory_recovery_success": fast_secure_memory_recovery_success,
        "recovery_latency_ms": round(recovery_latency_ms, 4),
        "recovery_extra_messages": int(recovery_extra_messages),
        "recovery_extra_bytes": int(recovery_extra_bytes),
        "replay_count": int(replay_count),
        "recovery_mode": recovery_mode,
        "throughput_score": round(throughput_score, 4),
        "detection_reason": _detection_reason(protocol, attack_type, attack_detected),
        "recovery_reason": recovery_reason,
    }


def save_rows(rows: List[Dict[str, Any]]) -> None:
    ensure_output_dir()
    fieldnames = list(rows[0].keys())

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = [simulate_protocol_result(**params) for params in iter_parameter_grid()]
    save_rows(rows)

    print("[BASELINE] protocol-level simulation results saved to", OUTPUT_CSV)
    print("[BASELINE] quick mode:", is_quick_mode())
    print("[BASELINE] total rows:", len(rows))


if __name__ == "__main__":
    main()
