# -*- coding: utf-8 -*-
# run_real_network_experiment.py

import csv
import json
import os
import socket
import time
from typing import Dict, Any, List, Tuple

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet


OUTPUT_DIR = "results/real_network"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "real_network_results.csv")

REAL_PROTOCOL = "gmcp_r"

MESSAGE_COUNTS = [1000, 3000, 5000]
PAYLOAD_SIZES = [128, 512, 1024]
ATTACK_TYPES = ["none", "drop", "modify", "replay", "prev_mem"]
REPEATS = [1, 2, 3]

SOCKET_TIMEOUT = 3.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "real-message-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def packet_without_auth(packet: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(packet)
    data.pop("auth_tag", None)
    return data


def modify_payload_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    attacked = dict(packet)
    attacked["payload"] = "attacked-real-payload"
    return attacked


def modify_prev_mem_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改 prev_mem，并重新计算 auth_tag。
    这样服务端会通过 HMAC，但会在 prev_mem mismatch 处拒绝。
    """
    attacked = dict(packet)
    attacked["prev_mem"] = "fake-real-network-memory"
    attacked.pop("auth_tag", None)
    attacked["auth_tag"] = hmac_sha256_hex(
        key=b"gmcp-demo-shared-key",
        data=attacked,
    )
    return attacked


def ping_server(sock: socket.socket, target: Tuple[str, int]) -> bool:
    msg = {
        "type": "PING",
        "timestamp": time.time(),
    }

    try:
        sock.sendto(json.dumps(msg).encode("utf-8"), target)
        data, _ = sock.recvfrom(65535)
        resp = json.loads(data.decode("utf-8"))
        return resp.get("ok") is True
    except Exception:
        return False


def run_one_real_experiment(
    message_count: int,
    payload_size: int,
    attack_type: str,
    repeat_id: int,
) -> Dict[str, Any]:

    session_id = (
        f"real-{attack_type}-m{message_count}-p{payload_size}-r{repeat_id}-"
        f"{int(time.time() * 1000000)}"
    )

    target = (SERVER_TARGET_HOST, DEFAULT_PORT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT)

    server_reachable = ping_server(sock, target)

    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")

    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    sent_count = 0

    detection_result = "normal" if attack_type == "none" else "missed"
    detection_reason = "normal"

    saved_packets: Dict[int, Dict[str, Any]] = {}

    rtts: List[float] = []

    attack_seq = min(500, max(2, message_count // 2))
    replay_seq = max(1, attack_seq // 2)

    start_time = time.time()

    for seq in range(1, message_count + 1):
        payload = make_payload(seq, payload_size)

        packet = build_data_packet(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_mem=current_mem,
            payload=payload,
        )

        if attack_type == "drop" and seq == attack_seq:
            # 模拟中间消息丢失：不发送该 seq，下一条会导致 seq gap
            continue

        if attack_type == "modify" and seq == attack_seq:
            packet = modify_payload_attack(packet)

        if attack_type == "prev_mem" and seq == attack_seq:
            packet = modify_prev_mem_attack(packet)

        if attack_type == "replay" and seq == attack_seq and replay_seq in saved_packets:
            packet = dict(saved_packets[replay_seq])

        raw = json.dumps(packet, ensure_ascii=False).encode("utf-8")

        send_time = time.time()
        sent_count += 1
        sock.sendto(raw, target)

        try:
            data, _ = sock.recvfrom(65535)
            recv_time = time.time()
            rtts.append((recv_time - send_time) * 1000)

            response = json.loads(data.decode("utf-8"))

        except socket.timeout:
            timeout_count += 1
            detection_reason = "client timeout waiting for server response"

            if attack_type != "none":
                detection_result = "detected_or_timeout"
            break

        if response.get("ok"):
            accepted_count += 1
            saved_packets[seq] = dict(packet)

            payload_hash = hash_text(payload)
            current_mem = update_memory(
                prev_mem=current_mem,
                session_id=session_id,
                epoch=EPOCH,
                seq=seq,
                payload_hash=payload_hash,
                sender_id=CLIENT_ID,
            )

        else:
            rejected_count += 1
            detection_reason = response.get("reason", "unknown rejection")

            if attack_type != "none":
                detection_result = "detected"
            break

    elapsed = time.time() - start_time
    throughput = accepted_count / elapsed if elapsed > 0 else 0

    avg_rtt_ms = sum(rtts) / len(rtts) if rtts else 0
    max_rtt_ms = max(rtts) if rtts else 0
    min_rtt_ms = min(rtts) if rtts else 0

    recovery_success = (
        attack_type == "none"
        and accepted_count == message_count
        and rejected_count == 0
        and timeout_count == 0
    )

    attack_detected = detection_result in ("detected", "detected_or_timeout")

    return {
        "protocol": REAL_PROTOCOL,
        "scenario": "real_network",
        "server_host": SERVER_TARGET_HOST,
        "server_port": DEFAULT_PORT,
        "session_id": session_id,
        "message_count": message_count,
        "payload_size": payload_size,
        "attack_type": attack_type,
        "repeat_id": repeat_id,
        "server_reachable": server_reachable,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "recovery_success": recovery_success,
        "attack_detected": attack_detected,
        "detection_result": detection_result,
        "detection_reason": detection_reason,
        "avg_rtt_ms": round(avg_rtt_ms, 4),
        "min_rtt_ms": round(min_rtt_ms, 4),
        "max_rtt_ms": round(max_rtt_ms, 4),
        "elapsed_ms": round(elapsed * 1000, 4),
        "throughput_msg_per_s": round(throughput, 2),
    }


def save_rows(rows: List[Dict[str, Any]]):
    if not rows:
        return

    ensure_output_dir()

    fieldnames = list(rows[0].keys())

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    print("[REAL_EXPERIMENT] target:", SERVER_TARGET_HOST, DEFAULT_PORT)

    rows: List[Dict[str, Any]] = []

    total = 0

    for attack_type in ATTACK_TYPES:
        for message_count in MESSAGE_COUNTS:
            for payload_size in PAYLOAD_SIZES:
                for repeat_id in REPEATS:
                    row = run_one_real_experiment(
                        message_count=message_count,
                        payload_size=payload_size,
                        attack_type=attack_type,
                        repeat_id=repeat_id,
                    )
                    rows.append(row)
                    total += 1

                    print(
                        "[REAL_EXPERIMENT]",
                        "attack=", attack_type,
                        "messages=", message_count,
                        "payload=", payload_size,
                        "repeat=", repeat_id,
                        "accepted=", row["accepted_count"],
                        "rejected=", row["rejected_count"],
                        "timeout=", row["timeout_count"],
                        "reason=", row["detection_reason"],
                    )

    save_rows(rows)

    print("[REAL_EXPERIMENT] results saved to", OUTPUT_CSV)
    print("[REAL_EXPERIMENT] total rows:", total)


if __name__ == "__main__":
    main()