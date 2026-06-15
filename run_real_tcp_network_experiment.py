# -*- coding: utf-8 -*-
# run_real_tcp_network_experiment.py

import csv
import json
import os
import socket
import time
from collections import deque
from typing import Dict, Any, List, Tuple, Deque

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    SHARED_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet


OUTPUT_DIR = "results/real_network"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "real_network_results.csv")

REAL_PROTOCOL = "gmcp_r"

# 小规模真实双端实验：稳定、不会跑太久
MESSAGE_COUNTS = [100, 500, 1000]
PAYLOAD_SIZES = [128, 512]
WINDOW_SIZES = [1, 5, 10]
ATTACK_TYPES = ["none", "drop", "modify", "replay", "prev_mem"]
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "1"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

SOCKET_TIMEOUT = 10.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "real-tcp-message-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def modify_payload_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    attacked = dict(packet)
    attacked["payload"] = "attacked-real-tcp-payload"
    return attacked


def modify_prev_mem_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改 prev_mem，并重新计算 HMAC。
    这样服务端会通过 auth_tag 验证，
    但会在 prev_mem mismatch 处拒绝。
    """
    attacked = dict(packet)
    attacked["prev_mem"] = "fake-real-tcp-memory"

    attacked.pop("auth_tag", None)
    attacked["auth_tag"] = hmac_sha256_hex(
        key=SHARED_KEY,
        data=attacked,
    )
    return attacked


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def enable_tcp_nodelay(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def percentile(values: List[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * percent
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    weight = pos - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def recv_json_line(file_obj):
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def close_tcp(sock, file_obj):
    try:
        if file_obj:
            file_obj.close()
    except Exception:
        pass

    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass

    try:
        if sock:
            sock.close()
    except Exception:
        pass


def ping_server() -> bool:
    sock = None
    file_obj = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        enable_tcp_nodelay(sock)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))

        file_obj = sock.makefile("r", encoding="utf-8", newline="\n")

        msg = {
            "type": "PING",
            "timestamp": time.time(),
        }

        send_json_line(sock, msg)
        resp = recv_json_line(file_obj)

        return resp.get("ok") is True

    except Exception:
        return False

    finally:
        close_tcp(sock, file_obj)


def run_one_real_tcp_experiment(
    message_count: int,
    payload_size: int,
    attack_type: str,
    repeat_id: int,
    window_size: int,
) -> Dict[str, Any]:

    session_id = (
        f"real-tcp-{attack_type}-m{message_count}-p{payload_size}-"
        f"w{window_size}-r{repeat_id}-{int(time.time() * 1000000)}"
    )

    server_reachable = ping_server()

    initial_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")

    # build_mem：客户端用于构造待发送消息链
    # ack_mem：客户端根据服务端已确认消息推进的记忆状态
    build_mem = initial_mem
    ack_mem = initial_mem

    final_server_mem = initial_mem
    final_server_last_seq = 0

    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    sent_count = 0

    detection_result = "normal" if attack_type == "none" else "missed"
    detection_reason = "normal"

    saved_packets: Dict[int, Dict[str, Any]] = {}

    rtts: List[float] = []

    attack_seq = min(50, max(2, message_count // 2))
    replay_seq = max(1, attack_seq // 2)

    start_time = time.time()

    sock = None
    file_obj = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        enable_tcp_nodelay(sock)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))

        file_obj = sock.makefile("r", encoding="utf-8", newline="\n")

        next_seq = 1

        # 每个元素：(logical_seq, send_time, payload_hash)
        inflight: Deque[Tuple[int, float, str]] = deque()

        while True:
            # 尽量把窗口填满
            while len(inflight) < window_size and next_seq <= message_count:
                seq = next_seq
                payload = make_payload(seq, payload_size)
                payload_hash = hash_text(payload)

                packet = build_data_packet(
                    session_id=session_id,
                    sender_id=CLIENT_ID,
                    epoch=EPOCH,
                    seq=seq,
                    prev_mem=build_mem,
                    payload=payload,
                )

                # drop：模拟第 attack_seq 条消息丢失。
                # 客户端本地认为它进入了历史链，但服务端没有收到。
                if attack_type == "drop" and seq == attack_seq:
                    build_mem = update_memory(
                        prev_mem=build_mem,
                        session_id=session_id,
                        epoch=EPOCH,
                        seq=seq,
                        payload_hash=payload_hash,
                        sender_id=CLIENT_ID,
                    )
                    next_seq += 1
                    continue

                if attack_type == "modify" and seq == attack_seq:
                    packet = modify_payload_attack(packet)

                if attack_type == "prev_mem" and seq == attack_seq:
                    packet = modify_prev_mem_attack(packet)

                if attack_type == "replay" and seq == attack_seq and replay_seq in saved_packets:
                    packet = dict(saved_packets[replay_seq])

                send_time = time.time()
                send_json_line(sock, packet)

                sent_count += 1
                inflight.append((seq, send_time, payload_hash))

                if seq not in saved_packets:
                    saved_packets[seq] = dict(packet)

                # 客户端发送侧记忆继续推进，用于构造后续消息
                build_mem = update_memory(
                    prev_mem=build_mem,
                    session_id=session_id,
                    epoch=EPOCH,
                    seq=seq,
                    payload_hash=payload_hash,
                    sender_id=CLIENT_ID,
                )

                next_seq += 1

            # 没有待确认消息，并且所有消息都处理完了
            if not inflight and next_seq > message_count:
                break

            if not inflight:
                continue

            logical_seq, send_time, payload_hash = inflight.popleft()

            try:
                response = recv_json_line(file_obj)
                recv_time = time.time()
                rtts.append((recv_time - send_time) * 1000)

            except socket.timeout:
                timeout_count += 1
                detection_reason = "client timeout waiting for server response"

                if attack_type != "none":
                    detection_result = "detected_or_timeout"
                break

            except Exception as e:
                timeout_count += 1
                detection_reason = "connection error: %s" % str(e)

                if attack_type != "none":
                    detection_result = "detected_or_timeout"
                break

            final_server_mem = response.get("last_mem", final_server_mem)
            final_server_last_seq = int(response.get("last_seq", final_server_last_seq))

            if response.get("ok"):
                accepted_count += 1

                # 客户端确认侧记忆推进
                ack_mem = update_memory(
                    prev_mem=ack_mem,
                    session_id=session_id,
                    epoch=EPOCH,
                    seq=logical_seq,
                    payload_hash=payload_hash,
                    sender_id=CLIENT_ID,
                )

            else:
                rejected_count += 1
                detection_reason = response.get("reason", "unknown rejection")

                if attack_type != "none":
                    detection_result = "detected"

                break

    except socket.timeout:
        timeout_count += 1
        detection_reason = "tcp connect or send timeout"

        if attack_type != "none":
            detection_result = "detected_or_timeout"

    except Exception as e:
        timeout_count += 1
        detection_reason = "tcp error: %s" % str(e)

        if attack_type != "none":
            detection_result = "detected_or_timeout"

    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time
    throughput = accepted_count / elapsed if elapsed > 0 else 0

    avg_rtt_ms = sum(rtts) / len(rtts) if rtts else 0
    max_rtt_ms = max(rtts) if rtts else 0
    min_rtt_ms = min(rtts) if rtts else 0
    p50_rtt_ms = percentile(rtts, 0.50)
    p95_rtt_ms = percentile(rtts, 0.95)

    recovery_success = (
        attack_type == "none"
        and accepted_count == message_count
        and rejected_count == 0
        and timeout_count == 0
    )

    attack_detected = detection_result in ("detected", "detected_or_timeout")

    memory_match = ack_mem == final_server_mem

    memory_verified = (
        attack_type == "none"
        and recovery_success
        and memory_match
        and final_server_last_seq == message_count
    )

    seq_consistent = final_server_last_seq == accepted_count

    return {
        "protocol": REAL_PROTOCOL,
        "scenario": "real_tcp_network_window_memory",
        "server_host": SERVER_TARGET_HOST,
        "server_port": DEFAULT_PORT,
        "session_id": session_id,

        "message_count": message_count,
        "payload_size": payload_size,
        "window_size": window_size,
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
        "p50_rtt_ms": round(p50_rtt_ms, 4),
        "p95_rtt_ms": round(p95_rtt_ms, 4),
        "elapsed_ms": round(elapsed * 1000, 4),
        "throughput_msg_per_s": round(throughput, 2),

        "final_client_mem": ack_mem,
        "final_server_mem": final_server_mem,
        "final_client_mem_short": ack_mem[:16],
        "final_server_mem_short": final_server_mem[:16],
        "memory_match": memory_match,
        "memory_verified": memory_verified,
        "server_last_seq": final_server_last_seq,
        "seq_consistent": seq_consistent,
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
    print("[REAL_TCP_EXPERIMENT] target:", SERVER_TARGET_HOST, DEFAULT_PORT)

    rows: List[Dict[str, Any]] = []
    total = 0

    for attack_type in ATTACK_TYPES:
        for message_count in MESSAGE_COUNTS:
            for payload_size in PAYLOAD_SIZES:
                for window_size in WINDOW_SIZES:
                    for repeat_id in REPEATS:
                        row = run_one_real_tcp_experiment(
                            message_count=message_count,
                            payload_size=payload_size,
                            attack_type=attack_type,
                            repeat_id=repeat_id,
                            window_size=window_size,
                        )

                        rows.append(row)
                        total += 1

                        print(
                            "[REAL_TCP_EXPERIMENT]",
                            "attack=", attack_type,
                            "messages=", message_count,
                            "payload=", payload_size,
                            "window=", window_size,
                            "repeat=", repeat_id,
                            "accepted=", row["accepted_count"],
                            "rejected=", row["rejected_count"],
                            "timeout=", row["timeout_count"],
                            "memory_match=", row["memory_match"],
                            "reason=", row["detection_reason"],
                        )

    save_rows(rows)

    print("[REAL_TCP_EXPERIMENT] results saved to", OUTPUT_CSV)
    print("[REAL_TCP_EXPERIMENT] total rows:", total)


if __name__ == "__main__":
    main()
