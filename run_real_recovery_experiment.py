# -*- coding: utf-8 -*-
# run_real_recovery_experiment.py

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
    SHARED_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.ticket import verify_memory_ticket_for_recovery


OUTPUT_DIR = "results/real_recovery"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "real_recovery_results.csv")

MESSAGE_COUNTS = [100, 500, 1000]
PAYLOAD_SIZES = [128, 512]
ATTACK_TYPES = ["drop", "modify", "replay", "prev_mem", "disconnect"]
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "1"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

SOCKET_TIMEOUT = 10.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "recovery-message-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def json_size(packet: Dict[str, Any]) -> int:
    return len(json.dumps(packet, ensure_ascii=False).encode("utf-8"))


def enable_tcp_nodelay(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


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


def open_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def modify_payload_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    attacked = dict(packet)
    attacked["payload"] = "attacked-recovery-payload"
    return attacked


def modify_prev_mem_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    attacked = dict(packet)
    attacked["prev_mem"] = "fake-recovery-memory"

    attacked.pop("auth_tag", None)
    attacked["auth_tag"] = hmac_sha256_hex(
        key=SHARED_KEY,
        data=attacked,
    )
    return attacked


def build_recovery_request(
    session_id: str,
    client_last_seq: int,
    client_last_mem: str,
    reason: str,
) -> Dict[str, Any]:

    request = {
        "type": "RECOVERY_REQUEST",
        "session_id": session_id,
        "client_id": CLIENT_ID,
        "epoch": EPOCH,
        "client_last_seq": client_last_seq,
        "client_last_mem": client_last_mem,
        "reason": reason,
        "timestamp": time.time(),
    }

    request["auth_tag"] = hmac_sha256_hex(SHARED_KEY, request)
    return request


def request_recovery(
    sock,
    file_obj,
    session_id: str,
    client_last_seq: int,
    client_last_mem: str,
    reason: str,
) -> Tuple[bool, Dict[str, Any], float, int, int, Dict[str, Any]]:

    start = time.time()

    request = build_recovery_request(
        session_id=session_id,
        client_last_seq=client_last_seq,
        client_last_mem=client_last_mem,
        reason=reason,
    )

    request_bytes = json_size(request)
    send_json_line(sock, request)
    response = recv_json_line(file_obj)
    response_bytes = json_size(response)

    latency_ms = (time.time() - start) * 1000

    ticket = response.get("memory_ticket")
    ticket_info = {
        "ticket_verified": False,
        "ticket_nonce": "",
        "ticket_expired": False,
        "ticket_replay_detected": False,
        "ticket_reason": "missing memory_ticket",
    }

    if isinstance(ticket, dict):
        ticket_ok, ticket_reason = verify_memory_ticket_for_recovery(
            ticket=ticket,
            expected_session_id=session_id,
            expected_client_id=CLIENT_ID,
            expected_epoch=EPOCH,
            min_last_seq=int(response.get("server_last_seq", 0)),
        )
        ticket_info = {
            "ticket_verified": ticket_ok,
            "ticket_nonce": ticket.get("ticket_nonce", ""),
            "ticket_expired": ticket_reason == "ticket expired",
            "ticket_replay_detected": "replay" in ticket_reason,
            "ticket_reason": ticket_reason,
        }

    ok = response.get("ok") is True and ticket_info["ticket_verified"]
    return ok, response, latency_ms, 2, request_bytes + response_bytes, ticket_info


def run_one_recovery_experiment(
    attack_type: str,
    message_count: int,
    payload_size: int,
    repeat_id: int,
) -> Dict[str, Any]:

    session_id = (
        f"real-recovery-{attack_type}-m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    initial_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    current_mem = initial_mem

    final_server_mem = initial_mem
    final_server_last_seq = 0

    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    sent_count = 0

    attack_detected = False
    recovery_requested = False
    recovery_success = False
    memory_match_after_recovery = False

    recovery_latency_ms = 0.0
    recovery_extra_messages = 0
    recovery_extra_bytes = 0
    detection_reason = "normal"
    recovery_reason = "not_started"
    ticket_verified = False
    ticket_nonce = ""
    ticket_expired = False
    ticket_replay_detected = False

    saved_packets: Dict[int, Dict[str, Any]] = {}

    attack_seq = min(50, max(2, message_count // 2))
    replay_seq = max(1, attack_seq // 2)

    attack_done = False
    recovered = False
    recovery_point_seq = 0

    pre_recovery_accepted = 0
    post_recovery_accepted = 0

    start_time = time.time()

    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp()

        seq = 1

        while seq <= message_count:
            payload = make_payload(seq, payload_size)
            payload_hash = hash_text(payload)

            # disconnect 攻击：在 attack_seq 处直接断开，然后发起恢复
            if attack_type == "disconnect" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_detected = True
                detection_reason = "client simulated disconnect"

                close_tcp(sock, file_obj)
                sock, file_obj = open_tcp()

                recovery_requested = True
                (
                    ok,
                    recovery_response,
                    recovery_latency_ms,
                    recovery_extra_messages,
                    recovery_extra_bytes,
                    ticket_info,
                ) = request_recovery(
                    sock=sock,
                    file_obj=file_obj,
                    session_id=session_id,
                    client_last_seq=seq - 1,
                    client_last_mem=current_mem,
                    reason=detection_reason,
                )
                ticket_verified = ticket_info["ticket_verified"]
                ticket_nonce = ticket_info["ticket_nonce"]
                ticket_expired = ticket_info["ticket_expired"]
                ticket_replay_detected = ticket_info["ticket_replay_detected"]

                if ok:
                    recovered = True
                    recovery_success = True
                    recovery_reason = recovery_response.get("reason", "ok")
                    final_server_last_seq = int(recovery_response.get("server_last_seq", 0))
                    final_server_mem = recovery_response.get("server_last_mem", initial_mem)
                    current_mem = final_server_mem
                    recovery_point_seq = final_server_last_seq
                    seq = final_server_last_seq + 1
                    continue
                else:
                    recovery_reason = ticket_info.get(
                        "ticket_reason",
                        recovery_response.get("reason", "recovery failed"),
                    )
                    break

            packet = build_data_packet(
                session_id=session_id,
                sender_id=CLIENT_ID,
                epoch=EPOCH,
                seq=seq,
                prev_mem=current_mem,
                payload=payload,
            )

            # drop 攻击：跳过 attack_seq，下一条会触发 seq gap
            if attack_type == "drop" and seq == attack_seq and not attack_done:
                attack_done = True
                seq += 1
                continue

            if attack_type == "modify" and seq == attack_seq and not attack_done:
                attack_done = True
                packet = modify_payload_attack(packet)

            if attack_type == "prev_mem" and seq == attack_seq and not attack_done:
                attack_done = True
                packet = modify_prev_mem_attack(packet)

            if attack_type == "replay" and seq == attack_seq and not attack_done:
                attack_done = True
                if replay_seq in saved_packets:
                    packet = dict(saved_packets[replay_seq])

            send_json_line(sock, packet)
            sent_count += 1

            try:
                response = recv_json_line(file_obj)
            except socket.timeout:
                timeout_count += 1
                detection_reason = "client timeout waiting for server response"
                break

            final_server_mem = response.get("last_mem", final_server_mem)
            final_server_last_seq = int(response.get("last_seq", final_server_last_seq))

            if response.get("ok"):
                accepted_count += 1

                if recovered:
                    post_recovery_accepted += 1
                else:
                    pre_recovery_accepted += 1

                saved_packets[seq] = dict(packet)

                current_mem = update_memory(
                    prev_mem=current_mem,
                    session_id=session_id,
                    epoch=EPOCH,
                    seq=seq,
                    payload_hash=payload_hash,
                    sender_id=CLIENT_ID,
                )

                seq += 1
                continue

            # 服务端拒绝，说明攻击被检测到了
            rejected_count += 1
            attack_detected = True
            detection_reason = response.get("reason", "unknown rejection")

            recovery_requested = True

            (
                ok,
                recovery_response,
                recovery_latency_ms,
                recovery_extra_messages,
                recovery_extra_bytes,
                ticket_info,
            ) = request_recovery(
                sock=sock,
                file_obj=file_obj,
                session_id=session_id,
                client_last_seq=seq - 1,
                client_last_mem=current_mem,
                reason=detection_reason,
            )
            ticket_verified = ticket_info["ticket_verified"]
            ticket_nonce = ticket_info["ticket_nonce"]
            ticket_expired = ticket_info["ticket_expired"]
            ticket_replay_detected = ticket_info["ticket_replay_detected"]

            if ok:
                recovered = True
                recovery_success = True
                recovery_reason = recovery_response.get("reason", "ok")
                final_server_last_seq = int(recovery_response.get("server_last_seq", 0))
                final_server_mem = recovery_response.get("server_last_mem", initial_mem)
                current_mem = final_server_mem
                recovery_point_seq = final_server_last_seq
                seq = final_server_last_seq + 1
                continue
            else:
                recovery_reason = ticket_info.get(
                    "ticket_reason",
                    recovery_response.get("reason", "recovery failed"),
                )
                break

    except socket.timeout:
        timeout_count += 1
        detection_reason = "tcp timeout"

    except Exception as e:
        timeout_count += 1
        detection_reason = "tcp error: %s" % str(e)

    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time
    throughput = accepted_count / elapsed if elapsed > 0 else 0

    memory_match_after_recovery = current_mem == final_server_mem

    final_seq_consistent = final_server_last_seq == message_count

    full_recovery_success = (
        attack_detected
        and recovery_requested
        and recovery_success
        and final_seq_consistent
        and memory_match_after_recovery
        and timeout_count == 0
    )

    return {
        "protocol": "gmcp_r",
        "scenario": "real_attack_recovery",
        "server_host": SERVER_TARGET_HOST,
        "server_port": DEFAULT_PORT,
        "session_id": session_id,
        "attack_type": attack_type,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "attack_seq": attack_seq,

        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,

        "attack_detected": attack_detected,
        "recovery_requested": recovery_requested,
        "recovery_success": recovery_success,
        "full_recovery_success": full_recovery_success,

        "pre_recovery_accepted": pre_recovery_accepted,
        "post_recovery_accepted": post_recovery_accepted,
        "recovery_point_seq": recovery_point_seq,

        "recovery_latency_ms": round(recovery_latency_ms, 4),
        "recovery_extra_messages": recovery_extra_messages,
        "recovery_extra_bytes": recovery_extra_bytes,
        "elapsed_ms": round(elapsed * 1000, 4),
        "throughput_msg_per_s": round(throughput, 2),

        "final_client_mem": current_mem,
        "final_server_mem": final_server_mem,
        "final_client_mem_short": current_mem[:16],
        "final_server_mem_short": final_server_mem[:16],
        "memory_match_after_recovery": memory_match_after_recovery,
        "server_last_seq": final_server_last_seq,
        "final_seq_consistent": final_seq_consistent,
        "ticket_verified": ticket_verified,
        "ticket_nonce": ticket_nonce,
        "ticket_expired": ticket_expired,
        "ticket_replay_detected": ticket_replay_detected,

        "detection_reason": detection_reason,
        "recovery_reason": recovery_reason,
        "recovery_mode": "memory_ticket_checkpoint",
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
    print("[REAL_RECOVERY_EXPERIMENT] target:", SERVER_TARGET_HOST, DEFAULT_PORT)

    rows = []
    total = 0

    for attack_type in ATTACK_TYPES:
        for message_count in MESSAGE_COUNTS:
            for payload_size in PAYLOAD_SIZES:
                for repeat_id in REPEATS:
                    row = run_one_recovery_experiment(
                        attack_type=attack_type,
                        message_count=message_count,
                        payload_size=payload_size,
                        repeat_id=repeat_id,
                    )

                    rows.append(row)
                    total += 1

                    print(
                        "[REAL_RECOVERY_EXPERIMENT]",
                        "attack=", attack_type,
                        "messages=", message_count,
                        "payload=", payload_size,
                        "accepted=", row["accepted_count"],
                        "rejected=", row["rejected_count"],
                        "recovery_success=", row["full_recovery_success"],
                        "memory_match=", row["memory_match_after_recovery"],
                        "reason=", row["detection_reason"],
                    )

    save_rows(rows)

    print("[REAL_RECOVERY_EXPERIMENT] results saved to", OUTPUT_CSV)
    print("[REAL_RECOVERY_EXPERIMENT] total rows:", total)


if __name__ == "__main__":
    main()
