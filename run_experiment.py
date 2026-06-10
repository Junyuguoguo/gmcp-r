# run_experiment.py

import json
import time
from typing import Dict, Any, Tuple, List

from gmcp.config import SESSION_ID, CLIENT_ID, EPOCH, SHARED_KEY
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, verify_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.metrics import MetricsRecorder
from gmcp.ticket import build_memory_ticket, verify_memory_ticket


PAYLOAD_SIZES = [128]
PROTOCOLS = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]
ATTACKS = ["none", "drop", "modify", "replay", "rollback_ticket"]
MESSAGE_COUNTS = [1000, 5000, 10000]
CHECKPOINT_INTERVALS = [50, 100, 500, 1000]


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "message-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def packet_without_auth(packet: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(packet)
    data.pop("auth_tag", None)
    return data


def build_packet(
    protocol: str,
    seq: int,
    prev_mem: str,
    payload: str,
) -> Dict[str, Any]:
    """
    根据协议类型构造 DATA 包。

    seq_mac / ticket_only:
        只使用 seq + payload_hash + auth_tag

    hash_chain / gmcp_r:
        额外使用 prev_mem，形成有记忆通信链
    """
    payload_hash = hash_text(payload)

    packet = {
        "type": "DATA",
        "session_id": SESSION_ID,
        "sender_id": CLIENT_ID,
        "epoch": EPOCH,
        "seq": seq,
        "payload": payload,
        "payload_hash": payload_hash,
        "timestamp": time.time(),
    }

    if protocol in ("hash_chain", "gmcp_r"):
        packet["prev_mem"] = prev_mem

    packet["auth_tag"] = hmac_sha256_hex(SHARED_KEY, packet)
    return packet


def verify_packet(
    protocol: str,
    packet: Dict[str, Any],
    server_last_seq: int,
    server_last_mem: str,
) -> Tuple[bool, str, int, str]:
    """
    返回：
        ok
        reason
        new_last_seq
        new_last_mem
    """

    if packet.get("type") != "DATA":
        return False, "invalid packet type", server_last_seq, server_last_mem

    recv_auth_tag = packet.get("auth_tag")
    if not recv_auth_tag:
        return False, "missing auth_tag", server_last_seq, server_last_mem

    data_for_auth = packet_without_auth(packet)
    if not verify_hmac(SHARED_KEY, data_for_auth, recv_auth_tag):
        return False, "auth_tag verification failed", server_last_seq, server_last_mem

    if packet.get("session_id") != SESSION_ID:
        return False, "session_id mismatch", server_last_seq, server_last_mem

    if packet.get("epoch") != EPOCH:
        return False, "epoch mismatch", server_last_seq, server_last_mem

    try:
        seq = int(packet.get("seq"))
    except (TypeError, ValueError):
        return False, "invalid seq", server_last_seq, server_last_mem

    if seq <= server_last_seq:
        return False, "replay or old packet detected", server_last_seq, server_last_mem

    if seq != server_last_seq + 1:
        return False, "seq gap detected", server_last_seq, server_last_mem

    payload = packet.get("payload", "")
    payload_hash = packet.get("payload_hash")

    if hash_text(payload) != payload_hash:
        return False, "payload_hash mismatch", server_last_seq, server_last_mem

    if protocol in ("hash_chain", "gmcp_r"):
        prev_mem = packet.get("prev_mem")
        if prev_mem != server_last_mem:
            return False, "prev_mem mismatch", server_last_seq, server_last_mem

        new_mem = update_memory(
            prev_mem=server_last_mem,
            session_id=SESSION_ID,
            epoch=EPOCH,
            seq=seq,
            payload_hash=payload_hash,
            sender_id=CLIENT_ID,
        )
    else:
        new_mem = server_last_mem

    return True, "ok", seq, new_mem


def modify_payload_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改 payload，但不重新计算 auth_tag。
    预期所有协议都应该检测到 auth_tag verification failed。
    """
    attacked = dict(packet)
    attacked["payload"] = "attacked-payload"
    return attacked


def estimate_packet_extra_bytes(protocol: str, packet: Dict[str, Any]) -> int:
    """
    粗略估计每条消息除了 payload 以外的协议开销。
    """
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8")
    payload = packet.get("payload", "")
    payload_bytes = payload.encode("utf-8")
    return max(0, len(raw) - len(payload_bytes))


def simulate_recovery(
    protocol: str,
    final_seq: int,
    final_mem: str,
    checkpoint_interval: int,
    payload_hash_log: List[str],
) -> Tuple[bool, float, int, int]:
    """
    模拟断线恢复。

    seq_mac:
        没有记忆状态，恢复成本最低，但不能恢复历史记忆。

    hash_chain:
        没有 checkpoint / ticket，需要从 M0 回放到 final_seq，恢复成本最高。

    ticket_only:
        普通 ticket 快速恢复连接，但不恢复 last_mem。

    gmcp_r:
        MemoryTicket 直接恢复 last_seq 和 last_mem。
    """

    start = time.time()

    if final_seq <= 0:
        return False, 0.0, 0, 0

    if protocol == "seq_mac":
        latency_ms = (time.time() - start) * 1000
        return True, latency_ms, 0, 0

    if protocol == "hash_chain":
        # 从头回放记忆链，模拟恢复成本
        mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, "demo-seed")

        replay_count = min(final_seq, len(payload_hash_log))
        for i in range(replay_count):
            seq = i + 1
            mem = update_memory(
                prev_mem=mem,
                session_id=SESSION_ID,
                epoch=EPOCH,
                seq=seq,
                payload_hash=payload_hash_log[i],
                sender_id=CLIENT_ID,
            )

        latency_ms = (time.time() - start) * 1000
        extra_messages = replay_count
        extra_bytes = replay_count * 128
        return True, latency_ms, extra_messages, extra_bytes

    if protocol == "ticket_only":
        # 普通 ticket 只恢复会话，不恢复 last_mem
        ticket = {
            "type": "SESSION_TICKET",
            "session_id": SESSION_ID,
            "client_id": CLIENT_ID,
            "expire_time": time.time() + 3600,
            "ticket_nonce": "ticket-only-%f" % time.time(),
        }
        ticket["auth_tag"] = hmac_sha256_hex(SHARED_KEY, ticket)

        data = dict(ticket)
        tag = data.pop("auth_tag")
        ok = verify_hmac(SHARED_KEY, data, tag)

        latency_ms = (time.time() - start) * 1000
        return ok, latency_ms, 1, len(json.dumps(ticket).encode("utf-8"))

    if protocol == "gmcp_r":
        checkpoint_seq = (final_seq // checkpoint_interval) * checkpoint_interval
        if checkpoint_seq <= 0:
            checkpoint_seq = final_seq

        ticket = build_memory_ticket(
            session_id=SESSION_ID,
            client_id=CLIENT_ID,
            epoch=EPOCH,
            last_seq=final_seq,
            last_mem=final_mem,
            checkpoint_seq=checkpoint_seq,
            checkpoint_mem=final_mem,
            ttl_seconds=3600,
        )

        ok, reason = verify_memory_ticket(ticket)

        latency_ms = (time.time() - start) * 1000
        extra_messages = 1
        extra_bytes = len(json.dumps(ticket).encode("utf-8"))
        return ok, latency_ms, extra_messages, extra_bytes

    latency_ms = (time.time() - start) * 1000
    return False, latency_ms, 0, 0


def simulate_rollback_ticket_attack(
    protocol: str,
    message_count: int,
    checkpoint_interval: int,
    final_mem: str,
) -> Tuple[str, bool, int, int, float, int, int]:
    """
    模拟旧 ticket 回滚攻击。

    ticket_only:
        普通 ticket 没有 last_mem / checkpoint_mem，容易误接受旧状态。

    gmcp_r:
        检查 last_seq 是否小于当前状态，检测回滚。
    """

    start = time.time()

    old_seq = max(1, message_count // 2)
    current_seq = message_count

    if protocol in ("seq_mac", "hash_chain"):
        latency_ms = (time.time() - start) * 1000
        return "not_applicable", True, message_count, 0, latency_ms, 0, 0

    if protocol == "ticket_only":
        # 普通 ticket 不携带 last_mem，无法判断历史记忆是否回滚
        latency_ms = (time.time() - start) * 1000
        return "missed", True, message_count, 0, latency_ms, 1, 128

    if protocol == "gmcp_r":
        old_ticket = build_memory_ticket(
            session_id=SESSION_ID,
            client_id=CLIENT_ID,
            epoch=EPOCH,
            last_seq=old_seq,
            last_mem="old-memory-state",
            checkpoint_seq=old_seq,
            checkpoint_mem="old-checkpoint-memory",
            ttl_seconds=3600,
        )

        ok, reason = verify_memory_ticket(old_ticket)

        if ok and old_ticket["last_seq"] < current_seq:
            detection_result = "detected"
            recovery_success = False
            rejected_count = 1
        else:
            detection_result = "missed"
            recovery_success = True
            rejected_count = 0

        latency_ms = (time.time() - start) * 1000
        extra_bytes = len(json.dumps(old_ticket).encode("utf-8"))
        return detection_result, recovery_success, message_count, rejected_count, latency_ms, 1, extra_bytes

    latency_ms = (time.time() - start) * 1000
    return "missed", False, 0, 1, latency_ms, 0, 0


def run_single_experiment(
    protocol: str,
    scenario: str,
    message_count: int,
    payload_size: int,
    checkpoint_interval: int,
    attack_type: str,
) -> Dict[str, Any]:

    # rollback_ticket 单独模拟
    if attack_type == "rollback_ticket":
        fake_final_mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, "demo-seed")
        detection_result, recovery_success, accepted_count, rejected_count, latency_ms, extra_messages, extra_bytes = (
            simulate_rollback_ticket_attack(
                protocol=protocol,
                message_count=message_count,
                checkpoint_interval=checkpoint_interval,
                final_mem=fake_final_mem,
            )
        )

        return {
            "protocol": protocol,
            "scenario": "rollback_ticket",
            "message_count": message_count,
            "payload_size": payload_size,
            "loss_rate": 0,
            "reorder_rate": 0,
            "checkpoint_interval": checkpoint_interval,
            "attack_type": attack_type,
            "recovery_success": recovery_success,
            "recovery_latency_ms": round(latency_ms, 4),
            "accepted_count": accepted_count,
            "rejected_count": rejected_count,
            "detection_result": detection_result,
            "extra_messages": extra_messages,
            "extra_bytes": extra_bytes,
            "throughput_msg_per_s": 0,
        }

    client_mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, "demo-seed")
    server_mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, "demo-seed")

    server_last_seq = 0
    accepted_count = 0
    rejected_count = 0
    detection_result = "normal" if attack_type == "none" else "missed"
    detection_reason = "normal"

    saved_packets: Dict[int, Dict[str, Any]] = {}
    payload_hash_log: List[str] = []

    extra_bytes = 0
    start_time = time.time()

    attack_seq = min(500, max(2, message_count // 2))
    replay_seq = max(1, attack_seq // 2)

    for seq in range(1, message_count + 1):
        payload = make_payload(seq, payload_size)
        payload_hash = hash_text(payload)

        packet = build_packet(
            protocol=protocol,
            seq=seq,
            prev_mem=client_mem,
            payload=payload,
        )

        # 删除攻击：跳过 attack_seq，下一条会触发 seq gap
        if attack_type == "drop" and seq == attack_seq:
            continue

        # 篡改攻击：修改 payload 但不重算 auth_tag
        if attack_type == "modify" and seq == attack_seq:
            packet = modify_payload_attack(packet)

        # 重放攻击：在 attack_seq 位置发送旧包
        if attack_type == "replay" and seq == attack_seq and replay_seq in saved_packets:
            packet = dict(saved_packets[replay_seq])

        ok, reason, new_seq, new_mem = verify_packet(
            protocol=protocol,
            packet=packet,
            server_last_seq=server_last_seq,
            server_last_mem=server_mem,
        )

        extra_bytes += estimate_packet_extra_bytes(protocol, packet)

        if ok:
            accepted_count += 1
            server_last_seq = new_seq
            server_mem = new_mem

            saved_packets[new_seq] = dict(packet)
            payload_hash_log.append(payload_hash)

            if protocol in ("hash_chain", "gmcp_r"):
                client_mem = update_memory(
                    prev_mem=client_mem,
                    session_id=SESSION_ID,
                    epoch=EPOCH,
                    seq=seq,
                    payload_hash=payload_hash,
                    sender_id=CLIENT_ID,
                )

        else:
            rejected_count += 1
            detection_reason = reason
            if attack_type != "none":
                detection_result = "detected"
            break

    elapsed = time.time() - start_time
    if elapsed <= 0:
        throughput = 0
    else:
        throughput = accepted_count / elapsed

    recovery_success, recovery_latency_ms, recovery_extra_messages, recovery_extra_bytes = simulate_recovery(
        protocol=protocol,
        final_seq=server_last_seq,
        final_mem=server_mem,
        checkpoint_interval=checkpoint_interval,
        payload_hash_log=payload_hash_log,
    )

    total_extra_messages = recovery_extra_messages
    total_extra_bytes = extra_bytes + recovery_extra_bytes

    if attack_type == "none":
        detection_result = "normal"
    elif detection_result != "detected":
        detection_result = "missed"

    return {
        "protocol": protocol,
        "scenario": scenario,
        "message_count": message_count,
        "payload_size": payload_size,
        "loss_rate": 0,
        "reorder_rate": 0,
        "checkpoint_interval": checkpoint_interval,
        "attack_type": attack_type,
        "recovery_success": recovery_success,
        "recovery_latency_ms": round(recovery_latency_ms, 4),
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "detection_result": detection_result,
        "detection_reason": detection_reason,
        "extra_messages": total_extra_messages,
        "extra_bytes": total_extra_bytes,
        "throughput_msg_per_s": round(throughput, 2),
    }


def main():
    recorder = MetricsRecorder("results/experiment_results.csv")

    total = 0

    for protocol in PROTOCOLS:
        for attack in ATTACKS:
            for count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for cp_interval in CHECKPOINT_INTERVALS:
                        row = run_single_experiment(
                            protocol=protocol,
                            scenario="formal_v1",
                            message_count=count,
                            payload_size=payload_size,
                            checkpoint_interval=cp_interval,
                            attack_type=attack,
                        )
                        recorder.add_row(row)
                        total += 1

    recorder.save()
    print("[EXPERIMENT] formal results saved to results/experiment_results.csv")
    print("[EXPERIMENT] total rows:", total)


if __name__ == "__main__":
    main()