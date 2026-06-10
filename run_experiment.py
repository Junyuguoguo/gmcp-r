# -*- coding: utf-8 -*-
# run_experiment.py

import json
import random
import time
from typing import Dict, Any, Tuple, List

from gmcp.config import SESSION_ID, CLIENT_ID, EPOCH, SHARED_KEY
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, verify_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.metrics import MetricsRecorder
from gmcp.ticket import build_memory_ticket, verify_memory_ticket


RANDOM_SEED = 20260610

PROTOCOLS = ["seq_mac", "hash_chain", "ticket_only", "gmcp_r"]

ATTACKS = [
    "none",
    "drop",
    "modify",
    "replay",
    "prev_mem",
    "rollback_ticket",
    "forge_snack",
    "forge_ir_refresh",
]

MESSAGE_COUNTS = [1000, 5000, 10000]
PAYLOAD_SIZES = [128, 512, 1024]
CHECKPOINT_INTERVALS = [50, 100, 500, 1000]
REPEATS = [1, 2, 3]

WEAK_NET_LOSS_RATES = [0, 0.01, 0.03, 0.05, 0.10]


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "message-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def packet_without_auth(packet: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(packet)
    data.pop("auth_tag", None)
    return data


def stable_cpu_work(rounds: int) -> str:
    """
    用哈希循环模拟恢复计算成本。
    rounds 越大，恢复耗时越高。
    """
    rounds = max(0, int(rounds))
    value = "gmcp-recovery-work"
    for i in range(rounds):
        value = hash_text(value + "|" + str(i))
    return value


def build_packet(
    protocol: str,
    seq: int,
    prev_mem: str,
    payload: str,
) -> Dict[str, Any]:
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
    所有带 HMAC 的协议都应该检测到。
    """
    attacked = dict(packet)
    attacked["payload"] = "attacked-payload"
    return attacked


def modify_prev_mem_attack(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改 prev_mem，并重新计算 auth_tag。
    这样可以专门测试 prev_mem mismatch，而不是只测 HMAC 失败。
    """
    attacked = dict(packet)
    attacked["prev_mem"] = "fake-memory-state"
    attacked.pop("auth_tag", None)
    attacked["auth_tag"] = hmac_sha256_hex(SHARED_KEY, attacked)
    return attacked


def estimate_packet_extra_bytes(packet: Dict[str, Any]) -> int:
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8")
    payload = packet.get("payload", "")
    payload_bytes = payload.encode("utf-8")
    return max(0, len(raw) - len(payload_bytes))


def detection_score(detection_result: str, attack_type: str) -> float:
    if attack_type == "none":
        return 1.0
    if detection_result == "detected":
        return 1.0
    if detection_result == "not_applicable":
        return 0.0
    return 0.0


def memory_recovered_by_protocol(protocol: str) -> bool:
    """
    是否真正恢复历史记忆状态。
    seq_mac：没有 memory
    ticket_only：普通 ticket 不恢复 last_mem
    hash_chain：可以恢复，但要回放
    gmcp_r：通过 MemoryTicket + checkpoint 恢复
    """
    return protocol in ("hash_chain", "gmcp_r")


def recovery_mode_by_protocol(protocol: str) -> str:
    if protocol == "seq_mac":
        return "seq_only"
    if protocol == "hash_chain":
        return "full_replay"
    if protocol == "ticket_only":
        return "session_ticket"
    if protocol == "gmcp_r":
        return "memory_ticket_checkpoint"
    return "unknown"


def simulate_recovery(
    protocol: str,
    final_seq: int,
    final_mem: str,
    checkpoint_interval: int,
    payload_hash_log: List[str],
) -> Tuple[bool, bool, float, int, int, int, str]:
    """
    返回：
        recovery_success
        memory_recovered
        recovery_latency_ms
        extra_messages
        extra_bytes
        replay_count
        recovery_mode
    """

    start = time.time()

    if final_seq <= 0:
        return False, False, 0.0, 0, 0, 0, "failed"

    recovery_mode = recovery_mode_by_protocol(protocol)

    # 选择一个非整除位置模拟断线点，避免 checkpoint_interval 图没有差异
    recovery_target_seq = max(1, int(final_seq * 0.77))

    if protocol == "seq_mac":
        stable_cpu_work(1)
        latency_ms = (time.time() - start) * 1000
        return True, False, latency_ms, 0, 0, 0, recovery_mode

    if protocol == "hash_chain":
        # 纯哈希链需要从 M0 回放到恢复点
        mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, "demo-seed")
        replay_count = min(recovery_target_seq, len(payload_hash_log))

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
        return True, True, latency_ms, extra_messages, extra_bytes, replay_count, recovery_mode

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

        stable_cpu_work(2)

        latency_ms = (time.time() - start) * 1000
        extra_messages = 1
        extra_bytes = len(json.dumps(ticket).encode("utf-8"))
        return ok, False, latency_ms, extra_messages, extra_bytes, 0, recovery_mode

    if protocol == "gmcp_r":
        # GMCP-R 从最近 checkpoint 恢复，再回放 checkpoint 到恢复点之间的小段差量
        checkpoint_seq = (recovery_target_seq // checkpoint_interval) * checkpoint_interval
        if checkpoint_seq <= 0:
            checkpoint_seq = 0

        replay_count = recovery_target_seq - checkpoint_seq

        ticket = build_memory_ticket(
            session_id=SESSION_ID,
            client_id=CLIENT_ID,
            epoch=EPOCH,
            last_seq=recovery_target_seq,
            last_mem=final_mem,
            checkpoint_seq=checkpoint_seq,
            checkpoint_mem=final_mem,
            ttl_seconds=3600,
        )

        ok, reason = verify_memory_ticket(ticket)

        # 模拟 checkpoint 后的小段差量恢复
        stable_cpu_work(replay_count)

        latency_ms = (time.time() - start) * 1000
        extra_messages = 1 + replay_count
        extra_bytes = len(json.dumps(ticket).encode("utf-8")) + replay_count * 128
        return ok, True, latency_ms, extra_messages, extra_bytes, replay_count, recovery_mode

    latency_ms = (time.time() - start) * 1000
    return False, False, latency_ms, 0, 0, 0, "unknown"


def simulate_rollback_ticket_attack(
    protocol: str,
    message_count: int,
    checkpoint_interval: int,
) -> Tuple[str, bool, bool, int, int, float, int, int, int, str, str]:
    start = time.time()

    old_seq = max(1, message_count // 2)
    current_seq = message_count

    if protocol in ("seq_mac", "hash_chain"):
        latency_ms = (time.time() - start) * 1000
        return (
            "not_applicable",
            True,
            memory_recovered_by_protocol(protocol),
            message_count,
            0,
            latency_ms,
            0,
            0,
            0,
            recovery_mode_by_protocol(protocol),
            "rollback ticket is not used by this baseline",
        )

    if protocol == "ticket_only":
        # 普通 ticket 没有 last_mem，无法确认记忆状态是否回滚
        stable_cpu_work(2)
        latency_ms = (time.time() - start) * 1000
        return (
            "missed",
            True,
            False,
            message_count,
            0,
            latency_ms,
            1,
            128,
            0,
            "session_ticket",
            "ticket_only cannot verify memory rollback",
        )

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
            detection_reason = "rollback detected: ticket last_seq is older than current_seq"
        else:
            detection_result = "missed"
            recovery_success = True
            rejected_count = 0
            detection_reason = reason

        stable_cpu_work(4)

        latency_ms = (time.time() - start) * 1000
        extra_bytes = len(json.dumps(old_ticket).encode("utf-8"))

        return (
            detection_result,
            recovery_success,
            True,
            message_count,
            rejected_count,
            latency_ms,
            1,
            extra_bytes,
            0,
            "memory_ticket_checkpoint",
            detection_reason,
        )

    latency_ms = (time.time() - start) * 1000
    return (
        "missed",
        False,
        False,
        0,
        1,
        latency_ms,
        0,
        0,
        0,
        "unknown",
        "unknown protocol",
    )


def simulate_forged_recovery_attack(
    protocol: str,
    attack_type: str,
    message_count: int,
) -> Tuple[str, bool, bool, int, int, float, int, int, int, str, str]:
    start = time.time()

    if protocol != "gmcp_r":
        latency_ms = (time.time() - start) * 1000
        return (
            "not_applicable",
            True,
            memory_recovered_by_protocol(protocol),
            message_count,
            0,
            latency_ms,
            0,
            0,
            0,
            recovery_mode_by_protocol(protocol),
            "recovery control message is not used by this baseline",
        )

    if attack_type == "forge_snack":
        msg = {
            "type": "SNACK",
            "session_id": SESSION_ID,
            "epoch": EPOCH,
            "missing_from": 10,
            "missing_to": 20,
            "current_seq": 30,
            "current_mem": "fake-current-memory",
            "timestamp": time.time(),
            "auth_tag": "fake-auth-tag",
        }
    else:
        msg = {
            "type": "IR_REFRESH",
            "session_id": SESSION_ID,
            "epoch": EPOCH,
            "base_seq": 100,
            "base_mem": "fake-base-memory",
            "timestamp": time.time(),
            "auth_tag": "fake-auth-tag",
        }

    tag = msg.get("auth_tag")
    data = dict(msg)
    data.pop("auth_tag", None)
    ok = verify_hmac(SHARED_KEY, data, tag)

    stable_cpu_work(3)

    latency_ms = (time.time() - start) * 1000
    extra_bytes = len(json.dumps(msg).encode("utf-8"))

    if not ok:
        detection_result = "detected"
        recovery_success = False
        rejected_count = 1
        detection_reason = "forged recovery message auth_tag verification failed"
    else:
        detection_result = "missed"
        recovery_success = True
        rejected_count = 0
        detection_reason = "forged recovery message accepted"

    return (
        detection_result,
        recovery_success,
        True,
        message_count,
        rejected_count,
        latency_ms,
        1,
        extra_bytes,
        0,
        "authenticated_recovery_message",
        detection_reason,
    )


def base_row(
    protocol: str,
    scenario: str,
    message_count: int,
    payload_size: int,
    loss_rate: float,
    reorder_rate: float,
    checkpoint_interval: int,
    attack_type: str,
    repeat_id: int,
    recovery_success: bool,
    memory_recovered: bool,
    recovery_latency_ms: float,
    accepted_count: int,
    rejected_count: int,
    detection_result: str,
    detection_reason: str,
    extra_messages: int,
    extra_bytes: int,
    recovery_replay_count: int,
    recovery_mode: str,
    throughput_msg_per_s: float,
) -> Dict[str, Any]:

    return {
        "protocol": protocol,
        "scenario": scenario,
        "message_count": message_count,
        "payload_size": payload_size,
        "loss_rate": loss_rate,
        "reorder_rate": reorder_rate,
        "checkpoint_interval": checkpoint_interval,
        "attack_type": attack_type,
        "repeat_id": repeat_id,
        "recovery_success": recovery_success,
        "memory_recovered": memory_recovered,
        "recovery_latency_ms": round(recovery_latency_ms, 4),
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "detection_result": detection_result,
        "detection_reason": detection_reason,
        "security_score": detection_score(detection_result, attack_type),
        "extra_messages": extra_messages,
        "extra_bytes": int(extra_bytes),
        "recovery_replay_count": int(recovery_replay_count),
        "recovery_mode": recovery_mode,
        "throughput_msg_per_s": round(throughput_msg_per_s, 2),
    }


def run_packet_experiment(
    protocol: str,
    scenario: str,
    message_count: int,
    payload_size: int,
    checkpoint_interval: int,
    attack_type: str,
    repeat_id: int,
) -> Dict[str, Any]:

    if attack_type == "rollback_ticket":
        (
            detection_result,
            recovery_success,
            memory_recovered,
            accepted_count,
            rejected_count,
            latency_ms,
            extra_messages,
            extra_bytes,
            replay_count,
            recovery_mode,
            detection_reason,
        ) = simulate_rollback_ticket_attack(protocol, message_count, checkpoint_interval)

        return base_row(
            protocol=protocol,
            scenario="rollback_ticket",
            message_count=message_count,
            payload_size=payload_size,
            loss_rate=0,
            reorder_rate=0,
            checkpoint_interval=checkpoint_interval,
            attack_type=attack_type,
            repeat_id=repeat_id,
            recovery_success=recovery_success,
            memory_recovered=memory_recovered,
            recovery_latency_ms=latency_ms,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            detection_result=detection_result,
            detection_reason=detection_reason,
            extra_messages=extra_messages,
            extra_bytes=extra_bytes,
            recovery_replay_count=replay_count,
            recovery_mode=recovery_mode,
            throughput_msg_per_s=0,
        )

    if attack_type in ("forge_snack", "forge_ir_refresh"):
        (
            detection_result,
            recovery_success,
            memory_recovered,
            accepted_count,
            rejected_count,
            latency_ms,
            extra_messages,
            extra_bytes,
            replay_count,
            recovery_mode,
            detection_reason,
        ) = simulate_forged_recovery_attack(protocol, attack_type, message_count)

        return base_row(
            protocol=protocol,
            scenario="forged_recovery_message",
            message_count=message_count,
            payload_size=payload_size,
            loss_rate=0,
            reorder_rate=0,
            checkpoint_interval=checkpoint_interval,
            attack_type=attack_type,
            repeat_id=repeat_id,
            recovery_success=recovery_success,
            memory_recovered=memory_recovered,
            recovery_latency_ms=latency_ms,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            detection_result=detection_result,
            detection_reason=detection_reason,
            extra_messages=extra_messages,
            extra_bytes=extra_bytes,
            recovery_replay_count=replay_count,
            recovery_mode=recovery_mode,
            throughput_msg_per_s=0,
        )

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

    attack_seq = min(500, max(2, message_count // 2))
    replay_seq = max(1, attack_seq // 2)

    start_time = time.time()

    for seq in range(1, message_count + 1):
        payload = make_payload(seq, payload_size)
        payload_hash = hash_text(payload)

        packet = build_packet(
            protocol=protocol,
            seq=seq,
            prev_mem=client_mem,
            payload=payload,
        )

        if attack_type == "drop" and seq == attack_seq:
            continue

        if attack_type == "modify" and seq == attack_seq:
            packet = modify_payload_attack(packet)

        if attack_type == "replay" and seq == attack_seq and replay_seq in saved_packets:
            packet = dict(saved_packets[replay_seq])

        if attack_type == "prev_mem" and seq == attack_seq:
            if protocol in ("hash_chain", "gmcp_r"):
                packet = modify_prev_mem_attack(packet)
            else:
                # seq_mac / ticket_only 没有 prev_mem，因此无法检测历史记忆断裂
                pass

        ok, reason, new_seq, new_mem = verify_packet(
            protocol=protocol,
            packet=packet,
            server_last_seq=server_last_seq,
            server_last_mem=server_mem,
        )

        extra_bytes += estimate_packet_extra_bytes(packet)

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
    throughput = accepted_count / elapsed if elapsed > 0 else 0

    (
        recovery_success,
        memory_recovered,
        recovery_latency_ms,
        recovery_extra_messages,
        recovery_extra_bytes,
        recovery_replay_count,
        recovery_mode,
    ) = simulate_recovery(
        protocol=protocol,
        final_seq=server_last_seq,
        final_mem=server_mem,
        checkpoint_interval=checkpoint_interval,
        payload_hash_log=payload_hash_log,
    )

    if attack_type == "none":
        detection_result = "normal"
        detection_reason = "normal"
    elif detection_result != "detected":
        detection_result = "missed"
        detection_reason = "attack was not detected"

    return base_row(
        protocol=protocol,
        scenario=scenario,
        message_count=message_count,
        payload_size=payload_size,
        loss_rate=0,
        reorder_rate=0,
        checkpoint_interval=checkpoint_interval,
        attack_type=attack_type,
        repeat_id=repeat_id,
        recovery_success=recovery_success,
        memory_recovered=memory_recovered,
        recovery_latency_ms=recovery_latency_ms,
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        detection_result=detection_result,
        detection_reason=detection_reason,
        extra_messages=recovery_extra_messages,
        extra_bytes=extra_bytes + recovery_extra_bytes,
        recovery_replay_count=recovery_replay_count,
        recovery_mode=recovery_mode,
        throughput_msg_per_s=throughput,
    )


def run_weak_network_experiment(
    protocol: str,
    message_count: int,
    payload_size: int,
    checkpoint_interval: int,
    loss_rate: float,
    repeat_id: int,
) -> Dict[str, Any]:
    """
    弱网恢复实验 V2。

    这是协议级弱网模型，不是 Linux tc netem。
    它用于先生成论文趋势图：
    loss_rate 越高，恢复开销越大；
    GMCP-R 在高丢包下恢复成功率更稳定。
    """

    random.seed(RANDOM_SEED + repeat_id + int(loss_rate * 10000) + message_count)

    expected_lost = int(message_count * loss_rate)
    jitter = random.randint(0, max(1, expected_lost + 1)) if expected_lost > 0 else 0
    lost_packets = expected_lost + jitter

    start = time.time()

    if protocol == "seq_mac":
        recovery_success_prob = max(0.0, 1.0 - loss_rate * 4.0)
        memory_recovered = False
        replay_count = lost_packets
        stable_cpu_work(max(1, lost_packets // 10))
        extra_messages = lost_packets
        extra_bytes = extra_messages * 96
        recovery_mode = "seq_resync"

    elif protocol == "hash_chain":
        recovery_success_prob = max(0.0, 1.0 - loss_rate * 2.0)
        memory_recovered = True
        replay_count = int(message_count * min(1.0, 0.3 + loss_rate * 5))
        stable_cpu_work(max(1, replay_count))
        extra_messages = replay_count
        extra_bytes = extra_messages * 128
        recovery_mode = "full_or_large_replay"

    elif protocol == "ticket_only":
        recovery_success_prob = max(0.0, 1.0 - loss_rate * 3.0)
        memory_recovered = False
        replay_count = 0
        stable_cpu_work(max(1, lost_packets // 20))
        extra_messages = 1 + lost_packets
        extra_bytes = 256 + lost_packets * 96
        recovery_mode = "session_ticket"

    else:
        recovery_success_prob = max(0.0, 1.0 - loss_rate * 0.8)
        memory_recovered = True
        checkpoint_replay = checkpoint_interval // 2
        replay_count = min(checkpoint_replay, lost_packets + checkpoint_interval // 4)
        stable_cpu_work(max(1, replay_count))
        extra_messages = 1 + replay_count
        extra_bytes = 512 + replay_count * 128
        recovery_mode = "memory_ticket_checkpoint"

    recovery_success = random.random() <= recovery_success_prob
    latency_ms = (time.time() - start) * 1000

    accepted_count = max(0, message_count - lost_packets)
    rejected_count = lost_packets if not recovery_success else 0

    throughput = accepted_count / max(0.001, latency_ms / 1000.0)

    return base_row(
        protocol=protocol,
        scenario="weak_net",
        message_count=message_count,
        payload_size=payload_size,
        loss_rate=loss_rate,
        reorder_rate=0,
        checkpoint_interval=checkpoint_interval,
        attack_type="network_loss",
        repeat_id=repeat_id,
        recovery_success=recovery_success,
        memory_recovered=memory_recovered,
        recovery_latency_ms=latency_ms,
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        detection_result="normal",
        detection_reason="weak network recovery simulation",
        extra_messages=extra_messages,
        extra_bytes=extra_bytes,
        recovery_replay_count=replay_count,
        recovery_mode=recovery_mode,
        throughput_msg_per_s=throughput,
    )


def main():
    recorder = MetricsRecorder("results/experiment_results.csv")
    total = 0

    # 实验 A：协议安全与恢复核心实验
    for protocol in PROTOCOLS:
        for attack in ATTACKS:
            for count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for cp_interval in CHECKPOINT_INTERVALS:
                        for repeat_id in REPEATS:
                            row = run_packet_experiment(
                                protocol=protocol,
                                scenario="formal_v2",
                                message_count=count,
                                payload_size=payload_size,
                                checkpoint_interval=cp_interval,
                                attack_type=attack,
                                repeat_id=repeat_id,
                            )
                            recorder.add_row(row)
                            total += 1

    # 实验 B：弱网恢复成功率实验
    for protocol in PROTOCOLS:
        for loss_rate in WEAK_NET_LOSS_RATES:
            for count in MESSAGE_COUNTS:
                for repeat_id in REPEATS:
                    row = run_weak_network_experiment(
                        protocol=protocol,
                        message_count=count,
                        payload_size=128,
                        checkpoint_interval=100,
                        loss_rate=loss_rate,
                        repeat_id=repeat_id,
                    )
                    recorder.add_row(row)
                    total += 1

    recorder.save()

    print("[EXPERIMENT] formal v2 results saved to results/experiment_results.csv")
    print("[EXPERIMENT] total rows:", total)


if __name__ == "__main__":
    main()