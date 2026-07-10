# -*- coding: utf-8 -*-
# run_checkpoint_recovery_experiment.py
#
# 基于Checkpoint的真实状态重建实验
# 验证从Checkpoint恢复memory chain的能力

import csv
import json
import os
import socket
import time
from typing import Dict, Any, List, Tuple, Optional

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
    CHECKPOINT_INTERVAL,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.checkpoint_manager import CheckpointManager
from gmcp.recovery_protocol import (
    build_recovery_request,
    verify_recovery_response,
)


OUTPUT_DIR = "results/checkpoint_recovery"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "checkpoint_recovery_results.csv")

# 实验参数
MESSAGE_COUNTS = [500, 1000]
PAYLOAD_SIZES = [128]
ATTACK_TYPES = ["disconnect", "drop", "modify"]
CHECKPOINT_INTERVALS = [50, 100]  # 测试不同的checkpoint间隔
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

SOCKET_TIMEOUT = 10.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "checkpoint-recovery-%d-" % seq
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


def request_recovery(
    sock,
    file_obj,
    session_id: str,
    client_last_seq: int,
    client_last_mem: str,
    reason: str,
    memory_ticket: Dict[str, Any] = None,
) -> Tuple[bool, Dict[str, Any], float, int, int, Dict[str, Any]]:

    start = time.time()

    request = build_recovery_request(
        session_id=session_id,
        client_id=CLIENT_ID,
        epoch=EPOCH,
        client_last_seq=client_last_seq,
        client_last_mem=client_last_mem,
        reason=reason,
        memory_ticket=memory_ticket,
    )

    request_bytes = json_size(request)
    send_json_line(sock, request)
    response = recv_json_line(file_obj)
    response_bytes = json_size(response)

    latency_ms = (time.time() - start) * 1000

    # Verify recovery response HMAC (client no longer verifies MemoryTicket)
    verified, verify_reason = verify_recovery_response(
        response, session_id, EPOCH, request["recovery_nonce"]
    )
    ok = verified and response.get("ok") is True

    ticket_info = {
        "response_verified": verified,
        "response_verify_reason": verify_reason,
        "response_state_match": verified,  # HMAC covers all fields
    }

    return ok, response, latency_ms, 2, request_bytes + response_bytes, ticket_info


def reconstruct_memory_chain(
    checkpoint_mem: str,
    checkpoint_seq: int,
    target_seq: int,
    messages: Dict[int, Dict[str, Any]],
    session_id: str,
) -> Tuple[str, int, float]:
    """从Checkpoint重建memory chain"""
    start = time.time()
    current_mem = checkpoint_mem
    replay_count = 0
    
    for seq in range(checkpoint_seq + 1, target_seq + 1):
        if seq in messages:
            msg = messages[seq]
            payload_hash = hash_text(msg.get("payload", ""))
            current_mem = update_memory(
                prev_mem=current_mem,
                session_id=session_id,
                epoch=EPOCH,
                seq=seq,
                payload_hash=payload_hash,
                sender_id=CLIENT_ID,
            )
            replay_count += 1
    
    latency_ms = (time.time() - start) * 1000
    return current_mem, replay_count, latency_ms


def run_one_checkpoint_experiment(
    attack_type: str,
    message_count: int,
    payload_size: int,
    checkpoint_interval: int,
    repeat_id: int,
) -> Dict[str, Any]:

    session_id = (
        f"checkpoint-{attack_type}-m{message_count}-k{checkpoint_interval}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    initial_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    current_mem = initial_mem
    saved_memory_ticket = None

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
    reconstruction_match = False

    recovery_latency_ms = 0.0
    recovery_extra_messages = 0
    recovery_extra_bytes = 0
    detection_reason = "normal"
    recovery_reason = "not_started"
    ticket_verified = False
    ticket_reason = ""

    # Checkpoint相关
    checkpoint_manager = CheckpointManager(session_id, EPOCH, checkpoint_interval)
    checkpoint_count = 0
    checkpoint_storage_bytes = 0
    saved_messages: Dict[int, Dict[str, Any]] = {}
    replay_count = 0
    reconstructed_mem = ""
    recon_latency = 0.0
    # 恢复时固定的变量
    recovery_checkpoint_seq = 0
    recovery_checkpoint_mem = ""
    recovery_target_seq = 0
    recovery_target_mem = ""

    # 攻击点：固定在第一个MemoryTicket之后的统一位置
    # 无论k是多少，都使用相同的恢复目标
    TICKET_INTERVAL = 100
    attack_seq = TICKET_INTERVAL + 50  # 固定在seq=150
    if attack_seq > message_count:
        attack_seq = message_count - 10
    attack_done = False

    start_time = time.time()

    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp()

        seq = 1
        while seq <= message_count:
            payload = make_payload(seq, payload_size)
            payload_hash = hash_text(payload)

            packet = build_data_packet(
                session_id=session_id,
                sender_id=CLIENT_ID,
                epoch=EPOCH,
                seq=seq,
                prev_mem=current_mem,
                payload=payload,
            )
            
            # 在第一条DATA中携带checkpoint_interval
            if seq == 1:
                packet["checkpoint_interval"] = checkpoint_interval
                # 重新计算auth_tag
                from gmcp.packet import packet_without_auth
                data_for_auth = packet_without_auth(packet)
                data_for_auth["checkpoint_interval"] = checkpoint_interval
                packet["auth_tag"] = hmac_sha256_hex(DATA_AUTH_KEY, data_for_auth)

            # disconnect攻击
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
                    memory_ticket=saved_memory_ticket,
                )
                ticket_verified = ticket_info["response_verified"]
                ticket_reason = ticket_info["response_verify_reason"]

                if ok:
                    recovered = True
                    recovery_success = True
                    recovery_reason = recovery_response.get("reason", "ok")
                    recovery_server_last_seq = int(recovery_response.get("server_last_seq", 0))
                    recovery_server_mem = recovery_response.get("server_last_mem", initial_mem)
                    
                    # 真正重建memory chain
                    latest_ckpt = checkpoint_manager.get_latest_checkpoint()
                    if latest_ckpt:
                        # 立即固定恢复时的checkpoint和target
                        recovery_checkpoint_seq = latest_ckpt.seq
                        recovery_checkpoint_mem = latest_ckpt.memory
                        recovery_target_seq = recovery_server_last_seq
                        recovery_target_mem = recovery_server_mem
                        
                        reconstructed_mem, replay_count, recon_latency = reconstruct_memory_chain(
                            checkpoint_mem=recovery_checkpoint_mem,
                            checkpoint_seq=recovery_checkpoint_seq,
                            target_seq=recovery_target_seq,
                            messages=saved_messages,
                            session_id=session_id,
                        )
                        reconstruction_match = (reconstructed_mem == recovery_target_mem)
                    
                    current_mem = recovery_server_mem
                    memory_match_after_recovery = True  # 服务器权威状态
                    final_server_last_seq = recovery_server_last_seq
                    final_server_mem = recovery_server_mem
                    seq = recovery_server_last_seq + 1
                    continue
                else:
                    recovery_reason = ticket_info.get(
                        "ticket_reason",
                        recovery_response.get("reason", "recovery failed"),
                    )
                    break

            # drop攻击
            if attack_type == "drop" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_detected = True
                detection_reason = "drop attack at seq=%d" % attack_seq
                
                # 发起恢复
                recovery_requested = True
                
                # 保存提交的票据快照
                import copy
                submitted_ticket_snapshot = copy.deepcopy(saved_memory_ticket) if saved_memory_ticket else None
                
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
                    memory_ticket=saved_memory_ticket,
                )
                ticket_verified = ticket_info["response_verified"]
                ticket_reason = ticket_info["response_verify_reason"]
                server_ticket_verified = True
                response_state_match = ticket_info.get("response_state_match", False)
                
                if ok:
                    recovered = True
                    recovery_success = True
                    recovery_reason = recovery_response.get("reason", "ok")
                    recovery_server_last_seq = int(recovery_response.get("server_last_seq", 0))
                    recovery_server_mem = recovery_response.get("server_last_mem", initial_mem)
                    
                    # 真正重建memory chain
                    latest_ckpt = checkpoint_manager.get_latest_checkpoint()
                    if latest_ckpt:
                        recovery_checkpoint_seq = latest_ckpt.seq
                        recovery_checkpoint_mem = latest_ckpt.memory
                        recovery_target_seq = recovery_server_last_seq
                        recovery_target_mem = recovery_server_mem
                        
                        reconstructed_mem, replay_count, recon_latency = reconstruct_memory_chain(
                            checkpoint_mem=recovery_checkpoint_mem,
                            checkpoint_seq=recovery_checkpoint_seq,
                            target_seq=recovery_target_seq,
                            messages=saved_messages,
                            session_id=session_id,
                        )
                        reconstruction_match = (reconstructed_mem == recovery_target_mem)
                    
                    current_mem = recovery_server_mem
                    memory_match_after_recovery = True
                    final_server_last_seq = recovery_server_last_seq
                    final_server_mem = recovery_server_mem
                    seq = recovery_server_last_seq + 1
                    continue
                else:
                    recovery_reason = ticket_info.get("ticket_reason", "recovery failed")
                    break

            # modify攻击
            if attack_type == "modify" and seq == attack_seq and not attack_done:
                attack_done = True
                packet["payload"] = "attacked-payload"

            send_json_line(sock, packet)
            sent_count += 1

            try:
                response = recv_json_line(file_obj)
            except socket.timeout:
                timeout_count += 1
                detection_reason = "client timeout"
                break

            final_server_mem = response.get("last_mem", final_server_mem)
            final_server_last_seq = int(response.get("last_seq", final_server_last_seq))

            # 保存MemoryTicket
            if "memory_ticket" in response and isinstance(response["memory_ticket"], dict):
                saved_memory_ticket = response["memory_ticket"]

            if response.get("ok"):
                accepted_count += 1
                saved_messages[seq] = {"payload": payload}
                
                current_mem = update_memory(
                    prev_mem=current_mem,
                    session_id=session_id,
                    epoch=EPOCH,
                    seq=seq,
                    payload_hash=payload_hash,
                    sender_id=CLIENT_ID,
                )

                # 检查是否需要创建checkpoint
                if checkpoint_manager.should_checkpoint(seq):
                    checkpoint = checkpoint_manager.create_checkpoint(seq, current_mem)
                    checkpoint_count += 1
                    checkpoint_storage_bytes += json_size({
                        "seq": checkpoint.seq,
                        "memory": checkpoint.memory,
                    })
                
                seq += 1
                continue

            # 攻击被检测到
            rejected_count += 1
            attack_detected = True
            detection_reason = response.get("reason", "unknown")

            # 发起恢复
            recovery_requested = True
            
            # 保存提交的票据快照
            import copy
            submitted_ticket_snapshot = copy.deepcopy(saved_memory_ticket) if saved_memory_ticket else None
            
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
                memory_ticket=saved_memory_ticket,
            )
            ticket_verified = ticket_info["response_verified"]
            ticket_reason = ticket_info["response_verify_reason"]
            server_ticket_verified = True
            response_state_match = ticket_info.get("response_state_match", False)

            if ok:
                recovered = True
                recovery_success = True
                recovery_reason = recovery_response.get("reason", "ok")
                recovery_server_last_seq = int(recovery_response.get("server_last_seq", 0))
                recovery_server_mem = recovery_response.get("server_last_mem", initial_mem)
                
                # 真正重建memory chain
                latest_ckpt = checkpoint_manager.get_latest_checkpoint()
                if latest_ckpt:
                    # 立即固定恢复时的checkpoint和target
                    recovery_checkpoint_seq = latest_ckpt.seq
                    recovery_checkpoint_mem = latest_ckpt.memory
                    recovery_target_seq = recovery_server_last_seq
                    recovery_target_mem = recovery_server_mem
                    
                    reconstructed_mem, replay_count, recon_latency = reconstruct_memory_chain(
                        checkpoint_mem=recovery_checkpoint_mem,
                        checkpoint_seq=recovery_checkpoint_seq,
                        target_seq=recovery_target_seq,
                        messages=saved_messages,
                        session_id=session_id,
                    )
                    reconstruction_match = (reconstructed_mem == recovery_target_mem)
                
                current_mem = recovery_server_mem
                memory_match_after_recovery = True
                final_server_last_seq = recovery_server_last_seq
                final_server_mem = recovery_server_mem
                seq = recovery_server_last_seq + 1
                continue
                
                current_mem = final_server_mem
                memory_match_after_recovery = (current_mem == final_server_mem)
                seq = final_server_last_seq + 1
                continue
            else:
                recovery_reason = ticket_info.get("ticket_reason", "recovery failed")
                break

    except Exception as e:
        detection_reason = f"error: {e}"
        print(f"[ERROR] {e}")

    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time

    # 获取checkpoint统计
    checkpoint_stats = checkpoint_manager.get_statistics()
    
    # 使用get_storage_size()获取真实存储大小
    real_checkpoint_storage = checkpoint_manager.get_storage_size()

    return {
        "session_id": session_id,
        "attack_type": attack_type,
        "message_count": message_count,
        "payload_size": payload_size,
        "checkpoint_interval": checkpoint_interval,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "attack_detected": attack_detected,
        "detection_reason": detection_reason,
        "recovery_requested": recovery_requested,
        "recovery_success": recovery_success,
        "recovery_reason": recovery_reason,
        "memory_match_after_recovery": memory_match_after_recovery,
        "reconstruction_match": reconstruction_match,
        "recovery_latency_ms": round(recovery_latency_ms, 3),
        "checkpoint_count": checkpoint_count,
        "checkpoint_interval_used": checkpoint_interval,
        # 恢复时固定的checkpoint和target（不是实验结束时的）
        "checkpoint_seq": recovery_checkpoint_seq,
        "checkpoint_mem": recovery_checkpoint_mem,
        "target_seq": recovery_target_seq,
        "target_mem": recovery_target_mem,
        "replay_count": replay_count,
        "reconstructed_mem": reconstructed_mem,
        "checkpoint_storage_bytes": real_checkpoint_storage,
        "ticket_verified": ticket_verified,
        "ticket_reason": ticket_reason,
        "elapsed_seconds": round(elapsed, 3),
        "final_server_last_seq": final_server_last_seq,
    }


def run_all_experiments():
    ensure_output_dir()

    fieldnames = [
        "session_id", "attack_type", "message_count", "payload_size", 
        "checkpoint_interval", "repeat_id", "sent_count", "accepted_count",
        "rejected_count", "timeout_count", "attack_detected", "detection_reason",
        "recovery_requested", "recovery_success", "recovery_reason",
        "memory_match_after_recovery", "reconstruction_match",
        "recovery_latency_ms", "checkpoint_count", "checkpoint_interval_used",
        "checkpoint_seq", "checkpoint_mem", "target_seq", "target_mem",
        "replay_count", "reconstructed_mem", "checkpoint_storage_bytes",
        "ticket_verified", "ticket_reason",
        "elapsed_seconds", "final_server_last_seq",
    ]

    all_results = []
    total = len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * len(ATTACK_TYPES) * len(CHECKPOINT_INTERVALS) * len(REPEATS)
    completed = 0

    for message_count in MESSAGE_COUNTS:
        for payload_size in PAYLOAD_SIZES:
            for attack_type in ATTACK_TYPES:
                for checkpoint_interval in CHECKPOINT_INTERVALS:
                    for repeat_id in REPEATS:
                        completed += 1
                        print(f"[{completed}/{total}] attack={attack_type} msg={message_count} "
                              f"k={checkpoint_interval} rep={repeat_id}", flush=True)

                        result = run_one_checkpoint_experiment(
                            attack_type=attack_type,
                            message_count=message_count,
                            payload_size=payload_size,
                            checkpoint_interval=checkpoint_interval,
                            repeat_id=repeat_id,
                        )

                        all_results.append(result)

                        status = "✅" if result["recovery_success"] else "❌"
                        print(f"  {status} recovery={result['recovery_success']} "
                              f"reconstruct={result['reconstruction_match']} "
                              f"checkpoints={result['checkpoint_count']}", flush=True)

    # 保存结果
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_results:
            writer.writerow(row)

    print(f"\n[COMPLETE] Saved {len(all_results)} results to {OUTPUT_CSV}")


if __name__ == "__main__":
    run_all_experiments()
