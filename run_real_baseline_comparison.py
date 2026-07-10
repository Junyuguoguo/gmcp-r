# -*- coding: utf-8 -*-
# run_real_baseline_comparison.py
#
# 真实Baseline对比实验
# 对比GMCP-R与hash_chain、seq_mac、ticket_only、authenticated_hash_chain协议
#
# 攻击模型拆分为两类：
#   1. 网络攻击者 (network_attacker) —— 不知道密钥，无法伪造有效MAC
#      - modify_unsigned:      修改payload，不更新HMAC
#      - metadata_tamper:      修改seq/session/prev_mem，不更新HMAC
#      - exact_replay:         保存第1条完整合法报文，原封不动重发
#
#   2. 恶意持钥客户端 (malicious_client) —— 知道DATA密钥，可计算有效MAC
#      - forged_prev_mem_valid_mac:  用合法HMAC构造与历史不连续的消息
#      - sequence_gap_valid_mac:     跳过序列号
#      - cross_session_valid_mac:    跨会话
#      - cross_epoch_valid_mac:      跨epoch

import csv
import argparse
import json
import os
import socket
import subprocess
import time
import sys
from typing import Dict, Any, List, Tuple, Optional

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, with_hmac, verify_tagged_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet as gmcp_build_data_packet
from gmcp.experiment_stats import (
    ExperimentTracker,
    collect_experiment_metadata,
    calculate_statistics,
    format_statistics_for_csv,
)

# 导入baseline协议
from gmcp.baselines.hash_chain import (
    create_initial_state as hash_chain_create_state,
    build_data_packet as hash_chain_build_packet,
    HashChainVerifier,
)
from gmcp.baselines.seq_mac import (
    create_initial_state as seq_mac_create_state,
    build_data_packet as seq_mac_build_packet,
    SeqMACVerifier as SeqMacVerifier,
)
from gmcp.baselines.ticket_only import (
    create_initial_state as ticket_only_create_state,
    build_data_packet as ticket_only_build_packet,
    TicketOnlyVerifier,
)
from gmcp.baselines.authenticated_hash_chain import (
    create_initial_state as auth_hc_create_state,
    build_data_packet as auth_hc_build_packet,
    AuthHashChainVerifier,
)

# 导入攻击模型
from gmcp.attack import (
    CATEGORY_NETWORK_ATTACKER,
    CATEGORY_MALICIOUS_CLIENT,
    ALL_ATTACK_TYPES,
    attack_category,
    attack_applicable_to_protocol,
    apply_modify_unsigned,
    apply_metadata_tamper,
    apply_exact_replay,
    build_forged_prev_mem_packet,
    build_sequence_gap_packet,
    build_cross_session_packet,
    build_cross_epoch_packet,
)


_OUTPUT_ROOT = os.getenv("GMCP_OUTPUT_ROOT")
if _OUTPUT_ROOT:
    OUTPUT_DIR = _OUTPUT_ROOT
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "baseline_comparison.csv")
else:
    OUTPUT_DIR = "results/real_baseline_comparison"
    OUTPUT_CSV = os.path.join(OUTPUT_DIR, "real_baseline_comparison_results.csv")

# 实验参数
PROTOCOLS = ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]
MESSAGE_COUNTS = [int(x) for x in os.getenv("GMCP_MESSAGE_COUNTS", "100,500,1000").split(",")]
PAYLOAD_SIZES = [int(x) for x in os.getenv("GMCP_PAYLOAD_SIZES", "128,512").split(",")]

# 攻击类型：两类攻击者模型
ATTACK_TYPES = list(ALL_ATTACK_TYPES)

REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

# 服务器端口（baseline服务器使用9001端口）
BASELINE_PORT = 9001

SOCKET_TIMEOUT = 10.0
SERVER_SPAWN_WAIT = 8


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "baseline-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


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
def send_hello(sock, file_obj, protocol, session_id, sender_id, epoch):
    """Send HELLO handshake and wait for HELLO_ACK."""
    # Normalize protocol name to match what packet builders produce
    hello_protocol = "gmcp" if protocol == "gmcp_r" else protocol
    hello = with_hmac(DATA_AUTH_KEY, {
        "type": "HELLO",
        "protocol": hello_protocol,
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "client_nonce": str(int(time.time() * 1000000)),
        "timestamp": time.time(),
    })
    send_json_line(sock, hello)
    ack = recv_json_line(file_obj)
    return ack


def _classify_rejection(reason: str) -> str:
    """Classify rejection reason into attack detection category."""
    if not reason:
        return ""
    r = reason.lower()
    if "connection" in r and "mismatch" in r:
        return "malicious_client_detected"
    if "auth_tag" in r or "mac mismatch" in r or "chain_hash" in r or "payload_hash" in r:
        return "network_attacker_detected"
    if "session_id" in r or "epoch" in r or "seq" in r or "prev_mem" in r or "prev_hash" in r:
        return "malicious_client_detected"
    return "other"




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


def open_tcp(port=BASELINE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def spawn_baseline_server(port=BASELINE_PORT):
    """Start real_baseline_server.py and wait until it accepts TCP connections."""
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "real_baseline_server.py"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.time() + SERVER_SPAWN_WAIT
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((SERVER_TARGET_HOST, port))
            s.close()
            print(f"[SPAWN] Baseline server ready on port {port}")
            return proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    raise RuntimeError(f"baseline server did not start on port {port}")


def build_packet_for_protocol(
    protocol: str,
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
    state: Any,
) -> Dict[str, Any]:
    """根据协议类型构建数据包"""
    
    if protocol == "gmcp_r" or protocol == "gmcp":
        return gmcp_build_data_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_mem=state.last_mem,
            payload=payload,
        )
    elif protocol == "hash_chain":
        return hash_chain_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
    elif protocol == "authenticated_hash_chain":
        return auth_hc_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
    elif protocol == "seq_mac":
        return seq_mac_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
        )
    elif protocol == "ticket_only":
        return ticket_only_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
            ticket=state.ticket,
        )
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def update_state_after_accept(protocol: str, state: Any, seq: int, packet: Dict[str, Any], response: Dict[str, Any]) -> None:
    """Update the local client state after the server accepts a packet."""
    if protocol == "gmcp_r" or protocol == "gmcp":
        state.last_seq = int(response.get("last_seq", state.last_seq))
        state.last_mem = response.get("last_mem", state.last_mem)
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        state.last_seq = seq
        state.last_hash = packet.get("chain_hash", state.last_hash)
    else:
        state.last_seq = seq


def expected_attack_reason(attack_type: str) -> str:
    """Primary reason substring expected for the attack packet response."""
    if attack_type == "cross_session_valid_mac":
        return "connection session mismatch"
    if attack_type == "cross_epoch_valid_mac":
        return "connection epoch mismatch"
    if attack_type == "sequence_gap_valid_mac":
        return "seq"
    if attack_type == "forged_prev_mem_valid_mac":
        return "prev"
    if attack_type in ("modify_unsigned", "metadata_tamper"):
        return "auth_tag"
    if attack_type == "exact_replay":
        return "seq"
    return ""


def _get_build_fn(protocol: str):
    """获取协议对应的build函数"""
    if protocol == "gmcp_r" or protocol == "gmcp":
        return gmcp_build_data_packet
    elif protocol == "hash_chain":
        return hash_chain_build_packet
    elif protocol == "authenticated_hash_chain":
        return auth_hc_build_packet
    elif protocol == "seq_mac":
        return seq_mac_build_packet
    elif protocol == "ticket_only":
        return ticket_only_build_packet
    raise ValueError(f"Unknown protocol: {protocol}")


def apply_attack(
    attack_type: str,
    protocol: str,
    packet: Dict[str, Any],
    seq: int,
    session_id: str,
    sender_id: str,
    epoch: int,
    payload: str,
    state: Any,
    saved_first_packet: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    应用攻击修改，返回 (modified_packet, attack_applicable)。
    如果attack_applicable为False，表示该攻击对当前协议不适用。
    返回None表示该包应该被跳过（drop场景，此处不使用）。
    """
    if attack_type == "none":
        return packet, True

    # ---- Category 1: 网络攻击者（不重算MAC） ----

    if attack_type == "modify_unsigned":
        return apply_modify_unsigned(packet), True

    if attack_type == "metadata_tamper":
        return apply_metadata_tamper(packet), True

    if attack_type == "exact_replay":
        if saved_first_packet is None:
            # 没有保存的首包，攻击无法执行
            return packet, False
        return apply_exact_replay(saved_first_packet), True

    # ---- Category 2: 恶意持钥客户端（重算有效MAC） ----

    if attack_type == "forged_prev_mem_valid_mac":
        if not attack_applicable_to_protocol(attack_type, protocol):
            return None, False
        build_fn = _get_build_fn(protocol)
        forged = build_forged_prev_mem_packet(
            protocol=protocol,
            build_fn=build_fn,
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
        )
        return forged, True

    if attack_type == "sequence_gap_valid_mac":
        build_fn = _get_build_fn(protocol)
        return build_sequence_gap_packet(
            protocol=protocol,
            build_fn=build_fn,
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
            state=state,
        ), True

    if attack_type == "cross_session_valid_mac":
        build_fn = _get_build_fn(protocol)
        return build_cross_session_packet(
            protocol=protocol,
            build_fn=build_fn,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
            state=state,
        ), True

    if attack_type == "cross_epoch_valid_mac":
        build_fn = _get_build_fn(protocol)
        return build_cross_epoch_packet(
            protocol=protocol,
            build_fn=build_fn,
            session_id=session_id,
            sender_id=sender_id,
            seq=seq,
            payload=payload,
            state=state,
        ), True

    raise ValueError(f"Unknown attack_type: {attack_type}")


def create_state_for_protocol(
    protocol: str,
    session_id: str,
    sender_id: str,
    epoch: int,
) -> Any:
    """根据协议类型创建初始状态"""
    
    if protocol == "gmcp_r" or protocol == "gmcp":
        from gmcp.memory import initial_memory
        initial_mem = initial_memory(session_id, sender_id, epoch, "demo-seed")
        from gmcp.protocol import GMCPState
        return GMCPState(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            last_seq=0,
            last_mem=initial_mem,
        )
    elif protocol == "hash_chain":
        return hash_chain_create_state(session_id, sender_id, epoch)
    elif protocol == "authenticated_hash_chain":
        return auth_hc_create_state(session_id, sender_id, epoch)
    elif protocol == "seq_mac":
        return seq_mac_create_state(session_id, sender_id, epoch)
    elif protocol == "ticket_only":
        return ticket_only_create_state(session_id, sender_id, epoch)
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def run_one_baseline_experiment(
    protocol: str,
    attack_type: str,
    message_count: int,
    payload_size: int,
    repeat_id: int,
) -> Dict[str, Any]:
    """运行单个baseline实验"""
    
    # 检查攻击是否适用于当前协议
    applicable = attack_applicable_to_protocol(attack_type, protocol)
    category = attack_category(attack_type)
    
    session_id = (
        f"baseline-{protocol}-{attack_type}-m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )
    
    # 创建初始状态
    state = create_state_for_protocol(protocol, session_id, CLIENT_ID, EPOCH)
    
    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    error_count = 0
    sent_count = 0
    
    attack_injected = False
    attack_detected_by_server = False
    attack_seq = min(50, max(2, message_count // 2))
    attack_done = False

    # Audit fields
    last_rejection_reason = ""
    last_rejection_class = ""
    expected_session_id = session_id
    packet_session_id = session_id
    connection_bound_session_id = session_id
    attack_expected_reason = ""
    attack_reason_match = False
    attack_packet_seq = ""
    attack_packet_sent = False
    attack_packet_accepted = False
    attack_packet_rejected = False
    attack_packet_reason = ""
    attack_packet_reason_class = ""
    post_attack_resynchronized = False
    retry_sent = False
    retry_accepted = False
    run_valid = True
    failure_reason = ""
    
    # exact_replay: 保存第1条完整合法报文
    saved_first_packet = None
    
    # 记录RTT
    rtt_list = []
    
    start_time = time.time()
    
    sock = None
    file_obj = None
    
    try:
        sock, file_obj = open_tcp()

        # Send HELLO handshake (required by server)
        hello_ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
        if not hello_ack.get("ok"):
            print(f"  [WARN] HELLO failed: {hello_ack.get('reason')}")
            close_tcp(sock, file_obj)
            return {
                "session_id": session_id, "protocol": protocol,
                "attack_type": attack_type, "attack_category": category,
                "attack_applicable": applicable,
                "message_count": message_count, "payload_size": payload_size,
                "repeat_id": repeat_id, "sent_count": 0, "accepted_count": 0,
                "rejected_count": 0, "timeout_count": 0, "error_count": 1,
                "success_rate": 0, "attack_injected": False,
                "attack_detected_by_server": False,
                "throughput_msg_per_sec": 0,
                "rtt_mean_ms": 0, "rtt_std_ms": 0, "rtt_min_ms": 0,
                "rtt_max_ms": 0, "rtt_median_ms": 0, "elapsed_seconds": 0,
                "expected_session_id": session_id,
                "packet_session_id": session_id,
                "connection_bound_session_id": session_id,
                "rejection_reason": "", "rejection_class": "",
                "attack_expected_reason": "", "attack_reason_match": False,
                "attack_packet_seq": "", "attack_packet_sent": False,
                "attack_packet_accepted": False, "attack_packet_rejected": False,
                "attack_packet_reason": "", "attack_packet_reason_class": "",
                "post_attack_resynchronized": False,
                "retry_sent": False, "retry_accepted": False,
                "run_valid": False, "failure_reason": hello_ack.get("reason", "HELLO failed"),
            }
        
        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            
            # 构建正常数据包
            packet = build_packet_for_protocol(
                protocol=protocol,
                session_id=session_id,
                sender_id=CLIENT_ID,
                epoch=EPOCH,
                seq=seq,
                payload=payload,
                state=state,
            )
            clean_packet = dict(packet)
            sent_attack_packet = False
            
            # 保存第1条合法报文（供exact_replay使用）
            if seq == 1 and saved_first_packet is None:
                saved_first_packet = dict(packet)
            
            # 攻击注入
            if attack_type != "none" and seq == attack_seq and not attack_done:
                # cross_session_valid_mac: server rejects via connection binding (not protocol verifier)
                if attack_type == "cross_session_valid_mac":
                    build_fn = _get_build_fn(protocol)
                    fake_session = "attacker-cross-session"
                    modified_packet, is_applicable = apply_attack(
                        attack_type=attack_type,
                        protocol=protocol,
                        packet=packet,
                        seq=seq,
                        session_id=session_id,
                        sender_id=CLIENT_ID,
                        epoch=EPOCH,
                        payload=payload,
                        state=state,
                        saved_first_packet=saved_first_packet,
                    )
                    if is_applicable and modified_packet is not None:
                        # Record audit fields for cross_session
                        expected_session_id = session_id
                        packet_session_id = fake_session
                        connection_bound_session_id = session_id
                        attack_expected_reason = expected_attack_reason(attack_type)
                        attack_packet_seq = seq
                        attack_packet_sent = True

                        send_start = time.time()
                        send_json_line(sock, modified_packet)
                        sent_count += 1
                        try:
                            response = recv_json_line(file_obj)
                            send_end = time.time()
                            rtt_ms = (send_end - send_start) * 1000
                            rtt_list.append(rtt_ms)

                            reason = response.get("reason", "")
                            # Lock audit fields to attack packet response
                            last_rejection_reason = reason
                            last_rejection_class = _classify_rejection(reason)
                            attack_packet_reason = reason
                            attack_packet_reason_class = last_rejection_class
                            attack_reason_match = attack_expected_reason in reason

                            if not response.get("ok"):
                                rejected_count += 1
                                attack_detected_by_server = True
                                attack_injected = True
                                attack_packet_rejected = True

                                retry_sent = True
                                retry_start = time.time()
                                send_json_line(sock, clean_packet)
                                sent_count += 1
                                retry_response = recv_json_line(file_obj)
                                retry_end = time.time()
                                rtt_list.append((retry_end - retry_start) * 1000)
                                retry_accepted = bool(retry_response.get("ok"))
                                if retry_accepted:
                                    accepted_count += 1
                                    post_attack_resynchronized = True
                                    update_state_after_accept(protocol, state, seq, clean_packet, retry_response)
                                else:
                                    rejected_count += 1
                                    run_valid = False
                                    failure_reason = "post_attack_resynchronization_failed"
                                    last_rejection_reason = retry_response.get("reason", "unknown")
                                    last_rejection_class = _classify_rejection(last_rejection_reason)
                                    break
                            else:
                                accepted_count += 1
                                attack_injected = True
                                attack_packet_accepted = True
                                update_state_after_accept(protocol, state, seq, modified_packet, response)
                        except socket.timeout:
                            timeout_count += 1
                            run_valid = False
                            failure_reason = "attack_packet_timeout"
                        attack_done = True
                        continue
                else:
                    modified_packet, is_applicable = apply_attack(
                        attack_type=attack_type,
                        protocol=protocol,
                        packet=packet,
                        seq=seq,
                        session_id=session_id,
                        sender_id=CLIENT_ID,
                        epoch=EPOCH,
                        payload=payload,
                        state=state,
                        saved_first_packet=saved_first_packet,
                    )
                    
                    if is_applicable and modified_packet is not None:
                        packet = modified_packet
                        sent_attack_packet = True
                        attack_packet_seq = seq
                        attack_packet_sent = True
                        attack_expected_reason = expected_attack_reason(attack_type)
                        attack_done = True
                        attack_injected = True
                    elif not is_applicable:
                        # 攻击不适用于此协议，跳过注入
                        attack_done = True
                        attack_injected = False
            
            # 发送数据包
            send_start = time.time()
            send_json_line(sock, packet)
            sent_count += 1
            
            try:
                response = recv_json_line(file_obj)
                send_end = time.time()
                
                rtt_ms = (send_end - send_start) * 1000
                rtt_list.append(rtt_ms)
                
                if response.get("ok"):
                    accepted_count += 1
                    if sent_attack_packet:
                        attack_packet_accepted = True
                    update_state_after_accept(protocol, state, seq, packet, response)
                else:
                    rejected_count += 1
                    reason = response.get("reason", "unknown")
                    last_rejection_reason = reason
                    last_rejection_class = _classify_rejection(reason)
                    # 只有当攻击已注入且服务端拒绝时，才算检测到攻击
                    if sent_attack_packet:
                        attack_detected_by_server = True
                        attack_packet_rejected = True
                        attack_packet_reason = reason
                        attack_packet_reason_class = last_rejection_class
                        if attack_expected_reason:
                            attack_reason_match = attack_expected_reason in reason

                        retry_sent = True
                        retry_start = time.time()
                        send_json_line(sock, clean_packet)
                        sent_count += 1
                        retry_response = recv_json_line(file_obj)
                        retry_end = time.time()
                        rtt_list.append((retry_end - retry_start) * 1000)
                        retry_accepted = bool(retry_response.get("ok"))
                        if retry_accepted:
                            accepted_count += 1
                            post_attack_resynchronized = True
                            update_state_after_accept(protocol, state, seq, clean_packet, retry_response)
                        else:
                            rejected_count += 1
                            run_valid = False
                            failure_reason = "post_attack_resynchronization_failed"
                            last_rejection_reason = retry_response.get("reason", "unknown")
                            last_rejection_class = _classify_rejection(last_rejection_reason)
                            break
                        
            except socket.timeout:
                timeout_count += 1
                if sent_attack_packet:
                    failure_reason = "attack_packet_timeout"
                    run_valid = False
            except Exception as e:
                error_count += 1
                run_valid = False
                failure_reason = str(e)
                print(f"[ERROR] seq={seq}: {e}")
    
    except Exception as e:
        run_valid = False
        failure_reason = str(e)
        print(f"[ERROR] Experiment failed: {e}")
    
    finally:
        close_tcp(sock, file_obj)
    
    elapsed = time.time() - start_time
    
    # 计算统计指标
    success_rate = accepted_count / message_count * 100 if message_count > 0 else 0
    throughput = accepted_count / elapsed if elapsed > 0 else 0
    
    # RTT统计
    rtt_stats = calculate_statistics(rtt_list) if rtt_list else {
        "mean": 0, "std": 0, "min": 0, "max": 0, "median": 0
    }
    
    return {
        "session_id": session_id,
        "protocol": protocol,
        "attack_type": attack_type,
        "attack_category": category,
        "attack_applicable": applicable,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "error_count": error_count,
        "success_rate": round(success_rate, 2),
        "attack_injected": attack_injected,
        "attack_detected_by_server": attack_detected_by_server,
        "throughput_msg_per_sec": round(throughput, 2),
        "rtt_mean_ms": round(rtt_stats["mean"], 2),
        "rtt_std_ms": round(rtt_stats["std"], 2),
        "rtt_min_ms": round(rtt_stats["min"], 2),
        "rtt_max_ms": round(rtt_stats["max"], 2),
        "rtt_median_ms": round(rtt_stats["median"], 2),
        "elapsed_seconds": round(elapsed, 2),
        "expected_session_id": expected_session_id,
        "packet_session_id": packet_session_id,
        "connection_bound_session_id": connection_bound_session_id,
        "rejection_reason": last_rejection_reason,
        "rejection_class": last_rejection_class,
        "attack_expected_reason": attack_expected_reason,
        "attack_reason_match": attack_reason_match,
        "attack_packet_seq": attack_packet_seq,
        "attack_packet_sent": attack_packet_sent,
        "attack_packet_accepted": attack_packet_accepted,
        "attack_packet_rejected": attack_packet_rejected,
        "attack_packet_reason": attack_packet_reason,
        "attack_packet_reason_class": attack_packet_reason_class,
        "post_attack_resynchronized": post_attack_resynchronized,
        "retry_sent": retry_sent,
        "retry_accepted": retry_accepted,
        "run_valid": run_valid,
        "failure_reason": failure_reason,
    }


def run_all_experiments():
    ensure_output_dir()
    
    # 创建实验跟踪器
    tracker = ExperimentTracker("real_baseline_comparison")
    
    fieldnames = [
        "session_id", "protocol", "attack_type", "attack_category",
        "attack_applicable",
        "message_count", "payload_size",
        "repeat_id", "sent_count", "accepted_count", "rejected_count", "timeout_count",
        "error_count", "success_rate", "attack_injected", "attack_detected_by_server",
        "throughput_msg_per_sec", "rtt_mean_ms", "rtt_std_ms", "rtt_min_ms",
        "rtt_max_ms", "rtt_median_ms", "elapsed_seconds",
        "expected_session_id", "packet_session_id", "connection_bound_session_id",
        "rejection_reason", "rejection_class",
        "attack_expected_reason", "attack_reason_match",
        "attack_packet_seq", "attack_packet_sent", "attack_packet_accepted",
        "attack_packet_rejected", "attack_packet_reason", "attack_packet_reason_class",
        "post_attack_resynchronized", "retry_sent", "retry_accepted",
        "run_valid", "failure_reason",
    ]
    
    total_experiments = len(PROTOCOLS) * len(ATTACK_TYPES) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * len(REPEATS)
    completed = 0
    
    for protocol in PROTOCOLS:
        for attack_type in ATTACK_TYPES:
            for message_count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for repeat_id in REPEATS:
                        completed += 1
                        category = attack_category(attack_type)
                        applicable = attack_applicable_to_protocol(attack_type, protocol)
                        print(f"\n[{completed}/{total_experiments}] "
                              f"protocol={protocol}, attack={attack_type} "
                              f"[{category}]{'(N/A)' if not applicable else ''}, "
                              f"msg={message_count}, payload={payload_size}, "
                              f"repeat={repeat_id}")
                        
                        result = run_one_baseline_experiment(
                            protocol=protocol,
                            attack_type=attack_type,
                            message_count=message_count,
                            payload_size=payload_size,
                            repeat_id=repeat_id,
                        )
                        
                        # 添加到跟踪器
                        tracker.add_result(result)
                        
                        # 采样性能
                        tracker.sample_performance()
                        
                        # 打印结果摘要
                        status = "✅" if result["success_rate"] > 50 else "❌"
                        print(f"  {status} success_rate={result['success_rate']}%, "
                              f"rtt={result['rtt_mean_ms']}ms, "
                              f"throughput={result['throughput_msg_per_sec']} msg/s")
    
    # 保存结果
    tracker.save_results_to_csv(OUTPUT_CSV, fieldnames)
    
    # 获取最终统计
    final_stats = tracker.finish()
    print(f"\n{'='*60}")
    print(f"[COMPLETE] Results saved to {OUTPUT_CSV}")
    print(f"[STATS] Total results: {final_stats['total_results']}")
    print(f"[STATS] Elapsed time: {final_stats['elapsed_seconds']}s")
    
    return tracker.results


def print_attack_matrix(results: list):
    """
    输出逐攻击检测矩阵。
    只统计 attack_applicable=True AND attack_injected=True 的攻击。
    N/A 攻击不计入漏检率。
    正常场景验证 accepted_count == message_count。
    """
    from collections import defaultdict

    # --- 1. 验证正常场景 ---
    normal_results = [r for r in results if r["attack_type"] == "none"]
    normal_failures = []
    for r in normal_results:
        if r["accepted_count"] != r["message_count"] or r["success_rate"] != 100:
            normal_failures.append(r)
    if normal_failures:
        print(f"\n⚠️  NORMAL SCENARIO FAILURES ({len(normal_failures)}):")
        for r in normal_failures:
            print(f"  protocol={r['protocol']}, msg={r['message_count']}, "
                  f"accepted={r['accepted_count']}, success_rate={r['success_rate']}%")
    else:
        print(f"\n✅ All normal scenarios: accepted_count == message_count, success_rate == 100%")

    # --- 2. 逐攻击检测矩阵 ---
    attack_results = [r for r in results if r["attack_type"] != "none"]

    # Group by (protocol, attack_type)
    matrix = defaultdict(lambda: {"applicable": False, "injected_count": 0, "detected_count": 0})

    for r in attack_results:
        key = (r["protocol"], r["attack_type"])
        if not r.get("attack_applicable", False):
            # N/A attack, skip
            continue
        matrix[key]["applicable"] = True
        if r.get("attack_injected", False):
            matrix[key]["injected_count"] += 1
            if r.get("attack_detected_by_server", False):
                matrix[key]["detected_count"] += 1

    print(f"\n{'='*80}")
    print(f"ATTACK DETECTION MATRIX (only applicable + injected attacks)")
    print(f"{'='*80}")
    print(f"{'Protocol':<30} {'Attack Type':<35} {'Injected':>8} {'Detected':>8} {'Rate':>8}")
    print(f"{'-'*30} {'-'*35} {'-'*8} {'-'*8} {'-'*8}")

    for (protocol, attack_type), stats in sorted(matrix.items()):
        inj = stats["injected_count"]
        det = stats["detected_count"]
        rate = f"{det / inj * 100:.1f}%" if inj > 0 else "N/A"
        print(f"{protocol:<30} {attack_type:<35} {inj:>8} {det:>8} {rate:>8}")

    # Summary of N/A attacks (not counted)
    na_attacks = [r for r in attack_results
                  if r.get("attack_applicable", True) == False]
    if na_attacks:
        print(f"\nN/A attacks (not counted): {len(na_attacks)}")
        na_types = set((r["protocol"], r["attack_type"]) for r in na_attacks)
        for p, a in sorted(na_types):
            print(f"  {p:<30} {a:<35} N/A")

    print(f"{'='*80}")


def baseline_results_valid(results: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Return whether baseline rows are execution-valid."""
    violations: List[str] = []
    for row in results:
        sent = int(row.get("sent_count", 0))
        accepted = int(row.get("accepted_count", 0))
        rejected = int(row.get("rejected_count", 0))
        timeout = int(row.get("timeout_count", 0))
        error = int(row.get("error_count", 0))
        if sent != accepted + rejected + timeout + error:
            violations.append(
                f"sent_count mismatch: protocol={row.get('protocol')} attack={row.get('attack_type')}"
            )
        if timeout or error:
            violations.append(
                f"timeout/error: protocol={row.get('protocol')} attack={row.get('attack_type')}"
            )
        if not row.get("run_valid", False):
            violations.append(
                f"run_valid false: protocol={row.get('protocol')} attack={row.get('attack_type')} "
                f"reason={row.get('failure_reason')}"
            )
    return not violations, violations


def main():
    parser = argparse.ArgumentParser(description="Run real baseline comparison experiments")
    parser.add_argument("--spawn-server", action="store_true", help="Start real_baseline_server.py for this run")
    args = parser.parse_args()

    server_proc = None
    try:
        if args.spawn_server:
            server_proc = spawn_baseline_server()
        results = run_all_experiments()
        print_attack_matrix(results)
        ok, violations = baseline_results_valid(results)
        if not ok:
            print("[BASELINE] INVALID RESULTS:", file=sys.stderr)
            for violation in violations[:20]:
                print(f"  - {violation}", file=sys.stderr)
            return 1
        return 0
    finally:
        if server_proc:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            print("[SPAWN] Baseline server terminated")


if __name__ == "__main__":
    sys.exit(main())
