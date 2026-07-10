# -*- coding: utf-8 -*-
# run_real_baseline_comparison.py
#
# 真实Baseline对比实验
# 对比GMCP-R与hash_chain、seq_mac、ticket_only协议

import csv
import json
import os
import socket
import time
import sys
from typing import Dict, Any, List, Tuple

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
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


OUTPUT_DIR = "results/real_baseline_comparison"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "real_baseline_comparison_results.csv")

# 实验参数
PROTOCOLS = ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]
MESSAGE_COUNTS = [100, 500, 1000]
PAYLOAD_SIZES = [128, 512]
ATTACK_TYPES = ["none", "drop", "modify", "replay", "prev_mem"]
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

# 服务器端口（baseline服务器使用9001端口）
BASELINE_PORT = 9001

SOCKET_TIMEOUT = 10.0


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
    
    if protocol == "gmcp_r":
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


def create_state_for_protocol(
    protocol: str,
    session_id: str,
    sender_id: str,
    epoch: int,
) -> Any:
    """根据协议类型创建初始状态"""
    
    if protocol == "gmcp_r":
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
    
    # 记录RTT
    rtt_list = []
    
    start_time = time.time()
    
    sock = None
    file_obj = None
    
    try:
        sock, file_obj = open_tcp()
        
        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            
            # 构建数据包
            packet = build_packet_for_protocol(
                protocol=protocol,
                session_id=session_id,
                sender_id=CLIENT_ID,
                epoch=EPOCH,
                seq=seq,
                payload=payload,
                state=state,
            )
            
            # 攻击模拟
            if attack_type == "drop" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_injected = True
                continue  # 跳过这个包
            
            if attack_type == "modify" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_injected = True
                packet["payload"] = "modified-payload"
            
            if attack_type == "replay" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_injected = True
                # 重放第一个包
                packet["seq"] = 1
            
            if attack_type == "prev_mem" and seq == attack_seq and not attack_done:
                attack_done = True
                attack_injected = True
                if "prev_mem" in packet:
                    packet["prev_mem"] = "fake-memory"
                elif "prev_hash" in packet:
                    packet["prev_hash"] = "fake-hash"
            
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
                    # 更新状态
                    if protocol == "gmcp_r":
                        state.last_seq = int(response.get("last_seq", state.last_seq))
                        state.last_mem = response.get("last_mem", state.last_mem)
                    elif protocol in ("hash_chain", "authenticated_hash_chain"):
                        state.last_seq = seq
                        state.last_hash = packet.get("chain_hash", state.last_hash)
                    else:
                        state.last_seq = seq
                else:
                    rejected_count += 1
                    reason = response.get("reason", "unknown")
                    # 只有当攻击已注入且服务端拒绝时，才算检测到攻击
                    if attack_injected and not response.get("ok"):
                        attack_detected_by_server = True
                        
            except socket.timeout:
                timeout_count += 1
            except Exception as e:
                error_count += 1
                print(f"[ERROR] seq={seq}: {e}")
    
    except Exception as e:
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
    }


def run_all_experiments():
    ensure_output_dir()
    
    # 创建实验跟踪器
    tracker = ExperimentTracker("real_baseline_comparison")
    
    fieldnames = [
        "session_id", "protocol", "attack_type", "message_count", "payload_size",
        "repeat_id", "sent_count", "accepted_count", "rejected_count", "timeout_count",
        "error_count", "success_rate", "attack_injected", "attack_detected_by_server",
        "throughput_msg_per_sec", "rtt_mean_ms", "rtt_std_ms", "rtt_min_ms",
        "rtt_max_ms", "rtt_median_ms", "elapsed_seconds",
    ]
    
    total_experiments = len(PROTOCOLS) * len(ATTACK_TYPES) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * len(REPEATS)
    completed = 0
    
    for protocol in PROTOCOLS:
        for attack_type in ATTACK_TYPES:
            for message_count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for repeat_id in REPEATS:
                        completed += 1
                        print(f"\n[{completed}/{total_experiments}] "
                              f"protocol={protocol}, attack={attack_type}, "
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


if __name__ == "__main__":
    run_all_experiments()
