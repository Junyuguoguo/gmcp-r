# -*- coding: utf-8 -*-
# run_weak_network_simulation.py
#
# 弱网仿真实验（完全重写）
#
# 实验矩阵：3 protocols × 5 loss_rates × 5 delay_ms × 2 repeats = 150 rows
#
# 核心改造点：
#   1. argparse 命令行参数
#   2. 确定性随机数（SHA-256 派生种子）
#   3. 真正应用层丢弃（should_drop 时不调用 sendall）
#   4. 公平重试策略（三种协议完全相同的 MAX_RETRIES, RETRY_DELAY, loss/delay scheduler）
#   5. 四类时间区分
#   6. 九个计数字段
#   7. 协议状态审计字段
#   8. HELLO 握手验证
#   9. 原子发布
#  10. 禁止静默异常

import argparse
import csv
import hashlib
import json
import math
import os
import random
import socket
import subprocess
import sys
import time
import platform
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import (
    SERVER_TARGET_HOST,
    SERVER_BIND_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, with_hmac, verify_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet as gmcp_build_data_packet
from gmcp.experiment_stats import (
    ExperimentTracker,
    calculate_statistics,
)

# 导入 baseline 协议
from gmcp.baselines.hash_chain import (
    create_initial_state as hash_chain_create_state,
    build_data_packet as hash_chain_build_packet,
)
from gmcp.baselines.seq_mac import (
    create_initial_state as seq_mac_create_state,
    build_data_packet as seq_mac_build_packet,
)

# =========================
# 常量
# =========================

OUTPUT_DIR = "results/weak_network_simulation"
PAPER_DATA_CSV = "paper_data/05_weak_network.csv"

PROTOCOLS = ["gmcp_r", "hash_chain", "seq_mac"]
LOSS_RATES = [0, 1, 2, 5, 10]       # 丢包率 (%)
DELAY_MS = [0, 20, 50, 100, 200]    # 延迟 (ms)
REORDER_RATE = 0                      # 乱序率固定 0

# 服务器端口映射（所有协议通过 real_baseline_server 统一处理，端口 9001）
PROTOCOL_PORT = {
    "gmcp_r": 9001,
    "hash_chain": 9001,
    "seq_mac": 9001,
}

# HELLO 握手时的协议名称映射（gmcp_r 在服务端注册为 "gmcp"）
WIRE_PROTOCOL_NAMES = {
    "gmcp_r": "gmcp",
    "hash_chain": "hash_chain",
    "seq_mac": "seq_mac",
}

SOCKET_TIMEOUT = 30.0
SERVER_SPAWN_WAIT = 10

# 重试策略（所有协议统一）
MAX_RETRIES = 3         # initial attempt + 3 retries = 4 attempts max
RETRY_DELAY_MS = 100    # 100ms between retries


# =========================
# 命令行参数
# =========================

def parse_args():
    parser = argparse.ArgumentParser(
        description="GMCP-R 弱网仿真实验"
    )
    parser.add_argument("--host", default=SERVER_TARGET_HOST, help="服务器地址")
    parser.add_argument("--port", type=int, default=None, help="服务器端口（覆盖默认映射）")
    parser.add_argument("--spawn-server", action="store_true", default=True,
                        help="自动启动服务器（默认启用）")
    parser.add_argument("--no-spawn-server", dest="spawn_server", action="store_false",
                        help="不自动启动服务器")
    parser.add_argument("--output", default=None, help="结果 CSV 输出路径")
    parser.add_argument("--paper-output", default=PAPER_DATA_CSV, help="paper_data 输出路径")
    parser.add_argument("--seed", type=int, default=20260711, help="基础随机种子")
    parser.add_argument("--repeats", type=int, default=2, help="每配置重复次数")
    parser.add_argument("--message-count", type=int, default=200, help="每轮消息数")
    parser.add_argument("--payload-size", type=int, default=128, help="载荷大小（字节）")
    parser.add_argument("--max-retries", type=int, default=3, help="最大重试次数")
    parser.add_argument("--retry-delay-ms", type=int, default=100, help="重试间隔（毫秒）")
    parser.add_argument("--smoke-only", action="store_true", help="仅运行 smoke 测试")
    parser.add_argument("--formal", action="store_true", help="运行正式 150 行实验")
    parser.add_argument("--allow-dirty", action="store_true", help="允许 dirty worktree 运行")
    return parser.parse_args()


# =========================
# 辅助函数
# =========================

def derive_run_seed(base_seed: int, protocol: str, loss_rate: float,
                    delay_ms: float, repeat_id: int,
                    message_count: int, payload_size: int) -> str:
    """确定性种子派生：SHA-256(base_seed|protocol|loss_rate|delay_ms|repeat_id|mc|ps)"""
    key = f"{base_seed}|{protocol}|{loss_rate}|{delay_ms}|{repeat_id}|{message_count}|{payload_size}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def make_loss_schedule(run_seed: str, message_count: int, loss_rate: float) -> List[bool]:
    """
    确定性丢包调度：对每条消息生成 should_drop 布尔值。
    使用独立的 RNG 实例，种子从 run_seed + '|loss' 派生。
    """
    loss_seed = hashlib.sha256(f"{run_seed}|loss".encode()).hexdigest()[:16]
    rng = random.Random(loss_seed)
    schedule = []
    for _ in range(message_count):
        schedule.append(rng.random() < loss_rate / 100.0)
    return schedule


def make_delay_schedule(run_seed: str, message_count: int, delay_ms: float) -> List[float]:
    """
    确定性延迟调度：±20% jitter。
    返回每条消息的实际延迟（毫秒）。
    使用独立的 RNG 实例，种子从 run_seed + '|delay' 派生。
    """
    delay_seed = hashlib.sha256(f"{run_seed}|delay".encode()).hexdigest()[:16]
    rng = random.Random(delay_seed)
    schedule = []
    for _ in range(message_count):
        jitter = delay_ms * 0.2
        actual_delay = delay_ms + (rng.random() - 0.5) * 2 * jitter
        schedule.append(max(0.0, actual_delay))
    return schedule


def loss_schedule_hash(drop_sequence: List[bool]) -> str:
    """计算实际attempt级丢弃序列的哈希，用于审计"""
    data = "".join("1" if d else "0" for d in drop_sequence)
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def make_payload(seq: int, payload_size: int) -> str:
    prefix = f"weaknet-{seq}-"
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


def collect_git_metadata() -> Dict[str, Any]:
    """收集 git 和环境元数据"""
    meta = {}
    try:
        meta["git_commit_full"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        meta["git_commit_full"] = ""
    try:
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL
        ).decode().strip()
        meta["git_dirty"] = "true" if dirty else "false"
    except Exception:
        meta["git_dirty"] = "unknown"
    meta["command_line"] = " ".join(sys.argv)
    meta["python_version"] = sys.version.split()[0]
    meta["os_info"] = f"{platform.system()} {platform.release()}"
    meta["hostname"] = platform.node()
    return meta


def check_git_dirty(allow_dirty: bool) -> None:
    """检查 git worktree 是否 dirty，除非 --allow-dirty"""
    if allow_dirty:
        return
    try:
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL
        ).decode().strip()
        if dirty:
            raise RuntimeError(
                "Git worktree is dirty. Commit or stash changes first, "
                "or pass --allow-dirty to override."
            )
    except subprocess.CalledProcessError:
        pass  # not in a git repo, skip check


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


def open_tcp(host: str, port: int) -> Tuple[socket.socket, object]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((host, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


# =========================
# HELLO 握手
# =========================

def send_hello(sock, file_obj, protocol: str, session_id: str,
               sender_id: str, epoch: int) -> Dict[str, Any]:
    """
    发送 HELLO 握手并等待 HELLO_ACK。
    验证：ok=True, type=HELLO_ACK, protocol, session_id。
    """
    wire_protocol = WIRE_PROTOCOL_NAMES.get(protocol, protocol)
    hello = with_hmac(DATA_AUTH_KEY, {
        "type": "HELLO",
        "protocol": wire_protocol,
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "client_nonce": str(int(time.time() * 1000000)),
        "timestamp": time.time(),
    })
    send_json_line(sock, hello)
    ack = recv_json_line(file_obj)

    # 验证 HELLO_ACK
    if not ack.get("ok"):
        raise ConnectionError(f"HELLO failed: {ack.get('reason')}")
    if ack.get("type") != "HELLO_ACK":
        raise ConnectionError(f"Expected HELLO_ACK, got type={ack.get('type')}")
    if ack.get("protocol") != wire_protocol:
        raise ConnectionError(
            f"HELLO_ACK protocol mismatch: expected {wire_protocol}, got {ack.get('protocol')}"
        )
    if ack.get("session_id") != session_id:
        raise ConnectionError(
            f"HELLO_ACK session_id mismatch: expected {session_id}, got {ack.get('session_id')}"
        )
    return ack


# =========================
# 协议状态管理
# =========================

def create_protocol_state(protocol: str, session_id: str, sender_id: str, epoch: int) -> Dict[str, Any]:
    """为每种协议创建独立初始状态"""
    if protocol == "gmcp_r":
        initial_mem = initial_memory(session_id, sender_id, epoch, "demo-seed")
        return {"last_seq": 0, "last_mem": initial_mem}
    elif protocol == "hash_chain":
        state = hash_chain_create_state(session_id, sender_id, epoch)
        return {"last_seq": 0, "last_hash": state.last_hash}
    elif protocol == "seq_mac":
        return {"last_seq": 0}
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def build_packet_for_protocol(protocol: str, session_id: str, sender_id: str,
                               epoch: int, seq: int, payload: str,
                               state: Dict[str, Any]) -> Dict[str, Any]:
    """使用正式构包函数构建数据包"""
    if protocol == "gmcp_r":
        return gmcp_build_data_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, prev_mem=state["last_mem"], payload=payload,
        )
    elif protocol == "hash_chain":
        return hash_chain_build_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, prev_hash=state["last_hash"], payload=payload,
        )
    elif protocol == "seq_mac":
        return seq_mac_build_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, payload=payload,
        )
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def update_state_after_accept(protocol: str, state: Dict[str, Any],
                               seq: int, packet: Dict[str, Any],
                               response: Dict[str, Any]):
    """服务端接受包后更新本地客户端状态"""
    if protocol == "gmcp_r":
        state["last_seq"] = int(response.get("last_seq", seq))
        state["last_mem"] = response.get("last_mem", state["last_mem"])
    elif protocol == "hash_chain":
        state["last_seq"] = seq
        state["last_hash"] = packet.get("chain_hash", state["last_hash"])
    elif protocol == "seq_mac":
        state["last_seq"] = seq


def get_protocol_audit(protocol: str, state: Dict[str, Any],
                       response: Dict[str, Any]) -> Dict[str, Any]:
    """
    协议状态审计：
    client_final_seq, server_final_seq, state_match
    GMCP-R: client_final_mem, server_final_mem, memory_match
    Hash Chain: client_final_hash, server_final_hash, hash_match
    Seq+MAC: sequence_match
    """
    client_seq = state["last_seq"]
    server_seq = int(response.get("last_seq", 0))

    audit = {
        "client_final_seq": client_seq,
        "server_final_seq": server_seq,
        "state_match": client_seq == server_seq,
    }

    if protocol == "gmcp_r":
        client_mem = state["last_mem"]
        server_mem = response.get("last_mem", "")
        audit["client_final_mem"] = client_mem[:32] if client_mem else ""
        audit["server_final_mem"] = server_mem[:32] if server_mem else ""
        audit["memory_match"] = client_mem == server_mem
        audit["client_final_hash"] = ""
        audit["server_final_hash"] = ""
        audit["hash_match"] = ""
        audit["sequence_match"] = ""
    elif protocol == "hash_chain":
        client_hash = state["last_hash"]
        server_hash = response.get("last_hash", "")
        audit["client_final_mem"] = ""
        audit["server_final_mem"] = ""
        audit["memory_match"] = ""
        audit["client_final_hash"] = client_hash[:32] if client_hash else ""
        audit["server_final_hash"] = server_hash[:32] if server_hash else ""
        audit["hash_match"] = client_hash == server_hash
        audit["sequence_match"] = ""
    elif protocol == "seq_mac":
        audit["client_final_mem"] = ""
        audit["server_final_mem"] = ""
        audit["memory_match"] = ""
        audit["client_final_hash"] = ""
        audit["server_final_hash"] = ""
        audit["hash_match"] = ""
        audit["sequence_match"] = client_seq == server_seq

    return audit


# =========================
# 服务器管理
# =========================

def spawn_server(script_name: str, port: int, label: str,
                 host: str = SERVER_TARGET_HOST) -> subprocess.Popen:
    """启动服务器并等待就绪"""
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, script_name],
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
            s.connect((host, port))
            s.close()
            print(f"[SPAWN] {label} ready on port {port}", flush=True)
            return proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    raise RuntimeError(f"{label} did not start on port {port}")


def kill_server(proc: Optional[subprocess.Popen], label: str):
    """停止服务器"""
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(f"[SPAWN] {label} terminated", flush=True)


# =========================
# 单个实验运行
# =========================

def run_one_experiment(
    protocol: str,
    loss_rate: float,
    delay_ms: float,
    message_count: int,
    payload_size: int,
    repeat_id: int,
    base_seed: int,
    max_retries: int,
    retry_delay_ms: int,
    host: str,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """运行单个弱网实验"""

    # 1. 确定性种子
    run_seed = derive_run_seed(base_seed, protocol, loss_rate, delay_ms,
                               repeat_id, message_count, payload_size)

    # 2. 确定性调度
    loss_schedule = make_loss_schedule(run_seed, message_count, loss_rate)
    delay_schedule = make_delay_schedule(run_seed, message_count, delay_ms)

    # 跟踪实际attempt级丢弃序列（Task 5）
    actual_drop_sequence: List[bool] = []

    # 存储最后一次成功服务器响应（Task 4）
    last_successful_response: Dict[str, Any] = {}

    # 3. Session ID（确定性，基于 run_seed）
    session_id = f"weaknet-{protocol}-l{loss_rate}-d{delay_ms}-r{repeat_id}-{run_seed}"

    # 4. 端口
    actual_port = port if port is not None else PROTOCOL_PORT.get(protocol, 9001)

    # 5. 创建协议状态
    state = create_protocol_state(protocol, session_id, CLIENT_ID, EPOCH)

    # 计数字段
    logical_message_count = 0
    transmission_attempt_count = 0
    actual_packets_sent = 0
    accepted_logical_messages = 0
    unrecovered_logical_messages = 0
    simulated_drop_count = 0
    server_rejected_attempt_count = 0
    socket_timeout_count = 0
    retry_count_total = 0

    # 时间收集
    configured_delay_list = []
    injected_delay_list = []
    retry_wait_list = []
    socket_rtt_list = []
    application_latency_list = []

    start_time = time.time()

    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp(host, actual_port)

        # HELLO 握手
        hello_ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
        # HELLO 验证已在 send_hello 内部完成

        for msg_idx in range(message_count):
            seq = msg_idx + 1
            logical_message_count += 1
            payload = make_payload(seq, payload_size)
            configured_delay = delay_schedule[msg_idx]
            configured_delay_list.append(configured_delay)

            # 本地状态推进（即使丢包也推进，模拟应用层已处理）
            packet = build_packet_for_protocol(
                protocol=protocol, session_id=session_id,
                sender_id=CLIENT_ID, epoch=EPOCH,
                seq=seq, payload=payload, state=state,
            )

            msg_start_time = time.time()

            # 为当前逻辑消息生成每attempt的丢包调度
            # loss_schedule 只决定初始丢包，重试时用确定性per-attempt判定
            msg_loss_seed = hashlib.sha256(
                f"{run_seed}|loss|msg{msg_idx}".encode()
            ).hexdigest()[:16]
            msg_rng = random.Random(int(msg_loss_seed, 16))

            accepted = False
            attempts_for_this_msg = 0

            for attempt in range(max_retries + 1):  # 0, 1, ..., max_retries
                if attempt > 0:
                    # 重试等待
                    retry_wait_list.append(retry_delay_ms)
                    retry_count_total += 1
                    time.sleep(retry_delay_ms / 1000.0)

                # 确定性丢包判定（per-attempt）
                should_drop = msg_rng.random() < (loss_rate / 100.0)

                transmission_attempt_count += 1
                attempts_for_this_msg += 1

                if should_drop:
                    # 真正应用层丢弃：不调用 sendall
                    simulated_drop_count += 1
                    actual_drop_sequence.append(True)
                    # 注入配置延迟
                    if configured_delay > 0:
                        injected_delay_list.append(configured_delay)
                        time.sleep(configured_delay / 1000.0)
                    continue  # 重试同一条消息

                actual_drop_sequence.append(False)

                # 重建包（本地状态未变，同一个 seq）
                packet = build_packet_for_protocol(
                    protocol=protocol, session_id=session_id,
                    sender_id=CLIENT_ID, epoch=EPOCH,
                    seq=seq, payload=payload, state=state,
                )

                # 注入配置延迟
                if configured_delay > 0:
                    injected_delay_list.append(configured_delay)
                    time.sleep(configured_delay / 1000.0)

                socket_start = time.time()
                try:
                    send_json_line(sock, packet)
                    actual_packets_sent += 1

                    response = recv_json_line(file_obj)
                    socket_rtt = (time.time() - socket_start) * 1000.0
                    socket_rtt_list.append(socket_rtt)

                    if response.get("ok"):
                        accepted_logical_messages += 1
                        update_state_after_accept(protocol, state, seq, packet, response)
                        last_successful_response = dict(response)
                        accepted = True
                        break
                    else:
                        server_rejected_attempt_count += 1

                except socket.timeout:
                    socket_timeout_count += 1
                except ConnectionError:
                    raise  # 连接断开，必须抛出

            if not accepted:
                unrecovered_logical_messages += 1

            application_latency_list.append((time.time() - msg_start_time) * 1000.0)

    except Exception as e:
        print(f"  [ERROR] {e}", flush=True)
        raise  # 禁止静默异常

    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time

    # 计算实际attempt级丢弃序列的哈希（Task 5）
    lsh = loss_schedule_hash(actual_drop_sequence)

    # 使用真实服务器最后一次成功响应做审计（Task 4）
    if last_successful_response:
        audit_response = last_successful_response
    else:
        audit_response = {"last_seq": 0}
    # 协议状态审计
    audit = get_protocol_audit(protocol, state, audit_response)

    # 统计
    success_rate = (accepted_logical_messages / logical_message_count * 100
                    if logical_message_count > 0 else 0.0)
    throughput = accepted_logical_messages / elapsed if elapsed > 0 else 0.0

    def safe_stats(values):
        if not values:
            return {"mean": 0.0, "std": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
        return calculate_statistics(values)

    socket_rtt_stats = safe_stats(socket_rtt_list)
    app_latency_stats = safe_stats(application_latency_list)

    result = {
        # 标识
        "session_id": session_id,
        "protocol": protocol,
        "loss_rate": loss_rate,
        "delay_ms": delay_ms,
        "reorder_rate": REORDER_RATE,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,

        # 种子审计
        "base_seed": base_seed,
        "run_seed": run_seed,
        "loss_schedule_hash": lsh,

        # 计数字段
        "logical_message_count": logical_message_count,
        "transmission_attempt_count": transmission_attempt_count,
        "actual_packets_sent": actual_packets_sent,
        "accepted_logical_messages": accepted_logical_messages,
        "unrecovered_logical_messages": unrecovered_logical_messages,
        "simulated_drop_count": simulated_drop_count,
        "server_rejected_attempt_count": server_rejected_attempt_count,
        "socket_timeout_count": socket_timeout_count,
        "retry_count_total": retry_count_total,

        # 成功率 / 吞吐量
        "success_rate": round(success_rate, 2),
        "throughput_msg_per_sec": round(throughput, 2),

        # 四类时间
        "configured_delay_ms": round(
            sum(configured_delay_list) / len(configured_delay_list), 2
        ) if configured_delay_list else 0.0,
        "injected_delay_total_ms": round(sum(injected_delay_list), 2),
        "retry_wait_total_ms": round(sum(retry_wait_list), 2),
        "socket_rtt_mean_ms": round(socket_rtt_stats["mean"], 2),
        "socket_rtt_std_ms": round(socket_rtt_stats["std"], 2),
        "application_latency_mean_ms": round(app_latency_stats["mean"], 2),

        # RTT 详情
        "rtt_mean_ms": round(socket_rtt_stats["mean"], 2),
        "rtt_std_ms": round(socket_rtt_stats["std"], 2),
        "rtt_min_ms": round(socket_rtt_stats["min"], 2),
        "rtt_max_ms": round(socket_rtt_stats["max"], 2),
        "rtt_median_ms": round(socket_rtt_stats["median"], 2),

        # 协议状态审计
        "client_final_seq": audit["client_final_seq"],
        "server_final_seq": audit["server_final_seq"],
        "state_match": audit["state_match"],
        "client_final_mem": audit.get("client_final_mem", ""),
        "server_final_mem": audit.get("server_final_mem", ""),
        "memory_match": audit.get("memory_match", ""),
        "client_final_hash": audit.get("client_final_hash", ""),
        "server_final_hash": audit.get("server_final_hash", ""),
        "hash_match": audit.get("hash_match", ""),
        "sequence_match": audit.get("sequence_match", ""),

        # 元数据
        "elapsed_seconds": round(elapsed, 4),
    }

    # 计算 run_valid
    protocol_match = {
        "gmcp_r": audit.get("memory_match") is True,
        "hash_chain": audit.get("hash_match") is True,
        "seq_mac": audit.get("sequence_match") is True,
    }.get(protocol, False)

    result["run_valid"] = (
        result["accepted_logical_messages"] == result["logical_message_count"]
        and result["unrecovered_logical_messages"] == 0
        and result["server_rejected_attempt_count"] == 0
        and result["socket_timeout_count"] == 0
        and audit.get("state_match") is True
        and protocol_match
    )

    return result


# =========================
# CSV 字段列表
# =========================

FIELDNAMES = [
    "session_id", "protocol", "loss_rate", "delay_ms", "reorder_rate",
    "message_count", "payload_size", "repeat_id",
    "base_seed", "run_seed", "loss_schedule_hash",
    "logical_message_count", "transmission_attempt_count", "actual_packets_sent",
    "accepted_logical_messages", "unrecovered_logical_messages",
    "simulated_drop_count", "server_rejected_attempt_count",
    "socket_timeout_count", "retry_count_total",
    "success_rate", "throughput_msg_per_sec",
    "configured_delay_ms", "injected_delay_total_ms", "retry_wait_total_ms",
    "socket_rtt_mean_ms", "socket_rtt_std_ms",
    "application_latency_mean_ms",
    "rtt_mean_ms", "rtt_std_ms", "rtt_min_ms", "rtt_max_ms", "rtt_median_ms",
    "client_final_seq", "server_final_seq", "state_match",
    "client_final_mem", "server_final_mem", "memory_match",
    "client_final_hash", "server_final_hash", "hash_match",
    "sequence_match",
    "elapsed_seconds",
    "run_valid",
    "git_commit_full", "git_dirty",
    "command_line", "python_version", "os_info", "hostname",
]


# =========================
# 校验
# =========================

def validate_result(result: Dict[str, Any]) -> Tuple[bool, str]:
    """校验单个实验结果"""
    if result["elapsed_seconds"] < 0:
        return False, "elapsed_seconds < 0"
    if result["logical_message_count"] <= 0:
        return False, "logical_message_count <= 0"
    if result["actual_packets_sent"] < 0:
        return False, "actual_packets_sent < 0"

    # success_rate 一致性检查
    expected_rate = round(
        result["accepted_logical_messages"] / result["logical_message_count"] * 100, 2
    ) if result["logical_message_count"] > 0 else 0
    if abs(result["success_rate"] - expected_rate) > 0.01:
        return False, (
            f"success_rate mismatch: got {result['success_rate']}, "
            f"expected {expected_rate}"
        )

    # 计数一致性
    expected_logical = result["accepted_logical_messages"] + result["unrecovered_logical_messages"]
    if expected_logical != result["logical_message_count"]:
        return False, (
            f"count mismatch: accepted({result['accepted_logical_messages']}) + "
            f"unrecovered({result['unrecovered_logical_messages']}) != "
            f"logical({result['logical_message_count']})"
        )

    # 正式实验要求100%成功
    if result.get("unrecovered_logical_messages", 0) != 0:
        return False, f"unrecovered({result['unrecovered_logical_messages']}) > 0"
    if result.get("server_rejected_attempt_count", 0) != 0:
        return False, f"server_rejected({result['server_rejected_attempt_count']}) > 0"
    if result.get("socket_timeout_count", 0) != 0:
        return False, f"socket_timeouts({result['socket_timeout_count']}) > 0"

    return True, "ok"


# =========================
# Smoke 测试
# =========================

def run_smoke_test(args) -> bool:
    """
    控制组 smoke 测试：
    每种协议 loss=0, delay=0, 20 条消息，全部必须 100% 成功
    """
    print("\n" + "=" * 60, flush=True)
    print("SMOKE TEST: loss=0, delay=0, 20 messages per protocol", flush=True)
    print("=" * 60, flush=True)

    all_passed = True
    for protocol in PROTOCOLS:
        print(f"\n  Testing {protocol}...", end=" ", flush=True)
        try:
            result = run_one_experiment(
                protocol=protocol,
                loss_rate=0,
                delay_ms=0,
                message_count=20,
                payload_size=args.payload_size,
                repeat_id=0,
                base_seed=args.seed,
                max_retries=args.max_retries,
                retry_delay_ms=args.retry_delay_ms,
                host=args.host,
                port=args.port,
            )

            if result["success_rate"] != 100.0:
                print(f"FAILED: success_rate={result['success_rate']}%")
                all_passed = False
            elif result["accepted_logical_messages"] != 20:
                print(f"FAILED: accepted={result['accepted_logical_messages']}/20")
                all_passed = False
            else:
                ok, msg = validate_result(result)
                if not ok:
                    print(f"VALIDATION FAILED: {msg}")
                    all_passed = False
                else:
                    print(f"100% ({result['socket_rtt_mean_ms']}ms RTT)")

        except Exception as e:
            print(f"EXCEPTION: {e}")
            all_passed = False

    print()
    if all_passed:
        print("ALL SMOKE TESTS PASSED", flush=True)
    else:
        print("SMOKE TESTS FAILED", flush=True)
    return all_passed


# =========================
# 正式实验
# =========================

def run_formal_experiments(args, git_meta: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """运行完整 150 行正式实验"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 输出到临时目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    formal_dir = os.path.join(OUTPUT_DIR, f"formal_{timestamp}")
    os.makedirs(formal_dir, exist_ok=True)
    formal_csv = os.path.join(formal_dir, "weak_network_simulation_results.csv")

    results: List[Dict[str, Any]] = []

    total_experiments = len(PROTOCOLS) * len(LOSS_RATES) * len(DELAY_MS) * args.repeats
    completed = 0
    failed = 0

    print(f"\n{'=' * 60}", flush=True)
    print(f"FORMAL EXPERIMENT: {total_experiments} rows", flush=True)
    print(f"  seed={args.seed}, repeats={args.repeats}", flush=True)
    print(f"  message_count={args.message_count}, payload_size={args.payload_size}", flush=True)
    print(f"  max_retries={args.max_retries}, retry_delay_ms={args.retry_delay_ms}", flush=True)
    print(f"  Protocols: {PROTOCOLS}", flush=True)
    print(f"  Loss rates: {LOSS_RATES}", flush=True)
    print(f"  Delay ms: {DELAY_MS}", flush=True)
    print(f"{'=' * 60}", flush=True)

    for protocol in PROTOCOLS:
        for loss_rate in LOSS_RATES:
            for delay_ms in DELAY_MS:
                for repeat_id in range(1, args.repeats + 1):
                    completed += 1
                    label = (
                        f"[{completed}/{total_experiments}] "
                        f"protocol={protocol}, loss={loss_rate}%, "
                        f"delay={delay_ms}ms, repeat={repeat_id}"
                    )
                    print(f"\n{label}", end=" ", flush=True)

                    try:
                        result = run_one_experiment(
                            protocol=protocol,
                            loss_rate=loss_rate,
                            delay_ms=delay_ms,
                            message_count=args.message_count,
                            payload_size=args.payload_size,
                            repeat_id=repeat_id,
                            base_seed=args.seed,
                            max_retries=args.max_retries,
                            retry_delay_ms=args.retry_delay_ms,
                            host=args.host,
                            port=args.port,
                        )

                        # 校验
                        ok, msg = validate_result(result)
                        if not ok:
                            print(f"VALIDATION: {msg}")
                            failed += 1
                            continue
                        # 添加 git 元数据
                        result.update(git_meta)
                        results.append(result)

                        status = (
                            "OK" if result["success_rate"] > 80
                            else "WARN" if result["success_rate"] > 50
                            else "FAIL"
                        )
                        print(
                            f"{status} success={result['success_rate']}%, "
                            f"throughput={result['throughput_msg_per_sec']} msg/s, "
                            f"rtt={result['socket_rtt_mean_ms']}ms"
                        )

                    except Exception as e:
                        print(f"FAILED: {e}")
                        failed += 1

    # 写入临时 CSV
    with open(formal_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"\n{'=' * 60}", flush=True)
    print(f"[COMPLETE] Results: {len(results)}/{total_experiments}", flush=True)
    print(f"[COMPLETE] Failed: {failed}", flush=True)
    print(f"[COMPLETE] Temp CSV: {formal_csv}", flush=True)

    return results, formal_csv


# =========================
# 原子发布
# =========================

def atomic_publish(results: List[Dict[str, Any]], formal_csv: str,
                   paper_output: str, expected_rows: int):
    """
    原子发布到 paper_data/:
    1. 验证行数
    2. 写入临时文件
    3. os.replace 到目标
    """
    if len(results) != expected_rows:
        raise RuntimeError(
            f"[PUBLISH] Expected {expected_rows} rows, got {len(results)}. "
            f"Refusing to publish incomplete results."
        )

    # 确保目录存在
    paper_dir = os.path.dirname(paper_output)
    if paper_dir:
        os.makedirs(paper_dir, exist_ok=True)

    # 写入临时文件
    tmp_output = paper_output + ".tmp"
    with open(tmp_output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # 验证临时文件行数
    with open(tmp_output, "r", encoding="utf-8") as f:
        row_count = sum(1 for _ in f) - 1  # 减去 header
    if row_count != len(results):
        os.remove(tmp_output)
        raise RuntimeError(
            f"Row count mismatch: expected {len(results)}, wrote {row_count}"
        )

    # 原子替换
    os.replace(tmp_output, paper_output)
    print(f"[PUBLISH] {len(results)} rows → {paper_output}", flush=True)


# =========================
# Main
# =========================

def main():
    args = parse_args()

    # --allow-dirty 检查（Task 3）
    check_git_dirty(args.allow_dirty)

    # 收集 git 元数据（Task 3）
    git_meta = collect_git_metadata()

    # 设置全局重试参数
    global MAX_RETRIES, RETRY_DELAY_MS
    MAX_RETRIES = args.max_retries
    RETRY_DELAY_MS = args.retry_delay_ms

    # 计算 expected_rows
    expected_rows = len(PROTOCOLS) * len(LOSS_RATES) * len(DELAY_MS) * args.repeats

    # 确定需要哪些服务器
    need_baseline_server = True  # 所有协议都走 baseline_server（port 9001）
    baseline_proc = None

    try:
        if args.spawn_server:
            # 启动 real_baseline_server（支持所有协议，port 9001）
            baseline_proc = spawn_server(
                "real_baseline_server.py", 9001, "Baseline Server", args.host
            )

        # Smoke 测试
        if args.smoke_only:
            ok = run_smoke_test(args)
            return 0 if ok else 1

        # 正式实验
        if args.formal:
            # 正式 paper 数据禁止 dirty
            if args.allow_dirty:
                print("[FATAL] --allow-dirty is forbidden for formal paper data.", flush=True)
                return 1

            # 先跑 smoke
            print("\n[PREFLIGHT] Running smoke test before formal experiment...", flush=True)
            if not run_smoke_test(args):
                print("[PREFLIGHT] Smoke test FAILED. Aborting.", flush=True)
                return 1

            results, formal_csv = run_formal_experiments(args, git_meta)

            # 原子发布（空结果也会抛异常）
            atomic_publish(results, formal_csv, args.paper_output, expected_rows)
            return 0

        # 默认：先 smoke 后 formal
        if not run_smoke_test(args):
            return 1

        results, formal_csv = run_formal_experiments(args, git_meta)
        atomic_publish(results, formal_csv, args.paper_output, expected_rows)
        return 0

    except Exception as e:
        print(f"\n[FATAL] {e}", flush=True)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        kill_server(baseline_proc, "Baseline Server")


if __name__ == "__main__":
    sys.exit(main())
