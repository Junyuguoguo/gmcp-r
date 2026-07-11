# -*- coding: utf-8 -*-
# run_weak_network_simulation.py
#
# 弱网仿真实验（完全重写）
#
# 实验矩阵：3 protocols × 5 loss_rates × 5 delay_ms × 2 repeats = 150 rows
# 每种协议使用独立状态管理 + HELLO握手 + 正式构包函数 + 重试策略

import csv
import json
import os
import socket
import subprocess
import sys
import time
from typing import Dict, Any, List, Tuple

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
from gmcp.packet import packet_without_auth
from gmcp.experiment_stats import (
    ExperimentTracker,
    calculate_statistics,
)

# 导入baseline协议
from gmcp.baselines.hash_chain import (
    create_initial_state as hash_chain_create_state,
    build_data_packet as hash_chain_build_packet,
)
from gmcp.baselines.seq_mac import (
    create_initial_state as seq_mac_create_state,
    build_data_packet as seq_mac_build_packet,
)

# =========================
# 实验参数
# =========================

OUTPUT_DIR = "results/weak_network_simulation"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "weak_network_simulation_results.csv")

PROTOCOLS = ["gmcp_r", "hash_chain", "seq_mac"]
LOSS_RATES = [0, 1, 2, 5, 10]       # 丢包率 (%)
DELAY_MS = [0, 20, 50, 100, 200]    # 延迟 (ms)
REORDER_RATE = 0                      # 乱序率固定0
MESSAGE_COUNT = 200
PAYLOAD_SIZE = 128
REPEATS = [1, 2]

# 所有协议统一使用 real_baseline_server (port 9001)
# gmcp_r 也需要 HELLO 握手，所以不能用 real_tcp_server (port 9000)
SERVER_PORT = 9001
SOCKET_TIMEOUT = 30.0
SERVER_SPAWN_WAIT = 8

# 重试策略
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # 100ms


# =========================
# 辅助函数
# =========================

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


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


def open_tcp(port: int = SERVER_PORT) -> Tuple[socket.socket, object]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def send_hello(sock, file_obj, protocol, session_id, sender_id, epoch):
    """Send HELLO handshake and wait for HELLO_ACK."""
    # Normalize protocol name: gmcp_r → gmcp (server sees "gmcp")
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


# =========================
# 协议状态管理
# =========================

def create_protocol_state(protocol, session_id, sender_id, epoch):
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


def build_packet_for_protocol(protocol, session_id, sender_id, epoch, seq, payload, state):
    """使用正式构包函数构建数据包"""
    if protocol == "gmcp_r":
        packet = gmcp_build_data_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_mem=state["last_mem"],
            payload=payload,
        )
        # build_data_packet 默认 protocol="gmcp"，服务器期望 "gmcp"
        return packet
    elif protocol == "hash_chain":
        packet = hash_chain_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash=state["last_hash"],
            payload=payload,
        )
        return packet
    elif protocol == "seq_mac":
        packet = seq_mac_build_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
        )
        return packet
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def update_state_after_accept(protocol, state, seq, packet, response):
    """
    服务端接受包后更新本地客户端状态。
    关键：hash_chain 从 packet['chain_hash'] 更新（不是 response['last_mem']！）
    """
    if protocol == "gmcp_r":
        state["last_seq"] = int(response.get("last_seq", seq))
        state["last_mem"] = response.get("last_mem", state["last_mem"])
    elif protocol == "hash_chain":
        state["last_seq"] = seq
        state["last_hash"] = packet.get("chain_hash", state["last_hash"])
    elif protocol == "seq_mac":
        state["last_seq"] = seq


# =========================
# 服务器管理
# =========================

def spawn_server(script_name, port, label):
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
            s.connect((SERVER_TARGET_HOST, port))
            s.close()
            print(f"[SPAWN] {label} ready on port {port}")
            return proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    raise RuntimeError(f"{label} did not start on port {port}")


def kill_server(proc, label):
    """停止服务器"""
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(f"[SPAWN] {label} terminated")


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
) -> Dict[str, Any]:
    """运行单个弱网实验"""

    session_id = (
        f"weaknet-{protocol}-l{loss_rate}-d{delay_ms}-"
        f"m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    # 创建协议状态
    state = create_protocol_state(protocol, session_id, CLIENT_ID, EPOCH)

    sent_count = 0
    accepted_count = 0
    rejected_count = 0
    dropped_count = 0
    retry_total = 0
    rtt_list = []

    start_time = time.time()

    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp()

        # HELLO 握手
        hello_ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
        if not hello_ack.get("ok"):
            raise ConnectionError(
                f"HELLO failed for {protocol}: {hello_ack.get('reason')}"
            )

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

            # 模拟丢包：通过 delay 模拟 TCP 重传开销
            # 真正跳过发送会导致 TCP 流失序，所以用 delay 模拟重传延迟
            simulate_loss = loss_rate > 0 and (hash(f"{session_id}-{seq}") % 100 < loss_rate)
            retry_count = 0

            if simulate_loss:
                dropped_count += 1
                # 模拟丢包重传延迟：每次重试消耗 delay_ms 时间
                # 模型：TCP 超时重传 → 额外延迟
                time.sleep(max(delay_ms, 50) / 1000.0)
                retry_total += 1

            # 应用延迟（弱网延迟模拟）
            if delay_ms > 0:
                jitter = delay_ms * 0.2
                actual_delay = delay_ms + (
                    (hash(f"{session_id}-{seq}-jitter") % 1000 / 1000.0 - 0.5) * 2 * jitter
                )
                time.sleep(max(0, actual_delay) / 1000.0)

            # 发送并等待响应
            send_start = time.time()
            send_json_line(sock, packet)
            sent_count += 1

            response = recv_json_line(file_obj)
            rtt_ms = (time.time() - send_start) * 1000
            rtt_list.append(rtt_ms)

            if response.get("ok"):
                accepted_count += 1
                update_state_after_accept(protocol, state, seq, packet, response)
            else:
                reason = response.get("reason", "unknown")
                rejected_count += 1

                # 重试策略：服务端明确拒绝时尝试重传
                retry_success = False
                for attempt in range(MAX_RETRIES):
                    retry_total += 1
                    time.sleep(RETRY_DELAY)

                    # 重建包（状态未变，同一个 seq）
                    retry_packet = build_packet_for_protocol(
                        protocol=protocol,
                        session_id=session_id,
                        sender_id=CLIENT_ID,
                        epoch=EPOCH,
                        seq=seq,
                        payload=payload,
                        state=state,
                    )

                    retry_start = time.time()
                    send_json_line(sock, retry_packet)
                    sent_count += 1

                    try:
                        retry_response = recv_json_line(file_obj)
                        retry_rtt = (time.time() - retry_start) * 1000
                        rtt_list.append(retry_rtt)

                        if retry_response.get("ok"):
                            accepted_count += 1
                            rejected_count -= 1  # 修正计数
                            update_state_after_accept(
                                protocol, state, seq, retry_packet, retry_response
                            )
                            retry_success = True
                            break
                    except Exception:
                        pass

                if not retry_success:
                    # 达到最大重试次数仍失败
                    pass

    except Exception as e:
        print(f"  [ERROR] {e}")
        raise  # 异常必须抛出

    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time

    # 统计指标
    success_rate = accepted_count / message_count * 100 if message_count > 0 else 0
    throughput = accepted_count / elapsed if elapsed > 0 else 0
    rtt_stats = calculate_statistics(rtt_list) if rtt_list else {
        "mean": 0, "std": 0, "min": 0, "max": 0, "median": 0
    }

    return {
        "session_id": session_id,
        "protocol": protocol,
        "loss_rate": loss_rate,
        "delay_ms": delay_ms,
        "reorder_rate": REORDER_RATE,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "dropped_count": dropped_count,
        "retry_total": retry_total,
        "success_rate": round(success_rate, 2),
        "throughput_msg_per_sec": round(throughput, 2),
        "rtt_mean_ms": round(rtt_stats["mean"], 2),
        "rtt_std_ms": round(rtt_stats["std"], 2),
        "rtt_min_ms": round(rtt_stats["min"], 2),
        "rtt_max_ms": round(rtt_stats["max"], 2),
        "rtt_median_ms": round(rtt_stats["median"], 2),
        "elapsed_seconds": round(elapsed, 4),
    }


# =========================
# 校验
# =========================

def validate_result(result: Dict[str, Any]) -> Tuple[bool, str]:
    """校验单个实验结果"""
    if result["elapsed_seconds"] < 0:
        return False, "elapsed_seconds < 0"
    if result["sent_count"] <= 0:
        return False, "sent_count <= 0"
    # success_rate 应与 accepted_count/message_count 一致
    expected_rate = round(
        result["accepted_count"] / result["message_count"] * 100, 2
    ) if result["message_count"] > 0 else 0
    if abs(result["success_rate"] - expected_rate) > 0.01:
        return False, (
            f"success_rate mismatch: got {result['success_rate']}, "
            f"expected {expected_rate}"
        )
    return True, "ok"


# =========================
# Smoke 测试
# =========================

def run_smoke_test() -> bool:
    """
    控制组 smoke 测试：
    每种协议 loss=0, delay=0, 20条消息，全部必须100%成功
    """
    print("\n" + "=" * 60)
    print("SMOKE TEST: loss=0, delay=0, 20 messages per protocol")
    print("=" * 60)

    all_passed = True
    for protocol in PROTOCOLS:
        print(f"\n  Testing {protocol}...", end=" ", flush=True)
        try:
            result = run_one_experiment(
                protocol=protocol,
                loss_rate=0,
                delay_ms=0,
                message_count=20,
                payload_size=128,
                repeat_id=0,
            )

            if result["success_rate"] != 100.0:
                print(f"❌ FAILED: success_rate={result['success_rate']}%")
                all_passed = False
            elif result["accepted_count"] != 20:
                print(f"❌ FAILED: accepted={result['accepted_count']}/20")
                all_passed = False
            else:
                ok, msg = validate_result(result)
                if not ok:
                    print(f"❌ VALIDATION FAILED: {msg}")
                    all_passed = False
                else:
                    print(f"✅ 100% ({result['rtt_mean_ms']}ms RTT)")

        except Exception as e:
            print(f"❌ EXCEPTION: {e}")
            all_passed = False

    print()
    if all_passed:
        print("✅ ALL SMOKE TESTS PASSED")
    else:
        print("❌ SMOKE TESTS FAILED — ABORT")
    return all_passed


# =========================
# 完整实验
# =========================

def run_all_experiments():
    ensure_output_dir()

    tracker = ExperimentTracker("weak_network_simulation")

    fieldnames = [
        "session_id", "protocol", "loss_rate", "delay_ms", "reorder_rate",
        "message_count", "payload_size", "repeat_id", "sent_count",
        "accepted_count", "rejected_count", "dropped_count", "retry_total",
        "success_rate", "throughput_msg_per_sec", "rtt_mean_ms", "rtt_std_ms",
        "rtt_min_ms", "rtt_max_ms", "rtt_median_ms", "elapsed_seconds",
    ]

    total_experiments = len(PROTOCOLS) * len(LOSS_RATES) * len(DELAY_MS) * len(REPEATS)
    completed = 0
    failed = 0

    for protocol in PROTOCOLS:
        for loss_rate in LOSS_RATES:
            for delay_ms in DELAY_MS:
                for repeat_id in REPEATS:
                    completed += 1
                    print(
                        f"\n[{completed}/{total_experiments}] "
                        f"protocol={protocol}, loss={loss_rate}%, "
                        f"delay={delay_ms}ms, repeat={repeat_id}",
                        end=" ",
                        flush=True,
                    )

                    try:
                        result = run_one_experiment(
                            protocol=protocol,
                            loss_rate=loss_rate,
                            delay_ms=delay_ms,
                            message_count=MESSAGE_COUNT,
                            payload_size=PAYLOAD_SIZE,
                            repeat_id=repeat_id,
                        )

                        # 校验结果
                        ok, msg = validate_result(result)
                        if not ok:
                            print(f"⚠️  VALIDATION: {msg}")
                            failed += 1
                            continue

                        tracker.add_result(result)

                        status = (
                            "✅" if result["success_rate"] > 80
                            else "⚠️" if result["success_rate"] > 50
                            else "❌"
                        )
                        print(
                            f"{status} success={result['success_rate']}%, "
                            f"throughput={result['throughput_msg_per_sec']} msg/s, "
                            f"rtt={result['rtt_mean_ms']}ms"
                        )

                    except Exception as e:
                        print(f"❌ FAILED: {e}")
                        failed += 1

    # 保存结果
    tracker.save_results_to_csv(OUTPUT_CSV, fieldnames)

    final_stats = tracker.finish()
    print(f"\n{'=' * 60}")
    print(f"[COMPLETE] Results saved to {OUTPUT_CSV}")
    print(f"[STATS] Total results: {final_stats['total_results']}")
    print(f"[STATS] Expected: {total_experiments}")
    print(f"[STATS] Failed: {failed}")
    print(f"[STATS] Elapsed time: {final_stats['elapsed_seconds']}s")

    return tracker.results


# =========================
# Main
# =========================

def main():
    baseline_proc = None

    try:
        # 启动 real_baseline_server (port 9001, 支持所有协议)
        baseline_proc = spawn_server(
            "real_baseline_server.py", SERVER_PORT, "Baseline Server"
        )

        # 1. Smoke 测试
        if not run_smoke_test():
            return 1

        # 2. 运行完整 150 行实验
        results = run_all_experiments()

        # 3. 复制到 paper_data
        paper_data_dir = "paper_data"
        os.makedirs(paper_data_dir, exist_ok=True)
        paper_csv = os.path.join(paper_data_dir, "05_weak_network.csv")

        if results:
            fieldnames = list(results[0].keys())
            with open(paper_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            print(f"[COPY] Results copied to {paper_csv}")
            print(f"[COPY] Total rows: {len(results)}")

        return 0

    finally:
        kill_server(baseline_proc, "Baseline Server")


if __name__ == "__main__":
    sys.exit(main())
