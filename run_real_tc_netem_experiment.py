# -*- coding: utf-8 -*-
# run_real_tc_netem_experiment.py
#
# 使用 tc/netem 进行真实弱网实验
# 支持参数化配置和自动清理
#
# 弱网参数：
# - 丢包率：0%, 1%, 2%, 5%, 10%
# - 延迟：0ms, 20ms, 50ms, 100ms, 200ms
# - 乱序率：0%, 1%, 5%, 10%

import csv
import json
import os
import socket
import time
import subprocess
import sys
import signal
from typing import Dict, Any, List, Tuple, Optional
from contextlib import contextmanager

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.experiment_stats import (
    ExperimentTracker,
    collect_experiment_metadata,
    calculate_statistics,
    format_statistics_for_csv,
)


# =========================
# 配置参数
# =========================

OUTPUT_DIR = "results/tc_netem"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "tc_netem_results.csv")

# 弱网参数（可通过环境变量覆盖）
LOSS_RATES = [int(x) for x in os.getenv("GMCP_LOSS_RATES", "0,1,2,5,10").split(",")]
DELAY_MS = [int(x) for x in os.getenv("GMCP_DELAY_MS", "0,20,50,100,200").split(",")]
REORDER_RATES = [int(x) for x in os.getenv("GMCP_REORDER_RATES", "0,1,5,10").split(",")]

# 实验参数
MESSAGE_COUNTS = [int(x) for x in os.getenv("GMCP_MESSAGE_COUNTS", "500,1000").split(",")]
PAYLOAD_SIZES = [int(x) for x in os.getenv("GMCP_PAYLOAD_SIZES", "128").split(",")]
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

# 网络参数
SOCKET_TIMEOUT = float(os.getenv("GMCP_SOCKET_TIMEOUT", "30.0"))
TC_INTERFACE = os.getenv("GMCP_TC_INTERFACE", "eth0")

# SSH 参数（用于远程服务器 tc 设置）
SSH_HOST = os.getenv("GMCP_SSH_HOST", "38.76.169.74")
SSH_USER = os.getenv("GMCP_SSH_USER", "root")
SSH_PASSWORD = os.getenv("GMCP_SSH_PASSWORD", "123456")

# 是否使用远程 tc（通过 SSH 在服务器端设置）
USE_REMOTE_TC = os.getenv("GMCP_USE_REMOTE_TC", "false").lower() == "true"


# =========================
# 工具函数
# =========================

def ensure_output_dir():
    """确保输出目录存在"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    """生成测试负载"""
    prefix = "tc-netem-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    """发送 JSON 行"""
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def enable_tcp_nodelay(sock: socket.socket) -> None:
    """启用 TCP_NODELAY"""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def recv_json_line(file_obj):
    """接收 JSON 行"""
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def close_tcp(sock, file_obj):
    """安全关闭 TCP 连接"""
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
    """打开 TCP 连接"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def ping_server() -> bool:
    """测试服务器是否可达"""
    sock = None
    file_obj = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        enable_tcp_nodelay(sock)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))
        file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
        
        msg = {"type": "PING", "timestamp": time.time()}
        send_json_line(sock, msg)
        resp = recv_json_line(file_obj)
        return resp.get("ok") is True
    except Exception:
        return False
    finally:
        close_tcp(sock, file_obj)


# =========================
# tc/netem 管理
# =========================

def run_ssh_command(command: str) -> Tuple[int, str, str]:
    """通过 SSH 执行远程命令"""
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, password=SSH_PASSWORD, timeout=10)
        
        stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        
        ssh.close()
        return exit_code, out, err
    except ImportError:
        print("[WARNING] paramiko not installed, falling back to local tc")
        return -1, "", "paramiko not installed"
    except Exception as e:
        return -1, "", str(e)


def run_local_command(command: List[str]) -> Tuple[int, str, str]:
    """执行本地命令"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def setup_tc_netem(loss_rate: int, delay_ms: int, reorder_rate: int) -> bool:
    """
    设置 tc/netem 弱网规则
    
    参数：
    - loss_rate: 丢包率 (%)
    - delay_ms: 延迟 (ms)
    - reorder_rate: 乱序率 (%)
    
    返回：
    - bool: 是否设置成功
    """
    # 先清除现有规则
    clear_tc_netem()
    
    # 构建 tc 命令
    tc_cmd = f"tc qdisc add dev {TC_INTERFACE} root netem"
    
    if loss_rate > 0:
        tc_cmd += f" loss {loss_rate}%"
    
    if delay_ms > 0:
        tc_cmd += f" delay {delay_ms}ms"
    
    if reorder_rate > 0:
        tc_cmd += f" reorder {reorder_rate}%"
    
    # 如果所有参数都是 0，设置 pfifo_fast（默认队列）
    if loss_rate == 0 and delay_ms == 0 and reorder_rate == 0:
        tc_cmd = f"tc qdisc add dev {TC_INTERFACE} root pfifo_fast"
    
    if USE_REMOTE_TC:
        # 通过 SSH 在远程服务器设置
        exit_code, out, err = run_ssh_command(tc_cmd)
    else:
        # 本地设置（需要 sudo）
        exit_code, out, err = run_local_command(["sudo"] + tc_cmd.split())
    
    if exit_code == 0:
        print(f"[TC] Setup: loss={loss_rate}%, delay={delay_ms}ms, reorder={reorder_rate}%")
        return True
    else:
        print(f"[TC] Failed to setup: {err}")
        return False


def clear_tc_netem() -> bool:
    """清除 tc/netem 规则"""
    tc_cmd = f"tc qdisc del dev {TC_INTERFACE} root"
    
    if USE_REMOTE_TC:
        exit_code, out, err = run_ssh_command(tc_cmd)
    else:
        exit_code, out, err = run_local_command(["sudo"] + tc_cmd.split())
    
    # 忽略 "No such file or directory" 错误（表示没有现有规则）
    if exit_code == 0 or "No such file or directory" in err:
        return True
    return False


@contextmanager
def tc_context(loss_rate: int, delay_ms: int, reorder_rate: int):
    """
    tc/netem 上下文管理器
    自动设置和清理 tc 规则
    """
    try:
        setup_tc_netem(loss_rate, delay_ms, reorder_rate)
        yield
    finally:
        clear_tc_netem()


def verify_tc_rules() -> Dict[str, Any]:
    """验证当前 tc 规则"""
    tc_cmd = f"tc qdisc show dev {TC_INTERFACE}"
    
    if USE_REMOTE_TC:
        exit_code, out, err = run_ssh_command(tc_cmd)
    else:
        exit_code, out, err = run_local_command(["sudo"] + tc_cmd.split())
    
    return {
        "exit_code": exit_code,
        "output": out,
        "error": err,
    }


# =========================
# 实验执行
# =========================

def run_one_tc_experiment(
    loss_rate: int,
    delay_ms: int,
    reorder_rate: int,
    message_count: int,
    payload_size: int,
    repeat_id: int,
) -> Dict[str, Any]:
    """运行单个弱网实验"""
    
    session_id = (
        f"tc-netem-l{loss_rate}-d{delay_ms}-r{reorder_rate}-"
        f"m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )
    
    initial_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    current_mem = initial_mem
    
    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    error_count = 0
    sent_count = 0
    
    rtts: List[float] = []
    
    start_time = time.time()
    
    sock = None
    file_obj = None
    
    try:
        sock, file_obj = open_tcp()
        
        for seq in range(1, message_count + 1):
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
            
            send_time = time.time()
            send_json_line(sock, packet)
            sent_count += 1
            
            try:
                response = recv_json_line(file_obj)
                recv_time = time.time()
                rtts.append((recv_time - send_time) * 1000)
                
                if response.get("ok"):
                    accepted_count += 1
                    current_mem = response.get("last_mem", current_mem)
                else:
                    rejected_count += 1
                    
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
    
    # 计算 RTT 统计
    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
    max_rtt = max(rtts) if rtts else 0
    min_rtt = min(rtts) if rtts else 0
    
    # 计算百分位数
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
    
    p50_rtt = percentile(rtts, 0.50)
    p95_rtt = percentile(rtts, 0.95)
    p99_rtt = percentile(rtts, 0.99)
    
    return {
        "session_id": session_id,
        "experiment_type": "tc_netem",
        "server_host": SERVER_TARGET_HOST,
        "server_port": DEFAULT_PORT,
        "loss_rate": loss_rate,
        "delay_ms": delay_ms,
        "reorder_rate": reorder_rate,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "error_count": error_count,
        "success_rate": round(success_rate, 2),
        "throughput_msg_per_sec": round(throughput, 2),
        "elapsed_seconds": round(elapsed, 2),
        "avg_rtt_ms": round(avg_rtt, 2),
        "min_rtt_ms": round(min_rtt, 2),
        "max_rtt_ms": round(max_rtt, 2),
        "p50_rtt_ms": round(p50_rtt, 2),
        "p95_rtt_ms": round(p95_rtt, 2),
        "p99_rtt_ms": round(p99_rtt, 2),
    }


# =========================
# 主流程
# =========================

def calculate_total_experiments() -> int:
    """计算总实验数"""
    total = 0
    for loss_rate in LOSS_RATES:
        for delay_ms in DELAY_MS:
            for reorder_rate in REORDER_RATES:
                # 跳过全0的组合（正常网络）
                if loss_rate == 0 and delay_ms == 0 and reorder_rate == 0:
                    continue
                for message_count in MESSAGE_COUNTS:
                    for payload_size in PAYLOAD_SIZES:
                        total += REPEAT_COUNT
    return total


def run_all_experiments():
    """运行所有实验"""
    ensure_output_dir()
    
    # 检查服务器是否可达
    print("[INFO] Checking server connectivity...")
    if not ping_server():
        print("[WARNING] Server not reachable, experiments may fail")
    
    # 检查 sudo 权限（本地 tc 模式）
    if not USE_REMOTE_TC:
        try:
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            if result.returncode != 0:
                print("[ERROR] This experiment requires sudo privileges.")
                print("[ERROR] Please run with sudo or configure passwordless sudo for tc commands.")
                print("[ERROR] Or set GMCP_USE_REMOTE_TC=true to use SSH-based tc management.")
                sys.exit(1)
        except Exception:
            print("[ERROR] Cannot check sudo privileges.")
            sys.exit(1)
    
    # 计算总实验数
    total_experiments = calculate_total_experiments()
    print(f"[INFO] Total experiments to run: {total_experiments}")
    print(f"[INFO] Loss rates: {LOSS_RATES}")
    print(f"[INFO] Delay (ms): {DELAY_MS}")
    print(f"[INFO] Reorder rates: {REORDER_RATES}")
    print(f"[INFO] Message counts: {MESSAGE_COUNTS}")
    print(f"[INFO] Payload sizes: {PAYLOAD_SIZES}")
    print(f"[INFO] Repeats per config: {REPEAT_COUNT}")
    print(f"[INFO] Output: {OUTPUT_CSV}")
    print()
    
    # 创建实验跟踪器
    tracker = ExperimentTracker("tc_netem")
    
    fieldnames = [
        "session_id", "experiment_type", "server_host", "server_port",
        "loss_rate", "delay_ms", "reorder_rate",
        "message_count", "payload_size", "repeat_id",
        "sent_count", "accepted_count", "rejected_count", 
        "timeout_count", "error_count", "success_rate",
        "throughput_msg_per_sec", "elapsed_seconds",
        "avg_rtt_ms", "min_rtt_ms", "max_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
    ]
    
    completed = 0
    start_time = time.time()
    
    # 注册信号处理器，确保异常退出时也能清理 tc 规则
    def signal_handler(sig, frame):
        print("\n[INTERRUPTED] Cleaning up tc rules...")
        clear_tc_netem()
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        for loss_rate in LOSS_RATES:
            for delay_ms in DELAY_MS:
                for reorder_rate in REORDER_RATES:
                    # 跳过全0的组合（正常网络）
                    if loss_rate == 0 and delay_ms == 0 and reorder_rate == 0:
                        continue
                    
                    # 使用上下文管理器自动管理 tc 规则
                    with tc_context(loss_rate, delay_ms, reorder_rate):
                        # 验证 tc 规则已设置
                        tc_status = verify_tc_rules()
                        if tc_status["exit_code"] != 0:
                            print(f"[SKIP] Failed to setup tc/netem: loss={loss_rate}%, delay={delay_ms}ms, reorder={reorder_rate}%")
                            print(f"[SKIP] Error: {tc_status['error']}")
                            # 跳过这个配置的所有实验
                            skipped = len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * REPEAT_COUNT
                            completed += skipped
                            continue
                        
                        for message_count in MESSAGE_COUNTS:
                            for payload_size in PAYLOAD_SIZES:
                                for repeat_id in REPEATS:
                                    completed += 1
                                    elapsed_total = time.time() - start_time
                                    eta = (elapsed_total / completed * (total_experiments - completed)) if completed > 0 else 0
                                    
                                    print(f"\n[{completed}/{total_experiments}] "
                                          f"loss={loss_rate}%, delay={delay_ms}ms, "
                                          f"reorder={reorder_rate}%, msg={message_count}, "
                                          f"payload={payload_size}, repeat={repeat_id}")
                                    print(f"  ETA: {eta/60:.1f} min")
                                    
                                    result = run_one_tc_experiment(
                                        loss_rate=loss_rate,
                                        delay_ms=delay_ms,
                                        reorder_rate=reorder_rate,
                                        message_count=message_count,
                                        payload_size=payload_size,
                                        repeat_id=repeat_id,
                                    )
                                    
                                    # 添加到跟踪器
                                    tracker.add_result(result)
                                    
                                    # 采样性能
                                    tracker.sample_performance()
                                    
                                    # 打印结果摘要
                                    print(f"  Result: success_rate={result['success_rate']}%, "
                                          f"throughput={result['throughput_msg_per_sec']} msg/s, "
                                          f"avg_rtt={result['avg_rtt_ms']}ms")
                                    
                                    # 定期保存中间结果
                                    if completed % 10 == 0:
                                        tracker.save_results_to_csv(OUTPUT_CSV, fieldnames)
                                        print(f"  [SAVED] Intermediate results to {OUTPUT_CSV}")
    
    finally:
        # 确保清除 tc 规则
        clear_tc_netem()
    
    # 保存最终结果
    tracker.save_results_to_csv(OUTPUT_CSV, fieldnames)
    
    # 获取最终统计
    final_stats = tracker.finish()
    print(f"\n{'='*60}")
    print(f"[COMPLETE] Results saved to {OUTPUT_CSV}")
    print(f"[STATS] Total results: {final_stats['total_results']}")
    print(f"[STATS] Elapsed time: {final_stats['elapsed_seconds']:.1f}s ({final_stats['elapsed_seconds']/60:.1f} min)")
    print(f"[STATS] Start time: {final_stats['start_time']}")
    print(f"[STATS] End time: {final_stats['end_time']}")
    
    return tracker.results


def run_quick_test():
    """快速测试（单个配置，少量重复）"""
    print("[QUICK TEST] Running quick test with reduced parameters...")
    
    # 使用最小参数
    global LOSS_RATES, DELAY_MS, REORDER_RATES, MESSAGE_COUNTS, REPEATS
    LOSS_RATES = [5]
    DELAY_MS = [50]
    REORDER_RATES = [5]
    MESSAGE_COUNTS = [100]
    REPEATS = [1, 2, 3]
    
    return run_all_experiments()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="tc/netem weak network experiment")
    parser.add_argument("--quick", action="store_true", help="Run quick test with reduced parameters")
    parser.add_argument("--loss-rates", type=str, help="Comma-separated loss rates (e.g., '0,1,5')")
    parser.add_argument("--delay-ms", type=str, help="Comma-separated delays in ms (e.g., '0,50,100')")
    parser.add_argument("--reorder-rates", type=str, help="Comma-separated reorder rates (e.g., '0,5,10')")
    parser.add_argument("--message-counts", type=str, help="Comma-separated message counts (e.g., '500,1000')")
    parser.add_argument("--repeats", type=int, help="Number of repeats per configuration")
    parser.add_argument("--remote-tc", action="store_true", help="Use SSH-based tc management")
    parser.add_argument("--ssh-host", type=str, help="SSH host for remote tc")
    parser.add_argument("--ssh-user", type=str, help="SSH user for remote tc")
    parser.add_argument("--ssh-password", type=str, help="SSH password for remote tc")
    
    args = parser.parse_args()
    
    # 应用命令行参数
    if args.loss_rates:
        LOSS_RATES = [int(x) for x in args.loss_rates.split(",")]
    if args.delay_ms:
        DELAY_MS = [int(x) for x in args.delay_ms.split(",")]
    if args.reorder_rates:
        REORDER_RATES = [int(x) for x in args.reorder_rates.split(",")]
    if args.message_counts:
        MESSAGE_COUNTS = [int(x) for x in args.message_counts.split(",")]
    if args.repeats:
        REPEATS = list(range(1, args.repeats + 1))
    if args.remote_tc:
        USE_REMOTE_TC = True
    if args.ssh_host:
        SSH_HOST = args.ssh_host
    if args.ssh_user:
        SSH_USER = args.ssh_user
    if args.ssh_password:
        SSH_PASSWORD = args.ssh_password
    
    if args.quick:
        run_quick_test()
    else:
        run_all_experiments()
