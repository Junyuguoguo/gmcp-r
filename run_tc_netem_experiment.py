# -*- coding: utf-8 -*-
# run_tc_netem_experiment.py
#
# 使用 tc/netem 进行真实弱网实验
# 模拟丢包、延迟、乱序等网络条件

import csv
import json
import os
import socket
import time
import subprocess
import sys
from typing import Dict, Any, List, Tuple

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


OUTPUT_DIR = "results/tc_netem"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "tc_netem_results.csv")

# 实验参数
MESSAGE_COUNTS = [500, 1000]
PAYLOAD_SIZES = [128]

# 弱网参数
LOSS_RATES = [0, 1, 5, 10]  # 丢包率 (%)
DELAY_MS = [0, 50, 100, 200]  # 延迟 (ms)
REORDER_RATES = [0, 5, 10]  # 乱序率 (%)

REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "1"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

SOCKET_TIMEOUT = 30.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "tc-netem-%d-" % seq
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


def open_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, DEFAULT_PORT))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def setup_tc_netem(loss_rate: int, delay_ms: int, reorder_rate: int, interface: str = "eth0") -> bool:
    """
    设置 tc/netem 弱网规则
    
    参数：
    - loss_rate: 丢包率 (%)
    - delay_ms: 延迟 (ms)
    - reorder_rate: 乱序率 (%)
    - interface: 网络接口
    
    返回：
    - bool: 是否设置成功
    """
    # 先清除现有规则
    clear_tc_netem(interface)
    
    # 构建 tc 命令
    cmd = ["sudo", "tc", "qdisc", "add", "dev", interface, "root", "netem"]
    
    if loss_rate > 0:
        cmd.extend(["loss", f"{loss_rate}%"])
    
    if delay_ms > 0:
        cmd.extend(["delay", f"{delay_ms}ms"])
    
    if reorder_rate > 0:
        cmd.extend(["reorder", f"{reorder_rate}%"])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[TC] Setup: loss={loss_rate}%, delay={delay_ms}ms, reorder={reorder_rate}%")
            return True
        else:
            print(f"[TC] Failed to setup: {result.stderr}")
            return False
    except Exception as e:
        print(f"[TC] Error: {e}")
        return False


def clear_tc_netem(interface: str = "eth0") -> bool:
    """清除 tc/netem 规则"""
    try:
        result = subprocess.run(
            ["sudo", "tc", "qdisc", "del", "dev", interface, "root"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


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
            
            send_json_line(sock, packet)
            sent_count += 1
            
            try:
                response = recv_json_line(file_obj)
                
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
    
    # 计算成功率
    success_rate = accepted_count / message_count * 100 if message_count > 0 else 0
    
    # 计算吞吐量
    throughput = accepted_count / elapsed if elapsed > 0 else 0
    
    return {
        "session_id": session_id,
        "experiment_type": "tc_netem",
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
    }


def run_all_experiments():
    ensure_output_dir()
    
    # 检查是否有 sudo 权限
    try:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
        if result.returncode != 0:
            print("[ERROR] This experiment requires sudo privileges.")
            print("[ERROR] Please run with sudo or configure passwordless sudo for tc commands.")
            sys.exit(1)
    except Exception:
        print("[ERROR] Cannot check sudo privileges.")
        sys.exit(1)
    
    # 创建实验跟踪器
    tracker = ExperimentTracker("tc_netem")
    
    fieldnames = [
        "session_id", "experiment_type", "loss_rate", "delay_ms", "reorder_rate",
        "message_count", "payload_size", "repeat_id", "sent_count", "accepted_count",
        "rejected_count", "timeout_count", "error_count", "success_rate",
        "throughput_msg_per_sec", "elapsed_seconds",
    ]
    
    for loss_rate in LOSS_RATES:
        for delay_ms in DELAY_MS:
            for reorder_rate in REORDER_RATES:
                # 跳过全0的组合（正常网络）
                if loss_rate == 0 and delay_ms == 0 and reorder_rate == 0:
                    continue
                
                # 设置弱网规则
                if not setup_tc_netem(loss_rate, delay_ms, reorder_rate):
                    print(f"[SKIP] Failed to setup tc/netem: loss={loss_rate}%, delay={delay_ms}ms, reorder={reorder_rate}%")
                    continue
                
                for message_count in MESSAGE_COUNTS:
                    for payload_size in PAYLOAD_SIZES:
                        for repeat_id in REPEATS:
                            print(f"\n[EXPERIMENT] loss={loss_rate}%, delay={delay_ms}ms, "
                                  f"reorder={reorder_rate}%, msg={message_count}, "
                                  f"payload={payload_size}, repeat={repeat_id}")
                            
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
                            print(f"[RESULT] success_rate={result['success_rate']}%, "
                                  f"throughput={result['throughput_msg_per_sec']} msg/s")
    
    # 清除 tc 规则
    clear_tc_netem()
    
    # 保存结果
    tracker.save_results_to_csv(OUTPUT_CSV, fieldnames)
    
    # 获取最终统计
    final_stats = tracker.finish()
    print(f"\n[COMPLETE] Results saved to {OUTPUT_CSV}")
    print(f"[STATS] Total results: {final_stats['total_results']}")
    print(f"[STATS] Elapsed time: {final_stats['elapsed_seconds']}s")
    
    return tracker.results


if __name__ == "__main__":
    run_all_experiments()
