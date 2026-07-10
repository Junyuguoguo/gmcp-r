# -*- coding: utf-8 -*-
# run_weak_network_simulation.py
#
# 弱网仿真实验
# 使用代码级仿真模拟丢包、延迟、乱序等网络条件
# 不需要服务器sudo权限

import csv
import os
import sys
import time
import random
import json
import socket
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field

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
from gmcp.packet import build_data_packet
from gmcp.experiment_stats import (
    ExperimentTracker,
    collect_experiment_metadata,
    calculate_statistics,
    format_statistics_for_csv,
)


OUTPUT_DIR = "results/weak_network_simulation"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "weak_network_simulation_results.csv")

# 实验参数
PROTOCOLS = ["gmcp_r", "hash_chain", "seq_mac"]
LOSS_RATES = [0, 1, 2, 5, 10]  # 丢包率 (%)
DELAY_MS = [0, 20, 50, 100, 200]  # 延迟 (ms)
REORDER_RATES = [0, 1, 5, 10]  # 乱序率 (%)
MESSAGE_COUNT = 200
PAYLOAD_SIZE = 128
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

# 服务器端口
BASELINE_PORT = 9001
SOCKET_TIMEOUT = 30.0


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = f"weaknet-{seq}-"
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def enable_tcp_nodelay(sock: socket.socket):
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


def open_tcp(port: int = BASELINE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


@dataclass
class NetworkCondition:
    """网络条件配置"""
    loss_rate: float = 0.0  # 丢包率 (%)
    delay_ms: float = 0.0  # 延迟 (ms)
    reorder_rate: float = 0.0  # 乱序率 (%)
    
    def should_drop(self) -> bool:
        """是否应该丢包"""
        return random.random() * 100 < self.loss_rate
    
    def get_delay(self) -> float:
        """获取延迟（秒）"""
        if self.delay_ms <= 0:
            return 0
        # 添加随机抖动 (±20%)
        jitter = self.delay_ms * 0.2
        actual_delay = self.delay_ms + random.uniform(-jitter, jitter)
        return max(0, actual_delay) / 1000.0
    
    def should_reorder(self) -> bool:
        """是否应该乱序"""
        return random.random() * 100 < self.reorder_rate


def simulate_send_with_conditions(
    sock: socket.socket,
    file_obj,
    packet: Dict[str, Any],
    condition: NetworkCondition,
) -> Tuple[bool, Dict[str, Any], float]:
    """
    模拟弱网条件下的发送
    
    返回：
    - success: 是否成功
    - response: 服务器响应
    - rtt_ms: 往返时间
    """
    start_time = time.time()
    
    # 模拟丢包
    if condition.should_drop():
        # 直接标记丢包，不等待超时
        return False, {"ok": False, "reason": "simulated packet loss"}, condition.delay_ms + 5
    
    # 模拟延迟
    delay = condition.get_delay()
    if delay > 0:
        time.sleep(delay)
    
    # 模拟乱序（通过延迟发送来模拟）
    if condition.should_reorder():
        reorder_delay = random.uniform(0.01, 0.1)
        time.sleep(reorder_delay)
    
    # 发送数据包
    send_json_line(sock, packet)
    
    # 接收响应
    try:
        response = recv_json_line(file_obj)
        rtt_ms = (time.time() - start_time) * 1000
        return True, response, rtt_ms
    except socket.timeout:
        rtt_ms = (time.time() - start_time) * 1000
        return False, {"ok": False, "reason": "timeout"}, rtt_ms
    except Exception as e:
        rtt_ms = (time.time() - start_time) * 1000
        return False, {"ok": False, "reason": str(e)}, rtt_ms


def run_one_weak_network_experiment(
    protocol: str,
    loss_rate: float,
    delay_ms: float,
    reorder_rate: float,
    message_count: int,
    payload_size: int,
    repeat_id: int,
) -> Dict[str, Any]:
    """运行单个弱网实验"""
    
    session_id = (
        f"weaknet-{protocol}-l{loss_rate}-d{delay_ms}-r{reorder_rate}-"
        f"m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )
    
    condition = NetworkCondition(
        loss_rate=loss_rate,
        delay_ms=delay_ms,
        reorder_rate=reorder_rate,
    )
    
    # 根据协议类型导入不同的构建函数
    if protocol == "hash_chain":
        from gmcp.baselines.hash_chain import (
            create_initial_state as hc_init,
            build_data_packet as hc_build,
        )
        hc_state = hc_init(session_id, CLIENT_ID, EPOCH)
        state = {"last_seq": 0, "last_mem": hc_state.last_hash, "_hc_state": hc_state}
        build_fn = hc_build
    elif protocol == "seq_mac":
        from gmcp.baselines.seq_mac import (
            create_initial_state as sm_init,
            build_data_packet as sm_build,
        )
        sm_state = sm_init(session_id, CLIENT_ID, EPOCH)
        state = {"last_seq": 0, "last_mem": "", "_sm_state": sm_state}
        build_fn = sm_build
    else:  # gmcp_r
        initial_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
        state = {"last_seq": 0, "last_mem": initial_mem}
        build_fn = None  # 使用默认的gmcp_r构建
    
    sent_count = 0
    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    dropped_count = 0
    rtt_list = []
    
    start_time = time.time()
    
    sock = None
    file_obj = None
    
    # 重传配置
    MAX_RETRIES = 3
    RETRY_DELAY = 0.1  # 100ms
    
    try:
        sock, file_obj = open_tcp()
        
        seq = 1
        while seq <= message_count:
            payload = make_payload(seq, payload_size)
            
            # 根据协议类型构建数据包
            if protocol == "hash_chain":
                packet = build_fn(
                    session_id=session_id,
                    sender_id=CLIENT_ID,
                    epoch=EPOCH,
                    seq=seq,
                    prev_hash=state["last_mem"],
                    payload=payload,
                )
                packet["protocol"] = protocol
            elif protocol == "seq_mac":
                packet = build_fn(
                    session_id=session_id,
                    sender_id=CLIENT_ID,
                    epoch=EPOCH,
                    seq=seq,
                    payload=payload,
                )
                packet["protocol"] = protocol
            else:  # gmcp_r
                packet = build_data_packet(
                    session_id=session_id,
                    sender_id=CLIENT_ID,
                    epoch=EPOCH,
                    seq=seq,
                    prev_mem=state["last_mem"],
                    payload=payload,
                )
                packet["protocol"] = protocol
            # 重新计算auth_tag以包含protocol字段
            from gmcp.packet import packet_without_auth
            data_for_auth = packet_without_auth(packet)
            data_for_auth["protocol"] = protocol
            packet["auth_tag"] = hmac_sha256_hex(DATA_AUTH_KEY, data_for_auth)
            
            # 带重传的发送
            retry_count = 0
            message_accepted = False
            
            while retry_count <= MAX_RETRIES and not message_accepted:
                # 模拟弱网条件发送
                success, response, rtt_ms = simulate_send_with_conditions(
                    sock, file_obj, packet, condition
                )
                
                sent_count += 1
                rtt_list.append(rtt_ms)
                
                if success:
                    if response.get("ok"):
                        accepted_count += 1
                        state["last_seq"] = int(response.get("last_seq", state["last_seq"]))
                        state["last_mem"] = response.get("last_mem", state["last_mem"])
                        message_accepted = True
                        # 成功后继续下一条消息
                        seq += 1
                    else:
                        rejected_count += 1
                        reason = response.get("reason", "unknown")
                        if "timeout" in reason.lower():
                            timeout_count += 1
                        
                        # 如果是seq gap或认证失败，尝试重传
                        if retry_count < MAX_RETRIES and (
                            "gap" in reason.lower() or 
                            "mismatch" in reason.lower() or
                            "replay" in reason.lower()
                        ):
                            retry_count += 1
                            time.sleep(RETRY_DELAY)
                        else:
                            # 无法恢复，跳到下一条
                            message_accepted = True
                            seq += 1
                else:
                    dropped_count += 1
                    if "timeout" in response.get("reason", "").lower():
                        timeout_count += 1
                    
                    # 丢包后尝试重传
                    if retry_count < MAX_RETRIES:
                        retry_count += 1
                        time.sleep(RETRY_DELAY)
                    else:
                        # 重试耗尽，跳到下一条
                        message_accepted = True
                        seq += 1
    
    except Exception as e:
        print(f"[ERROR] {e}")
    
    finally:
        close_tcp(sock, file_obj)
    
    elapsed = time.time() - start_time
    
    # 计算统计指标
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
        "reorder_rate": reorder_rate,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "dropped_count": dropped_count,
        "success_rate": round(success_rate, 2),
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
    tracker = ExperimentTracker("weak_network_simulation")
    
    fieldnames = [
        "session_id", "protocol", "loss_rate", "delay_ms", "reorder_rate",
        "message_count", "payload_size", "repeat_id", "sent_count", "accepted_count",
        "rejected_count", "timeout_count", "dropped_count", "success_rate",
        "throughput_msg_per_sec", "rtt_mean_ms", "rtt_std_ms", "rtt_min_ms",
        "rtt_max_ms", "rtt_median_ms", "elapsed_seconds",
    ]
    
    total_experiments = len(PROTOCOLS) * len(LOSS_RATES) * len(DELAY_MS) * len(REPEATS)
    completed = 0
    
    for protocol in PROTOCOLS:
        for loss_rate in LOSS_RATES:
            for delay_ms in DELAY_MS:
                for repeat_id in REPEATS:
                    completed += 1
                    print(f"\n[{completed}/{total_experiments}] "
                          f"protocol={protocol}, loss={loss_rate}%, delay={delay_ms}ms, "
                          f"repeat={repeat_id}")
                    
                    result = run_one_weak_network_experiment(
                        protocol=protocol,
                        loss_rate=loss_rate,
                        delay_ms=delay_ms,
                        reorder_rate=0,  # 简化：只测试丢包和延迟
                        message_count=MESSAGE_COUNT,
                        payload_size=PAYLOAD_SIZE,
                        repeat_id=repeat_id,
                    )
                    
                    # 添加到跟踪器
                    tracker.add_result(result)
                    
                    # 打印结果摘要
                    status = "✅" if result["success_rate"] > 80 else "⚠️" if result["success_rate"] > 50 else "❌"
                    print(f"  {status} success={result['success_rate']}%, "
                          f"throughput={result['throughput_msg_per_sec']} msg/s, "
                          f"rtt={result['rtt_mean_ms']}ms")
    
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
