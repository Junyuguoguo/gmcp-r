# -*- coding: utf-8 -*-
# run_concurrent_experiment.py
#
# 多客户端并发测试实验
# 支持 1, 2, 5, 10, 20 个并发客户端
# 使用线程池管理并发，收集每个客户端的独立指标
# Lock strategy dimension: per_session_lock / global_lock

import csv
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field
from threading import Lock, Barrier, BrokenBarrierError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import (
    SERVER_TARGET_HOST,
    CLIENT_ID,
    EPOCH,
)
from gmcp.crypto_utils import hmac_sha256_hex
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet
from gmcp.protocol import GMCPState
from gmcp.experiment_stats import (
    ExperimentTracker,
    collect_experiment_metadata,
    calculate_statistics,
    format_statistics_for_csv,
)

# =========================
# 实验参数
# =========================

CONCURRENCY_LEVELS = [1, 2, 5, 10, 20]
MESSAGES_PER_CLIENT = 200
PAYLOAD_SIZE = 128
REPEAT_COUNT = int(os.getenv("GMCP_REPEATS", "30"))
REPEATS = list(range(1, REPEAT_COUNT + 1))

# Two lock strategies to compare
LOCK_STRATEGIES = ["per_session_lock", "global_lock"]

BASELINE_PORT = int(os.getenv("GMCP_PORT", "9000"))
SOCKET_TIMEOUT = 30.0
WARMUP_MESSAGES = 5
COOL_BETWEEN_TESTS_SEC = 1.0

OUTPUT_DIR = os.getenv("GMCP_OUTPUT_ROOT", "results/concurrent")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "concurrent_results.csv")
DETAIL_CSV = os.path.join(OUTPUT_DIR, "concurrent_detail.csv")

_print_lock = Lock()


# =========================
# 工具函数
# =========================

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = f"conc-{seq}-"
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def recv_json_line(file_obj):
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def enable_tcp_nodelay(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def open_tcp(port: int = BASELINE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


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


# =========================
# 单客户端工作线程
# =========================

@dataclass
class ClientResult:
    """单个客户端的实验结果"""
    client_id: str
    sent_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    timeout_count: int = 0
    error_count: int = 0
    rtt_list: List[float] = field(default_factory=list)
    elapsed: float = 0.0
    success: bool = True
    error_msg: str = ""


def run_single_client(
    client_id: str,
    session_id: str,
    message_count: int,
    payload_size: int,
    session_lock: Lock,
) -> ClientResult:
    """单个客户端的工作函数，在线程池中执行"""
    result = ClientResult(client_id=client_id)
    state = None
    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp()

        # 创建 GMCP 状态
        initial_mem = initial_memory(session_id, client_id, EPOCH, "demo-seed")
        state = GMCPState(
            session_id=session_id,
            sender_id=client_id,
            epoch=EPOCH,
            last_seq=0,
            last_mem=initial_mem,
        )

        start_time = time.time()

        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = build_data_packet(
                session_id=session_id,
                sender_id=client_id,
                epoch=EPOCH,
                seq=seq,
                prev_mem=state.last_mem,
                payload=payload,
                protocol="gmcp_r",
            )

            send_start = time.time()
            try:
                # Acquire lock before sending/receiving to serialize access
                with session_lock:
                    send_json_line(sock, packet)
                    result.sent_count += 1
            except Exception as e:
                result.error_count += 1
                continue
            try:
                with session_lock:
                    response = recv_json_line(file_obj)
                send_end = time.time()
                rtt_ms = (send_end - send_start) * 1000
                result.rtt_list.append(rtt_ms)

                if response.get("ok"):
                    result.accepted_count += 1
                    state.last_seq = int(response.get("last_seq", state.last_seq))
                    state.last_mem = response.get("last_mem", state.last_mem)
                else:
                    result.rejected_count += 1
            except socket.timeout:
                result.timeout_count += 1
            except Exception as e:
                result.error_count += 1

        result.elapsed = time.time() - start_time

    except Exception as e:
        result.success = False
        result.error_msg = str(e)
    finally:
        close_tcp(sock, file_obj)

    return result


def np_mean(values):
    """简单的均值计算，避免每次导入 numpy"""
    if not values:
        return 0.0
    return sum(values) / len(values)


# =========================
# 并发实验执行
# =========================

def run_concurrent_test(
    concurrency: int,
    message_count: int,
    payload_size: int,
    repeat_id: int,
    lock_strategy: str = "per_session_lock",
) -> Tuple[Dict[str, Any], List[ClientResult]]:
    """
    运行一次并发测试
    启动 concurrency 个客户端同时向服务器发送消息

    lock_strategy:
      - "per_session_lock": each client gets its own Lock
      - "global_lock": all clients share one Lock
    """
    base_session = f"conc-c{concurrency}-r{repeat_id}-{lock_strategy}-{int(time.time() * 1000000)}"

    # 使用 barrier 确保所有线程同时开始
    barrier = Barrier(concurrency + 1)  # +1 for main thread

    # Create locks based on strategy
    global_lock = Lock()
    per_session_locks = {i: Lock() for i in range(concurrency)}

    results: List[ClientResult] = []

    def barrier_client(idx: int, cid: str, sid: str, msg_count: int, pay_size: int):
        """带屏障的客户端工作函数"""
        try:
            # 等待所有客户端就绪
            barrier.wait(timeout=30)
        except BrokenBarrierError:
            return ClientResult(client_id=cid, success=False, error_msg="barrier broken")

        # Select lock based on strategy
        if lock_strategy == "global_lock":
            lock = global_lock
        else:
            lock = per_session_locks[idx]

        return run_single_client(cid, sid, msg_count, pay_size, lock)

    test_start = time.time()

    with ThreadPoolExecutor(max_workers=concurrency + 2) as pool:
        futures = {}
        for i in range(concurrency):
            client_id = CLIENT_ID
            session_id = f"{base_session}-client-{i:03d}"
            fut = pool.submit(barrier_client, i, client_id, session_id, message_count, payload_size)
            futures[fut] = client_id

        # 主线程也需要在barrier上等待
        try:
            barrier.wait(timeout=30)
        except BrokenBarrierError:
            pass

        for fut in as_completed(futures):
            try:
                res = fut.result(timeout=SOCKET_TIMEOUT + 60)
                results.append(res)
            except Exception as e:
                cid = futures[fut]
                results.append(ClientResult(client_id=cid, success=False, error_msg=str(e)))

    test_elapsed = time.time() - test_start

    # 汇总
    total_sent = sum(r.sent_count for r in results)
    total_accepted = sum(r.accepted_count for r in results)
    total_rejected = sum(r.rejected_count for r in results)
    total_timeout = sum(r.timeout_count for r in results)
    total_error = sum(r.error_count for r in results)
    successful_clients = sum(1 for r in results if r.success)

    # 合并所有 RTT
    all_rtts = []
    for r in results:
        all_rtts.extend(r.rtt_list)

    rtt_stats = calculate_statistics(all_rtts) if all_rtts else {
        "mean": 0, "std": 0, "ci_95": 0, "min": 0, "max": 0, "median": 0, "n": 0,
    }

    # 每客户端的 RTT 均值
    per_client_rtts = [np_mean(r.rtt_list) for r in results if r.rtt_list]
    per_client_throughput = [
        r.accepted_count / r.elapsed if r.elapsed > 0 else 0
        for r in results if r.success
    ]

    per_client_rtt_stats = calculate_statistics(per_client_rtts) if per_client_rtts else {
        "mean": 0, "std": 0, "ci_95": 0, "min": 0, "max": 0, "median": 0, "n": 0,
    }
    per_client_tp_stats = calculate_statistics(per_client_throughput) if per_client_throughput else {
        "mean": 0, "std": 0, "ci_95": 0, "min": 0, "max": 0, "median": 0, "n": 0,
    }

    overall_success_rate = total_accepted / total_sent * 100 if total_sent > 0 else 0
    overall_throughput = total_accepted / test_elapsed if test_elapsed > 0 else 0

    summary = {
        "lock_strategy": lock_strategy,
        "concurrency": concurrency,
        "repeat_id": repeat_id,
        "message_count_per_client": message_count,
        "payload_size": payload_size,
        "total_sent": total_sent,
        "total_accepted": total_accepted,
        "total_rejected": total_rejected,
        "total_timeout": total_timeout,
        "total_error": total_error,
        "successful_clients": successful_clients,
        "success_rate_pct": round(overall_success_rate, 2),
        "overall_throughput_msg_per_sec": round(overall_throughput, 2),
        "test_elapsed_sec": round(test_elapsed, 2),
        # 全局 RTT（所有客户端所有消息合并）
        "rtt_mean_ms": round(rtt_stats["mean"], 3),
        "rtt_std_ms": round(rtt_stats["std"], 3),
        "rtt_ci95_ms": round(rtt_stats["ci_95"], 3),
        "rtt_min_ms": round(rtt_stats["min"], 3),
        "rtt_max_ms": round(rtt_stats["max"], 3),
        "rtt_median_ms": round(rtt_stats["median"], 3),
        "rtt_n": rtt_stats["n"],
        # 每客户端 RTT 均值的统计（反映客户端间差异）
        "per_client_rtt_mean_ms": round(per_client_rtt_stats["mean"], 3),
        "per_client_rtt_std_ms": round(per_client_rtt_stats["std"], 3),
        "per_client_rtt_ci95_ms": round(per_client_rtt_stats["ci_95"], 3),
        # 每客户端吞吐量的统计
        "per_client_tp_mean_msg_per_sec": round(per_client_tp_stats["mean"], 2),
        "per_client_tp_std_msg_per_sec": round(per_client_tp_stats["std"], 2),
        "per_client_tp_ci95_msg_per_sec": round(per_client_tp_stats["ci_95"], 2),
    }

    return summary, results


# =========================
# 主实验流程
# =========================

def run_all_experiments():
    ensure_output_dir()

    tracker = ExperimentTracker("concurrent_clients")

    summary_fieldnames = [
        "lock_strategy", "concurrency", "repeat_id",
        "message_count_per_client", "payload_size",
        "total_sent", "total_accepted", "total_rejected", "total_timeout",
        "total_error", "successful_clients", "success_rate_pct",
        "overall_throughput_msg_per_sec", "test_elapsed_sec",
        "rtt_mean_ms", "rtt_std_ms", "rtt_ci95_ms", "rtt_min_ms", "rtt_max_ms",
        "rtt_median_ms", "rtt_n",
        "per_client_rtt_mean_ms", "per_client_rtt_std_ms", "per_client_rtt_ci95_ms",
        "per_client_tp_mean_msg_per_sec", "per_client_tp_std_msg_per_sec",
        "per_client_tp_ci95_msg_per_sec",
    ]

    detail_fieldnames = [
        "lock_strategy", "concurrency", "repeat_id", "client_id",
        "sent_count", "accepted_count", "rejected_count", "timeout_count", "error_count",
        "rtt_mean_ms", "rtt_std_ms", "rtt_min_ms", "rtt_max_ms", "rtt_median_ms",
        "elapsed_sec", "throughput_msg_per_sec", "success", "error_msg",
    ]

    total_combos = len(LOCK_STRATEGIES) * len(CONCURRENCY_LEVELS) * len(REPEATS)
    completed = 0

    # 打开 detail CSV
    detail_file = open(DETAIL_CSV, "w", newline="", encoding="utf-8")
    detail_writer = csv.DictWriter(detail_file, fieldnames=detail_fieldnames, extrasaction="ignore")
    detail_writer.writeheader()

    for lock_strategy in LOCK_STRATEGIES:
        for concurrency in CONCURRENCY_LEVELS:
            for repeat_id in REPEATS:
                completed += 1
                print(
                    f"\n[{completed}/{total_combos}] "
                    f"lock={lock_strategy}, concurrency={concurrency}, "
                    f"repeat={repeat_id}/{REPEAT_COUNT}",
                    flush=True,
                )

                summary, client_results = run_concurrent_test(
                    concurrency=concurrency,
                    message_count=MESSAGES_PER_CLIENT,
                    payload_size=PAYLOAD_SIZE,
                    repeat_id=repeat_id,
                    lock_strategy=lock_strategy,
                )

                # 写入汇总
                tracker.add_result(summary)
                tracker.sample_performance()

                # 写入详细结果
                for cr in client_results:
                    cr_rtts = calculate_statistics(cr.rtt_list) if cr.rtt_list else {
                        "mean": 0, "std": 0, "min": 0, "max": 0, "median": 0,
                    }
                    detail_writer.writerow({
                        "lock_strategy": lock_strategy,
                        "concurrency": concurrency,
                        "repeat_id": repeat_id,
                        "client_id": cr.client_id,
                        "sent_count": cr.sent_count,
                        "accepted_count": cr.accepted_count,
                        "rejected_count": cr.rejected_count,
                        "timeout_count": cr.timeout_count,
                        "error_count": cr.error_count,
                        "rtt_mean_ms": round(cr_rtts["mean"], 3),
                        "rtt_std_ms": round(cr_rtts["std"], 3),
                        "rtt_min_ms": round(cr_rtts["min"], 3),
                        "rtt_max_ms": round(cr_rtts["max"], 3),
                        "rtt_median_ms": round(cr_rtts["median"], 3),
                        "elapsed_sec": round(cr.elapsed, 2),
                        "throughput_msg_per_sec": round(
                            cr.accepted_count / cr.elapsed if cr.elapsed > 0 else 0, 2
                        ),
                        "success": cr.success,
                        "error_msg": cr.error_msg,
                    })
                detail_file.flush()

                # 打印摘要
                status = "✅" if summary["success_rate_pct"] > 90 else "⚠️" if summary["success_rate_pct"] > 50 else "❌"
                with _print_lock:
                    print(
                        f"  {status} lock={lock_strategy}, "
                        f"clients={summary['successful_clients']}/{concurrency}, "
                        f"success={summary['success_rate_pct']}%, "
                        f"throughput={summary['overall_throughput_msg_per_sec']} msg/s, "
                        f"rtt={summary['rtt_mean_ms']}ms",
                        flush=True,
                    )

                # 冷却
                time.sleep(COOL_BETWEEN_TESTS_SEC)

    detail_file.close()

    # 保存汇总 CSV
    tracker.save_results_to_csv(OUTPUT_CSV, summary_fieldnames)

    final_stats = tracker.finish()
    print(f"\n{'=' * 60}")
    print(f"[COMPLETE] Summary saved to {OUTPUT_CSV}")
    print(f"[COMPLETE] Detail saved to {DETAIL_CSV}")
    print(f"[STATS] Total experiments: {final_stats['total_results']}")
    print(f"[STATS] Elapsed time: {final_stats['elapsed_seconds']}s")
    print(f"[CONFIG] Lock strategies: {LOCK_STRATEGIES}")
    print(f"[CONFIG] Concurrency levels: {CONCURRENCY_LEVELS}")
    print(f"[CONFIG] Messages per client: {MESSAGES_PER_CLIENT}")
    print(f"[CONFIG] Repeats per config: {REPEAT_COUNT}")


if __name__ == "__main__":
    run_all_experiments()
