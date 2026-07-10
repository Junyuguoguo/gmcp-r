# -*- coding: utf-8 -*-
# run_performance_benchmark.py
#
# GMCP-R 性能基准测试
# ─────────────────────────────────────────
# 测试维度：
#   1. 吞吐量（不同消息大小、窗口大小）
#   2. 延迟分布（RTT: p50/p95/p99）
#   3. 资源消耗（CPU、内存、带宽）
#
# 运行模式：
#   --mode local    纯本地计算基准（无需服务器，测量协议开销）
#   --mode network  端到端网络基准（需要 real_baseline_server 运行在 9001 端口）
#
# 用法：
#   .venv/bin/python run_performance_benchmark.py --mode local
#   .venv/bin/python run_performance_benchmark.py --mode network
#   .venv/bin/python run_performance_benchmark.py --mode both

import argparse
import csv
import json
import os
import socket
import sys
import time
from typing import Dict, Any, List, Optional, Tuple

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import (
    SERVER_TARGET_HOST,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet as gmcp_build_data_packet
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.experiment_stats import (
    ExperimentTracker,
    collect_experiment_metadata,
    calculate_statistics,
)
from monitor_resources import ResourceMonitor

# Baseline protocols
from gmcp.baselines.hash_chain import (
    create_initial_state as hash_chain_create_state,
    build_data_packet as hash_chain_build_packet,
    HashChainVerifier,
)
from gmcp.baselines.seq_mac import (
    create_initial_state as seq_mac_create_state,
    build_data_packet as seq_mac_build_packet,
    SeqMACVerifier,
)
from gmcp.baselines.ticket_only import (
    create_initial_state as ticket_only_create_state,
    build_data_packet as ticket_only_build_packet,
    TicketOnlyVerifier,
    issue_ticket,
)

# ─────────────────────────────────────────
# 常量
# ─────────────────────────────────────────

OUTPUT_DIR = "results/performance"
RESULTS_CSV = os.path.join(OUTPUT_DIR, "performance_benchmark_results.csv")
RESOURCE_JSON = os.path.join(OUTPUT_DIR, "resource_stats.json")
RTT_CSV = os.path.join(OUTPUT_DIR, "rtt_distribution.csv")
METADATA_JSON = os.path.join(OUTPUT_DIR, "benchmark_metadata.json")

PROTOCOLS = ["gmcp_r", "hash_chain", "seq_mac", "ticket_only"]

# 基准参数
MESSAGE_SIZES = [64, 128, 256, 512, 1024]
WINDOW_SIZES = [1, 10, 50, 100]  # 窗口大小（本地模式下无实际意义，用于 network 模式）
MSG_COUNTS = [500, 1000]         # 每轮消息数
REPEATS = int(os.getenv("GMCP_BENCH_REPEATS", "3"))

BASELINE_PORT = 9001
SOCKET_TIMEOUT = 10.0


# ─────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    """构造固定大小的 payload"""
    prefix = f"bench-{seq}-"
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def calc_percentiles(values: List[float]) -> Dict[str, float]:
    """计算百分位数"""
    if not values:
        return {"p50": 0, "p90": 0, "p95": 0, "p99": 0, "p999": 0}
    arr = np.array(values)
    return {
        "p50": round(float(np.percentile(arr, 50)), 4),
        "p90": round(float(np.percentile(arr, 90)), 4),
        "p95": round(float(np.percentile(arr, 95)), 4),
        "p99": round(float(np.percentile(arr, 99)), 4),
        "p999": round(float(np.percentile(arr, 99.9)), 4),
    }


# ─────────────────────────────────────────
# 协议工厂
# ─────────────────────────────────────────

def create_state(protocol: str, session_id: str, sender_id: str, epoch: int):
    if protocol == "gmcp_r":
        m0 = initial_memory(session_id, sender_id, epoch, "bench-seed")
        return GMCPState(session_id=session_id, sender_id=sender_id,
                         epoch=epoch, last_seq=0, last_mem=m0)
    elif protocol == "hash_chain":
        return hash_chain_create_state(session_id, sender_id, epoch)
    elif protocol == "seq_mac":
        return seq_mac_create_state(session_id, sender_id, epoch)
    elif protocol == "ticket_only":
        return ticket_only_create_state(session_id, sender_id, epoch)
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def create_verifier(protocol: str, state):  # type: ignore[type-arg]
    if protocol == "gmcp_r":
        return GMCPVerifier(state)
    elif protocol == "hash_chain":
        return HashChainVerifier(state)
    elif protocol == "seq_mac":
        return SeqMACVerifier(state)
    elif protocol == "ticket_only":
        return TicketOnlyVerifier(state)  # type: ignore[arg-type]
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def build_packet(protocol: str, session_id: str, sender_id: str,
                 epoch: int, seq: int, payload: str, state) -> Dict[str, Any]:
    if protocol == "gmcp_r":
        return gmcp_build_data_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, prev_mem=state.last_mem, payload=payload,
        )
    elif protocol == "hash_chain":
        return hash_chain_build_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, prev_hash=state.last_hash, payload=payload,
        )
    elif protocol == "seq_mac":
        return seq_mac_build_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, payload=payload,
        )
    elif protocol == "ticket_only":
        return ticket_only_build_packet(
            session_id=session_id, sender_id=sender_id, epoch=epoch,
            seq=seq, payload=payload, ticket=state.ticket,
        )
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def update_state_after_accept(protocol: str, state, seq: int, packet: Dict, response: Dict):
    """服务端验证通过后更新客户端状态"""
    if protocol == "gmcp_r":
        state.last_seq = int(response.get("last_seq", seq))
        state.last_mem = response.get("last_mem", state.last_mem)
    elif protocol == "hash_chain":
        state.last_seq = seq
        state.last_hash = packet.get("chain_hash", state.last_hash)
    else:
        state.last_seq = seq


# ─────────────────────────────────────────
# 本地基准（纯计算开销）
# ─────────────────────────────────────────

def run_local_benchmark_single(protocol: str, msg_count: int,
                                payload_size: int) -> Dict[str, Any]:
    """
    本地基准：构建 + 验证 N 条消息，测量纯计算开销
    """
    session_id = f"bench-local-{protocol}-{payload_size}-{int(time.time()*1e6)}"
    state = create_state(protocol, session_id, CLIENT_ID, EPOCH)
    verifier = create_verifier(protocol, state)

    # 预热
    for i in range(5):
        payload = make_payload(i, payload_size)
        pkt = build_packet(protocol, session_id, CLIENT_ID, EPOCH, i + 1, payload, state)
        ok, reason = verifier.verify_data_packet(pkt)

    # 正式测量
    build_times: List[float] = []
    verify_times: List[float] = []
    end_to_end_times: List[float] = []

    # 重置状态
    state = create_state(protocol, session_id, CLIENT_ID, EPOCH)
    verifier = create_verifier(protocol, state)

    wall_start = time.perf_counter()

    for seq in range(1, msg_count + 1):
        payload = make_payload(seq, payload_size)

        t0 = time.perf_counter()
        pkt = build_packet(protocol, session_id, CLIENT_ID, EPOCH, seq, payload, state)
        t1 = time.perf_counter()

        ok, reason = verifier.verify_data_packet(pkt)
        t2 = time.perf_counter()

        build_times.append((t1 - t0) * 1e6)   # 微秒
        verify_times.append((t2 - t1) * 1e6)   # 微秒
        end_to_end_times.append((t2 - t0) * 1e6)  # 微秒

        if ok:
            resp: Dict[str, Any] = {"last_seq": seq}
            last_mem = getattr(state, "last_mem", None)
            if last_mem is not None:
                resp["last_mem"] = last_mem
            update_state_after_accept(protocol, state, seq, pkt, resp)

    wall_elapsed = time.perf_counter() - wall_start

    build_stats = calc_percentiles(build_times)
    verify_stats = calc_percentiles(verify_times)
    e2e_stats = calc_percentiles(end_to_end_times)
    build_agg = calculate_statistics(build_times)
    verify_agg = calculate_statistics(verify_times)
    e2e_agg = calculate_statistics(end_to_end_times)

    return {
        "mode": "local",
        "protocol": protocol,
        "msg_count": msg_count,
        "payload_size": payload_size,
        "wall_time_sec": round(wall_elapsed, 4),
        "throughput_msg_per_sec": round(msg_count / wall_elapsed, 2) if wall_elapsed > 0 else 0,
        # 构建耗时 (μs)
        "build_mean_us": round(build_agg["mean"], 2),
        "build_std_us": round(build_agg["std"], 2),
        "build_p50_us": build_stats["p50"],
        "build_p95_us": build_stats["p95"],
        "build_p99_us": build_stats["p99"],
        # 验证耗时 (μs)
        "verify_mean_us": round(verify_agg["mean"], 2),
        "verify_std_us": round(verify_agg["std"], 2),
        "verify_p50_us": verify_stats["p50"],
        "verify_p95_us": verify_stats["p95"],
        "verify_p99_us": verify_stats["p99"],
        # 端到端耗时 (μs)
        "e2e_mean_us": round(e2e_agg["mean"], 2),
        "e2e_std_us": round(e2e_agg["std"], 2),
        "e2e_p50_us": e2e_stats["p50"],
        "e2e_p95_us": e2e_stats["p95"],
        "e2e_p99_us": e2e_stats["p99"],
    }


def run_local_benchmarks(repeats: int = REPEATS,
                         msg_counts: Optional[List[int]] = None,
                         msg_sizes: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """运行全部本地基准测试"""
    if msg_counts is None:
        msg_counts = MSG_COUNTS
    if msg_sizes is None:
        msg_sizes = MESSAGE_SIZES
    results = []
    total = len(PROTOCOLS) * len(msg_sizes) * len(msg_counts) * repeats
    idx = 0

    for protocol in PROTOCOLS:
        for payload_size in msg_sizes:
            for msg_count in msg_counts:
                for rep in range(1, repeats + 1):
                    idx += 1
                    print(f"\n[LOCAL {idx}/{total}] {protocol} | "
                          f"size={payload_size} | count={msg_count} | rep={rep}")
                    result = run_local_benchmark_single(protocol, msg_count, payload_size)
                    result["repeat_id"] = rep
                    results.append(result)

                    status = "✅"
                    print(f"  {status} throughput={result['throughput_msg_per_sec']} msg/s | "
                          f"e2e_p50={result['e2e_p50_us']}μs | "
                          f"e2e_p99={result['e2e_p99_us']}μs")

    return results


# ─────────────────────────────────────────
# 网络基准（端到端 RTT）
# ─────────────────────────────────────────

def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def recv_json_line(file_obj):
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def open_tcp(port: int = BASELINE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
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


def run_network_benchmark_single(protocol: str, msg_count: int,
                                  payload_size: int,
                                  window_size: int = 1) -> Dict[str, Any]:
    """
    网络基准：通过 TCP 发送消息到 baseline 服务器，测量 RTT
    """
    session_id = f"bench-net-{protocol}-{payload_size}-w{window_size}-{int(time.time()*1e6)}"
    state = create_state(protocol, session_id, CLIENT_ID, EPOCH)

    rtt_list: List[float] = []
    accepted = 0
    rejected = 0
    errors = 0

    sock = None
    file_obj = None
    wall_start = time.perf_counter()

    try:
        sock, file_obj = open_tcp()

        for seq in range(1, msg_count + 1):
            payload = make_payload(seq, payload_size)
            pkt = build_packet(protocol, session_id, CLIENT_ID, EPOCH,
                               seq, payload, state)

            t0 = time.perf_counter()
            send_json_line(sock, pkt)

            try:
                response = recv_json_line(file_obj)
                t1 = time.perf_counter()

                rtt_ms = (t1 - t0) * 1000
                rtt_list.append(rtt_ms)

                if response.get("ok"):
                    accepted += 1
                    update_state_after_accept(protocol, state, seq, pkt, response)
                else:
                    rejected += 1

            except socket.timeout:
                errors += 1
            except Exception as e:
                errors += 1

    except Exception as e:
        print(f"  [ERROR] {e}")
    finally:
        close_tcp(sock, file_obj)

    wall_elapsed = time.perf_counter() - wall_start
    rtt_stats = calc_percentiles(rtt_list)
    rtt_agg = calculate_statistics(rtt_list)

    return {
        "mode": "network",
        "protocol": protocol,
        "msg_count": msg_count,
        "payload_size": payload_size,
        "window_size": window_size,
        "accepted": accepted,
        "rejected": rejected,
        "errors": errors,
        "wall_time_sec": round(wall_elapsed, 4),
        "throughput_msg_per_sec": round(accepted / wall_elapsed, 2) if wall_elapsed > 0 else 0,
        # RTT (ms)
        "rtt_mean_ms": round(rtt_agg["mean"], 4),
        "rtt_std_ms": round(rtt_agg["std"], 4),
        "rtt_min_ms": round(rtt_agg["min"], 4),
        "rtt_max_ms": round(rtt_agg["max"], 4),
        "rtt_p50_ms": rtt_stats["p50"],
        "rtt_p90_ms": rtt_stats["p90"],
        "rtt_p95_ms": rtt_stats["p95"],
        "rtt_p99_ms": rtt_stats["p99"],
        "rtt_p999_ms": rtt_stats["p999"],
        "rtt_raw": rtt_list,  # 保存原始数据供绘图
    }


def run_network_benchmarks(repeats: int = REPEATS,
                           msg_sizes: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """运行全部网络基准测试"""
    if msg_sizes is None:
        msg_sizes = [128, 512, 1024]
    results = []
    # 网络模式下只测 500 条消息，减少耗时
    net_msg_counts = [500]
    # 窗口大小在当前串行 send-recv 模型下均为 1
    # 保留参数供将来扩展

    total = len(PROTOCOLS) * len(msg_sizes) * len(net_msg_counts) * repeats
    idx = 0

    for protocol in PROTOCOLS:
        for payload_size in msg_sizes:
            for msg_count in net_msg_counts:
                for rep in range(1, repeats + 1):
                    idx += 1
                    print(f"\n[NET  {idx}/{total}] {protocol} | "
                          f"size={payload_size} | count={msg_count} | rep={rep}")
                    result = run_network_benchmark_single(
                        protocol, msg_count, payload_size, window_size=1
                    )
                    result["repeat_id"] = rep

                    # 提取 rtt_raw 单独保存
                    rtt_raw = result.pop("rtt_raw", [])
                    results.append(result)

                    # 保存 RTT 分布到单独 CSV
                    _save_rtt_distribution(protocol, payload_size, rep, rtt_raw)

                    status = "✅" if result["accepted"] > 0 else "❌"
                    print(f"  {status} throughput={result['throughput_msg_per_sec']} msg/s | "
                          f"rtt_p50={result['rtt_p50_ms']}ms | "
                          f"rtt_p99={result['rtt_p99_ms']}ms")

    return results


def _save_rtt_distribution(protocol: str, payload_size: int,
                           repeat_id: int, rtt_list: List[float]):
    """追加保存 RTT 原始分布数据"""
    if not rtt_list:
        return

    file_exists = os.path.exists(RTT_CSV)
    with open(RTT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["protocol", "payload_size", "repeat_id", "seq", "rtt_ms"])
        for i, rtt in enumerate(rtt_list, 1):
            writer.writerow([protocol, payload_size, repeat_id, i, round(rtt, 4)])


# ─────────────────────────────────────────
# 结果保存
# ─────────────────────────────────────────

def save_results(results: List[Dict[str, Any]], fieldnames: List[str]):
    """保存基准测试结果到 CSV"""
    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"\n[SAVED] {len(results)} results → {RESULTS_CSV}")


def save_metadata(metadata: Dict[str, Any]):
    """保存实验元数据"""
    with open(METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False, default=str)
    print(f"[SAVED] metadata → {METADATA_JSON}")


# ─────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GMCP-R 性能基准测试")
    parser.add_argument("--mode", choices=["local", "network", "both"],
                        default="local", help="运行模式")
    parser.add_argument("--repeats", type=int, default=REPEATS,
                        help="每组重复次数")
    parser.add_argument("--msg-counts", type=int, nargs="+", default=MSG_COUNTS,
                        help="消息数量列表")
    parser.add_argument("--msg-sizes", type=int, nargs="+", default=MESSAGE_SIZES,
                        help="消息大小列表 (bytes)")
    args = parser.parse_args()

    repeats = args.repeats
    msg_counts = args.msg_counts
    msg_sizes = args.msg_sizes

    ensure_output_dir()

    # 清空旧的 RTT CSV
    if os.path.exists(RTT_CSV):
        os.remove(RTT_CSV)

    metadata = collect_experiment_metadata()
    metadata["experiment_type"] = "performance_benchmark"
    metadata["mode"] = args.mode
    metadata["protocols"] = PROTOCOLS
    metadata["msg_counts"] = msg_counts
    metadata["msg_sizes"] = msg_sizes
    metadata["repeats"] = repeats

    monitor = ResourceMonitor(interval=0.5)
    monitor.start()

    all_results: List[Dict[str, Any]] = []

    # ── 本地基准 ──
    if args.mode in ("local", "both"):
        print("\n" + "=" * 60)
        print("  LOCAL BENCHMARK (pure computation)")
        print("=" * 60)
        local_results = run_local_benchmarks(repeats=repeats, msg_counts=msg_counts, msg_sizes=msg_sizes)
        all_results.extend(local_results)

    # ── 网络基准 ──
    if args.mode in ("network", "both"):
        print("\n" + "=" * 60)
        print("  NETWORK BENCHMARK (end-to-end RTT)")
        print("=" * 60)
        network_results = run_network_benchmarks(repeats=repeats, msg_sizes=msg_sizes)
        all_results.extend(network_results)

    monitor.stop()
    resource_stats = monitor.get_stats()

    # 保存资源统计
    with open(RESOURCE_JSON, "w", encoding="utf-8") as f:
        json.dump(resource_stats, f, indent=2, ensure_ascii=False)
    print(f"[SAVED] resource stats → {RESOURCE_JSON}")

    # 确定 CSV 字段
    if all_results:
        # 取所有 key 的并集（排除 rtt_raw 等非标量字段）
        exclude_keys = {"rtt_raw"}
        fieldnames = []
        seen = set()
        for row in all_results:
            for k in row:
                if k not in seen and k not in exclude_keys:
                    fieldnames.append(k)
                    seen.add(k)
        save_results(all_results, fieldnames)

    metadata["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    metadata["total_results"] = len(all_results)
    metadata["resource_stats"] = resource_stats
    save_metadata(metadata)

    # ── 摘要 ──
    print("\n" + "=" * 60)
    print("  BENCHMARK SUMMARY")
    print("=" * 60)

    if args.mode in ("local", "both"):
        print("\n  LOCAL MODE (build+verify latency):")
        print(f"  {'Protocol':<14} {'Size':>6} {'Count':>6} {'TP(msg/s)':>10} {'e2e_p50(μs)':>12} {'e2e_p99(μs)':>12}")
        print("  " + "-" * 64)
        for r in all_results:
            if r.get("mode") == "local" and r.get("repeat_id") == 1:
                print(f"  {r['protocol']:<14} {r['payload_size']:>6} {r['msg_count']:>6} "
                      f"{r['throughput_msg_per_sec']:>10.0f} {r['e2e_p50_us']:>12.1f} {r['e2e_p99_us']:>12.1f}")

    if args.mode in ("network", "both"):
        print("\n  NETWORK MODE (RTT over TCP):")
        print(f"  {'Protocol':<14} {'Size':>6} {'TP(msg/s)':>10} {'p50(ms)':>9} {'p95(ms)':>9} {'p99(ms)':>9}")
        print("  " + "-" * 62)
        for r in all_results:
            if r.get("mode") == "network" and r.get("repeat_id") == 1:
                print(f"  {r['protocol']:<14} {r['payload_size']:>6} "
                      f"{r['throughput_msg_per_sec']:>10.1f} "
                      f"{r['rtt_p50_ms']:>9.3f} {r['rtt_p95_ms']:>9.3f} {r['rtt_p99_ms']:>9.3f}")

    print(f"\n  Resource usage during benchmark:")
    print(f"    CPU  avg={resource_stats.get('proc_cpu_pct_mean', 0):.1f}%  "
          f"max={resource_stats.get('proc_cpu_pct_max', 0):.1f}%")
    print(f"    RSS  avg={resource_stats.get('rss_mb_mean', 0):.1f}MB  "
          f"max={resource_stats.get('rss_mb_max', 0):.1f}MB")
    print(f"    Net  sent={resource_stats.get('total_mb_sent', 0):.2f}MB  "
          f"recv={resource_stats.get('total_mb_recv', 0):.2f}MB")
    print(f"\n  Results saved to: {OUTPUT_DIR}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
