#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tc/netem 弱网实验验证框架
==========================

使用 Linux tc/netem 工具模拟 6 种代表性网络条件，在本地或远程服务器上
运行 GMCP-R 协议对比实验。

矩阵：
  3 protocols × 6 conditions × 10 repeats = 180 rows

使用方法（需要 sudo 权限）：
  sudo python run_netem_validation.py --interface eth0
  sudo python run_netem_validation.py --interface eth0 --quick   # 1 repeat

关键设计：
  - 没有 sudo 权限时拒绝生成数据
  - 使用 trap 确保实验结束后清理 tc 规则（通过 context manager）
  - 6 个代表性条件覆盖从正常到极端恶劣的网络场景
"""

import csv
import json
import os
import socket
import subprocess
import sys
import time
import platform
from datetime import datetime
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# GMCP-R imports
# ---------------------------------------------------------------------------
from gmcp.config import (
    SERVER_BIND_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.checkpoint_manager import CheckpointManager
from gmcp.session_registry import SessionContext, SessionRegistry

# Baseline protocol builders
from gmcp.baselines.seq_mac import build_data_packet as seq_mac_build
from gmcp.baselines.seq_mac import SeqMACVerifier, create_initial_state as sm_init_state
from gmcp.baselines.hash_chain import build_data_packet as hc_build
from gmcp.baselines.authenticated_hash_chain import build_data_packet as ahc_build
from gmcp.baselines.authenticated_hash_chain import AuthHashChainVerifier, create_initial_state as ahc_init_state

from gmcp.experiment_stats import get_git_commit, get_python_version, get_os_info

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = "results/netem_validation"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "netem_validation_results.csv")

PROTOCOLS = ["gmcp_r", "seq_mac", "authenticated_hash_chain"]
REPEAT_COUNT = 10

SOCKET_TIMEOUT = 15.0
MESSAGE_COUNT = 500
PAYLOAD_SIZE = 128

# ---------------------------------------------------------------------------
# 6 Representative Network Conditions
# ---------------------------------------------------------------------------
# Each condition is (name, description, loss%, delay_ms, jitter_ms, reorder%)
NETEM_CONDITIONS: List[Tuple[str, str, int, int, int, int]] = [
    ("control",  "No impairment (baseline)",                        0,  0,   0,  0),
    ("mild",     "Light loss + moderate delay (good WiFi)",         1, 30,  10,  0),
    ("mobile",   "Mobile 4G-like (moderate loss + jitter)",         2, 60,  30,  5),
    ("poor",     "Poor connectivity (high loss + delay)",           5, 100, 50,  5),
    ("severe",   "Severe degradation (satellite-like)",            10, 200, 80, 10),
    ("loss_heavy","Heavy packet loss (congested network)",         20,  50, 20,  5),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_sudo_available() -> bool:
    """Check if we have passwordless sudo access."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def check_tc_available() -> bool:
    """Check if the tc command is available."""
    try:
        result = subprocess.run(
            ["tc", "-Version"],
            capture_output=True, timeout=5,
        )
        output = (result.stderr or b"") + (result.stdout or b"")
        return result.returncode == 0 or b"Utility" in output
    except FileNotFoundError:
        return False


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "netem-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def send_json_line(sock: socket.socket, packet: Dict[str, Any]):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def recv_json_line(file_obj) -> Dict[str, Any]:
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def enable_tcp_nodelay(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def open_tcp(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((host, port))
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


# ---------------------------------------------------------------------------
# tc/netem management
# ---------------------------------------------------------------------------

def setup_tc_netem(
    interface: str,
    loss: int,
    delay_ms: int,
    jitter_ms: int,
    reorder: int,
) -> bool:
    """
    Set tc/netem rules on the given interface.
    Returns True on success.
    """
    # Clear existing
    clear_tc_netem(interface)
    time.sleep(0.1)

    if loss == 0 and delay_ms == 0 and jitter_ms == 0 and reorder == 0:
        # Control condition: no impairment
        return True

    cmd = ["sudo", "tc", "qdisc", "add", "dev", interface, "root", "netem"]

    if delay_ms > 0:
        cmd.extend(["delay", f"{delay_ms}ms"])
        if jitter_ms > 0:
            cmd.extend([f"{jitter_ms}ms"])

    if loss > 0:
        cmd.extend(["loss", f"{loss}%"])

    if reorder > 0:
        cmd.extend(["reorder", f"{reorder}%"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True
        else:
            print(f"[TC] Failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[TC] Error: {e}")
        return False


def clear_tc_netem(interface: str) -> bool:
    """Remove all tc/netem rules from the interface."""
    try:
        result = subprocess.run(
            ["sudo", "tc", "qdisc", "del", "dev", interface, "root"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0 or "No such file" in (result.stderr or "")
    except Exception:
        return False


@contextmanager
def tc_condition(interface: str, loss: int, delay_ms: int, jitter_ms: int, reorder: int):
    """
    Context manager that sets a tc/netem condition and guarantees cleanup.
    """
    condition_desc = f"loss={loss}% delay={delay_ms}ms jitter={jitter_ms}ms reorder={reorder}%"
    print(f"[TC] Applying: {condition_desc}")
    ok = setup_tc_netem(interface, loss, delay_ms, jitter_ms, reorder)
    if not ok:
        raise RuntimeError(f"[TC] Failed to apply condition: {condition_desc}")
    try:
        yield
    finally:
        print("[TC] Cleaning up ...")
        clear_tc_netem(interface)


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def build_packet_for_protocol(
    protocol: str,
    session_id: str,
    seq: int,
    payload: str,
    current_mem: str,
) -> Dict[str, Any]:
    if protocol == "gmcp_r":
        return build_data_packet(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_mem=current_mem,
            payload=payload,
        )
    elif protocol == "seq_mac":
        return seq_mac_build(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            payload=payload,
        )
    elif protocol == "authenticated_hash_chain":
        return ahc_build(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_hash=current_mem,
            payload=payload,
        )
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def get_initial_state(protocol: str, session_id: str) -> str:
    if protocol == "gmcp_r":
        return initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    elif protocol == "seq_mac":
        return ""
    elif protocol == "authenticated_hash_chain":
        return hash_text(f"init:{session_id}")
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


# ---------------------------------------------------------------------------
# Single experiment
# ---------------------------------------------------------------------------

def run_one_experiment(
    protocol: str,
    condition_name: str,
    repeat_id: int,
    server_host: str,
    server_port: int,
    message_count: int,
    payload_size: int,
) -> Dict[str, Any]:
    """Run one experiment. Returns result dict."""
    session_id = (
        f"netem-{protocol}-{condition_name}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    current_mem = get_initial_state(protocol, session_id)

    accepted = 0
    rejected = 0
    timeouts = 0
    errors = 0
    sent = 0
    rtts: List[float] = []
    run_valid = True
    failure_reason = ""

    start_time = time.time()
    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp(server_host, server_port)

        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = build_packet_for_protocol(
                protocol, session_id, seq, payload, current_mem
            )

            t_send = time.perf_counter()
            send_json_line(sock, packet)
            sent += 1

            try:
                response = recv_json_line(file_obj)
                t_recv = time.perf_counter()
                rtts.append((t_recv - t_send) * 1000.0)

                if response.get("ok"):
                    accepted += 1
                    if protocol == "gmcp_r":
                        current_mem = response.get("last_mem", current_mem)
                else:
                    rejected += 1
                    run_valid = False
                    failure_reason = response.get("reason", "server_rejected")

            except socket.timeout:
                timeouts += 1
                run_valid = False
                failure_reason = "socket_timeout"
            except Exception as e:
                errors += 1
                run_valid = False
                failure_reason = str(e)

    except Exception as e:
        run_valid = False
        failure_reason = str(e)
        print(f"  [ERROR] {protocol} {condition_name} r{repeat_id}: {e}")
    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time
    success_rate = accepted / message_count * 100 if message_count > 0 else 0
    throughput = accepted / elapsed if elapsed > 0 else 0

    def percentile(values: List[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        pos = (len(ordered) - 1) * pct
        low = int(pos)
        high = min(low + 1, len(ordered) - 1)
        weight = pos - low
        return ordered[low] * (1 - weight) + ordered[high] * weight

    avg_rtt = sum(rtts) / len(rtts) if rtts else 0

    return {
        "session_id": session_id,
        "experiment_type": "netem_validation",
        "protocol": protocol,
        "condition_name": condition_name,
        "loss_rate_pct": next(c[2] for c in NETEM_CONDITIONS if c[0] == condition_name),
        "delay_ms": next(c[3] for c in NETEM_CONDITIONS if c[0] == condition_name),
        "jitter_ms": next(c[4] for c in NETEM_CONDITIONS if c[0] == condition_name),
        "reorder_pct": next(c[5] for c in NETEM_CONDITIONS if c[0] == condition_name),
        "server_host": server_host,
        "server_port": server_port,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent,
        "accepted_count": accepted,
        "rejected_count": rejected,
        "timeout_count": timeouts,
        "error_count": errors,
        "success_rate": round(success_rate, 2),
        "throughput_msg_per_sec": round(throughput, 2),
        "elapsed_seconds": round(elapsed, 3),
        "avg_rtt_ms": round(avg_rtt, 2),
        "p50_rtt_ms": round(percentile(rtts, 0.50), 2),
        "p95_rtt_ms": round(percentile(rtts, 0.95), 2),
        "p99_rtt_ms": round(percentile(rtts, 0.99), 2),
        "run_valid": run_valid,
        "failure_reason": failure_reason,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Embedded TCP server
# ---------------------------------------------------------------------------

def _session_factory(session_id: str, checkpoint_interval: int) -> SessionContext:
    """Create a SessionContext for a composite key like 'protocol:session_id'."""
    protocol, _, sid = session_id.partition(":")
    if protocol == "gmcp_r":
        mem_seed = "demo-seed"
        m0 = initial_memory(sid, CLIENT_ID, EPOCH, mem_seed)
        state = GMCPState(
            session_id=sid,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            last_seq=0,
            last_mem=m0,
        )
        verifier = GMCPVerifier(state)
    elif protocol == "seq_mac":
        state = sm_init_state(sid, CLIENT_ID, EPOCH)
        verifier = SeqMACVerifier(state)
    elif protocol == "authenticated_hash_chain":
        state = ahc_init_state(sid, CLIENT_ID, EPOCH)
        verifier = AuthHashChainVerifier(state)
    else:
        raise ValueError(f"unsupported protocol: {protocol}")
    cp_mgr = CheckpointManager(
        session_id=sid,
        epoch=EPOCH,
        checkpoint_interval=checkpoint_interval,
    )
    return SessionContext(
        session_id=session_id,
        state=state,
        verifier=verifier,
        checkpoint_manager=cp_mgr,
    )


import threading


class EmbeddedTCPServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._registry = SessionRegistry(factory=_session_factory)
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(f"[SERVER] Listening on {self.host}:{self.port}")

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                assert self._server_sock is not None
                conn, addr = self._server_sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                ).start()
            except OSError:
                break

    def _handle_client(self, conn: socket.socket, addr):
        file_obj = None
        try:
            file_obj = conn.makefile("r", encoding="utf-8", newline="\n")
            while True:
                line = file_obj.readline()
                if not line:
                    break
                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ptype = packet.get("type", "")
                if ptype == "PING":
                    self._send(conn, {"ok": True, "type": "PONG", "server_time": time.time()})
                elif ptype == "DATA":
                    self._send(conn, self._handle_data(packet))
                else:
                    self._send(conn, {"ok": False, "reason": f"unknown type: {ptype}"})
        except (ConnectionError, socket.timeout, OSError):
            pass
        finally:
            close_tcp(conn, file_obj)

    def _handle_data(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        session_id = packet.get("session_id", "unknown")
        protocol = packet.get("protocol", "gmcp_r")
        registry_key = f"{protocol}:{session_id}"
        ctx = self._registry.get_or_create(registry_key)

        ok, reason = ctx.verifier.verify_data_packet(packet)
        resp = {"ok": ok, "reason": reason, "last_seq": ctx.state.last_seq}
        if protocol == "gmcp_r":
            resp["last_mem"] = ctx.state.last_mem
        return resp

    @staticmethod
    def _send(conn: socket.socket, resp: Dict[str, Any]):
        raw = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            conn.sendall(raw)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="GMCP-R tc/netem weak-network experiment validation"
    )
    parser.add_argument(
        "--interface", "-i",
        default=os.getenv("GMCP_TC_INTERFACE", "lo0" if not is_linux() else "lo"),
        help="Network interface to apply tc/netem rules (default: lo0/lo)",
    )
    parser.add_argument("--port", type=int, default=9002, help="Server port")
    parser.add_argument("--quick", action="store_true", help="Quick mode: 1 repeat")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument("--conditions", default=None, help="Comma-separated condition names to run")
    args = parser.parse_args()

    repeats = 1 if args.quick else (args.repeats or REPEAT_COUNT)

    # ---- Platform / privilege checks ----
    if not is_linux():
        print("[ERROR] tc/netem is a Linux-only feature.")
        print("        This experiment must run on a Linux host with sudo access.")
        print(f"        Detected platform: {sys.platform}")
        sys.exit(1)

    if not check_tc_available():
        print("[ERROR] 'tc' command not found. Install iproute2:")
        print("        sudo apt-get install iproute2")
        sys.exit(1)

    if not check_sudo_available():
        print("[ERROR] This experiment requires passwordless sudo for tc commands.")
        print("        Configure with: sudo visudo  →  add NOPASSWD for tc")
        print("        Or run the entire script with: sudo python run_netem_validation.py")
        sys.exit(1)

    # Filter conditions
    if args.conditions:
        selected_names = [c.strip() for c in args.conditions.split(",")]
        conditions = [c for c in NETEM_CONDITIONS if c[0] in selected_names]
        if not conditions:
            print(f"[ERROR] No matching conditions for: {selected_names}")
            print(f"        Available: {[c[0] for c in NETEM_CONDITIONS]}")
            sys.exit(1)
    else:
        conditions = NETEM_CONDITIONS

    server_host = "127.0.0.1"
    server_port = args.port
    interface = args.interface

    # ---- Start embedded server ----
    print(f"[MODE] Starting embedded server on {server_host}:{server_port}")
    srv = EmbeddedTCPServer(server_host, server_port)
    srv.start()
    time.sleep(0.3)

    ensure_output_dir()

    fieldnames = [
        "session_id", "experiment_type", "protocol",
        "condition_name", "loss_rate_pct", "delay_ms", "jitter_ms", "reorder_pct",
        "server_host", "server_port",
        "message_count", "payload_size", "repeat_id",
        "sent_count", "accepted_count", "rejected_count",
        "timeout_count", "error_count",
        "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
        "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
        "run_valid", "failure_reason",
        "timestamp",
        "git_commit", "python_version", "os_info",
    ]

    total = len(PROTOCOLS) * len(conditions) * repeats

    # Collect metadata once
    git_commit = get_git_commit()
    python_version = get_python_version()
    os_info = get_os_info()

    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {PROTOCOLS}")
    print(f"[INFO] Conditions: {[c[0] for c in conditions]}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Interface: {interface}")
    print(f"[INFO] Output: {OUTPUT_CSV}")
    print()

    completed = 0
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for cond_name, cond_desc, loss, delay, jitter, reorder in conditions:
            print(f"\n{'='*60}")
            print(f"[CONDITION] {cond_name}: {cond_desc}")
            print(f"            loss={loss}% delay={delay}ms jitter={jitter}ms reorder={reorder}%")
            print(f"{'='*60}")

            with tc_condition(interface, loss, delay, jitter, reorder):
                for protocol in PROTOCOLS:
                    for repeat_id in range(1, repeats + 1):
                        result = run_one_experiment(
                            protocol=protocol,
                            condition_name=cond_name,
                            repeat_id=repeat_id,
                            server_host=server_host,
                            server_port=server_port,
                            message_count=MESSAGE_COUNT,
                            payload_size=PAYLOAD_SIZE,
                        )
                        result["git_commit"] = git_commit
                        result["python_version"] = python_version
                        result["os_info"] = os_info
                        writer.writerow(result)
                        f.flush()
                        completed += 1
                        print(
                            f"  [{completed}/{total}] {protocol} {cond_name} r{repeat_id}: "
                            f"acc={result['accepted_count']} rej={result['rejected_count']} "
                            f"rtt={result['avg_rtt_ms']:.1f}ms"
                        )

    # Final cleanup (safety net)
    clear_tc_netem(interface)
    srv.stop()

    print(f"\n[DONE] Results written to {OUTPUT_CSV}")
    print(f"[DONE] {completed} experiments completed.")


if __name__ == "__main__":
    main()
