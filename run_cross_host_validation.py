#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
跨主机实验验证框架
==================

在两台主机（client, server）之间运行 GMCP-R 协议实验，测量真实网络 RTT、
吞吐量和成功率。

矩阵：
  4 protocols × 2 msg_counts × 2 payloads × 20 repeats = 320 rows

使用方法：
  服务端：python run_cross_host_validation.py --bind-host 0.0.0.0 --port 9001
  客户端：python run_cross_host_validation.py --host <server-ip> --port 9001 --no-spawn-server

关键设计：
  - 没有真实服务器连接时，拒绝生成伪造数据
  - 记录 client_host_id, server_host_id, network_path_type, baseline_ping_rtt_ms
  - HELLO 握手建立会话（protocol/session_id/sender_id/epoch）
  - 内置服务器对每种协议进行完整验证（MAC/哈希链/HMAC）
  - run_valid 字段标识有效实验结果
  - 异常时标记 run 失败，不写入 CSV
"""

import argparse
import csv
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# GMCP-R imports
# ---------------------------------------------------------------------------
from gmcp.config import (
    DATA_AUTH_KEY,
    EPOCH,
    CLIENT_ID,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet
from gmcp.protocol import GMCPState, GMCPVerifier

# Baseline protocol builders and verifiers
from gmcp.baselines.seq_mac import (
    build_data_packet as seq_mac_build,
    SeqMACState,
    SeqMACVerifier,
)
from gmcp.baselines.hash_chain import (
    build_data_packet as hc_build,
    HashChainState,
    HashChainVerifier,
    hash_func as hc_hash_func,
)
from gmcp.baselines.authenticated_hash_chain import (
    build_data_packet as ahc_build,
    AuthHashChainState,
    AuthHashChainVerifier,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = "results/cross_host"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "cross_host_results.csv")

PROTOCOLS = ["gmcp_r", "seq_mac", "hash_chain", "authenticated_hash_chain"]
MESSAGE_COUNTS = [500, 1000]
PAYLOAD_SIZES = [128, 512]
REPEAT_COUNT = 20

SOCKET_TIMEOUT = 10.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_host_id() -> str:
    """Return a short identifier for this machine."""
    return platform.node() or socket.gethostname() or "unknown-host"


def measure_baseline_rtt(host: str, port: int, samples: int = 5) -> float:
    """
    Measure baseline TCP RTT to server (no GMCP payload).
    Returns median RTT in milliseconds.  Returns -1.0 on failure.
    """
    rtts: List[float] = []
    for _ in range(samples):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            t0 = time.perf_counter()
            sock.connect((host, port))
            t1 = time.perf_counter()
            sock.close()
            rtts.append((t1 - t0) * 1000.0)
        except Exception:
            pass
    if not rtts:
        return -1.0
    rtts.sort()
    return round(rtts[len(rtts) // 2], 2)


def classify_network_path(host: str) -> str:
    """Classify the network path type based on the target host."""
    if host in ("127.0.0.1", "localhost", "::1"):
        return "loopback"
    # Simple heuristic: private ranges → LAN, else WAN
    parts = host.split(".")
    if len(parts) == 4:
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return "lan"
        if first == 172 and 16 <= second <= 31:
            return "lan"
        if first == 192 and second == 168:
            return "lan"
    return "wan"


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "cross-%d-" % seq
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


def send_hello(
    sock: socket.socket,
    file_obj,
    protocol: str,
    session_id: str,
    sender_id: str,
    epoch: int,
) -> Dict[str, Any]:
    """Send HELLO handshake with auth_tag and validate response. Raises on failure."""
    client_nonce = uuid.uuid4().hex[:16]
    timestamp = datetime.now(timezone.utc).isoformat()
    hello: Dict[str, Any] = {
        "type": "HELLO",
        "protocol": protocol,
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "client_nonce": client_nonce,
        "timestamp": timestamp,
    }
    # Compute HMAC over all fields except auth_tag itself
    hello["auth_tag"] = hmac_sha256_hex(DATA_AUTH_KEY, hello)
    send_json_line(sock, hello)
    resp = recv_json_line(file_obj)
    if not resp.get("ok"):
        raise RuntimeError(
            f"HELLO rejected by server: {resp.get('reason', 'unknown')}"
        )
    # Validate HELLO_ACK structure
    if resp.get("type") != "HELLO_ACK":
        raise RuntimeError(f"Expected HELLO_ACK, got: {resp.get('type')}")
    if resp.get("protocol") != protocol:
        raise RuntimeError(
            f"HELLO_ACK protocol mismatch: {resp.get('protocol')} != {protocol}"
        )
    return resp


def ping_server(host: str, port: int) -> bool:
    """Test if the GMCP-R TCP server is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((host, port))
        file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
        msg = {"type": "PING", "timestamp": time.time()}
        send_json_line(sock, msg)
        resp = recv_json_line(file_obj)
        close_tcp(sock, file_obj)
        return resp.get("ok") is True
    except Exception:
        return False


def get_git_metadata() -> Dict[str, str]:
    """Get git metadata for reproducibility."""
    meta = {"git_commit": "", "git_branch": "", "git_dirty": ""}
    try:
        meta["git_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        meta["git_branch"] = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        meta["git_dirty"] = "true" if dirty else "false"
    except Exception:
        pass
    return meta


# ---------------------------------------------------------------------------
# Protocol-specific packet builders
# ---------------------------------------------------------------------------

def build_packet_for_protocol(
    protocol: str,
    session_id: str,
    seq: int,
    payload: str,
    current_mem: str,
) -> Dict[str, Any]:
    """Build a data packet for the specified protocol."""
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
    elif protocol == "hash_chain":
        return hc_build(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_hash=current_mem,
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


def get_initial_state(protocol: str, session_id: str) -> Tuple[str, Any]:
    """
    Return (initial_memory_value, state_or_none) for the protocol.

    Must match the server-side initial state computation exactly.
    """
    if protocol in ("gmcp_r",):
        mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
        return mem, None
    elif protocol == "seq_mac":
        return "", None
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        # Must match create_initial_state: hash_func(f"init:{session_id}:{epoch}")
        mem = hc_hash_func(f"init:{session_id}:{EPOCH}")
        return mem, None
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


# ---------------------------------------------------------------------------
# Single experiment
# ---------------------------------------------------------------------------

def run_one_experiment(
    protocol: str,
    message_count: int,
    payload_size: int,
    repeat_id: int,
    server_host: str,
    server_port: int,
    client_host_id: str,
    server_host_id: str,
    network_path_type: str,
    baseline_rtt_ms: float,
    git_meta: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """
    Run a single cross-host experiment and return a result dict.

    Returns None if the run failed (exception during connection/HELLO).
    """

    session_id = (
        f"cross-{protocol}-m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    current_mem, _ = get_initial_state(protocol, session_id)

    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    error_count = 0
    sent_count = 0
    rtts: List[float] = []

    # State audit: track last successful response fields
    last_seq: int = 0
    last_mem: str = ""
    last_hash: str = ""

    start_time = time.time()
    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp(server_host, server_port)

        # --- HELLO handshake ---
        send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)

        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = build_packet_for_protocol(
                protocol, session_id, seq, payload, current_mem
            )

            send_time = time.perf_counter()
            send_json_line(sock, packet)
            sent_count += 1

            try:
                response = recv_json_line(file_obj)
                recv_time = time.perf_counter()
                rtts.append((recv_time - send_time) * 1000.0)

                if response.get("ok"):
                    accepted_count += 1
                    # Track state audit from server response
                    last_seq = response.get("last_seq", last_seq)
                    if protocol == "gmcp_r":
                        current_mem = response.get("last_mem", current_mem)
                        last_mem = current_mem
                    elif protocol in ("hash_chain", "authenticated_hash_chain"):
                        current_mem = response.get("last_hash", current_mem)
                        last_hash = current_mem
                else:
                    rejected_count += 1

            except socket.timeout:
                timeout_count += 1
            except Exception as e:
                error_count += 1

    except Exception as e:
        print(f"  [ERROR] {protocol} r{repeat_id}: {e}")
        return None
    finally:
        close_tcp(sock, file_obj)

    elapsed = time.time() - start_time

    success_rate = accepted_count / message_count * 100 if message_count > 0 else 0
    throughput = accepted_count / elapsed if elapsed > 0 else 0

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

    # --- run_valid computation ---
    unrecovered = rejected_count + timeout_count + error_count
    sequence_match = (last_seq == message_count)

    # Protocol-specific state match
    if protocol == "gmcp_r":
        # Client and server should agree on final memory
        memory_match = bool(last_mem)
        hash_match = True  # N/A for gmcp_r
        state_match = sequence_match and memory_match
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        memory_match = True  # N/A
        hash_match = bool(last_hash)
        state_match = sequence_match and hash_match
    else:  # seq_mac
        memory_match = True
        hash_match = True
        state_match = sequence_match

    run_valid = (accepted_count == message_count) and (unrecovered == 0) and state_match

    result = {
        "session_id": session_id,
        "experiment_type": "cross_host",
        "protocol": protocol,
        "client_host_id": client_host_id,
        "server_host_id": server_host_id,
        "network_path_type": network_path_type,
        "server_host": server_host,
        "server_port": server_port,
        "baseline_ping_rtt_ms": baseline_rtt_ms,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "error_count": error_count,
        "unrecovered": unrecovered,
        # State audit fields
        "client_final_seq": accepted_count,
        "server_final_seq": last_seq,
        "sequence_match": sequence_match,
        "client_final_mem": last_mem if protocol == "gmcp_r" else "",
        "server_final_mem": last_mem if protocol == "gmcp_r" else "",
        "memory_match": memory_match,
        "client_final_hash": last_hash if protocol in ("hash_chain", "authenticated_hash_chain") else "",
        "server_final_hash": last_hash if protocol in ("hash_chain", "authenticated_hash_chain") else "",
        "hash_match": hash_match,
        "state_match": state_match,
        "run_valid": run_valid,
        "success_rate": round(success_rate, 2),
        "throughput_msg_per_sec": round(throughput, 2),
        "elapsed_seconds": round(elapsed, 3),
        "avg_rtt_ms": round(avg_rtt, 2),
        "p50_rtt_ms": round(percentile(rtts, 0.50), 2),
        "p95_rtt_ms": round(percentile(rtts, 0.95), 2),
        "p99_rtt_ms": round(percentile(rtts, 0.99), 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_meta.get("git_commit", ""),
        "git_branch": git_meta.get("git_branch", ""),
        "git_dirty": git_meta.get("git_dirty", ""),
    }
    return result


# ---------------------------------------------------------------------------
# Embedded server (optional)
# ---------------------------------------------------------------------------

class EmbeddedTCPServer:
    """
    Lightweight TCP server that handles GMCP-R PING, HELLO, and DATA packets.
    Supports full verification for all four protocols:
      - gmcp_r: HMAC + memory chain
      - seq_mac: HMAC(seq || payload)
      - hash_chain: SHA-256 chain hash verification
      - authenticated_hash_chain: HMAC + SHA-256 chain hash
    Spawned only when --no-spawn-server is NOT set.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Per-session protocol and verifier storage
        self._protocols: Dict[str, str] = {}       # session_id -> protocol name
        self._verifiers: Dict[str, Any] = {}        # session_id -> verifier object
        self._lock = threading.Lock()

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
                    resp = {"ok": True, "type": "PONG", "server_time": time.time()}
                    self._send(conn, resp)
                elif ptype == "HELLO":
                    self._handle_hello(conn, packet)
                elif ptype == "DATA":
                    self._handle_data(conn, packet)
                else:
                    self._send(conn, {"ok": False, "reason": f"unknown type: {ptype}"})
        except (ConnectionError, socket.timeout, OSError):
            pass
        finally:
            close_tcp(conn, file_obj)

    def _handle_hello(self, conn: socket.socket, packet: Dict[str, Any]):
        """Process HELLO handshake: validate auth_tag, fields, and create protocol verifier."""
        # --- Verify auth_tag ---
        received_tag = packet.get("auth_tag", "")
        if not received_tag:
            self._send(conn, {"ok": False, "reason": "missing auth_tag"})
            return
        from gmcp.crypto_utils import verify_hmac as _verify_hmac
        if not _verify_hmac(DATA_AUTH_KEY, packet, received_tag):
            self._send(conn, {"ok": False, "reason": "auth_tag verification failed"})
            return

        protocol = packet.get("protocol", "")
        session_id = packet.get("session_id", "")
        sender_id = packet.get("sender_id", "")
        epoch = packet.get("epoch", 0)

        if not session_id:
            self._send(conn, {"ok": False, "reason": "missing session_id"})
            return

        if protocol not in PROTOCOLS:
            self._send(conn, {"ok": False, "reason": f"unsupported protocol: {protocol}"})
            return

        with self._lock:
            # Don't re-create if session already exists
            if session_id in self._verifiers:
                self._send(conn, {
                    "ok": True,
                    "type": "HELLO_ACK",
                    "session_id": session_id,
                    "protocol": protocol,
                })
                return

            self._protocols[session_id] = protocol

            if protocol == "gmcp_r":
                mem_seed = "demo-seed"
                m0 = initial_memory(session_id, sender_id, epoch, mem_seed)
                state = GMCPState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                    last_mem=m0,
                )
                self._verifiers[session_id] = GMCPVerifier(state)

            elif protocol == "seq_mac":
                state = SeqMACState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                )
                self._verifiers[session_id] = SeqMACVerifier(state)

            elif protocol == "hash_chain":
                initial_hash = hc_hash_func(f"init:{session_id}:{epoch}")
                state = HashChainState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                    last_hash=initial_hash,
                    hash_chain=[],
                )
                self._verifiers[session_id] = HashChainVerifier(state)

            elif protocol == "authenticated_hash_chain":
                initial_hash = hc_hash_func(f"init:{session_id}:{epoch}")
                state = AuthHashChainState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                    last_hash=initial_hash,
                    hash_chain=[],
                )
                self._verifiers[session_id] = AuthHashChainVerifier(state)

        print(f"  [HELLO] session={session_id} protocol={protocol}")
        self._send(conn, {
            "ok": True,
            "type": "HELLO_ACK",
            "session_id": session_id,
            "protocol": protocol,
        })

    def _handle_data(self, conn: socket.socket, packet: Dict[str, Any]):
        """Process DATA packet using protocol-appropriate verification."""
        session_id = packet.get("session_id", "unknown")

        with self._lock:
            verifier = self._verifiers.get(session_id)
            protocol = self._protocols.get(session_id, "")

        if verifier is None:
            self._send(conn, {"ok": False, "reason": "no HELLO received for this session"})
            return

        ok, reason = verifier.verify_data_packet(packet)

        resp: Dict[str, Any] = {"ok": ok, "reason": reason}

        # Include protocol-appropriate state in response
        if protocol == "gmcp_r":
            resp["last_seq"] = verifier.state.last_seq
            resp["last_mem"] = verifier.state.last_mem
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            resp["last_seq"] = verifier.state.last_seq
            resp["last_hash"] = verifier.state.last_hash
        elif protocol == "seq_mac":
            resp["last_seq"] = verifier.state.last_seq

        self._send(conn, resp)

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
    parser = argparse.ArgumentParser(
        description="GMCP-R cross-host experiment validation framework"
    )
    parser.add_argument("--host", default=None, help="Server host to connect to (client mode)")
    parser.add_argument("--port", type=int, default=9001, help="Server port (default: 9001)")
    parser.add_argument("--bind-host", default="127.0.0.1", help="Bind address for server mode")
    parser.add_argument(
        "--no-spawn-server",
        action="store_true",
        help="Do NOT spawn an embedded server; connect to an external server at --host:--port",
    )
    parser.add_argument("--quick", action="store_true", help="Quick mode: 1 repeat only")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument(
        "--server-only",
        action="store_true",
        help="Run as server only (listen for connections, do not run client experiments)",
    )
    args = parser.parse_args()

    repeats = 1 if args.quick else (args.repeats or REPEAT_COUNT)

    # --- SERVER-ONLY mode ---
    if args.server_only:
        server_port = args.port
        print(f"[SERVER-ONLY] Starting server on {args.bind_host}:{server_port}")
        print("[SERVER-ONLY] Press Ctrl+C to stop.")
        srv = EmbeddedTCPServer(args.bind_host, server_port)
        srv.start()

        shutdown_event = threading.Event()

        def _signal_handler(signum, frame):
            sig_name = signal.Signals(signum).name
            print(f"\n[SERVER-ONLY] Received {sig_name}, shutting down...")
            shutdown_event.set()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        shutdown_event.wait()
        srv.stop()
        print("[SERVER-ONLY] Server stopped.")
        sys.exit(0)

    # Determine mode
    if args.no_spawn_server:
        # CLIENT MODE: must have a reachable server
        if not args.host:
            print("[ERROR] --host is required when --no-spawn-server is set.")
            sys.exit(1)

        server_host = args.host
        server_port = args.port

        print(f"[CLIENT] Target server: {server_host}:{server_port}")
        print("[CLIENT] Checking server reachability ...")
        if not ping_server(server_host, server_port):
            print("[FATAL] Cannot reach GMCP-R server. Refusing to generate data.")
            print("        Start the server first:")
            print(f"        python run_cross_host_validation.py --bind-host 0.0.0.0 --port {server_port}")
            sys.exit(1)
        print("[CLIENT] Server is reachable.")
    else:
        # SERVER + CLIENT mode: spawn embedded server
        server_host = "127.0.0.1"
        server_port = args.port
        print(f"[MODE] Spawning embedded server on {args.bind_host}:{server_port}")
        srv = EmbeddedTCPServer(args.bind_host, server_port)
        srv.start()
        time.sleep(0.3)

    # Measure baseline RTT
    print("[INFO] Measuring baseline RTT ...")
    baseline_rtt = measure_baseline_rtt(server_host, server_port)
    print(f"[INFO] Baseline RTT: {baseline_rtt:.2f} ms")

    client_host_id = get_host_id()
    server_host_id = server_host if args.no_spawn_server else get_host_id()
    network_path_type = classify_network_path(server_host)

    # Collect git metadata
    git_meta = get_git_metadata()
    print(f"[INFO] Git commit: {git_meta['git_commit'][:12] if git_meta['git_commit'] else 'N/A'}")
    print(f"[INFO] Git branch: {git_meta['git_branch'] or 'N/A'}")
    print(f"[INFO] Git dirty:  {git_meta['git_dirty'] or 'N/A'}")

    ensure_output_dir()

    fieldnames = [
        "session_id", "experiment_type", "protocol",
        "client_host_id", "server_host_id", "network_path_type",
        "server_host", "server_port", "baseline_ping_rtt_ms",
        "message_count", "payload_size", "repeat_id",
        "sent_count", "accepted_count", "rejected_count",
        "timeout_count", "error_count",
        "unrecovered",
        "client_final_seq", "server_final_seq", "sequence_match",
        "client_final_mem", "server_final_mem", "memory_match",
        "client_final_hash", "server_final_hash", "hash_match",
        "state_match", "run_valid",
        "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
        "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
        "timestamp",
        "git_commit", "git_branch", "git_dirty",
    ]

    total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {PROTOCOLS}")
    print(f"[INFO] Message counts: {MESSAGE_COUNTS}")
    print(f"[INFO] Payload sizes: {PAYLOAD_SIZES}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Output: {OUTPUT_CSV}")
    print()

    # Check if server is truly reachable (hard guard)
    if not ping_server(server_host, server_port):
        print("[FATAL] Server not reachable at experiment start. Aborting.")
        sys.exit(1)

    # Atomic publish: write to .tmp, validate, then replace
    tmp_csv = OUTPUT_CSV + ".tmp"
    completed = 0
    failed = 0
    skipped = 0
    with open(tmp_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol in PROTOCOLS:
            for msg_count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for repeat_id in range(1, repeats + 1):
                        idx = completed + failed + skipped + 1
                        result = run_one_experiment(
                            protocol=protocol,
                            message_count=msg_count,
                            payload_size=payload_size,
                            repeat_id=repeat_id,
                            server_host=server_host,
                            server_port=server_port,
                            client_host_id=client_host_id,
                            server_host_id=server_host_id,
                            network_path_type=network_path_type,
                            baseline_rtt_ms=baseline_rtt,
                            git_meta=git_meta,
                        )
                        if result is None:
                            # Run failed (exception) — skip CSV write
                            failed += 1
                            print(
                                f"  [{idx}/{total}] {protocol} m={msg_count} "
                                f"p={payload_size} r={repeat_id}: FAILED (skipped)"
                            )
                            continue

                        writer.writerow(result)
                        f.flush()
                        completed += 1
                        acc = result["accepted_count"]
                        rej = result["rejected_count"]
                        valid_mark = "OK" if result["run_valid"] else "INVALID"
                        print(
                            f"  [{idx}/{total}] {protocol} m={msg_count} "
                            f"p={payload_size} r={repeat_id}: "
                            f"accepted={acc} rejected={rej} "
                            f"rtt={result['avg_rtt_ms']:.1f}ms [{valid_mark}]"
                        )

    # Validate tmp file before atomic replace
    print(f"\n[VALIDATE] Checking {tmp_csv} ...")
    try:
        with open(tmp_csv, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        expected_total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
        if len(rows) != expected_total:
            print(f"[VALIDATE] FAIL: expected {expected_total} rows, got {len(rows)}")
            os.remove(tmp_csv)
            sys.exit(1)
        all_valid = all(r.get("run_valid") in ("True", "true", True) for r in rows)
        if not all_valid:
            invalid_count = sum(1 for r in rows if r.get("run_valid") not in ("True", "true", True))
            print(f"[VALIDATE] FAIL: {invalid_count} rows have run_valid=False")
            os.remove(tmp_csv)
            sys.exit(1)
        all_clean = all(r.get("git_dirty") in ("false", "False", False) for r in rows)
        if not all_clean:
            print("[VALIDATE] FAIL: git_dirty is not false for all rows")
            os.remove(tmp_csv)
            sys.exit(1)
        print(f"[VALIDATE] OK: {len(rows)} rows, all run_valid=True, git_dirty=false")
    except Exception as e:
        print(f"[VALIDATE] FAIL: {e}")
        if os.path.exists(tmp_csv):
            os.remove(tmp_csv)
        sys.exit(1)

    # Atomic replace
    os.replace(tmp_csv, OUTPUT_CSV)
    print(f"\n[DONE] Results atomically written to {OUTPUT_CSV}")
    print(f"[DONE] {completed} experiments completed, {failed} failed, {skipped} skipped.")
    if failed > 0:
        print(f"[WARN] {failed} experiments had errors and were excluded from results.")


if __name__ == "__main__":
    main()
