#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
跨主机实验验证框架
==================

在两台主机（client, server）之间运行协议实验，测量真实网络 RTT、
吞吐量和成功率。

矩阵：
  5 protocols × 2 msg_counts × 2 payloads × 20 repeats = 400 rows

使用方法：
  服务端：python run_cross_host_validation.py --server-only --bind-host 0.0.0.0 --port 9001
  客户端：python run_cross_host_validation.py --host <server-ip> --port 9001 --no-spawn-server

关键设计：
  - 没有真实服务器连接时，拒绝生成伪造数据
  - 记录 client_host_id, server_host_id, network_path_type, tcp_connect_latency_ms
  - HELLO 握手建立会话（protocol/session_id/sender_id/epoch）
  - 内置服务器对每种协议进行完整验证（MAC/哈希链/HMAC/ticket）
  - 使用 ProtocolAdapter 做独立状态审计
  - run_valid 字段标识有效实验结果
  - 异常时标记 run 失败，不写入 CSV
  - 记录服务端环境信息（git_commit, python_version, os_info, hostname）
"""

import argparse
import csv
import json
import os
import platform
import signal
import socket
import sys
import time
import threading
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
from gmcp.crypto_utils import verify_tagged_hmac
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier

# Baseline protocol builders and verifiers
from gmcp.baselines.seq_mac import (
    SeqMACState,
    SeqMACVerifier,
)
from gmcp.baselines.hash_chain import (
    HashChainState,
    HashChainVerifier,
    hash_func as hc_hash_func,
)
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState,
    AuthHashChainVerifier,
)
from gmcp.baselines.ticket_only import (
    TicketOnlyState,
    TicketOnlyVerifier,
    issue_ticket,
)

# Shared transport module
from gmcp.experiment_transport import (
    WIRE_PROTOCOL_NAMES,
    DISPLAY_PROTOCOL_NAMES,
    ALL_PROTOCOLS,
    ProtocolAdapter,
    send_hello,
    send_json_line,
    recv_json_line,
    get_git_metadata,
    get_server_env_info,
    get_cpu_model,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = "results/cross_host"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "cross_host_results.csv")

PROTOCOLS = ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]
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
) -> Dict[str, Any]:
    """
    Run a single cross-host experiment and return a result dict.

    Always returns a result dict (never None). On exception, returns
    a dict with run_valid=False and failure details.
    Uses ProtocolAdapter for protocol-agnostic state tracking and
    independent state comparison.
    """

    session_id = (
        f"cross-{protocol}-m{message_count}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    accepted_count = 0
    rejected_count = 0
    timeout_count = 0
    error_count = 0
    failure_reason = ""
    sent_count = 0
    rtts: List[float] = []

    # Server environment info (populated from HELLO_ACK)
    server_env: Dict[str, str] = {}

    # Protocol adapter (initialized before try so it's always bound)
    adapter: Optional[ProtocolAdapter] = None

    start_time = time.time()
    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp(server_host, server_port)

        # --- HELLO handshake ---
        # send_hello uses wire protocol names and validates the response
        ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)

        # Extract server environment info from HELLO_ACK
        server_env = {
            "server_git_commit": ack.get("server_git_commit", ""),
            "server_python_version": ack.get("server_python_version", ""),
            "server_os_info": ack.get("server_os_info", ""),
            "server_hostname": ack.get("server_hostname", ""),
            "server_git_dirty": ack.get("server_git_dirty", ""),
            "server_cpu_model": ack.get("server_cpu_model", ""),
        }

        # Extract ticket for ticket_only protocol
        ticket = ack.get("ticket", "")

        # Create protocol adapter for state tracking
        adapter = ProtocolAdapter(
            protocol=protocol,
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            ticket=ticket,
        )

        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = adapter.build_packet(seq, payload)

            send_time = time.perf_counter()
            send_json_line(sock, packet)
            sent_count += 1

            try:
                response = recv_json_line(file_obj)
                recv_time = time.perf_counter()
                rtts.append((recv_time - send_time) * 1000.0)

                if response.get("ok"):
                    accepted_count += 1
                    # Update adapter: client state from packet, server state from response
                    adapter.update_after_accept(packet, response)
                else:
                    rejected_count += 1

            except socket.timeout:
                timeout_count += 1
                failure_reason = "socket_timeout"
                break  # Stop this run, don't continue with next seq
            except Exception as e:
                error_count += 1
                failure_reason = str(e)
                break  # Stop this run, don't continue with next seq

    except Exception as e:
        print(f"  [ERROR] {protocol} r{repeat_id}: {e}")
        failure_reason = failure_reason or str(e)
        error_count = max(error_count, 1)
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

    if adapter is not None:
        sequence_match = (adapter.last_seq == message_count)
        state_match = adapter.check_state_match() and sequence_match
        run_valid = (accepted_count == message_count) and (unrecovered == 0) and state_match
        state_fields = adapter.get_final_state_for_csv()
    else:
        # Adapter was never created (connection/HELLO failed)
        sequence_match = False
        state_match = False
        run_valid = False
        state_fields = {
            "client_final_seq": 0,
            "server_final_seq": 0,
            "client_final_mem": "",
            "server_final_mem": "",
            "client_final_hash": "",
            "server_final_hash": "",
        }

    # Real memory/hash match from independent comparison
    memory_match = True
    hash_match = True
    if protocol == "gmcp_r":
        memory_match = (
            state_fields["client_final_mem"] == state_fields["server_final_mem"]
        )
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        hash_match = (
            state_fields["client_final_hash"] == state_fields["server_final_hash"]
        )

    result = {
        "session_id": session_id,
        "experiment_type": "cross_host",
        "protocol": protocol,
        "client_host_id": client_host_id,
        "server_host_id": server_host_id,
        "network_path_type": network_path_type,
        "server_host": server_host,
        "server_port": server_port,
        "tcp_connect_latency_ms": baseline_rtt_ms,
        "message_count": message_count,
        "payload_size": payload_size,
        "repeat_id": repeat_id,
        "sent_count": sent_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "timeout_count": timeout_count,
        "error_count": error_count,
        "failure_reason": failure_reason,
        "unrecovered": unrecovered,
        # State audit fields (from ProtocolAdapter)
        "client_final_seq": state_fields["client_final_seq"],
        "server_final_seq": state_fields["server_final_seq"],
        "sequence_match": sequence_match,
        "client_final_mem": state_fields["client_final_mem"],
        "server_final_mem": state_fields["server_final_mem"],
        "memory_match": memory_match,
        "client_final_hash": state_fields["client_final_hash"],
        "server_final_hash": state_fields["server_final_hash"],
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
        # Client environment info
        "client_python_version": platform.python_version(),
        "client_os_info": f"{platform.system()} {platform.release()}",
        "client_cpu_model": git_meta.get("client_cpu_model", ""),
        # Server environment info (from HELLO_ACK)
        "server_git_commit": server_env.get("server_git_commit", ""),
        "server_python_version": server_env.get("server_python_version", ""),
        "server_os_info": server_env.get("server_os_info", ""),
        "server_hostname": server_env.get("server_hostname", ""),
        "server_git_dirty": server_env.get("server_git_dirty", ""),
        "server_cpu_model": server_env.get("server_cpu_model", ""),
    }
    return result


# ---------------------------------------------------------------------------
# Embedded server (optional)
# ---------------------------------------------------------------------------

class EmbeddedTCPServer:
    """
    Lightweight TCP server that handles PING, HELLO, and DATA packets.
    Supports full verification for all five protocols:
      - gmcp_r: HMAC + memory chain
      - seq_mac: HMAC(seq || payload)
      - hash_chain: SHA-256 chain hash verification
      - authenticated_hash_chain: HMAC + SHA-256 chain hash
      - ticket_only: session ticket verification
    Spawned only when --no-spawn-server is NOT set.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Per-session protocol and verifier storage
        self._protocols: Dict[str, str] = {}       # session_id -> protocol display name
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
        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            self._send(conn, {"ok": False, "reason": "auth_tag verification failed"})
            return

        # Map wire protocol name to display name
        wire_protocol = packet.get("protocol", "")
        display_protocol = DISPLAY_PROTOCOL_NAMES.get(wire_protocol, wire_protocol)

        session_id = packet.get("session_id", "")
        sender_id = packet.get("sender_id", "")
        epoch = packet.get("epoch", 0)

        if not session_id:
            self._send(conn, {"ok": False, "reason": "missing session_id"})
            return

        if display_protocol not in ALL_PROTOCOLS:
            self._send(conn, {"ok": False, "reason": f"unsupported protocol: {wire_protocol}"})
            return

        with self._lock:
            # Don't re-create if session already exists
            if session_id in self._verifiers:
                ack = {
                    "ok": True,
                    "type": "HELLO_ACK",
                    "session_id": session_id,
                    "protocol": wire_protocol,
                }
                ack.update(get_server_env_info())
                self._send(conn, ack)
                return

            self._protocols[session_id] = display_protocol

            if display_protocol == "gmcp_r":
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

            elif display_protocol == "seq_mac":
                state = SeqMACState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                )
                self._verifiers[session_id] = SeqMACVerifier(state)

            elif display_protocol == "hash_chain":
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

            elif display_protocol == "authenticated_hash_chain":
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

            elif display_protocol == "ticket_only":
                ticket = issue_ticket(session_id, epoch)
                state = TicketOnlyState(
                    session_id=session_id,
                    sender_id=sender_id,
                    epoch=epoch,
                    last_seq=0,
                    ticket=ticket,
                )
                self._verifiers[session_id] = TicketOnlyVerifier(state)
                # Include ticket in HELLO_ACK so client can use it
                self._current_ticket = ticket

        print(f"  [HELLO] session={session_id} protocol={display_protocol} (wire={wire_protocol})")

        ack: Dict[str, Any] = {
            "ok": True,
            "type": "HELLO_ACK",
            "session_id": session_id,
            "protocol": wire_protocol,
        }

        # Include ticket for ticket_only protocol
        if display_protocol == "ticket_only":
            ack["ticket"] = getattr(self, "_current_ticket", "")

        # Include server environment info
        ack.update(get_server_env_info())

        self._send(conn, ack)

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
        elif protocol in ("seq_mac", "ticket_only"):
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
    parser.add_argument("--quick", action="store_true", help="Quick mode: 1 repeat only, output to smoke CSV")
    parser.add_argument("--formal", action="store_true", help="Formal mode: full run with strict guards")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument("--allow-mixed-commits", action="store_true",
        help="Allow client and server to run different git commits (formal mode)")
    parser.add_argument(
        "--server-only",
        action="store_true",
        help="Run as server only (listen for connections, do not run client experiments)",
    )
    args = parser.parse_args()

    # --- Formal mode: force repeats=20 ---
    if args.formal:
        if args.allow_mixed_commits:
            print("[FORMAL] --allow-mixed-commits: skipping commit consistency check")
        if args.repeats is not None and args.repeats != 20:
            parser.error('--formal requires exactly 20 repeats (or omit for default 20)')

    # --- Mutual exclusion: --quick and --formal ---
    if args.quick and args.formal:
        print("[ERROR] --quick and --formal are mutually exclusive.")
        sys.exit(1)

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
            print(f"        python run_cross_host_validation.py --server-only --bind-host 0.0.0.0 --port {server_port}")
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

    # --- Formal mode guards ---
    if args.formal:
        if not args.no_spawn_server:
            print("[ERROR] --formal requires --no-spawn-server (must connect to a real server).")
            sys.exit(1)
        network_path_check = classify_network_path(server_host)
        if network_path_check == "loopback":
            print("[ERROR] --formal requires a non-loopback network path.")
            sys.exit(1)
        client_hid = get_host_id()
        # server_hostname is not known until HELLO_ACK; we can at least check != server_host
        if client_hid == server_host:
            print("[ERROR] --formal requires client_host_id != server_host.")
            sys.exit(1)

    # Determine output CSV based on mode
    if args.quick:
        output_csv = os.path.join(OUTPUT_DIR, "cross_host_smoke.csv")
    elif args.formal:
        output_csv = os.path.join(OUTPUT_DIR, "cross_host_results.csv")
    else:
        output_csv = os.path.join(OUTPUT_DIR, "cross_host_dev.csv")

    # Measure baseline RTT
    print("[INFO] Measuring baseline RTT ...")
    baseline_rtt = measure_baseline_rtt(server_host, server_port)
    print(f"[INFO] Baseline RTT: {baseline_rtt:.2f} ms")

    client_host_id = get_host_id()
    server_host_id = server_host if args.no_spawn_server else get_host_id()
    network_path_type = classify_network_path(server_host)

    # Collect git metadata
    git_meta = get_git_metadata()
    # Add client CPU model to git_meta for use in run_one_experiment
    git_meta["client_cpu_model"] = get_cpu_model()
    print(f"[INFO] Git commit: {git_meta['git_commit'][:12] if git_meta['git_commit'] else 'N/A'}")
    print(f"[INFO] Git branch: {git_meta['git_branch'] or 'N/A'}")
    print(f"[INFO] Git dirty:  {git_meta['git_dirty'] or 'N/A'}")

    # Capture command line
    command_line = " ".join(sys.argv)

    ensure_output_dir()

    fieldnames = [
        "session_id", "experiment_type", "protocol",
        "client_host_id", "server_host_id", "network_path_type",
        "server_host", "server_port", "tcp_connect_latency_ms",
        "message_count", "payload_size", "repeat_id",
        "sent_count", "accepted_count", "rejected_count",
        "timeout_count", "error_count", "failure_reason",
        "unrecovered",
        "client_final_seq", "server_final_seq", "sequence_match",
        "client_final_mem", "server_final_mem", "memory_match",
        "client_final_hash", "server_final_hash", "hash_match",
        "state_match", "run_valid",
        "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
        "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
        "timestamp",
        "git_commit", "git_branch", "git_dirty",
        "client_python_version", "client_os_info", "client_cpu_model",
        "server_git_commit", "server_python_version", "server_os_info",
        "server_hostname", "server_git_dirty", "server_cpu_model",
        "command_line",
    ]

    total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
    mode_label = "formal" if args.formal else ("smoke" if args.quick else "default")
    print(f"[INFO] Mode: {mode_label}")
    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {PROTOCOLS}")
    print(f"[INFO] Message counts: {MESSAGE_COUNTS}")
    print(f"[INFO] Payload sizes: {PAYLOAD_SIZES}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Output: {output_csv}")
    print()

    # Check if server is truly reachable (hard guard)
    if not ping_server(server_host, server_port):
        print("[FATAL] Server not reachable at experiment start. Aborting.")
        sys.exit(1)

    # --- Journal for crash recovery ---
    journal_path = output_csv + ".journal"
    journal_entries = []

    def write_journal(event: str, **extra):
        """Append a timestamped event to the journal file."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **extra,
        }
        journal_entries.append(entry)
        try:
            with open(journal_path, "a", encoding="utf-8") as jf:
                jf.write(json.dumps(entry, ensure_ascii=False) + "\n")
                jf.flush()
        except Exception:
            pass

    write_journal("run_start", total=total, mode=mode_label, output=output_csv)

    # Batch mode: write to .tmp incrementally, flush after each experiment
    tmp_csv = output_csv + ".tmp"
    completed = 0
    failed = 0
    with open(tmp_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol in PROTOCOLS:
            for msg_count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    for repeat_id in range(1, repeats + 1):
                        idx = completed + failed + 1
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

                        # Inject command_line into each result
                        result["command_line"] = command_line

                        # Always write to CSV (failed rows preserved with run_valid=False)
                        writer.writerow(result)
                        f.flush()

                        if not result["run_valid"]:
                            failed += 1
                            write_journal(
                                "experiment_failed",
                                protocol=protocol,
                                msg_count=msg_count,
                                payload_size=payload_size,
                                repeat_id=repeat_id,
                                failure_reason=result.get("failure_reason", ""),
                            )
                        else:
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

    write_journal("run_end", completed=completed, failed=failed, total=total)

    # Validate tmp file before atomic replace
    # (relaxed: allow failed rows — only check structural integrity)
    print(f"\n[VALIDATE] Checking {tmp_csv} ...")
    try:
        with open(tmp_csv, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        expected_total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
        if len(rows) != expected_total:
            print(f"[VALIDATE] FAIL: expected {expected_total} rows, got {len(rows)}")
            os.remove(tmp_csv)
            sys.exit(1)

        # Count valid vs invalid
        invalid_count = sum(1 for r in rows if r.get("run_valid") not in ("True", "true", True))
        valid_count = len(rows) - invalid_count
        if invalid_count > 0:
            print(f"[VALIDATE] WARN: {invalid_count} rows have run_valid=False (preserved in output)")

        all_clean = all(r.get("git_dirty") in ("false", "False", False) for r in rows)
        if not all_clean:
            print("[VALIDATE] FAIL: git_dirty is not false for all rows")
            os.remove(tmp_csv)
            sys.exit(1)
        # Formal mode: also check server_git_dirty and cross-host authenticity
        if args.formal:
            for i, r in enumerate(rows):
                # Skip failed rows for strict server-side checks
                if r.get("run_valid") not in ("True", "true", True):
                    continue
                # server_git_dirty strict check (no empty string allowed)
                server_dirty = r.get('server_git_dirty', '')
                if server_dirty not in ('false', 'False', False):
                    print(f"[VALIDATE] FAIL row {i+1}: server_git_dirty={server_dirty}")
                    os.remove(tmp_csv)
                    sys.exit(1)
                # server_git_commit must be 40-char hex
                serv_commit = r.get('server_git_commit', '')
                if len(serv_commit) != 40:
                    print(f"[VALIDATE] FAIL row {i+1}: server_git_commit length {len(serv_commit)} != 40")
                    os.remove(tmp_csv)
                    sys.exit(1)
                # Real cross-host: server_hostname must differ from client_host_id
                if r.get('server_hostname') == r.get('client_host_id'):
                    print(f"[VALIDATE] FAIL row {i+1}: client and server on same host")
                    os.remove(tmp_csv)
                    sys.exit(1)
                # Real cross-host: no loopback in formal data
                if r.get('network_path_type') == 'loopback':
                    print(f"[VALIDATE] FAIL row {i+1}: formal data cannot use loopback")
                    os.remove(tmp_csv)
                    sys.exit(1)
                # Commit consistency
                client_commit = r.get('git_commit', '')
                server_commit = r.get('server_git_commit', '')
                if not args.allow_mixed_commits and client_commit != server_commit:
                    print(f"[VALIDATE] FAIL row {i+1}: client commit {client_commit[:8]} != server commit {server_commit[:8]}")
                    os.remove(tmp_csv)
                    sys.exit(1)
            client_dirty = any(
                r.get("git_dirty") not in ("false", "False", False)
                for r in rows
            )
            if client_dirty:
                print("[VALIDATE] FAIL: client git_dirty is not false for all rows")
                os.remove(tmp_csv)
                sys.exit(1)
        print(f"[VALIDATE] OK: {len(rows)} rows ({valid_count} valid, {invalid_count} failed), git_dirty=false")
    except Exception as e:
        print(f"[VALIDATE] FAIL: {e}")
        if os.path.exists(tmp_csv):
            os.remove(tmp_csv)
        sys.exit(1)

    # Atomic replace
    os.replace(tmp_csv, output_csv)
    print(f"\n[DONE] Results atomically written to {output_csv}")
    print(f"[DONE] {completed} experiments completed, {failed} failed.")
    if failed > 0:
        print(f"[WARN] {failed} experiments had errors and were preserved with run_valid=False.")
    print(f"[JOURNAL] Crash-recovery journal: {journal_path}")


if __name__ == "__main__":
    main()
