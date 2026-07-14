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
import hashlib
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

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


def _find_enclosing_git_root(path: Path) -> Optional[Path]:
    """Return the nearest enclosing Git root for path, using filesystem markers."""
    resolved = path.resolve()
    for candidate in (resolved, *resolved.parents):
        marker = candidate / ".git"
        if marker.exists():
            return candidate
    return None


def ensure_formal_batch_run_dir(parser: argparse.ArgumentParser, run_dir: str) -> Path:
    """Create and validate a formal batch run directory before any output is opened."""
    path = Path(run_dir)
    if not path.is_absolute():
        parser.error("--formal-batch requires --run-dir to be an absolute path")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"--run-dir could not be created: {exc}")

    git_root = _find_enclosing_git_root(path)
    if git_root is not None:
        parser.error(f"--run-dir must not be inside a Git repository: {git_root}")

    probe = path / f".write-test-{uuid4().hex}"
    try:
        with probe.open("x", encoding="utf-8") as f:
            f.write("ok\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        parser.error(f"--run-dir is not writable: {exc}")
    finally:
        try:
            probe.unlink()
        except FileNotFoundError:
            pass
    return path


def build_arg_parser() -> argparse.ArgumentParser:
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
    parser.add_argument("--formal-batch", action="store_true",
        help="Formal batch mode: like --formal but skips TTY confirmation prompts for CI/automation")
    parser.add_argument("--repeat-id", type=int, default=None,
        help="For --formal-batch: specific repeat_id (1-20) to run")
    parser.add_argument("--run-dir", type=str, default=None,
        help="Absolute path for journal and batch output files")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument("--attempt-number", type=int, default=None, dest="attempt_number_arg",
        help="For --formal-batch: required explicit attempt number (1, 2, or 3)")
    parser.add_argument("--no-overwrite", action="store_true",
        help="Development mode only: refuse to overwrite existing output CSV")
    parser.add_argument("--allow-mixed-commits", action="store_true",
        help="Allow client and server to run different git commits (formal mode)")
    parser.add_argument(
        "--server-only",
        action="store_true",
        help="Run as server only (listen for connections, do not run client experiments)",
    )
    return parser


def normalize_and_validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Apply mode implications and fail-fast CLI validation."""
    effective_formal = args.formal or args.formal_batch
    if args.formal_batch:
        args.formal = True
    if args.quick and effective_formal:
        parser.error("--quick and --formal/--formal-batch are mutually exclusive")

    if effective_formal:
        if args.allow_mixed_commits:
            print("[FORMAL] --allow-mixed-commits: skipping commit consistency check")
        if args.formal_batch:
            if args.repeat_id is None:
                parser.error("--formal-batch requires --repeat-id (1-20)")
            if not (1 <= args.repeat_id <= 20):
                parser.error("--repeat-id must be 1-20")
            if args.run_dir is None:
                parser.error("--formal-batch requires --run-dir (absolute path)")
            ensure_formal_batch_run_dir(parser, args.run_dir)
            if args.attempt_number_arg is None:
                parser.error("--formal-batch requires --attempt-number N (N must be 1, 2, or 3)")
            if args.attempt_number_arg not in (1, 2, 3):
                parser.error("--attempt-number must be 1, 2, or 3")
            args.repeats = 1
        else:
            if args.repeats is not None and args.repeats != 20:
                parser.error("--formal requires exactly 20 repeats (or omit for default 20)")


def resolve_output_csv(args: argparse.Namespace) -> str:
    if args.formal_batch and args.run_dir and args.repeat_id:
        return os.path.join(args.run_dir, f"cross_host_batch_r{args.repeat_id:02d}.csv")
    if args.quick:
        return os.path.join(OUTPUT_DIR, "cross_host_smoke.csv")
    if args.formal_batch:
        return os.path.join(OUTPUT_DIR, "cross_host_formal_batch.csv")
    if args.formal:
        return os.path.join(OUTPUT_DIR, "cross_host_results.csv")
    return os.path.join(OUTPUT_DIR, "cross_host_dev.csv")


def enforce_startup_output_guards(args: argparse.Namespace, output_csv: str) -> None:
    """Refuse stale success/tmp artifacts before any CSV is opened."""
    if args.formal_batch and os.path.exists(output_csv):
        print(f"[FATAL] formal-batch output already exists: {output_csv}")
        print("        Formal batch results are immutable; choose a clean run directory.")
        sys.exit(1)
    if getattr(args, "no_overwrite", False) and os.path.exists(output_csv):
        print(f"[FATAL] --no-overwrite: output file already exists: {output_csv}")
        print("        Remove it first or choose a different output path.")
        sys.exit(1)
    tmp_csv = output_csv + ".tmp"
    if os.path.exists(tmp_csv):
        print(f"[FATAL] stale tmp file already exists: {tmp_csv}")
        print("        Preserve or inspect it before starting a new run.")
        sys.exit(1)


def preserve_failed_artifact(tmp_path: str, failed_path: str) -> str:
    """Move tmp to a failed artifact without ever replacing an existing artifact."""
    tmp = Path(tmp_path)
    failed = Path(failed_path)
    if not tmp.exists():
        return str(failed)
    if not failed.exists():
        tmp.rename(failed)
        return str(failed)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    conflict = failed.with_name(f"{failed.stem}.conflict-{stamp}-{uuid4().hex[:8]}{failed.suffix}")
    tmp.rename(conflict)
    return str(conflict)


def publish_tmp_csv(tmp_csv: str, output_csv: str, no_overwrite: bool) -> None:
    """Publish tmp CSV, using no-overwrite semantics for formal outputs."""
    if no_overwrite:
        os.link(tmp_csv, output_csv)
        os.unlink(tmp_csv)
    else:
        os.replace(tmp_csv, output_csv)


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

    # Structured failure classification
    failure_type = ""  # connection_error | hello_error | socket_timeout | recv_error | exception

    start_time = time.time()
    sock = None
    file_obj = None

    try:
        sock, file_obj = open_tcp(server_host, server_port)

        # --- HELLO handshake ---
        # send_hello uses wire protocol names and validates the response
        try:
            ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
        except Exception as he:
            failure_type = "hello_error"
            raise

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
                failure_type = "socket_timeout"
                failure_reason = "socket_timeout"
                break  # Stop this run, don't continue with next seq
            except UnicodeDecodeError as ude:
                error_count += 1
                failure_type = "recv_error"
                failure_reason = f"UnicodeDecodeError: {ude}"
                break
            except Exception as e:
                error_count += 1
                failure_type = failure_type or "recv_error"
                failure_reason = str(e)
                break  # Stop this run, don't continue with next seq

    except socket.timeout:
        failure_type = failure_type or "connection_error"
        failure_reason = failure_reason or "connection_timeout"
        error_count = max(error_count, 1)
    except ConnectionRefusedError:
        failure_type = "connection_error"
        failure_reason = failure_reason or "connection_refused"
        error_count = max(error_count, 1)
    except OSError as oe:
        failure_type = "connection_error"
        failure_reason = failure_reason or f"OSError: {oe}"
        error_count = max(error_count, 1)
    except Exception as e:
        failure_type = failure_type or "exception"
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
    # Failed rows (adapter=None) get empty state_fields → match must be "" not True
    if adapter is None:
        memory_match = ""
        hash_match = ""
    else:
        memory_match = True
        hash_match = True
        if protocol == "gmcp_r":
            memory_match = (
                state_fields["client_final_mem"] == state_fields["server_final_mem"]
            ) and state_fields["client_final_mem"] != ""
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            hash_match = (
                state_fields["client_final_hash"] == state_fields["server_final_hash"]
            ) and state_fields["client_final_hash"] != ""

    partial_state_auditable = adapter is not None and accepted_count > 0
    final_state_complete = (
        run_valid
        and sent_count == message_count
        and accepted_count == message_count
        and unrecovered == 0
        and sequence_match
        and state_match
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
        "failure_type": failure_type,
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
        "state_auditable": partial_state_auditable,
        "partial_state_auditable": partial_state_auditable,
        "final_state_complete": final_state_complete,
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
        except UnicodeDecodeError as ude:
            print(f"[SERVER] UnicodeDecodeError from {addr}: {type(ude).__name__}: {ude}", flush=True)
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
    parser = build_arg_parser()
    args = parser.parse_args()
    normalize_and_validate_args(parser, args)

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

    output_csv = resolve_output_csv(args)
    output_parent = os.path.dirname(output_csv)
    if output_parent:
        os.makedirs(output_parent, exist_ok=True)
    enforce_startup_output_guards(args, output_csv)

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
        "timeout_count", "error_count", "failure_reason", "failure_type",
        "unrecovered",
        "client_final_seq", "server_final_seq", "sequence_match",
        "client_final_mem", "server_final_mem", "memory_match",
        "client_final_hash", "server_final_hash", "hash_match",
        "state_match", "state_auditable", "partial_state_auditable", "final_state_complete", "run_valid",
        "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
        "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
        "timestamp",
        "git_commit", "git_branch", "git_dirty",
        "client_python_version", "client_os_info", "client_cpu_model",
        "server_git_commit", "server_python_version", "server_os_info",
        "server_hostname", "server_git_dirty", "server_cpu_model",
        "attempt_number",
        "schema_version",
        "command_line",
    ]

    total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
    mode_label = "formal-batch" if args.formal_batch else ("formal" if args.formal else ("smoke" if args.quick else "default"))
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
    journal_path = (os.path.join(args.run_dir, "attempts.jsonl") if args.run_dir else output_csv + ".journal")
    journal_entries = []

    # --- Attempt number ---
    if args.formal_batch:
        _attempt_id = args.attempt_number_arg
    else:
        # Non-formal development modes may continue auto-detecting from journal.
        _attempt_id = 1
        if os.path.exists(journal_path):
            try:
                with open(journal_path, "r", encoding="utf-8") as jf:
                    for line in jf:
                        try:
                            entry = json.loads(line)
                            if entry.get("event") == "run_start":
                                _attempt_id += 1
                        except (json.JSONDecodeError, KeyError):
                            pass
            except Exception:
                pass  # fresh start
        if args.attempt_number_arg is not None:
            _attempt_id = args.attempt_number_arg

    if (args.formal_batch or args.attempt_number_arg is not None) and _attempt_id not in (1, 2, 3):
        parser.error("--attempt-number must be 1, 2, or 3")

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
                os.fsync(jf.fileno())
        except Exception as je:
            print(f"[JOURNAL] FATAL: failed to write journal: {je}")
            sys.exit(1)

    write_journal("run_start", total=total, mode=mode_label, output=output_csv, attempt_number=_attempt_id)

    # Batch mode: write to .tmp incrementally, flush after each experiment
    tmp_csv = output_csv + ".tmp"
    completed = 0
    failed = 0
    with open(tmp_csv, "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol in PROTOCOLS:
            for msg_count in MESSAGE_COUNTS:
                for payload_size in PAYLOAD_SIZES:
                    # Batch mode: single repeat_id from CLI; normal mode: range
                    repeat_range = [args.repeat_id] if args.formal_batch else range(1, repeats + 1)
                    for repeat_id in repeat_range:
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

                        # Inject metadata into each result
                        result["command_line"] = command_line
                        result["attempt_number"] = _attempt_id
                        result["schema_version"] = "2"

                        # Always write to CSV (failed rows preserved with run_valid=False)
                        writer.writerow(result)
                        f.flush()

                        # Journal: experiment_result for every experiment (success or fail)
                        if not result["run_valid"]:
                            failed += 1
                        else:
                            completed += 1
                        write_journal(
                            "experiment_result",
                            matrix_index=idx,
                            total=total,
                            protocol=protocol,
                            msg_count=msg_count,
                            payload_size=payload_size,
                            repeat_id=repeat_id,
                            sent_count=result["sent_count"],
                            attempt_number=_attempt_id,
                            client_git_commit=result.get("git_commit", ""),
                            server_git_commit=result.get("server_git_commit", ""),
                            client_host_id=result.get("client_host_id", ""),
                            server_hostname=result.get("server_hostname", ""),
                            schema_version=result.get("schema_version", ""),
                            run_valid=result["run_valid"],
                            accepted_count=result["accepted_count"],
                            rejected_count=result["rejected_count"],
                            timeout_count=result["timeout_count"],
                            error_count=result["error_count"],
                            failure_type=result.get("failure_type", ""),
                            failure_reason=result.get("failure_reason", ""),
                            state_auditable=result.get("state_auditable", False),
                            partial_state_auditable=result.get("partial_state_auditable", False),
                            final_state_complete=result.get("final_state_complete", False),
                            state_match=result.get("state_match", ""),
                            sequence_match=result.get("sequence_match", ""),
                            memory_match=result.get("memory_match", ""),
                            hash_match=result.get("hash_match", ""),
                            client_final_seq=result.get("client_final_seq", 0),
                            server_final_seq=result.get("server_final_seq", 0),
                            session_id=result.get("session_id", ""),
                        )

                        acc = result["accepted_count"]
                        rej = result["rejected_count"]
                        valid_mark = "OK" if result["run_valid"] else "INVALID"
                        print(
                            f"  [{idx}/{total}] {protocol} m={msg_count} "
                            f"p={payload_size} r={repeat_id}: "
                            f"accepted={acc} rejected={rej} "
                            f"rtt={result['avg_rtt_ms']:.1f}ms [{valid_mark}]"
                        )

    write_journal("run_end", completed=completed, failed=failed, total=total, attempt_number=_attempt_id)

    # Validate tmp file before atomic replace
    # NEVER delete tmp — on failure, rename to .failed.csv for forensics
    print(f"\n[VALIDATE] Checking {tmp_csv} ...")
    def fail_validation(message: str) -> None:
        failed_csv = tmp_csv.replace(".tmp", f"_attempt{_attempt_id:02d}.failed.csv")
        preserved_csv = preserve_failed_artifact(tmp_csv, failed_csv)
        print(message)
        print(f"[VALIDATE] Failed artifact: {preserved_csv}")
        if os.path.exists(preserved_csv):
            sha = hashlib.sha256(open(preserved_csv, "rb").read()).hexdigest()
            print(f"[VALIDATE] SHA-256: {sha}")
        sys.exit(1)

    try:
        with open(tmp_csv, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        expected_total = len(PROTOCOLS) * len(MESSAGE_COUNTS) * len(PAYLOAD_SIZES) * repeats
        if len(rows) != expected_total:
            fail_validation(f"[VALIDATE] FAIL: expected {expected_total} rows, got {len(rows)}")

        # Count valid vs invalid
        invalid_count = sum(1 for r in rows if r.get("run_valid") not in ("True", "true", True))
        valid_count = len(rows) - invalid_count

        # Fail-closed: any invalid row blocks formal publish
        if invalid_count > 0:
            fail_validation(f"[VALIDATE] FAIL: {invalid_count}/{len(rows)} rows have run_valid=False")

        all_clean = all(r.get("git_dirty") in ("false", "False", False) for r in rows)
        if not all_clean:
            fail_validation("[VALIDATE] FAIL: git_dirty is not false for all rows")
        # Formal mode: also check server_git_dirty and cross-host authenticity
        if args.formal:
            for i, r in enumerate(rows):
                # Skip failed rows for strict server-side checks
                if r.get("run_valid") not in ("True", "true", True):
                    continue
                # server_git_dirty strict check (no empty string allowed)
                server_dirty = r.get('server_git_dirty', '')
                if server_dirty not in ('false', 'False', False):
                    fail_validation(f"[VALIDATE] FAIL row {i+1}: server_git_dirty={server_dirty}")
                # server_git_commit must be 40-char hex
                serv_commit = r.get('server_git_commit', '')
                if len(serv_commit) != 40:
                    fail_validation(f"[VALIDATE] FAIL row {i+1}: server_git_commit length {len(serv_commit)} != 40")
                # Real cross-host: server_hostname must differ from client_host_id
                if r.get('server_hostname') == r.get('client_host_id'):
                    fail_validation(f"[VALIDATE] FAIL row {i+1}: client and server on same host")
                # Real cross-host: no loopback in formal data
                if r.get('network_path_type') == 'loopback':
                    fail_validation(f"[VALIDATE] FAIL row {i+1}: formal data cannot use loopback")
                # Commit consistency
                client_commit = r.get('git_commit', '')
                server_commit = r.get('server_git_commit', '')
                if not args.allow_mixed_commits and client_commit != server_commit:
                    fail_validation(f"[VALIDATE] FAIL row {i+1}: client commit {client_commit[:8]} != server commit {server_commit[:8]}")
            client_dirty = any(
                r.get("git_dirty") not in ("false", "False", False)
                for r in rows
            )
            if client_dirty:
                fail_validation("[VALIDATE] FAIL: client git_dirty is not false for all rows")
        print(f"[VALIDATE] OK: {len(rows)} rows ({valid_count} valid, {invalid_count} failed), git_dirty=false")
    except Exception as e:
        if os.path.exists(tmp_csv):
            fail_validation(f"[VALIDATE] FAIL: {e}")
        print(f"[VALIDATE] FAIL: {e}")
        sys.exit(1)

    publish_tmp_csv(tmp_csv, output_csv, no_overwrite=args.formal_batch or args.no_overwrite)
    print(f"\n[DONE] Results atomically written to {output_csv}")
    print(f"[DONE] {completed} experiments completed, {failed} failed.")
    if failed > 0:
        print(f"[WARN] {failed} experiments had errors and were preserved with run_valid=False.")
    print(f"[JOURNAL] Crash-recovery journal: {journal_path}")

    # --- Aggregator: print summary statistics ---
    aggregate_results(output_csv)


def aggregate_results(csv_path: str):
    """Read the output CSV and print per-protocol summary statistics.

    Called at the end of a run to provide a quick overview without
    requiring manual CSV inspection.
    """
    import csv as _csv
    from collections import defaultdict

    if not os.path.exists(csv_path):
        print("[AGGREGATE] No results file found — skipping summary.")
        return

    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        rows = list(_csv.DictReader(f))

    if not rows:
        print("[AGGREGATE] Empty results file — skipping summary.")
        return

    total = len(rows)
    valid = sum(1 for r in rows if r.get("run_valid") in ("True", "true", True))
    failed = total - valid

    print(f"\n{'='*72}")
    print(f"AGGREGATE RESULTS — {csv_path}")
    print(f"{'='*72}")
    print(f"Total rows: {total}   Valid: {valid}   Failed: {failed}")
    print()

    # Group by protocol
    by_protocol: Dict[str, list] = defaultdict(list)
    for r in rows:
        by_protocol[r.get("protocol", "unknown")].append(r)

    header = f"{'Protocol':<22} {'N':>4} {'Valid':>5} {'Acc%':>7} {'RTT p50':>8} {'RTT p99':>8} {'TPut':>10}"
    print(header)
    print("-" * len(header))

    for proto in sorted(by_protocol.keys()):
        proto_rows = by_protocol[proto]
        n = len(proto_rows)
        n_valid = sum(1 for r in proto_rows if r.get("run_valid") in ("True", "true", True))

        acc_rates = []
        p50s = []
        p99s = []
        tputs = []
        for r in proto_rows:
            try:
                acc_rates.append(float(r.get("success_rate", 0)))
                p50s.append(float(r.get("p50_rtt_ms", 0)))
                p99s.append(float(r.get("p99_rtt_ms", 0)))
                tputs.append(float(r.get("throughput_msg_per_sec", 0)))
            except (ValueError, TypeError):
                pass

        avg_acc = sum(acc_rates) / len(acc_rates) if acc_rates else 0
        med_p50 = sorted(p50s)[len(p50s) // 2] if p50s else 0
        med_p99 = sorted(p99s)[len(p99s) // 2] if p99s else 0
        avg_tput = sum(tputs) / len(tputs) if tputs else 0

        print(
            f"{proto:<22} {n:>4} {n_valid:>5} {avg_acc:>6.1f}% "
            f"{med_p50:>7.1f} {med_p99:>7.1f} {avg_tput:>9.1f}"
        )

    print(f"{'='*72}\n")


if __name__ == "__main__":
    main()
