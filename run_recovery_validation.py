#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一跨协议恢复实验验证框架
============================

在指定断线点执行连接断开/重连，验证各协议的恢复行为。

矩阵：
  3 protocols × 3 disconnect_points × 2 disconnect_types × 10 repeats = 180 rows

使用方法：
  python run_recovery_validation.py --run-dir /path/to/results --quick
  python run_recovery_validation.py --run-dir /path/to/results --formal --attempt-number 1
  python run_recovery_validation.py --server-only --port 9003

关键设计：
  - 每个(protocol, disconnect_point, disconnect_type, repeat_id)组合独立执行
  - 断线前发送disconnect_point条消息，断线后重新连接继续发送剩余消息
  - client_close: 客户端主动关闭socket
  - server_close: 服务端在收到disconnect_point条消息后主动关闭连接
  - 使用嵌入式server，支持所有断线类型
  - 原子发布：tmp独占创建 → 验证 → link发布
  - 失败时rename为.failed.csv保留诊断信息
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import signal
import socket
import sys
import threading
import time
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

from gmcp.baselines.seq_mac import SeqMACVerifier, create_initial_state as sm_init_state
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState,
    AuthHashChainVerifier,
)
from gmcp.baselines.hash_chain import (
    HashChainState,
    HashChainVerifier,
    hash_func as hc_hash_func,
)

from gmcp.experiment_transport import (
    ProtocolAdapter,
    send_hello,
    send_json_line,
    recv_json_line,
    get_git_commit as _transport_get_git_commit,
    get_git_dirty as _transport_get_git_dirty,
    get_git_metadata,
    get_server_env_info,
    get_cpu_model,
    WIRE_PROTOCOL_NAMES,
    DISPLAY_PROTOCOL_NAMES,
    ALL_PROTOCOLS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPEAT_COUNT = 10
SOCKET_TIMEOUT = 10.0
RECONNECT_DELAY_MS = 100

PROTOCOLS = ["gmcp_r", "seq_mac", "authenticated_hash_chain"]
DISCONNECT_POINTS = [50, 250, 450]
DISCONNECT_TYPES = ["client_close", "server_close"]

SCHEMA_VERSION = "2"

# ---------------------------------------------------------------------------
# Git / provenance helpers
# ---------------------------------------------------------------------------

def get_git_commit() -> str:
    """Return full 40-char SHA."""
    return _transport_get_git_commit()


def get_git_dirty() -> bool:
    return _transport_get_git_dirty()


def get_host_id() -> str:
    import platform as _plat
    return _plat.node() or socket.gethostname() or "unknown-host"


# ---------------------------------------------------------------------------
# Path / output protection
# ---------------------------------------------------------------------------

def _find_enclosing_git_root(path: Path) -> Optional[Path]:
    """Return the nearest enclosing Git root for path."""
    resolved = path.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def validate_run_dir(parser: argparse.ArgumentParser, run_dir: str) -> Path:
    """Validate --run-dir is absolute and outside any Git repository."""
    path = Path(run_dir)
    if not path.is_absolute():
        parser.error(f"--run-dir must be an absolute path, got: {run_dir}")

    # Ensure directory exists
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"--run-dir could not be created: {exc}")

    # Check not inside git repo
    git_root = _find_enclosing_git_root(path)
    if git_root is not None:
        parser.error(f"--run-dir must not be inside a Git repository: {git_root}")

    # Verify writable via exclusive probe
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


def publish_tmp_no_clobber(tmp_path: str, final_path: str) -> None:
    """Atomically publish tmp to final without overwriting existing final."""
    os.link(tmp_path, final_path)
    os.unlink(tmp_path)


def preserve_failed_artifact(tmp_path: str, failed_path: str) -> str:
    """Move tmp to a failed artifact without ever replacing existing."""
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


def enforce_startup_output_guards(output_csv: str, no_overwrite: bool) -> None:
    """Refuse stale success/tmp artifacts before any CSV is opened."""
    if no_overwrite and os.path.exists(output_csv):
        print(f"[FATAL] --no-overwrite: output file already exists: {output_csv}")
        sys.exit(1)
    tmp_csv = output_csv + ".tmp"
    if os.path.exists(tmp_csv):
        print(f"[FATAL] stale tmp file already exists: {tmp_csv}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# TCP helpers
# ---------------------------------------------------------------------------

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
# Payload
# ---------------------------------------------------------------------------

def make_payload(seq: int, payload_size: int) -> str:
    prefix = "recovery-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


# ---------------------------------------------------------------------------
# Single recovery experiment
# ---------------------------------------------------------------------------

def run_one_recovery_experiment(
    protocol: str,
    message_count: int,
    payload_size: int,
    disconnect_point: int,
    disconnect_type: str,
    repeat_id: int,
    server_host: str,
    server_port: int,
    git_meta: Dict[str, str],
) -> Dict[str, Any]:
    """
    Run one recovery experiment: connect → send messages → disconnect → reconnect → continue.

    Returns a result dict with all required CSV fields.
    """

    session_id = (
        f"recovery-{protocol}-d{disconnect_point}-{disconnect_type}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

    # Pre-disconnect tracking
    pre_disconnect_sent = 0
    pre_disconnect_accepted = 0
    # Post-disconnect tracking
    post_disconnect_sent = 0
    post_disconnect_accepted = 0
    # Totals
    total_rejected = 0
    total_timeout = 0
    total_error = 0
    duplicate_count = 0
    unrecovered_count = 0
    reconnect_success = False
    reconnect_latency_ms = 0.0

    failure_type = ""
    failure_reason = ""
    failure_timestamp = ""

    # State tracking (will be set after adapter creation)
    final_client_seq = 0
    final_server_seq = 0
    memory_match = ""
    hash_match = ""
    final_state_match = False
    final_sequence_match = False

    start_time = time.time()

    # --- Phase 1: Pre-disconnect ---
    sock1 = None
    file_obj1 = None
    adapter1 = None
    server_env = {}

    try:
        sock1, file_obj1 = open_tcp(server_host, server_port)

        # HELLO handshake (phase 1)
        try:
            ack = send_hello(sock1, file_obj1, protocol, session_id, CLIENT_ID, EPOCH)
        except Exception as he:
            failure_type = "hello_error"
            failure_timestamp = datetime.now(timezone.utc).isoformat()
            raise

        server_env = {
            "server_git_commit": ack.get("server_git_commit", ""),
            "server_python_version": ack.get("server_python_version", ""),
            "server_os_info": ack.get("server_os_info", ""),
            "server_hostname": ack.get("server_hostname", ""),
            "server_git_dirty": ack.get("server_git_dirty", ""),
            "server_cpu_model": ack.get("server_cpu_model", ""),
        }

        adapter1 = ProtocolAdapter(
            protocol=protocol,
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
        )

        for seq in range(1, disconnect_point + 1):
            payload = make_payload(seq, payload_size)
            packet = adapter1.build_packet(seq, payload)

            send_json_line(sock1, packet)
            pre_disconnect_sent += 1

            try:
                response = recv_json_line(file_obj1)
                if response.get("ok"):
                    pre_disconnect_accepted += 1
                    adapter1.update_after_accept(packet, response)
                else:
                    total_rejected += 1
            except socket.timeout:
                total_timeout += 1
                failure_type = "socket_timeout"
                failure_reason = "pre_disconnect_timeout"
                failure_timestamp = datetime.now(timezone.utc).isoformat()
                break
            except Exception as e:
                total_error += 1
                failure_type = failure_type or "recv_error"
                failure_reason = str(e)
                failure_timestamp = datetime.now(timezone.utc).isoformat()
                break

    except socket.timeout:
        failure_type = failure_type or "connection_error"
        failure_reason = failure_reason or "connection_timeout"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except ConnectionRefusedError:
        failure_type = "connection_error"
        failure_reason = "connection_refused"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except OSError as oe:
        failure_type = failure_type or "connection_error"
        failure_reason = failure_reason or f"OSError: {oe}"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        failure_type = failure_type or "exception"
        failure_reason = failure_reason or str(e)
        failure_timestamp = datetime.now(timezone.utc).isoformat()

    # --- Phase 2: Disconnect ---
    disconnect_success = True
    if disconnect_type == "client_close":
        close_tcp(sock1, file_obj1)
        sock1, file_obj1 = None, None
    elif disconnect_type == "server_close":
        # Server close: we need to tell the server to close.
        # The embedded server will close when it receives disconnect_point messages.
        # For client_close, we just close the socket ourselves.
        # For server_close with external server, we send a special DISCONNECT message
        # to signal the server to close the connection.
        if disconnect_type == "server_close":
            try:
                # Send disconnect signal to server
                disconnect_msg = {
                    "type": "DISCONNECT",
                    "session_id": session_id,
                    "at_seq": disconnect_point,
                }
                send_json_line(sock1, disconnect_msg)
                # Server should close, try to read and expect error
                try:
                    recv_json_line(file_obj1)
                except (ConnectionError, socket.timeout, json.JSONDecodeError):
                    pass
            except Exception:
                pass
            close_tcp(sock1, file_obj1)
            sock1, file_obj1 = None, None

    # Wait before reconnecting
    time.sleep(RECONNECT_DELAY_MS / 1000.0)

    # --- Phase 3: Reconnect and continue ---
    sock2 = None
    file_obj2 = None
    adapter2 = None

    try:
        reconnect_start = time.perf_counter()
        sock2, file_obj2 = open_tcp(server_host, server_port)
        reconnect_latency_ms = (time.perf_counter() - reconnect_start) * 1000.0
        reconnect_success = True

        # HELLO handshake (phase 2) — new session for recovery
        session_id_2 = session_id + "-reconnected"
        ack2 = send_hello(sock2, file_obj2, protocol, session_id_2, CLIENT_ID, EPOCH)

        adapter2 = ProtocolAdapter(
            protocol=protocol,
            session_id=session_id_2,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
        )

        for seq in range(disconnect_point + 1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = adapter2.build_packet(seq, payload)

            send_json_line(sock2, packet)
            post_disconnect_sent += 1

            try:
                response = recv_json_line(file_obj2)
                if response.get("ok"):
                    post_disconnect_accepted += 1
                    adapter2.update_after_accept(packet, response)
                else:
                    total_rejected += 1
            except socket.timeout:
                total_timeout += 1
                failure_type = failure_type or "socket_timeout"
                failure_reason = failure_reason or "post_disconnect_timeout"
                failure_timestamp = failure_timestamp or datetime.now(timezone.utc).isoformat()
                break
            except Exception as e:
                total_error += 1
                failure_type = failure_type or "recv_error"
                failure_reason = failure_reason or str(e)
                failure_timestamp = failure_timestamp or datetime.now(timezone.utc).isoformat()
                break

    except Exception as e:
        reconnect_success = False
        failure_type = failure_type or "reconnect_error"
        failure_reason = failure_reason or str(e)
        failure_timestamp = failure_timestamp or datetime.now(timezone.utc).isoformat()

    finally:
        close_tcp(sock2, file_obj2)

    # --- Compute results ---
    total_sent = pre_disconnect_sent + post_disconnect_sent
    total_accepted = pre_disconnect_accepted + post_disconnect_accepted
    unrecovered_count = message_count - total_accepted

    # Use adapter2 (post-reconnect) for final state
    if adapter2 is not None and adapter2.last_seq > 0:
        final_client_seq = adapter2.last_seq
        final_server_seq = adapter2.server_state.get("last_seq", 0)
        final_state_match = adapter2.check_state_match()
        final_sequence_match = (final_client_seq == message_count)

        state_fields = adapter2.get_final_state_for_csv()
        if protocol == "gmcp_r":
            memory_match = (
                state_fields["client_final_mem"] == state_fields["server_final_mem"]
                and state_fields["client_final_mem"] != ""
            )
        elif protocol == "authenticated_hash_chain":
            hash_match = (
                state_fields["client_final_hash"] == state_fields["server_final_hash"]
                and state_fields["client_final_hash"] != ""
            )
    elif adapter1 is not None:
        final_client_seq = adapter1.last_seq
        final_server_seq = adapter1.server_state.get("last_seq", 0)
        final_sequence_match = (final_client_seq == disconnect_point)

    state_auditable = adapter2 is not None and post_disconnect_accepted > 0
    final_state_complete = (
        reconnect_success
        and total_accepted == message_count
        and unrecovered_count == 0
        and final_sequence_match
        and final_state_match
    )

    elapsed = time.time() - start_time

    execution_valid = total_accepted == message_count and unrecovered_count == 0
    result_success = execution_valid and reconnect_success
    run_valid = result_success and final_state_match

    result = {
        "session_id": session_id,
        "experiment_type": "recovery_validation",
        "protocol": protocol,
        "message_count": message_count,
        "payload_size": payload_size,
        "disconnect_point": disconnect_point,
        "disconnect_type": disconnect_type,
        "repeat_id": repeat_id,
        "pre_disconnect_sent": pre_disconnect_sent,
        "pre_disconnect_accepted": pre_disconnect_accepted,
        "post_disconnect_sent": post_disconnect_sent,
        "post_disconnect_accepted": post_disconnect_accepted,
        "total_sent": total_sent,
        "total_accepted": total_accepted,
        "total_rejected": total_rejected,
        "total_timeout": total_timeout,
        "duplicate_count": duplicate_count,
        "unrecovered_count": unrecovered_count,
        "reconnect_success": reconnect_success,
        "reconnect_latency_ms": round(reconnect_latency_ms, 2),
        "final_state_match": final_state_match,
        "final_sequence_match": final_sequence_match,
        "final_client_seq": final_client_seq,
        "final_server_seq": final_server_seq,
        "memory_match": memory_match if protocol == "gmcp_r" else "",
        "hash_match": hash_match if protocol == "authenticated_hash_chain" else "",
        "execution_valid": execution_valid,
        "result_success": result_success,
        "run_valid": run_valid,
        "failure_type": failure_type,
        "failure_reason": failure_reason,
        "failure_timestamp": failure_timestamp,
        "state_auditable": state_auditable,
        "final_state_complete": final_state_complete,
        "schema_version": SCHEMA_VERSION,
        # Provenance
        "client_git_commit": git_meta.get("git_commit", ""),
        "server_git_commit": server_env.get("server_git_commit", ""),
        "client_git_dirty": git_meta.get("git_dirty", ""),
        "server_git_dirty": server_env.get("server_git_dirty", ""),
        "client_hostname": get_host_id(),
        "server_hostname": server_env.get("server_hostname", ""),
        # Timestamps
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 3),
    }

    return result


# ---------------------------------------------------------------------------
# Embedded TCP server
# ---------------------------------------------------------------------------

class EmbeddedTCPServer:
    """
    Lightweight TCP server that handles PING, HELLO, DATA, and DISCONNECT.

    For server_close disconnect type: when a DISCONNECT message is received
    with at_seq, the server closes the connection after receiving that many
    DATA messages.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._protocols: Dict[str, str] = {}
        self._verifiers: Dict[str, Any] = {}
        self._disconnect_points: Dict[str, int] = {}  # session_id -> disconnect_at_seq
        self._data_counts: Dict[str, int] = {}  # session_id -> received DATA count
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
                    self._send(conn, {"ok": True, "type": "PONG", "server_time": time.time()})
                elif ptype == "HELLO":
                    self._handle_hello(conn, packet)
                elif ptype == "DATA":
                    self._handle_data(conn, packet)
                elif ptype == "DISCONNECT":
                    self._handle_disconnect(conn, packet)
                else:
                    self._send(conn, {"ok": False, "reason": f"unknown type: {ptype}"})
        except UnicodeDecodeError:
            pass
        except (ConnectionError, socket.timeout, OSError):
            pass
        finally:
            close_tcp(conn, file_obj)

    def _handle_hello(self, conn: socket.socket, packet: Dict[str, Any]):
        """Process HELLO handshake."""
        received_tag = packet.get("auth_tag", "")
        if not received_tag:
            self._send(conn, {"ok": False, "reason": "missing auth_tag"})
            return
        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            self._send(conn, {"ok": False, "reason": "auth_tag verification failed"})
            return

        wire_protocol = packet.get("protocol", "")
        display_protocol = DISPLAY_PROTOCOL_NAMES.get(wire_protocol, wire_protocol)
        session_id = packet.get("session_id", "")
        sender_id = packet.get("sender_id", "")
        epoch = int(packet.get("epoch", 0))

        if not session_id:
            self._send(conn, {"ok": False, "reason": "missing session_id"})
            return

        if display_protocol not in ALL_PROTOCOLS:
            self._send(conn, {"ok": False, "reason": f"unsupported protocol: {wire_protocol}"})
            return

        with self._lock:
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
            self._data_counts[session_id] = 0

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
                state = sm_init_state(session_id, sender_id, epoch)
                self._verifiers[session_id] = SeqMACVerifier(state)

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

        print(f"  [HELLO] session={session_id} protocol={display_protocol} (wire={wire_protocol})")

        ack: Dict[str, Any] = {
            "ok": True,
            "type": "HELLO_ACK",
            "session_id": session_id,
            "protocol": wire_protocol,
        }
        ack.update(get_server_env_info())
        self._send(conn, ack)

    def _handle_data(self, conn: socket.socket, packet: Dict[str, Any]):
        """Process DATA packet."""
        session_id = packet.get("session_id", "unknown")

        with self._lock:
            verifier = self._verifiers.get(session_id)
            protocol = self._protocols.get(session_id, "")

            if session_id in self._data_counts:
                self._data_counts[session_id] += 1

            # Check if we should disconnect (server_close)
            disconnect_at = self._disconnect_points.get(session_id, -1)
            current_count = self._data_counts.get(session_id, 0)

        if verifier is None:
            self._send(conn, {"ok": False, "reason": "no HELLO received for this session"})
            return

        ok, reason = verifier.verify_data_packet(packet)

        resp: Dict[str, Any] = {"ok": ok, "reason": reason}

        if protocol == "gmcp_r":
            resp["last_seq"] = verifier.state.last_seq
            resp["last_mem"] = verifier.state.last_mem
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            resp["last_seq"] = verifier.state.last_seq
            resp["last_hash"] = verifier.state.last_hash
        elif protocol in ("seq_mac",):
            resp["last_seq"] = verifier.state.last_seq

        self._send(conn, resp)

        # Server close: close connection after receiving disconnect_at messages
        if disconnect_at > 0 and current_count >= disconnect_at:
            print(f"  [SERVER_CLOSE] session={session_id} at count={current_count}")
            with self._lock:
                self._disconnect_points.pop(session_id, None)
            try:
                conn.close()
            except Exception:
                pass

    def _handle_disconnect(self, conn: socket.socket, packet: Dict[str, Any]):
        """Handle DISCONNECT message for server_close type."""
        session_id = packet.get("session_id", "")
        at_seq = int(packet.get("at_seq", 0))

        with self._lock:
            self._disconnect_points[session_id] = at_seq

        self._send(conn, {"ok": True, "type": "DISCONNECT_ACK"})

    @staticmethod
    def _send(conn: socket.socket, resp: Dict[str, Any]):
        raw = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            conn.sendall(raw)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GMCP-R unified cross-protocol recovery validation"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9003, help="Server port (default: 9003)")
    parser.add_argument("--interface", default="lo", help="Network interface for tc/netem")
    parser.add_argument("--protocols", default=None,
        help="Comma-separated protocols (default: gmcp_r,seq_mac,authenticated_hash_chain)")
    parser.add_argument("--disconnect-points", default=None,
        help="Comma-separated disconnect points (default: 50,250,450)")
    parser.add_argument("--disconnect-types", default=None,
        help="Comma-separated disconnect types (default: client_close,server_close)")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument("--message-count", type=int, default=500, help="Total message count")
    parser.add_argument("--payload-size", type=int, default=128, help="Payload size in bytes")
    parser.add_argument("--formal", action="store_true", help="Formal mode: full matrix")
    parser.add_argument("--quick", action="store_true", help="Quick mode: 1 repeat, 2 disconnect points")
    parser.add_argument("--run-dir", type=str, default=None,
        help="Absolute path for output directory (required)")
    parser.add_argument("--attempt-number", type=int, default=None,
        help="Attempt number (1, 2, or 3)")
    parser.add_argument("--no-overwrite", action="store_true",
        help="Refuse to overwrite existing output CSV")
    parser.add_argument("--server-only", action="store_true",
        help="Run as server only")
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # --- Server-only mode ---
    if args.server_only:
        server_port = args.port
        print(f"[SERVER-ONLY] Starting server on {args.host}:{server_port}")
        srv = EmbeddedTCPServer(args.host, server_port)
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

    # --- Validate --run-dir ---
    if args.run_dir is None:
        parser.error("--run-dir is required")

    run_dir_path = validate_run_dir(parser, args.run_dir)

    # --- Parse matrix parameters ---
    protocols = PROTOCOLS
    if args.protocols:
        protocols = [p.strip() for p in args.protocols.split(",")]

    disconnect_points = DISCONNECT_POINTS
    if args.disconnect_points:
        disconnect_points = [int(x.strip()) for x in args.disconnect_points.split(",")]

    disconnect_types = DISCONNECT_TYPES
    if args.disconnect_types:
        disconnect_types = [t.strip() for t in args.disconnect_types.split(",")]

    repeats = args.repeats or REPEAT_COUNT
    if args.quick:
        repeats = 1
        disconnect_points = disconnect_points[:2]  # Use first 2 disconnect points

    message_count = args.message_count
    payload_size = args.payload_size

    # --- Output CSV path ---
    if args.quick:
        output_csv = os.path.join(str(run_dir_path), "recovery_smoke.csv")
    elif args.formal:
        output_csv = os.path.join(str(run_dir_path), "recovery_validation_results.csv")
    else:
        output_csv = os.path.join(str(run_dir_path), "recovery_dev.csv")

    os.makedirs(os.path.dirname(output_csv) or str(run_dir_path), exist_ok=True)
    enforce_startup_output_guards(output_csv, args.no_overwrite)

    # --- Git metadata ---
    git_meta = get_git_metadata()
    git_meta["client_cpu_model"] = get_cpu_model()

    commit = git_meta.get("git_commit", "")
    if not commit or len(commit) != 40:
        print(f"[FATAL] client git_commit must be 40-char hex, got: {commit!r}")
        sys.exit(1)
    dirty = git_meta.get("git_dirty", "false")
    if dirty not in ("false", False):
        print(f"[FATAL] client git_dirty={dirty}, must be clean for formal runs")
        sys.exit(1)

    print(f"[INFO] Git commit: {commit[:12]}")
    print(f"[INFO] Git dirty:  {dirty}")

    # --- Attempt number ---
    attempt_number = args.attempt_number or 1
    if args.attempt_number is not None and attempt_number not in (1, 2, 3):
        parser.error("--attempt-number must be 1, 2, or 3")

    # --- Spawn embedded server ---
    server_host = args.host
    server_port = args.port
    print(f"[MODE] Spawning embedded server on {server_host}:{server_port}")
    srv = EmbeddedTCPServer(server_host, server_port)
    srv.start()
    time.sleep(0.3)

    # --- Compute matrix ---
    total = len(protocols) * len(disconnect_points) * len(disconnect_types) * repeats
    print(f"[INFO] Mode: {'quick' if args.quick else ('formal' if args.formal else 'default')}")
    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {protocols}")
    print(f"[INFO] Disconnect points: {disconnect_points}")
    print(f"[INFO] Disconnect types: {disconnect_types}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Message count: {message_count}")
    print(f"[INFO] Payload size: {payload_size}")
    print(f"[INFO] Output: {output_csv}")

    # --- Fieldnames ---
    fieldnames = [
        "session_id", "experiment_type", "protocol",
        "message_count", "payload_size",
        "disconnect_point", "disconnect_type",
        "repeat_id",
        "pre_disconnect_sent", "pre_disconnect_accepted",
        "post_disconnect_sent", "post_disconnect_accepted",
        "total_sent", "total_accepted", "total_rejected", "total_timeout",
        "duplicate_count", "unrecovered_count",
        "reconnect_success", "reconnect_latency_ms",
        "final_state_match", "final_sequence_match",
        "final_client_seq", "final_server_seq",
        "memory_match", "hash_match",
        "execution_valid", "result_success", "run_valid",
        "failure_type", "failure_reason", "failure_timestamp",
        "state_auditable", "final_state_complete",
        "schema_version",
        "client_git_commit", "server_git_commit",
        "client_git_dirty", "server_git_dirty",
        "client_hostname", "server_hostname",
        "attempt_number",
        "timestamp", "elapsed_seconds",
    ]

    # --- Write CSV ---
    tmp_csv = output_csv + ".tmp"
    completed = 0
    failed = 0

    with open(tmp_csv, "x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol in protocols:
            for disconnect_point in disconnect_points:
                for disconnect_type in disconnect_types:
                    for repeat_id in range(1, repeats + 1):
                        idx = completed + failed + 1

                        result = run_one_recovery_experiment(
                            protocol=protocol,
                            message_count=message_count,
                            payload_size=payload_size,
                            disconnect_point=disconnect_point,
                            disconnect_type=disconnect_type,
                            repeat_id=repeat_id,
                            server_host=server_host,
                            server_port=server_port,
                            git_meta=git_meta,
                        )
                        result["attempt_number"] = attempt_number

                        writer.writerow(result)
                        f.flush()

                        if not result["run_valid"]:
                            failed += 1
                        else:
                            completed += 1

                        acc = result["total_accepted"]
                        valid_mark = "OK" if result["run_valid"] else "INVALID"
                        print(
                            f"  [{idx}/{total}] {protocol} d={disconnect_point} "
                            f"t={disconnect_type} r={repeat_id}: "
                            f"accepted={acc}/{message_count} [{valid_mark}]"
                        )

    srv.stop()

    # --- Validate tmp file ---
    print(f"\n[VALIDATE] Checking {tmp_csv} ...")
    try:
        with open(tmp_csv, "r", newline="", encoding="utf-8") as vf:
            rows = list(csv.DictReader(vf))

        expected_total = len(protocols) * len(disconnect_points) * len(disconnect_types) * repeats
        if len(rows) != expected_total:
            failed_csv = tmp_csv.replace(".tmp", f"_attempt{attempt_number:02d}.failed.csv")
            preserved = preserve_failed_artifact(tmp_csv, failed_csv)
            print(f"[VALIDATE] FAIL: expected {expected_total} rows, got {len(rows)}")
            print(f"[VALIDATE] Failed artifact: {preserved}")
            sys.exit(1)

        # Check git_commit 40-char
        for i, r in enumerate(rows):
            gc = r.get("client_git_commit", "")
            if len(gc) != 40:
                failed_csv = tmp_csv.replace(".tmp", f"_attempt{attempt_number:02d}.failed.csv")
                preserved = preserve_failed_artifact(tmp_csv, failed_csv)
                print(f"[VALIDATE] FAIL row {i+1}: client_git_commit length {len(gc)} != 40")
                sys.exit(1)

        print(f"[VALIDATE] OK: {len(rows)} rows ({completed} valid, {failed} failed)")
    except Exception as e:
        failed_csv = tmp_csv.replace(".tmp", f"_attempt{attempt_number:02d}.failed.csv")
        preserved = preserve_failed_artifact(tmp_csv, failed_csv)
        print(f"[VALIDATE] FAIL: {e}")
        print(f"[VALIDATE] Failed artifact: {preserved}")
        sys.exit(1)

    # --- Atomic publish ---
    publish_tmp_no_clobber(tmp_csv, output_csv)
    print(f"\n[DONE] Results atomically written to {output_csv}")
    print(f"[DONE] {completed} experiments completed, {failed} failed.")

    sha = hashlib.sha256(open(output_csv, "rb").read()).hexdigest()
    print(f"[DONE] SHA-256: {sha}")


if __name__ == "__main__":
    main()
