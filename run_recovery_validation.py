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
import re
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

# ---------------------------------------------------------------------------
# GMCP-R imports
# ---------------------------------------------------------------------------
from gmcp.config import (
    DATA_AUTH_KEY,
    EPOCH,
    CLIENT_ID,
)
from gmcp.crypto_utils import verify_tagged_hmac, with_hmac
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
    DISPLAY_PROTOCOL_NAMES,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPEAT_COUNT = 10
SOCKET_TIMEOUT = 10.0
RECONNECT_DELAY_MS = 100
FIXED_MESSAGE_COUNT = 500
FIXED_PAYLOAD_SIZE = 128

PROTOCOLS = ["gmcp_r", "seq_mac", "authenticated_hash_chain"]
DISCONNECT_POINTS = [50, 250, 450]
DISCONNECT_TYPES = ["client_close", "server_close"]

SCHEMA_VERSION = "2"
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

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


def enforce_startup_output_guards(output_csv: str, protect_final: bool) -> None:
    """Refuse stale success/tmp artifacts before any CSV is opened."""
    if protect_final and os.path.exists(output_csv):
        print(f"[FATAL] output file already exists: {output_csv}")
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


def _is_clean_dirty_value(value: Any) -> bool:
    return value is False or str(value).strip().lower() == "false"


def provenance_is_valid(
    client_commit: Any,
    server_commit: Any,
    client_dirty: Any,
    server_dirty: Any,
) -> bool:
    client = str(client_commit or "")
    server = str(server_commit or "")
    return (
        COMMIT_RE.fullmatch(client) is not None
        and COMMIT_RE.fullmatch(server) is not None
        and client == server
        and _is_clean_dirty_value(client_dirty)
        and _is_clean_dirty_value(server_dirty)
    )


def _send_authenticated_control(
    sock: socket.socket,
    file_obj,
    payload: Dict[str, Any],
    expected_type: str,
) -> Dict[str, Any]:
    send_json_line(sock, with_hmac(DATA_AUTH_KEY, payload))
    response = recv_json_line(file_obj)
    if not verify_tagged_hmac(DATA_AUTH_KEY, response):
        raise RuntimeError(f"unauthenticated {expected_type} response")
    if response.get("type") != expected_type:
        raise RuntimeError(
            f"expected {expected_type}, got {response.get('type', '')}"
        )
    if not response.get("ok"):
        raise RuntimeError(
            f"{expected_type} rejected: {response.get('reason', 'unknown')}"
        )
    return response


def arm_server_close(
    sock: socket.socket,
    file_obj,
    session_id: str,
    disconnect_point: int,
) -> Dict[str, Any]:
    """Arm a server-initiated close before the first DATA packet."""
    return _send_authenticated_control(
        sock,
        file_obj,
        {
            "type": "ARM_SERVER_CLOSE",
            "session_id": session_id,
            "disconnect_point": disconnect_point,
        },
        "ARM_SERVER_CLOSE_ACK",
    )


def request_final_state(
    sock: socket.socket,
    file_obj,
    session_id: str,
    message_count: int,
) -> Dict[str, Any]:
    """Read authenticated server counters and final protocol state."""
    return _send_authenticated_control(
        sock,
        file_obj,
        {
            "type": "FINAL_STATE",
            "session_id": session_id,
            "message_count": message_count,
        },
        "FINAL_STATE_ACK",
    )


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
    reconnect_session_id = ""
    same_session_resume = False
    server_resume_seq = -1
    resume_state_match = False
    resumed_from_existing_state = False

    disconnect_armed = False
    disconnect_triggered = False
    disconnect_initiator = ""
    disconnect_observed = False
    disconnect_observed_seq = 0
    disconnect_boundary = ""
    post_reconnect_first_seq = 0

    server_total_received = 0
    server_unique_accepted = 0
    server_duplicate_count = 0
    server_rejected_count = 0
    missing_seq_count = message_count
    client_server_count_match = False
    final_state_response: Dict[str, Any] = {}
    hello1_ok = False
    hello2_ok = False
    internal_exception = False

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
            hello1_ok = True
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

        if disconnect_type == "server_close":
            arm_ack = arm_server_close(
                sock1, file_obj1, session_id, disconnect_point
            )
            disconnect_armed = bool(arm_ack.get("armed"))

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
                internal_exception = True
                failure_type = "socket_timeout"
                failure_reason = "pre_disconnect_timeout"
                failure_timestamp = datetime.now(timezone.utc).isoformat()
                break
            except Exception as e:
                total_error += 1
                internal_exception = True
                failure_type = failure_type or "recv_error"
                failure_reason = str(e)
                failure_timestamp = datetime.now(timezone.utc).isoformat()
                break

    except socket.timeout:
        internal_exception = True
        failure_type = failure_type or "connection_error"
        failure_reason = failure_reason or "connection_timeout"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except ConnectionRefusedError:
        internal_exception = True
        failure_type = "connection_error"
        failure_reason = "connection_refused"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except OSError as oe:
        internal_exception = True
        failure_type = failure_type or "connection_error"
        failure_reason = failure_reason or f"OSError: {oe}"
        failure_timestamp = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        internal_exception = True
        failure_type = failure_type or "exception"
        failure_reason = failure_reason or str(e)
        failure_timestamp = datetime.now(timezone.utc).isoformat()

    # --- Phase 2: Disconnect ---
    if disconnect_type == "client_close":
        disconnect_initiator = "client"
        disconnect_triggered = pre_disconnect_accepted == disconnect_point
        disconnect_observed = disconnect_triggered
        disconnect_observed_seq = disconnect_point if disconnect_observed else 0
        disconnect_boundary = "after_ack" if disconnect_observed else ""
        close_tcp(sock1, file_obj1)
        sock1, file_obj1 = None, None
    elif disconnect_type == "server_close":
        disconnect_initiator = "server"
        try:
            unexpected = recv_json_line(file_obj1)
            failure_type = failure_type or "disconnect_error"
            failure_reason = failure_reason or (
                f"server_close not observed; received {unexpected.get('type', 'packet')}"
            )
        except (ConnectionError, OSError):
            disconnect_observed = True
            disconnect_observed_seq = disconnect_point
            disconnect_boundary = "after_ack"
        except socket.timeout:
            total_timeout += 1
            failure_type = failure_type or "disconnect_timeout"
            failure_reason = failure_reason or "server_close was not observed"
        except Exception as exc:
            failure_type = failure_type or "disconnect_error"
            failure_reason = failure_reason or str(exc)
        disconnect_triggered = disconnect_observed
        close_tcp(sock1, file_obj1)
        sock1, file_obj1 = None, None

    # Wait before reconnecting
    time.sleep(RECONNECT_DELAY_MS / 1000.0)

    # --- Phase 3: Reconnect and continue ---
    sock2 = None
    file_obj2 = None
    adapter2 = adapter1

    try:
        reconnect_start = time.perf_counter()
        sock2, file_obj2 = open_tcp(server_host, server_port)
        reconnect_latency_ms = (time.perf_counter() - reconnect_start) * 1000.0

        reconnect_session_id = session_id
        ack2 = send_hello(
            sock2, file_obj2, protocol, reconnect_session_id, CLIENT_ID, EPOCH
        )
        hello2_ok = True
        reconnect_success = True
        same_session_resume = reconnect_session_id == session_id
        server_resume_seq = int(ack2.get("server_last_seq", -1))
        resumed_from_existing_state = bool(
            ack2.get("resumed") and ack2.get("resumed_from_existing_state")
        )

        resume_state_match = (
            adapter2 is not None
            and server_resume_seq == disconnect_point
            and adapter2.last_seq == disconnect_point
        )
        if protocol == "gmcp_r" and adapter2 is not None:
            resume_state_match = resume_state_match and (
                ack2.get("server_last_mem", "")
                == adapter2.client_state.get("last_mem", "")
            )
        elif protocol == "authenticated_hash_chain" and adapter2 is not None:
            resume_state_match = resume_state_match and (
                ack2.get("server_last_hash", "")
                == adapter2.client_state.get("last_hash", "")
            )

        for seq in range(disconnect_point + 1, message_count + 1):
            if post_reconnect_first_seq == 0:
                post_reconnect_first_seq = seq
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

        final_state_response = request_final_state(
            sock2, file_obj2, session_id, message_count
        )
        server_total_received = int(
            final_state_response.get("server_total_received", 0)
        )
        server_unique_accepted = int(
            final_state_response.get("server_unique_accepted", 0)
        )
        server_duplicate_count = int(
            final_state_response.get("server_duplicate_count", 0)
        )
        server_rejected_count = int(
            final_state_response.get("server_rejected_count", 0)
        )
        missing_seq_count = int(
            final_state_response.get("missing_seq_count", message_count)
        )
        if disconnect_type == "server_close":
            disconnect_triggered = bool(
                final_state_response.get("disconnect_triggered")
            )

    except Exception as e:
        reconnect_success = hello2_ok
        internal_exception = True
        failure_type = failure_type or "reconnect_error"
        failure_reason = failure_reason or str(e)
        failure_timestamp = failure_timestamp or datetime.now(timezone.utc).isoformat()

    finally:
        close_tcp(sock2, file_obj2)

    # --- Compute results ---
    total_sent = pre_disconnect_sent + post_disconnect_sent
    total_accepted = pre_disconnect_accepted + post_disconnect_accepted
    duplicate_count = server_duplicate_count
    unrecovered_count = missing_seq_count
    client_server_count_match = bool(final_state_response) and (
        server_total_received == total_sent
        and server_unique_accepted == total_accepted
        and server_rejected_count == total_rejected
    )

    if adapter2 is not None and adapter2.last_seq > 0:
        final_client_seq = adapter2.last_seq
        final_server_seq = int(
            final_state_response.get(
                "last_seq", adapter2.server_state.get("last_seq", 0)
            )
        )
        final_state_match = bool(final_state_response) and adapter2.check_state_match(
            final_state_response
        )
        final_sequence_match = (
            final_client_seq == message_count
            and final_server_seq == message_count
        )

        if protocol == "gmcp_r":
            memory_match = (
                adapter2.client_state.get("last_mem", "")
                == final_state_response.get("last_mem", "")
                and adapter2.client_state.get("last_mem", "") != ""
            )
        elif protocol == "authenticated_hash_chain":
            hash_match = (
                adapter2.client_state.get("last_hash", "")
                == final_state_response.get("last_hash", "")
                and adapter2.client_state.get("last_hash", "") != ""
            )
    elif adapter1 is not None:
        final_client_seq = adapter1.last_seq
        final_server_seq = adapter1.server_state.get("last_seq", 0)
        final_sequence_match = (final_client_seq == disconnect_point)

    state_auditable = bool(final_state_response)
    final_state_complete = (
        state_auditable
        and final_sequence_match
        and final_state_match
        and client_server_count_match
    )

    elapsed = time.time() - start_time

    matrix_valid = (
        protocol in PROTOCOLS
        and disconnect_type in DISCONNECT_TYPES
        and 0 < disconnect_point < message_count
        and repeat_id >= 1
        and payload_size > 0
    )
    provenance_valid = provenance_is_valid(
        git_meta.get("git_commit", ""),
        server_env.get("server_git_commit", ""),
        git_meta.get("git_dirty", ""),
        server_env.get("server_git_dirty", ""),
    )
    disconnect_valid = (
        disconnect_triggered
        and disconnect_observed
        and disconnect_initiator == disconnect_type.removesuffix("_close")
        and disconnect_observed_seq == disconnect_point
        and disconnect_boundary == "after_ack"
        and (disconnect_type != "server_close" or disconnect_armed)
    )
    execution_valid = (
        matrix_valid
        and hello1_ok
        and hello2_ok
        and disconnect_valid
        and reconnect_success
        and same_session_resume
        and resumed_from_existing_state
        and server_resume_seq == disconnect_point
        and resume_state_match
        and not internal_exception
        and provenance_valid
        and state_auditable
    )
    result_success = (
        execution_valid
        and server_unique_accepted == message_count
        and total_timeout == 0
        and unrecovered_count == 0
    )
    run_valid = (
        result_success
        and final_sequence_match
        and final_state_match
        and resume_state_match
        and duplicate_count == 0
        and server_rejected_count == 0
        and unrecovered_count == 0
    )

    if run_valid:
        failure_type = ""
        failure_reason = ""
        failure_timestamp = ""
    elif not failure_type:
        failure_type = "validation_error"
        failure_reason = "; ".join(
            name
            for name, ok in (
                ("matrix_invalid", matrix_valid),
                ("hello1_failed", hello1_ok),
                ("disconnect_invalid", disconnect_valid),
                ("hello2_failed", hello2_ok),
                ("same_session_resume_failed", same_session_resume),
                ("resume_state_mismatch", resume_state_match),
                ("provenance_invalid", provenance_valid),
                ("final_state_not_auditable", state_auditable),
                ("client_server_count_mismatch", client_server_count_match),
                ("result_incomplete", result_success),
            )
            if not ok
        )
        failure_timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "session_id": session_id,
        "reconnect_session_id": reconnect_session_id,
        "same_session_resume": same_session_resume,
        "server_resume_seq": server_resume_seq,
        "resume_state_match": resume_state_match,
        "resumed_from_existing_state": resumed_from_existing_state,
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
        "server_total_received": server_total_received,
        "server_unique_accepted": server_unique_accepted,
        "server_duplicate_count": server_duplicate_count,
        "server_rejected_count": server_rejected_count,
        "missing_seq_count": missing_seq_count,
        "client_server_count_match": client_server_count_match,
        "reconnect_success": reconnect_success,
        "reconnect_latency_ms": round(reconnect_latency_ms, 2),
        "final_state_match": final_state_match,
        "final_sequence_match": final_sequence_match,
        "final_client_seq": final_client_seq,
        "final_server_seq": final_server_seq,
        "memory_match": memory_match if protocol == "gmcp_r" else "",
        "hash_match": hash_match if protocol == "authenticated_hash_chain" else "",
        "disconnect_armed": disconnect_armed,
        "disconnect_triggered": disconnect_triggered,
        "disconnect_initiator": disconnect_initiator,
        "disconnect_observed": disconnect_observed,
        "disconnect_observed_seq": disconnect_observed_seq,
        "disconnect_boundary": disconnect_boundary,
        "post_reconnect_first_seq": post_reconnect_first_seq,
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
    Loopback recovery server with persistent per-session verifier state.

    Server-close boundaries are armed before DATA begins.  Final counters and
    state are returned only through authenticated FINAL_STATE messages.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._protocols: Dict[str, str] = {}
        self._verifiers: Dict[str, Any] = {}
        self._disconnect_points: Dict[str, int] = {}
        self._disconnect_triggered: Dict[str, bool] = {}
        self._received_seq_counts: Dict[str, Dict[int, int]] = {}
        self._accepted_unique_seqs: Dict[str, Set[int]] = {}
        self._rejected_counts: Dict[str, int] = {}
        self._duplicate_counts: Dict[str, int] = {}
        self._connections: Set[socket.socket] = set()
        self._client_threads: Set[threading.Thread] = set()
        self._lock = threading.Lock()

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self.port = int(self._server_sock.getsockname()[1])
        self._server_sock.listen(16)
        self._server_sock.settimeout(0.2)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(f"[SERVER] Listening on {self.host}:{self.port}")

    def stop(self):
        with self._lock:
            self._running = False
        server_sock = self._server_sock
        self._server_sock = None
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass

        current = threading.current_thread()
        if self._thread and self._thread is not current:
            self._thread.join(timeout=2.0)

        with self._lock:
            connections = list(self._connections)
            client_threads = list(self._client_threads)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        for thread in client_threads:
            if thread is not current:
                thread.join(timeout=2.0)

    def _accept_loop(self):
        while self._running:
            try:
                server_sock = self._server_sock
                if server_sock is None:
                    break
                conn, addr = server_sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                thread = threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                )
                with self._lock:
                    should_start = self._running
                    if should_start:
                        self._connections.add(conn)
                        self._client_threads.add(thread)
                if not should_start:
                    conn.close()
                    break
                thread.start()
            except socket.timeout:
                continue
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
                    if self._handle_data(conn, packet):
                        break
                elif ptype == "ARM_SERVER_CLOSE":
                    self._handle_arm_server_close(conn, packet)
                elif ptype == "FINAL_STATE":
                    self._handle_final_state(conn, packet)
                else:
                    self._send(conn, {"ok": False, "reason": f"unknown type: {ptype}"})
        except UnicodeDecodeError:
            pass
        except (ConnectionError, socket.timeout, OSError):
            pass
        finally:
            close_tcp(conn, file_obj)
            with self._lock:
                self._connections.discard(conn)
                self._client_threads.discard(threading.current_thread())

    @staticmethod
    def _state_fields(verifier: Any, protocol: str) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"server_last_seq": verifier.state.last_seq}
        if protocol == "gmcp_r":
            fields["server_last_mem"] = verifier.state.last_mem
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            fields["server_last_hash"] = verifier.state.last_hash
        return fields

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

        if display_protocol not in PROTOCOLS:
            self._send(conn, {"ok": False, "reason": f"unsupported protocol: {wire_protocol}"})
            return

        with self._lock:
            if session_id in self._verifiers:
                verifier = self._verifiers[session_id]
                existing_protocol = self._protocols[session_id]
                if (
                    existing_protocol != display_protocol
                    or verifier.state.sender_id != sender_id
                    or verifier.state.epoch != epoch
                ):
                    self._send(
                        conn,
                        {"ok": False, "reason": "existing session metadata mismatch"},
                    )
                    return
                ack = {
                    "ok": True,
                    "type": "HELLO_ACK",
                    "session_id": session_id,
                    "protocol": wire_protocol,
                    "resumed": True,
                    "resumed_from_existing_state": True,
                }
                ack.update(self._state_fields(verifier, existing_protocol))
                ack.update(get_server_env_info())
                self._send(conn, ack)
                return

            self._protocols[session_id] = display_protocol
            self._received_seq_counts[session_id] = {}
            self._accepted_unique_seqs[session_id] = set()
            self._rejected_counts[session_id] = 0
            self._duplicate_counts[session_id] = 0
            self._disconnect_triggered[session_id] = False

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

            verifier = self._verifiers[session_id]

        print(f"  [HELLO] session={session_id} protocol={display_protocol} (wire={wire_protocol})")

        ack: Dict[str, Any] = {
            "ok": True,
            "type": "HELLO_ACK",
            "session_id": session_id,
            "protocol": wire_protocol,
            "resumed": False,
            "resumed_from_existing_state": False,
        }
        ack.update(self._state_fields(verifier, display_protocol))
        ack.update(get_server_env_info())
        self._send(conn, ack)

    def _handle_data(self, conn: socket.socket, packet: Dict[str, Any]) -> bool:
        """Process DATA and return True when this connection must close."""
        session_id = packet.get("session_id", "unknown")

        with self._lock:
            verifier = self._verifiers.get(session_id)
            protocol = self._protocols.get(session_id, "")
            if verifier is None:
                resp = {
                    "ok": False,
                    "reason": "no HELLO received for this session",
                }
                should_close = False
            else:
                try:
                    seq = int(packet.get("seq", 0))
                except (TypeError, ValueError):
                    seq = 0
                counts = self._received_seq_counts[session_id]
                counts[seq] = counts.get(seq, 0) + 1
                if counts[seq] > 1:
                    self._duplicate_counts[session_id] += 1

                ok, reason = verifier.verify_data_packet(packet)
                if ok:
                    self._accepted_unique_seqs[session_id].add(seq)
                else:
                    self._rejected_counts[session_id] += 1

                disconnect_at = self._disconnect_points.get(session_id, -1)
                should_close = ok and disconnect_at > 0 and seq == disconnect_at
                resp = {"ok": ok, "reason": reason}
                state_fields = self._state_fields(verifier, protocol)
                resp["last_seq"] = state_fields["server_last_seq"]
                if "server_last_mem" in state_fields:
                    resp["last_mem"] = state_fields["server_last_mem"]
                if "server_last_hash" in state_fields:
                    resp["last_hash"] = state_fields["server_last_hash"]

        response_sent = self._send(conn, resp)

        if should_close:
            if response_sent:
                with self._lock:
                    self._disconnect_triggered[session_id] = True
                    self._disconnect_points.pop(session_id, None)
            print(f"  [SERVER_CLOSE] session={session_id} at seq={packet.get('seq')}")
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return should_close

    def _handle_arm_server_close(
        self, conn: socket.socket, packet: Dict[str, Any]
    ) -> None:
        """Authenticate and register a server-close boundary before DATA."""
        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            self._send_control(
                conn,
                {
                    "ok": False,
                    "type": "ARM_SERVER_CLOSE_ACK",
                    "reason": "auth_tag verification failed",
                },
            )
            return

        session_id = str(packet.get("session_id", ""))
        try:
            disconnect_point = int(packet.get("disconnect_point", 0))
        except (TypeError, ValueError):
            disconnect_point = 0

        with self._lock:
            verifier = self._verifiers.get(session_id)
            valid = verifier is not None and disconnect_point > verifier.state.last_seq
            if valid:
                self._disconnect_points[session_id] = disconnect_point

        self._send_control(
            conn,
            {
                "ok": valid,
                "type": "ARM_SERVER_CLOSE_ACK",
                "session_id": session_id,
                "disconnect_point": disconnect_point,
                "armed": valid,
                "reason": "" if valid else "invalid session or disconnect point",
            },
        )

    def _handle_final_state(
        self, conn: socket.socket, packet: Dict[str, Any]
    ) -> None:
        """Return authenticated final state and exact per-session counts."""
        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            self._send_control(
                conn,
                {
                    "ok": False,
                    "type": "FINAL_STATE_ACK",
                    "reason": "auth_tag verification failed",
                },
            )
            return

        session_id = str(packet.get("session_id", ""))
        try:
            message_count = int(packet.get("message_count", 0))
        except (TypeError, ValueError):
            message_count = 0

        with self._lock:
            verifier = self._verifiers.get(session_id)
            protocol = self._protocols.get(session_id, "")
            if verifier is None or message_count <= 0:
                response = {
                    "ok": False,
                    "type": "FINAL_STATE_ACK",
                    "session_id": session_id,
                    "reason": "invalid session or message_count",
                }
            else:
                received = self._received_seq_counts[session_id]
                accepted = self._accepted_unique_seqs[session_id]
                response = {
                    "ok": True,
                    "type": "FINAL_STATE_ACK",
                    "session_id": session_id,
                    "server_total_received": sum(received.values()),
                    "server_unique_accepted": len(accepted),
                    "server_duplicate_count": self._duplicate_counts[session_id],
                    "server_rejected_count": self._rejected_counts[session_id],
                    "missing_seq_count": sum(
                        1 for seq in range(1, message_count + 1) if seq not in accepted
                    ),
                    "disconnect_triggered": self._disconnect_triggered[session_id],
                    "reason": "",
                }
                state_fields = self._state_fields(verifier, protocol)
                response["last_seq"] = state_fields["server_last_seq"]
                if "server_last_mem" in state_fields:
                    response["last_mem"] = state_fields["server_last_mem"]
                if "server_last_hash" in state_fields:
                    response["last_hash"] = state_fields["server_last_hash"]

        self._send_control(conn, response)

    def _send_control(self, conn: socket.socket, resp: Dict[str, Any]) -> None:
        self._send(conn, with_hmac(DATA_AUTH_KEY, resp))

    @staticmethod
    def _send(conn: socket.socket, resp: Dict[str, Any]) -> bool:
        raw = json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            conn.sendall(raw)
            return True
        except Exception:
            return False


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
    parser.add_argument(
        "--message-count", type=int, default=FIXED_MESSAGE_COUNT,
        help="Total message count",
    )
    parser.add_argument(
        "--payload-size", type=int, default=FIXED_PAYLOAD_SIZE,
        help="Payload size in bytes",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--formal", action="store_true", help="Formal mode: full matrix"
    )
    mode_group.add_argument(
        "--quick", action="store_true", help="Quick mode: fixed 12-row matrix"
    )
    parser.add_argument("--run-dir", type=str, default=None,
        help="Absolute path for output directory (required)")
    parser.add_argument("--attempt-number", type=int, default=None,
        help="Attempt number (1, 2, or 3)")
    parser.add_argument("--no-overwrite", action="store_true",
        help="Refuse to overwrite existing output CSV in development mode")
    parser.add_argument("--server-only", action="store_true",
        help="Run as server only")
    return parser


def resolve_mode_config(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> Tuple[str, List[str], List[int], List[str], int, int, int]:
    """Validate mode locks and return the effective experiment matrix."""
    if args.formal:
        forbidden = []
        if args.protocols is not None:
            forbidden.append("--protocols")
        if args.disconnect_points is not None:
            forbidden.append("--disconnect-points")
        if args.disconnect_types is not None:
            forbidden.append("--disconnect-types")
        if args.repeats is not None:
            forbidden.append("--repeats")
        if args.message_count != FIXED_MESSAGE_COUNT:
            forbidden.append("--message-count")
        if args.payload_size != FIXED_PAYLOAD_SIZE:
            forbidden.append("--payload-size")
        if forbidden:
            parser.error(
                "formal mode fixes the full matrix; forbidden override(s): "
                + ", ".join(forbidden)
            )
        mode = "formal"
        protocols = list(PROTOCOLS)
        disconnect_points = list(DISCONNECT_POINTS)
        disconnect_types = list(DISCONNECT_TYPES)
        repeats = REPEAT_COUNT
    elif args.quick:
        forbidden = []
        if args.protocols is not None:
            forbidden.append("--protocols")
        if args.disconnect_points is not None:
            forbidden.append("--disconnect-points")
        if args.disconnect_types is not None:
            forbidden.append("--disconnect-types")
        if args.repeats is not None:
            forbidden.append("--repeats")
        if args.message_count != FIXED_MESSAGE_COUNT:
            forbidden.append("--message-count")
        if args.payload_size != FIXED_PAYLOAD_SIZE:
            forbidden.append("--payload-size")
        if forbidden:
            parser.error(
                "quick mode fixes the experiment matrix and message shape; "
                "forbidden override(s): " + ", ".join(forbidden)
            )
        mode = "quick"
        protocols = list(PROTOCOLS)
        disconnect_points = list(DISCONNECT_POINTS[:2])
        disconnect_types = list(DISCONNECT_TYPES)
        repeats = 1
    else:
        mode = "development"
        protocols = (
            [p.strip() for p in args.protocols.split(",")]
            if args.protocols
            else list(PROTOCOLS)
        )
        try:
            disconnect_points = (
                [int(value.strip()) for value in args.disconnect_points.split(",")]
                if args.disconnect_points
                else list(DISCONNECT_POINTS)
            )
        except ValueError:
            parser.error("--disconnect-points must contain integers")
        disconnect_types = (
            [value.strip() for value in args.disconnect_types.split(",")]
            if args.disconnect_types
            else list(DISCONNECT_TYPES)
        )
        repeats = args.repeats if args.repeats is not None else REPEAT_COUNT

    if not protocols or len(protocols) != len(set(protocols)):
        parser.error("protocol list must be non-empty and unique")
    unsupported_protocols = sorted(set(protocols) - set(PROTOCOLS))
    if unsupported_protocols:
        parser.error(f"unsupported protocol(s): {', '.join(unsupported_protocols)}")
    if not disconnect_types or len(disconnect_types) != len(set(disconnect_types)):
        parser.error("disconnect type list must be non-empty and unique")
    unsupported_types = sorted(set(disconnect_types) - set(DISCONNECT_TYPES))
    if unsupported_types:
        parser.error(f"unsupported disconnect type(s): {', '.join(unsupported_types)}")
    if repeats <= 0:
        parser.error("--repeats must be positive")
    if args.message_count <= 0 or args.payload_size <= 0:
        parser.error("--message-count and --payload-size must be positive")
    if not disconnect_points or len(disconnect_points) != len(set(disconnect_points)):
        parser.error("disconnect point list must be non-empty and unique")
    if any(point <= 0 or point >= args.message_count for point in disconnect_points):
        parser.error("every disconnect point must be between 1 and message-count - 1")

    return (
        mode,
        protocols,
        disconnect_points,
        disconnect_types,
        repeats,
        args.message_count,
        args.payload_size,
    )


def _csv_bool(value: Any) -> bool:
    return value is True or str(value).strip().lower() == "true"


def _csv_int(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def validate_recovery_rows(
    rows: List[Dict[str, Any]],
    protocols: List[str],
    disconnect_points: List[int],
    disconnect_types: List[str],
    repeats: int,
    message_count: int,
    payload_size: int,
) -> List[Tuple[Optional[int], str]]:
    """Return every post-hoc publication-gate violation."""
    issues: List[Tuple[Optional[int], str]] = []
    expected_combinations = {
        (protocol, point, disconnect_type, repeat_id)
        for protocol in protocols
        for point in disconnect_points
        for disconnect_type in disconnect_types
        for repeat_id in range(1, repeats + 1)
    }
    if len(rows) != len(expected_combinations):
        issues.append(
            (None, f"expected {len(expected_combinations)} rows, got {len(rows)}")
        )

    session_ids = [str(row.get("session_id", "")) for row in rows]
    if any(not session_id for session_id in session_ids):
        issues.append((None, "every row must have a non-empty session_id"))
    if len(session_ids) != len(set(session_ids)):
        issues.append((None, "session_id values must be unique"))

    actual_combinations = {
        (
            str(row.get("protocol", "")),
            _csv_int(row.get("disconnect_point")),
            str(row.get("disconnect_type", "")),
            _csv_int(row.get("repeat_id")),
        )
        for row in rows
    }
    if actual_combinations != expected_combinations:
        issues.append((None, "rows do not match the fixed experiment matrix"))

    for index, row in enumerate(rows):
        row_issues: List[str] = []
        disconnect_point = _csv_int(row.get("disconnect_point"))
        disconnect_type = str(row.get("disconnect_type", ""))
        expected_initiator = disconnect_type.removesuffix("_close")

        for field in (
            "execution_valid",
            "result_success",
            "run_valid",
            "same_session_resume",
            "reconnect_success",
            "resume_state_match",
            "resumed_from_existing_state",
            "client_server_count_match",
            "final_state_match",
            "final_sequence_match",
            "final_state_complete",
            "disconnect_triggered",
            "disconnect_observed",
        ):
            if not _csv_bool(row.get(field)):
                row_issues.append(f"{field} must be True")

        if disconnect_type == "server_close" and not _csv_bool(
            row.get("disconnect_armed")
        ):
            row_issues.append("disconnect_armed must be True for server_close")
        if str(row.get("disconnect_initiator", "")) != expected_initiator:
            row_issues.append("disconnect_initiator mismatch")
        if str(row.get("disconnect_boundary", "")) != "after_ack":
            row_issues.append("disconnect_boundary must be after_ack")
        if _csv_int(row.get("disconnect_observed_seq")) != disconnect_point:
            row_issues.append("disconnect_observed_seq mismatch")
        if str(row.get("reconnect_session_id", "")) != str(
            row.get("session_id", "")
        ):
            row_issues.append("reconnect_session_id mismatch")
        if _csv_int(row.get("server_resume_seq")) != disconnect_point:
            row_issues.append("server_resume_seq mismatch")
        if _csv_int(row.get("post_reconnect_first_seq")) != disconnect_point + 1:
            row_issues.append("post_reconnect_first_seq mismatch")

        exact_counts = {
            "message_count": message_count,
            "payload_size": payload_size,
            "total_accepted": message_count,
            "server_total_received": message_count,
            "server_unique_accepted": message_count,
            "duplicate_count": 0,
            "server_duplicate_count": 0,
            "unrecovered_count": 0,
            "missing_seq_count": 0,
            "total_rejected": 0,
            "server_rejected_count": 0,
            "total_timeout": 0,
        }
        for field, expected in exact_counts.items():
            if _csv_int(row.get(field)) != expected:
                row_issues.append(f"{field} must equal {expected}")

        if str(row.get("schema_version", "")) != SCHEMA_VERSION:
            row_issues.append(f"schema_version must equal {SCHEMA_VERSION}")
        if not provenance_is_valid(
            row.get("client_git_commit", ""),
            row.get("server_git_commit", ""),
            row.get("client_git_dirty", ""),
            row.get("server_git_dirty", ""),
        ):
            row_issues.append("provenance mismatch or dirty worktree")
        if str(row.get("failure_type", "")).strip():
            row_issues.append("failure_type must be empty for a successful row")
        if str(row.get("failure_reason", "")).strip():
            row_issues.append("failure_reason must be empty for a successful row")

        for reason in row_issues:
            issues.append((index, reason))

    return issues


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.server_only:
        srv = EmbeddedTCPServer(args.host, args.port)
        shutdown_event = threading.Event()

        def _signal_handler(signum, frame):
            sig_name = signal.Signals(signum).name
            print(f"\n[SERVER-ONLY] Received {sig_name}, shutting down...")
            shutdown_event.set()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
        try:
            print(f"[SERVER-ONLY] Starting server on {args.host}:{args.port}")
            srv.start()
            shutdown_event.wait()
        finally:
            srv.stop()
        print("[SERVER-ONLY] Server stopped.")
        return

    if args.run_dir is None:
        parser.error("--run-dir is required")

    (
        mode,
        protocols,
        disconnect_points,
        disconnect_types,
        repeats,
        message_count,
        payload_size,
    ) = resolve_mode_config(parser, args)
    run_dir_path = validate_run_dir(parser, args.run_dir)

    attempt_number = args.attempt_number if args.attempt_number is not None else 1
    if attempt_number not in (1, 2, 3):
        parser.error("--attempt-number must be 1, 2, or 3")

    output_name = {
        "quick": "recovery_smoke.csv",
        "formal": "recovery_validation_results.csv",
        "development": "recovery_dev.csv",
    }[mode]
    output_csv = str(run_dir_path / output_name)
    tmp_csv = output_csv + ".tmp"
    failed_csv = str(
        run_dir_path / f"{Path(output_name).stem}_attempt{attempt_number:02d}.failed.csv"
    )
    enforce_startup_output_guards(
        output_csv,
        protect_final=(mode in ("quick", "formal") or args.no_overwrite),
    )

    git_meta = get_git_metadata()
    git_meta["client_cpu_model"] = get_cpu_model()
    commit = str(git_meta.get("git_commit", ""))
    dirty = git_meta.get("git_dirty", "true")
    if COMMIT_RE.fullmatch(commit) is None:
        print(f"[FATAL] client git_commit must be 40-char hex, got: {commit!r}")
        sys.exit(1)
    if not _is_clean_dirty_value(dirty):
        print(f"[FATAL] client git_dirty={dirty}, must be false")
        sys.exit(1)

    fieldnames = [
        "session_id", "reconnect_session_id", "same_session_resume",
        "server_resume_seq", "resume_state_match", "resumed_from_existing_state",
        "experiment_type", "protocol", "message_count", "payload_size",
        "disconnect_point", "disconnect_type", "repeat_id",
        "pre_disconnect_sent", "pre_disconnect_accepted",
        "post_disconnect_sent", "post_disconnect_accepted",
        "total_sent", "total_accepted", "total_rejected", "total_timeout",
        "duplicate_count", "unrecovered_count",
        "server_total_received", "server_unique_accepted",
        "server_duplicate_count", "server_rejected_count", "missing_seq_count",
        "client_server_count_match", "reconnect_success", "reconnect_latency_ms",
        "final_state_match", "final_sequence_match",
        "final_client_seq", "final_server_seq", "memory_match", "hash_match",
        "disconnect_armed", "disconnect_triggered", "disconnect_initiator",
        "disconnect_observed", "disconnect_observed_seq", "disconnect_boundary",
        "post_reconnect_first_seq",
        "execution_valid", "result_success", "run_valid",
        "failure_type", "failure_reason", "failure_timestamp",
        "state_auditable", "final_state_complete", "schema_version",
        "client_git_commit", "server_git_commit",
        "client_git_dirty", "server_git_dirty",
        "client_hostname", "server_hostname", "attempt_number",
        "timestamp", "elapsed_seconds",
    ]

    total = len(protocols) * len(disconnect_points) * len(disconnect_types) * repeats
    print(f"[INFO] Git commit: {commit[:12]}")
    print(f"[INFO] Git dirty:  {dirty}")
    print(f"[MODE] Spawning embedded server on {args.host}:{args.port}")
    print(f"[INFO] Mode: {mode}")
    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {protocols}")
    print(f"[INFO] Disconnect points: {disconnect_points}")
    print(f"[INFO] Disconnect types: {disconnect_types}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Message count: {message_count}")
    print(f"[INFO] Payload size: {payload_size}")
    print(f"[INFO] Output: {output_csv}")

    srv = EmbeddedTCPServer(args.host, args.port)
    published = False
    server_stopped = False
    completed = 0
    failed = 0

    try:
        srv.start()
        server_port = srv.port

        with open(tmp_csv, "x", newline="", encoding="utf-8") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=fieldnames)
            writer.writeheader()
            index = 0
            for protocol in protocols:
                for disconnect_point in disconnect_points:
                    for disconnect_type in disconnect_types:
                        for repeat_id in range(1, repeats + 1):
                            index += 1
                            result = run_one_recovery_experiment(
                                protocol=protocol,
                                message_count=message_count,
                                payload_size=payload_size,
                                disconnect_point=disconnect_point,
                                disconnect_type=disconnect_type,
                                repeat_id=repeat_id,
                                server_host=args.host,
                                server_port=server_port,
                                git_meta=git_meta,
                            )
                            result["attempt_number"] = attempt_number
                            writer.writerow(result)
                            output_file.flush()

                            if result["run_valid"]:
                                completed += 1
                            else:
                                failed += 1
                            valid_mark = "OK" if result["run_valid"] else "INVALID"
                            print(
                                f"  [{index}/{total}] {protocol} d={disconnect_point} "
                                f"t={disconnect_type} r={repeat_id}: "
                                f"accepted={result['total_accepted']}/{message_count} "
                                f"[{valid_mark}]"
                            )

            output_file.flush()
            os.fsync(output_file.fileno())

        srv.stop()
        server_stopped = True

        print(f"\n[VALIDATE] Checking {tmp_csv} ...")
        with open(tmp_csv, "r", newline="", encoding="utf-8") as input_file:
            rows = list(csv.DictReader(input_file))
        issues = validate_recovery_rows(
            rows,
            protocols,
            disconnect_points,
            disconnect_types,
            repeats,
            message_count,
            payload_size,
        )
        if issues:
            grouped: Dict[Optional[int], List[str]] = {}
            for row_index, reason in issues:
                grouped.setdefault(row_index, []).append(reason)
            for row_index, reasons in grouped.items():
                if row_index is None:
                    print(f"[VALIDATE] FAIL: {'; '.join(reasons)}")
                    continue
                row = rows[row_index]
                print(
                    "[VALIDATE] FAIL row "
                    f"{row_index + 1}: protocol={row.get('protocol', '')} "
                    f"disconnect_point={row.get('disconnect_point', '')} "
                    f"disconnect_type={row.get('disconnect_type', '')} "
                    f"repeat_id={row.get('repeat_id', '')} "
                    f"failure_type={row.get('failure_type', '')} "
                    f"failure_reason={row.get('failure_reason', '')} "
                    f"gate={' | '.join(reasons)}"
                )
            raise RuntimeError("post-hoc recovery validation failed")

        publish_tmp_no_clobber(tmp_csv, output_csv)
        published = True
        print(f"[VALIDATE] OK: {len(rows)} rows ({completed} valid, {failed} failed)")

    except BaseException as exc:
        if not server_stopped:
            srv.stop()
            server_stopped = True
        preserved = ""
        if not published and os.path.exists(tmp_csv):
            try:
                preserved = preserve_failed_artifact(tmp_csv, failed_csv)
            except Exception as preserve_error:
                print(f"[FATAL] failed to preserve tmp evidence: {preserve_error}")
        print(f"[FATAL] recovery runner failed: {type(exc).__name__}: {exc}")
        if preserved:
            print(f"[FATAL] Failed artifact: {preserved}")
        if isinstance(exc, SystemExit) and exc.code not in (None, 0):
            raise
        raise SystemExit(1) from exc
    finally:
        if not server_stopped:
            srv.stop()

    print(f"\n[DONE] Results atomically written to {output_csv}")
    print(f"[DONE] {completed} experiments completed, {failed} failed.")
    with open(output_csv, "rb") as result_file:
        sha = hashlib.sha256(result_file.read()).hexdigest()
    print(f"[DONE] SHA-256: {sha}")


if __name__ == "__main__":
    main()
