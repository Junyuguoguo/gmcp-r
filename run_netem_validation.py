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
  sudo python run_netem_validation.py --host 10.0.0.1 --interface eth0  # cross-host

关键设计：
  - 没有 sudo 权限时拒绝生成数据
  - 使用 trap 确保实验结束后清理 tc 规则（通过 context manager）
  - 6 个代表性条件覆盖从正常到极端恶劣的网络场景
  - 本机模式强制 --interface lo，跨主机模式校验 ip route
  - 原子发布：tmp → 矩阵验证 → tc清理验证 → no-clobber link publish
"""

import csv
import json
import os
import re as _re
import socket
import subprocess
import sys
import time
import platform
from datetime import datetime
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# GMCP-R imports
# ---------------------------------------------------------------------------
from gmcp.config import (
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.crypto_utils import verify_tagged_hmac
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier

# Baseline protocol state/verifier imports (server-side only)
from gmcp.baselines.seq_mac import SeqMACVerifier, create_initial_state as sm_init_state
from gmcp.baselines.authenticated_hash_chain import AuthHashChainVerifier
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState as _AHCState,
)
from gmcp.baselines.hash_chain import (
    HashChainState, HashChainVerifier,
    hash_func as hc_hash_func,
)

from gmcp.experiment_stats import get_git_commit, get_python_version, get_os_info, get_command_line
from gmcp.experiment_transport import (
    ProtocolAdapter,
    send_hello,
    send_json_line as _transport_send_json_line,
    recv_json_line as _transport_recv_json_line,
    WIRE_PROTOCOL_NAMES,
    DISPLAY_PROTOCOL_NAMES,
    get_git_commit as _transport_get_git_commit,
    get_git_dirty as _transport_get_git_dirty,
    get_git_metadata as _transport_get_git_metadata,
    get_server_env_info,
    get_cpu_model,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# OUTPUT_DIR is set dynamically from --run-dir argument
OUTPUT_DIR: str = ""
FORMAL_CSV: str = ""
SMOKE_CSV: str = ""
DEV_CSV: str = ""

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

FULL_HEX_COMMIT_RE = _re.compile(r"^[0-9a-fA-F]{40}$")


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


def ensure_output_dir(run_dir: str) -> None:
    """Set OUTPUT_DIR and derived paths from run_dir (must be absolute)."""
    global OUTPUT_DIR, FORMAL_CSV, SMOKE_CSV, DEV_CSV
    OUTPUT_DIR = run_dir
    FORMAL_CSV = os.path.join(OUTPUT_DIR, "netem_validation_results.csv")
    SMOKE_CSV = os.path.join(OUTPUT_DIR, "netem_smoke.csv")
    DEV_CSV = os.path.join(OUTPUT_DIR, "netem_dev.csv")
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def is_full_hex_commit(commit: str) -> bool:
    """Return True only for a full 40-character hexadecimal Git commit."""
    return bool(FULL_HEX_COMMIT_RE.fullmatch(commit or ""))


def validate_run_dir(parser: Any, run_dir: str) -> None:
    """Validate --run-dir is absolute and outside any Git repository/worktree."""
    if not os.path.isabs(run_dir):
        parser.error(f"--run-dir must be an absolute path, got: {run_dir}")

    abs_run_dir = os.path.abspath(run_dir)
    check_path = abs_run_dir
    while check_path and check_path != "/":
        git_marker = os.path.join(check_path, ".git")
        if os.path.exists(git_marker):
            parser.error(f"--run-dir must NOT be inside a git repository ({git_marker})")
        check_path = os.path.dirname(check_path)

    probe_path = abs_run_dir
    while not os.path.exists(probe_path):
        parent = os.path.dirname(probe_path)
        if parent == probe_path:
            break
        probe_path = parent
    try:
        result = subprocess.run(
            ["git", "-C", probe_path, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return
    if result.returncode == 0:
        top = result.stdout.strip()
        parser.error(f"--run-dir must NOT be inside a git repository ({top})")


def publish_tmp_no_clobber(tmp_path: str, final_path: str) -> None:
    """Atomically publish tmp to final without overwriting an existing final file."""
    os.link(tmp_path, final_path)
    os.unlink(tmp_path)


def cleanup_tc_and_verify(interface: str) -> Tuple[bool, str]:
    """Clear tc rules and verify the final qdisc snapshot has no netem residue."""
    try:
        clear_tc_netem(interface)
    except BaseException:
        pass
    snapshot_ok, snapshot, snapshot_error = get_tc_snapshot_checked(interface)
    if not snapshot_ok:
        return False, f"tc snapshot failure after cleanup: {snapshot_error}"
    if "netem" in snapshot:
        return False, snapshot
    return True, snapshot


def make_payload(seq: int, payload_size: int) -> str:
    prefix = "netem-%d-" % seq
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


# Reuse transport helpers
send_json_line = _transport_send_json_line
recv_json_line = _transport_recv_json_line


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


def parse_tc_snapshot(snap: str) -> Dict[str, float]:
    """Parse actual tc qdisc parameters from a snapshot string.

    Returns dict with keys: delay_ms, jitter_ms, loss_pct
    Values are 0.0 if not found.
    """
    result: Dict[str, float] = {"delay_ms": 0.0, "jitter_ms": 0.0, "loss_pct": 0.0, "reorder_pct": 0.0}

    # Parse delay: "delay 100ms" or "delay 100.00ms"
    delay_match = _re.search(r'delay\s+([\d.]+)ms', snap)
    if delay_match:
        result["delay_ms"] = float(delay_match.group(1))

    # Parse jitter: after delay, the next ms value is jitter
    # Format: "delay 100ms  50ms" where 50ms is jitter
    jitter_match = _re.search(r'delay\s+[\d.]+ms\s+([\d.]+)ms', snap)
    if jitter_match:
        result["jitter_ms"] = float(jitter_match.group(1))

    # Parse loss: "loss 5%"
    loss_match = _re.search(r'loss\s+([\d.]+)%', snap)
    if loss_match:
        result["loss_pct"] = float(loss_match.group(1))

    # Parse reorder: "reorder 5%" or "reorder 5% 50%"
    reorder_match = _re.search(r'reorder\s+([\d.]+)%', snap)
    if reorder_match:
        result["reorder_pct"] = float(reorder_match.group(1))

    return result


def verify_tc_snapshot(
    snap: str,
    condition_name: str,
    requested: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str, Dict[str, float]]:
    """Verify tc qdisc snapshot matches expected condition.

    - control: allows any qdisc (noqueue/default) — netem not required.
    - non-control: snapshot must contain 'netem'.
    - 25% tolerance for all parameters (delay, loss, jitter, reorder).

    Returns (ok, reason, actual_params).
    """
    if requested is None:
        requested = {}
    actual = parse_tc_snapshot(snap)

    if condition_name == "control":
        if "netem" in snap:
            return False, "control condition still contains netem from previous run", actual
        return True, "control clean", actual
    if "netem" not in snap:
        return False, "netem not in qdisc", actual

    tolerance = 0.25  # 25% tolerance
    checks: List[str] = []

    # Verify delay
    req_delay = requested.get("delay_ms", 0)
    if req_delay > 0:
        if abs(actual["delay_ms"] - req_delay) > req_delay * tolerance:
            checks.append(f'delay mismatch: actual={actual["delay_ms"]:.1f} vs requested={req_delay}')

    # Verify loss
    req_loss = requested.get("loss_pct", 0)
    if req_loss > 0:
        if abs(actual["loss_pct"] - req_loss) > req_loss * tolerance:
            checks.append(f'loss mismatch: actual={actual["loss_pct"]:.1f} vs requested={req_loss}')

    # Verify jitter
    req_jitter = requested.get("jitter_ms", 0)
    if req_jitter > 0:
        if abs(actual["jitter_ms"] - req_jitter) > req_jitter * tolerance:
            checks.append(f'jitter mismatch: actual={actual["jitter_ms"]:.1f} vs requested={req_jitter}')

    # Verify reorder
    req_reorder = requested.get("reorder_pct", 0)
    if req_reorder > 0:
        if abs(actual["reorder_pct"] - req_reorder) > req_reorder * tolerance:
            checks.append(f'reorder mismatch: actual={actual["reorder_pct"]:.1f} vs requested={req_reorder}')

    if checks:
        return False, "; ".join(checks), actual

    return True, "ok", actual

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

    # Verify cleared state has no netem residue
    snap_after_clear = subprocess.check_output(
        ["sudo", "tc", "qdisc", "show", "dev", interface],
        text=True, timeout=10,
    )
    if "netem" in snap_after_clear:
        raise RuntimeError(f"Failed to clear previous netem rules on {interface}")

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


def get_tc_snapshot_checked(interface: str) -> Tuple[bool, str, str]:
    """Strictly read tc qdisc state for interface.

    Returns (ok, snapshot, error). A clean snapshot must come from a
    successful command and must be non-empty.
    """
    try:
        result = subprocess.run(
            ["sudo", "tc", "qdisc", "show", "dev", interface],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        return False, "", f"tc qdisc show timed out after {exc.timeout}s"
    except Exception as exc:
        return False, "", f"tc qdisc show failed: {exc}"

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = stderr or stdout or f"returncode={result.returncode}"
        return False, "", f"tc qdisc show failed with returncode={result.returncode}: {detail}"
    if not stdout:
        return False, "", "empty tc qdisc snapshot"
    return True, stdout, ""


def get_tc_snapshot(interface: str) -> str:
    """Compatibility wrapper for callers that only need display text."""
    ok, snapshot, _ = get_tc_snapshot_checked(interface)
    return snapshot if ok else ""


def validate_interface_for_mode(interface: str, host: Optional[str]) -> None:
    """
    Validate network interface matches the execution mode.
    - Local mode (no --host): force --interface lo
    - Cross-host mode (with --host): validate ip route get output matches --interface
    """
    if host is None:
        # Local mode: must use loopback
        if interface != "lo":
            print(f"[ERROR] Local mode (no --host) requires --interface lo, got '{interface}'")
            sys.exit(1)
    else:
        # Cross-host mode: validate interface via ip route get
        try:
            result = subprocess.run(
                ["ip", "route", "get", host],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                print(f"[ERROR] Cannot resolve route to {host}: {result.stderr.strip()}")
                sys.exit(1)
            # Parse output: "10.0.0.1 via ... dev eth0 ..."
            route_output = result.stdout.strip()
            if f"dev {interface}" not in route_output:
                # Extract actual interface
                parts = route_output.split()
                actual_iface = ""
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        actual_iface = parts[idx + 1]
                print(f"[ERROR] Interface mismatch: requested '{interface}', "
                      f"but route to {host} uses '{actual_iface}'")
                print(f"        Route output: {route_output}")
                sys.exit(1)
            print(f"[OK] Interface '{interface}' validated for route to {host}")
        except FileNotFoundError:
            print("[WARN] 'ip' command not found, skipping interface validation")
        except Exception as e:
            print(f"[WARN] Interface validation failed: {e}")


@contextmanager
def tc_condition(interface: str, loss: int, delay_ms: int, jitter_ms: int, reorder: int) -> Generator[str, None, None]:
    """
    Context manager that sets a tc/netem condition and guarantees cleanup.
    Yields tc snapshot string after applying rules.
    """
    condition_desc = f"loss={loss}% delay={delay_ms}ms jitter={jitter_ms}ms reorder={reorder}%"
    print(f"[TC] Applying: {condition_desc}")
    applied = False
    try:
        ok = setup_tc_netem(interface, loss, delay_ms, jitter_ms, reorder)
        if not ok:
            raise RuntimeError(f"[TC] Failed to apply condition: {condition_desc}")
        applied = True
        snapshot_ok, snapshot, snapshot_error = get_tc_snapshot_checked(interface)
        if not snapshot_ok:
            raise RuntimeError(f"[TC] Failed to read qdisc snapshot after apply: {snapshot_error}")
        print(f"[TC] Snapshot: {snapshot[:120]}...")
        yield snapshot
    finally:
        if applied:
            print("[TC] Cleaning up ...")
            cleanup_ok, snap_after = cleanup_tc_and_verify(interface)
            if not cleanup_ok:
                raise RuntimeError(
                    f"[TC] cleanup verification failed on {interface}: {snap_after[:200]}"
                )



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
    """Run one experiment using ProtocolAdapter for state tracking.

    Uses HELLO handshake and protocol-agnostic packet building.
    Returns result dict.
    """
    session_id = (
        f"netem-{protocol}-{condition_name}-"
        f"r{repeat_id}-{int(time.time() * 1000000)}"
    )

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
    adapter = None
    hello_ack: Dict[str, Any] = {}

    try:
        sock, file_obj = open_tcp(server_host, server_port)

        # --- HELLO handshake ---
        try:
            ack = send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
            hello_ack = ack
        except Exception as e:
            run_valid = False
            failure_reason = f"HELLO failed: {e}"
            raise

        # Create protocol adapter for state tracking
        adapter = ProtocolAdapter(
            protocol=protocol,
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
        )

        for seq in range(1, message_count + 1):
            payload = make_payload(seq, payload_size)
            packet = adapter.build_packet(seq, payload)

            t_send = time.perf_counter()
            send_json_line(sock, packet)
            sent += 1

            try:
                response = recv_json_line(file_obj)
                t_recv = time.perf_counter()
                rtts.append((t_recv - t_send) * 1000.0)

                if response.get("ok"):
                    accepted += 1
                    adapter.update_after_accept(packet, response)
                else:
                    rejected += 1
                    run_valid = False
                    failure_reason = response.get("reason", "server_rejected")

            except socket.timeout:
                timeouts += 1
                run_valid = False
                failure_reason = "socket_timeout"
                break  # timeout ends this run — no further seq
            except Exception as e:
                errors += 1
                run_valid = False
                failure_reason = str(e)
                break  # error also ends this run

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

    # State match via adapter (independent state comparison)
    if adapter and adapter.last_seq > 0:
        state_match = adapter.check_state_match()
        final_state = adapter.get_final_state_for_csv()
    else:
        state_match = False
        final_state = {
            "client_final_seq": 0,
            "server_final_seq": 0,
            "client_final_mem": "",
            "server_final_mem": "",
            "client_final_hash": "",
            "server_final_hash": "",
        }

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
        "state_match": state_match,
        "client_final_seq": final_state.get("client_final_seq", 0),
        "server_final_seq": final_state.get("server_final_seq", 0),
        "client_final_mem": final_state.get("client_final_mem", ""),
        "server_final_mem": final_state.get("server_final_mem", ""),
        "client_final_hash": final_state.get("client_final_hash", ""),
        "server_final_hash": final_state.get("server_final_hash", ""),
        "hello_ack": hello_ack,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Embedded TCP server
# ---------------------------------------------------------------------------

import threading
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState as _AHCState,
)


class EmbeddedTCPServer:
    """
    Lightweight TCP server that handles PING, HELLO, and DATA packets.

    Wire protocol name mapping: "gmcp" → "gmcp_r" via DISPLAY_PROTOCOL_NAMES.
    Sessions are established via HELLO handshake; DATA packets are verified
    by the protocol-appropriate verifier created during HELLO.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Per-session protocol and verifier storage
        self._protocols: Dict[str, str] = {}       # session_id -> display protocol
        self._verifiers: Dict[str, Any] = {}        # session_id -> verifier
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
        """Process HELLO handshake: validate auth_tag, map wire→display protocol, create verifier."""
        # Verify auth_tag
        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            self._send(conn, {"ok": False, "reason": "auth_tag verification failed"})
            return

        # Map wire protocol name to display name
        wire_protocol = packet.get("protocol", "")
        display_protocol = DISPLAY_PROTOCOL_NAMES.get(wire_protocol, wire_protocol)

        session_id = packet.get("session_id", "")
        sender_id = packet.get("sender_id", CLIENT_ID)
        epoch = int(packet.get("epoch", EPOCH))

        if not session_id:
            self._send(conn, {"ok": False, "reason": "missing session_id"})
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
                state = sm_init_state(session_id, sender_id, epoch)
                self._verifiers[session_id] = SeqMACVerifier(state)

            elif display_protocol == "authenticated_hash_chain":
                initial_hash = hc_hash_func(f"init:{session_id}:{epoch}")
                state = _AHCState(
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

            else:
                self._send(conn, {"ok": False, "reason": f"unsupported protocol: {wire_protocol}"})
                return

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
    parser.add_argument("--host", default=None, help="Remote server host (omit for local mode)")
    parser.add_argument("--quick", action="store_true", help="Quick mode: 1 repeat")
    parser.add_argument("--formal", action="store_true", help="Formal mode: all 6 conditions, 10 repeats")
    parser.add_argument("--repeats", type=int, default=None, help="Override repeat count")
    parser.add_argument("--no-spawn-server", action="store_true",
        help="Do NOT spawn embedded server; connect to --host:--port directly")
    parser.add_argument("--conditions", default=None, help="Comma-separated condition names to run")
    parser.add_argument("--run-dir", required=True,
        help="Absolute path for output directory (must not be inside a git repo)")
    args = parser.parse_args()

    if args.quick and args.formal:
        parser.error("--quick and --formal are mutually exclusive")

    # ---- Validate --run-dir ----
    validate_run_dir(parser, args.run_dir)

    repeats = 1 if args.quick else (args.repeats or REPEAT_COUNT)

    # ---- Formal mode validation ----
    if args.formal:
        if args.conditions is not None:
            parser.error('--formal cannot use --conditions subset')
        if args.repeats is not None and args.repeats != 10:
            parser.error('--formal requires 10 repeats')
        repeats = 10

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
    srv = None

    def stop_server() -> None:
        if srv:
            srv.stop()

    def cleanup_or_report(context: str) -> bool:
        cleanup_ok, final_snapshot = cleanup_tc_and_verify(interface)
        if not cleanup_ok:
            print(f"[FATAL] tc cleanup verification failed during {context}")
            print(f"[FATAL] Final qdisc snapshot: {final_snapshot}")
        return cleanup_ok

    # ---- Interface validation ----
    validate_interface_for_mode(interface, args.host)

    if args.no_spawn_server:
        # Remote mode: connect to --host:--port, no local server
        if not args.host:
            print("[ERROR] --no-spawn-server requires --host")
            sys.exit(1)
        server_host = args.host
        print(f"[MODE] Remote mode: connecting to {server_host}:{server_port}")
    else:
        # Local mode: start embedded server
        if args.host:
            server_host = args.host
        print(f"[MODE] Starting embedded server on {server_host}:{server_port}")
        srv = EmbeddedTCPServer(server_host, server_port)
        srv.start()
        time.sleep(0.3)


    ensure_output_dir(args.run_dir)

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
        "execution_valid", "result_success", "state_audit_available",
        "interface", "requested_netem_config", "actual_qdisc_config",
        "actual_delay_ms", "actual_loss_pct", "actual_jitter_ms", "actual_reorder_pct",
        "state_match",
        "client_final_seq", "server_final_seq",
        "client_final_mem", "server_final_mem",
        "client_final_hash", "server_final_hash",
        "execution_mode", "impairment_direction", "tc_endpoint",
        "server_git_commit", "server_git_dirty",
        "server_python_version", "server_os_info",
        "server_hostname", "server_cpu_model",
        "client_git_commit", "client_git_dirty",
        "client_hostname", "client_cpu_model",
        "client_python_version", "client_os_info",
        "command_line",
        "timestamp",
    ]

    total = len(PROTOCOLS) * len(conditions) * repeats

    # Collect metadata once (client-side)
    git_commit = _transport_get_git_commit()
    git_dirty = _transport_get_git_dirty()  # fail-closed: returns True on error
    python_version = get_python_version()
    os_info = get_os_info()
    command_line = get_command_line()
    client_hostname = socket.gethostname()
    client_cpu = get_cpu_model()
    # Formal mode requires clean worktree
    if args.formal and git_dirty:
        print("[ERROR] Formal mode requires a clean client worktree. Commit or stash changes first.")
        sys.exit(1)
    # Formal mode requires full 40-char hexadecimal commit
    if args.formal and not is_full_hex_commit(git_commit):
        print(f"[ERROR] Formal mode requires full 40-char hexadecimal git commit, got: {git_commit!r}")
        sys.exit(1)
    server_env_from_ack: Dict[str, str] = {}  # populated from first HELLO_ACK in remote mode

    print(f"[INFO] Total experiments: {total}")
    print(f"[INFO] Protocols: {PROTOCOLS}")
    print(f"[INFO] Conditions: {[c[0] for c in conditions]}")
    print(f"[INFO] Repeats: {repeats}")
    print(f"[INFO] Interface: {interface}")
    output_csv = SMOKE_CSV if args.quick else (FORMAL_CSV if args.formal else DEV_CSV)
    # Guard: refuse to overwrite existing final CSV
    if os.path.exists(output_csv):
        print(f"[ERROR] Final CSV already exists: {output_csv}")
        print(f"        Move or remove it before re-running.")
        cleanup_or_report("startup final-output guard")
        stop_server()
        sys.exit(1)
    print(f"[INFO] Output: {output_csv}")
    print()

    # ---- Atomic publish: write to tmp first ----
    tmp_csv = output_csv + ".tmp"
    # Guard: refuse if tmp already exists (previous crash left residue)
    if os.path.exists(tmp_csv):
        print(f"[ERROR] Stale tmp file exists: {tmp_csv}")
        print(f"        Remove it before re-running (previous run may have crashed).")
        cleanup_or_report("startup tmp guard")
        stop_server()
        sys.exit(1)
    completed = 0
    any_execution_failure = False
    # Exclusive creation: fail if file already exists (race-safe)
    try:
        f = open(tmp_csv, "x", newline="", encoding="utf-8")
    except FileExistsError:
        print(f"[ERROR] Cannot create tmp file (exists): {tmp_csv}")
        cleanup_or_report("tmp creation failure")
        stop_server()
        sys.exit(1)
    try:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for cond_name, cond_desc, loss, delay, jitter, reorder in conditions:
            print(f"\n{'='*60}")
            print(f"[CONDITION] {cond_name}: {cond_desc}")
            print(f"            loss={loss}% delay={delay}ms jitter={jitter}ms reorder={reorder}%")
            print(f"{'='*60}")
            requested_config = f"loss={loss}% delay={delay}ms jitter={jitter}ms reorder={reorder}%"
            with tc_condition(interface, loss, delay, jitter, reorder) as tc_snap:
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
                        result["interface"] = interface
                        result["requested_netem_config"] = requested_config
                        result["actual_qdisc_config"] = tc_snap
                        # Impairment direction metadata
                        if args.host:
                            result["execution_mode"] = "cross_host"
                            result["impairment_direction"] = "client_egress"
                        else:
                            result["execution_mode"] = "local_loopback"
                            result["impairment_direction"] = "bidirectional_loopback"
                        result["tc_endpoint"] = "client"
                        # Client metadata
                        result["client_git_commit"] = git_commit
                        result["client_git_dirty"] = str(git_dirty).lower()
                        result["client_hostname"] = client_hostname
                        result["client_cpu_model"] = client_cpu
                        result["client_python_version"] = python_version
                        result["client_os_info"] = os_info
                        result["command_line"] = command_line
                        # Populate server_env_from_ack from first HELLO_ACK in remote mode
                        if args.no_spawn_server and not server_env_from_ack:
                            ack = result.get("hello_ack", {})
                            for k in ("server_git_commit", "server_git_dirty",
                                      "server_python_version", "server_os_info",
                                      "server_hostname", "server_cpu_model"):
                                if k in ack:
                                    server_env_from_ack[k] = ack[k]
                        # server git info: from HELLO_ACK in remote mode, local otherwise
                        if args.no_spawn_server:
                            result["server_git_commit"] = server_env_from_ack.get("server_git_commit", "")
                            result["server_git_dirty"] = server_env_from_ack.get("server_git_dirty", "")
                            result["server_python_version"] = server_env_from_ack.get("server_python_version", "")
                            result["server_os_info"] = server_env_from_ack.get("server_os_info", "")
                            result["server_hostname"] = server_env_from_ack.get("server_hostname", "")
                            result["server_cpu_model"] = server_env_from_ack.get("server_cpu_model", "")
                        else:
                            result["server_git_commit"] = git_commit
                            result["server_git_dirty"] = str(git_dirty)
                            result["server_python_version"] = python_version
                            result["server_os_info"] = os_info
                            result["server_hostname"] = socket.gethostname()
                            result["server_cpu_model"] = ""
                        # execution_valid: composite of sub-checks
                        tc_requested = {
                            "delay_ms": delay,
                            "loss_pct": loss,
                            "jitter_ms": jitter,
                            "reorder_pct": reorder,
                        }
                        tc_ok, _tc_reason, tc_actual = verify_tc_snapshot(
                            tc_snap, cond_name,
                            requested=tc_requested,
                        )
                        result["actual_delay_ms"] = round(tc_actual["delay_ms"], 2)
                        result["actual_loss_pct"] = round(tc_actual["loss_pct"], 2)
                        result["actual_jitter_ms"] = round(tc_actual["jitter_ms"], 2)
                        result["actual_reorder_pct"] = round(tc_actual["reorder_pct"], 2)
                        no_internal_exception = result["error_count"] == 0
                        no_response_mismatch = result["rejected_count"] == 0
                        have_last_server_response = result["accepted_count"] > 0
                        server_last_seq = result.get("server_final_seq", 0) if have_last_server_response else None
                        client_state_available = result.get("client_final_seq", 0) > 0
                        no_malformed_response = no_response_mismatch
                        final_state_auditable = (
                            have_last_server_response
                            and server_last_seq is not None
                            and client_state_available
                            and no_malformed_response
                        )
                        is_timeout = result["timeout_count"] > 0
                        exec_valid = (
                            tc_ok
                            and no_internal_exception
                            and no_response_mismatch
                            and (final_state_auditable or is_timeout)
                        )
                        result["state_audit_available"] = final_state_auditable
                        result["result_success"] = not is_timeout and result["error_count"] == 0 and result["rejected_count"] == 0
                        if is_timeout:
                            result["result_success"] = False
                            result["state_audit_available"] = False
                            result["result_success"] = False
                            result["state_audit_available"] = False
                        result["execution_valid"] = exec_valid
                        if not exec_valid:
                            any_execution_failure = True
                        result.pop("hello_ack", None)
                        writer.writerow(result)
                        f.flush()
                        completed += 1
                        print(
                            f"  [{completed}/{total}] {protocol} {cond_name} r{repeat_id}: "
                            f"acc={result['accepted_count']} rej={result['rejected_count']} "
                            f"rtt={result['avg_rtt_ms']:.1f}ms "
                            f"exec={'OK' if exec_valid else 'FAIL'}"
                        )
    except BaseException:
        # On any exception during writing, clean up tc, verify, and keep tmp.
        f.close()
        cleanup_or_report("exception path")
        stop_server()
        raise
    f.flush()
    os.fsync(f.fileno())
    f.close()

    # ---- Validate matrix completeness ----
    expected_rows = len(PROTOCOLS) * len(conditions) * repeats
    if completed != expected_rows:
        print(f"[ERROR] Matrix incomplete: {completed}/{expected_rows} rows written")
        any_execution_failure = True

    # ---- Validator: strict post-hoc checks ----
    import csv as _csv
    issues: List[str] = []
    sane_issues: List[str] = []
    exec_issues: List[str] = []
    tc_issues: List[str] = []
    with open(tmp_csv, "r", encoding="utf-8") as vf:
        reader = _csv.DictReader(vf)
        for i, row in enumerate(reader, 1):
            # Execution validity
            if row.get("execution_valid") not in ("True", "true", "1"):
                exec_issues.append(f"row {i}: execution_valid={row.get('execution_valid')}")
            # tc verification
            if row.get("condition_name") != "control":
                if "mismatch" in str(row.get("failure_reason", "")):
                    tc_issues.append(f"row {i}: tc mismatch: {row.get('failure_reason')}")
            # Sane values
            sr = float(row.get("success_rate", 0))
            if sr < 0 or sr > 100:
                sane_issues.append(f"row {i}: success_rate={sr} out of range")
            # Git commits must be full 40-character hex SHAs
            gc = row.get("server_git_commit", "")
            if not is_full_hex_commit(gc):
                issues.append(f"row {i}: server_git_commit is not a full 40-char hex SHA")
            # Git dirty must be false
            gd = row.get("server_git_dirty", "")
            if str(gd).lower() != "false":
                issues.append(f"row {i}: server_git_dirty={gd} (expected false)")
            cgc = row.get("client_git_commit", "")
            if not is_full_hex_commit(cgc):
                issues.append(f"row {i}: client_git_commit is not a full 40-char hex SHA")
            # Client git dirty must be false
            cgd = row.get("client_git_dirty", "")
            if str(cgd).lower() != "false":
                issues.append(f"row {i}: client_git_dirty={cgd} (expected false)")
            # Control conditions must not have netem
            if row.get("condition_name") == "control":
                actual_qdisc = row.get("actual_qdisc_config", "")
                if "netem" in actual_qdisc:
                    issues.append(f"row {i}: control condition has netem in actual_qdisc_config")
            # Formal mode: client and server commits must match
            if args.formal and gc and cgc and gc != cgc:
                issues.append(f"row {i}: commit mismatch client={cgc[:12]}... server={gc[:12]}...")

    all_critical = issues + sane_issues + exec_issues + tc_issues
    if all_critical:
        print(f"[FAIL] {len(all_critical)} critical issues found:")
        for iss in all_critical[:20]:
            print(f"  - {iss}")
        if len(all_critical) > 20:
            print(f"  ... and {len(all_critical) - 20} more")
        cleanup_or_report("validation failure")
        stop_server()
        sys.exit(1)

    # ---- Atomic replace: tmp → final ----
    if any_execution_failure:
        print(f"[ERROR] Execution failures detected. Keeping tmp file: {tmp_csv}")
        print(f"        Final CSV NOT published.")
        cleanup_or_report("execution failure")
        stop_server()
        sys.exit(1)
    cleanup_ok, final_snapshot = cleanup_tc_and_verify(interface)
    if not cleanup_ok:
        print(f"[FATAL] tc cleanup verification failed before publish")
        print(f"[FATAL] Final qdisc snapshot: {final_snapshot}")
        print(f"[FATAL] Keeping tmp file: {tmp_csv}")
        print(f"        Final CSV NOT published.")
        stop_server()
        sys.exit(1)
    try:
        publish_tmp_no_clobber(tmp_csv, output_csv)
    except BaseException as e:
        cleanup_or_report("publish failure")
        print(f"[FATAL] Failed to publish final CSV without clobbering: {e}")
        print(f"[FATAL] Keeping tmp file: {tmp_csv}")
        stop_server()
        sys.exit(1)
    print(f"[OK] All {completed} experiments passed execution_valid")

    stop_server()

    print(f"\n[DONE] Results written to {output_csv}")
    print(f"[DONE] {completed} experiments completed.")


if __name__ == "__main__":
    main()
