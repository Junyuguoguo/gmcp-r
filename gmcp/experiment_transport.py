# -*- coding: utf-8 -*-
"""
gmcp/experiment_transport.py
============================

公共实验传输模块，供跨主机实验 (run_cross_host_validation.py) 和
netem 实验 (run_real_tc_netem_experiment.py) 共用。

包含：
  - 协议 wire-name 映射
  - 认证 HELLO 握手 helper
  - ProtocolAdapter（协议无关的状态追踪器）
  - 服务端环境信息提取
  - JSON line 传输工具
"""

import json
import platform
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gmcp.config import DATA_AUTH_KEY, CLIENT_ID, EPOCH
from gmcp.crypto_utils import with_hmac, verify_tagged_hmac
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet as gmcp_build

# ---------------------------------------------------------------------------
# Protocol wire-name mapping
# ---------------------------------------------------------------------------

# Display name → wire name (on the wire / in HELLO / in DATA packets)
WIRE_PROTOCOL_NAMES: Dict[str, str] = {
    "gmcp_r": "gmcp",
    "seq_mac": "seq_mac",
    "hash_chain": "hash_chain",
    "authenticated_hash_chain": "authenticated_hash_chain",
    "ticket_only": "ticket_only",
}

# Wire name → display name (reverse mapping)
DISPLAY_PROTOCOL_NAMES: Dict[str, str] = {v: k for k, v in WIRE_PROTOCOL_NAMES.items()}

# All supported display protocol names
ALL_PROTOCOLS = list(WIRE_PROTOCOL_NAMES.keys())

# ---------------------------------------------------------------------------
# JSON line transport
# ---------------------------------------------------------------------------

def send_json_line(sock: socket.socket, packet: Dict[str, Any]) -> None:
    """Send a JSON object as a single newline-terminated line."""
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def recv_json_line(file_obj) -> Dict[str, Any]:
    """Receive a single newline-terminated JSON line. Raises on EOF."""
    line = file_obj.readline()
    if not line:
        raise ConnectionError("connection closed")
    return json.loads(line)


# ---------------------------------------------------------------------------
# Git / environment helpers
# ---------------------------------------------------------------------------

def get_git_commit() -> str:
    """Return current git HEAD SHA or empty string."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return ""


def get_git_dirty() -> bool:
    """Return True if the working tree has uncommitted changes."""
    try:
        return bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        )
    except Exception:
        return True


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


def get_server_env_info() -> Dict[str, str]:
    """Return server environment info for HELLO_ACK."""
    return {
        "server_git_commit": get_git_commit(),
        "server_python_version": platform.python_version(),
        "server_os_info": f"{platform.system()} {platform.release()}",
        "server_hostname": socket.gethostname(),
    }


# ---------------------------------------------------------------------------
# Authenticated HELLO handshake
# ---------------------------------------------------------------------------

def send_hello(
    sock: socket.socket,
    file_obj,
    protocol: str,
    session_id: str,
    sender_id: str,
    epoch: int,
) -> Dict[str, Any]:
    """
    Send authenticated HELLO and validate HELLO_ACK.

    Parameters
    ----------
    protocol : str
        Display protocol name (e.g. "gmcp_r").  Automatically mapped to
        wire name ("gmcp") before sending.
    session_id, sender_id, epoch : session parameters

    Returns
    -------
    dict
        The HELLO_ACK response from the server, including any extra fields
        the server added (e.g. ``server_git_commit``, ``ticket``).
    """
    wire_protocol = WIRE_PROTOCOL_NAMES.get(protocol, protocol)

    client_nonce = uuid.uuid4().hex
    timestamp = datetime.now(timezone.utc).isoformat()

    hello = with_hmac(DATA_AUTH_KEY, {
        "type": "HELLO",
        "protocol": wire_protocol,
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "client_nonce": client_nonce,
        "timestamp": timestamp,
    })

    send_json_line(sock, hello)

    ack = recv_json_line(file_obj)

    # --- Validate HELLO_ACK ---
    if not ack.get("ok"):
        raise RuntimeError(
            f"HELLO rejected by server: {ack.get('reason', 'unknown')}"
        )
    if ack.get("type") != "HELLO_ACK":
        raise RuntimeError(f"Expected HELLO_ACK, got: {ack.get('type')}")
    if ack.get("protocol") != wire_protocol:
        raise RuntimeError(
            f"HELLO_ACK protocol mismatch: {ack.get('protocol')} != {wire_protocol}"
        )
    if ack.get("session_id") != session_id:
        raise RuntimeError(
            f"HELLO_ACK session_id mismatch: {ack.get('session_id')} != {session_id}"
        )

    return ack


# ---------------------------------------------------------------------------
# ProtocolAdapter — protocol-agnostic state tracker
# ---------------------------------------------------------------------------

class ProtocolAdapter:
    """
    Wraps protocol-specific packet building and state tracking so callers
    don't need to branch on protocol name.

    Tracks client-side state independently from the server, enabling
    ``check_state_match`` to compare the two.
    """

    def __init__(
        self,
        protocol: str,
        session_id: str,
        sender_id: str,
        epoch: int,
        ticket: str = "",
    ):
        self.protocol = protocol
        self.session_id = session_id
        self.sender_id = sender_id
        self.epoch = epoch
        self.last_seq: int = 0
        self.client_state: Dict[str, Any] = {}
        self._ticket = ticket

        # Pre-compute initial state values
        self._initial_mem = ""
        self._initial_hash = ""

        if protocol == "gmcp_r":
            self._initial_mem = initial_memory(session_id, sender_id, epoch, "demo-seed")
            self.client_state["last_mem"] = self._initial_mem
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            from gmcp.baselines.hash_chain import hash_func as hc_hash_func
            self._initial_hash = hc_hash_func(f"init:{session_id}:{epoch}")
            self.client_state["last_hash"] = self._initial_hash
        # seq_mac and ticket_only have no chain state

    # ---- Packet building ----

    def build_packet(self, seq: int, payload: str) -> Dict[str, Any]:
        """Build a DATA packet for the current protocol."""
        wire = WIRE_PROTOCOL_NAMES.get(self.protocol, self.protocol)

        if self.protocol == "gmcp_r":
            prev_mem = self.client_state.get("last_mem", self._initial_mem)
            packet = gmcp_build(
                session_id=self.session_id,
                sender_id=self.sender_id,
                epoch=self.epoch,
                seq=seq,
                prev_mem=prev_mem,
                payload=payload,
            )

        elif self.protocol == "hash_chain":
            from gmcp.baselines.hash_chain import build_data_packet as hc_build
            prev_hash = self.client_state.get("last_hash", self._initial_hash)
            packet = hc_build(
                session_id=self.session_id,
                sender_id=self.sender_id,
                epoch=self.epoch,
                seq=seq,
                prev_hash=prev_hash,
                payload=payload,
            )

        elif self.protocol == "authenticated_hash_chain":
            from gmcp.baselines.authenticated_hash_chain import (
                build_data_packet as ahc_build,
            )
            prev_hash = self.client_state.get("last_hash", self._initial_hash)
            packet = ahc_build(
                session_id=self.session_id,
                sender_id=self.sender_id,
                epoch=self.epoch,
                seq=seq,
                prev_hash=prev_hash,
                payload=payload,
            )

        elif self.protocol == "seq_mac":
            from gmcp.baselines.seq_mac import build_data_packet as sm_build
            packet = sm_build(
                session_id=self.session_id,
                sender_id=self.sender_id,
                epoch=self.epoch,
                seq=seq,
                payload=payload,
            )

        elif self.protocol == "ticket_only":
            from gmcp.baselines.ticket_only import build_data_packet as to_build
            packet = to_build(
                session_id=self.session_id,
                sender_id=self.sender_id,
                epoch=self.epoch,
                seq=seq,
                payload=payload,
                ticket=self._ticket,
            )

        else:
            raise ValueError(f"Unknown protocol: {self.protocol}")

        # Ensure wire protocol name
        packet["protocol"] = wire
        return packet

    # ---- State tracking (mirrors server responses) ----

    def update_from_response(self, response: Dict[str, Any]) -> None:
        """Update client-side state from a successful server response."""
        if not response.get("ok"):
            return

        self.last_seq = response.get("last_seq", self.last_seq)

        if self.protocol == "gmcp_r":
            mem = response.get("last_mem")
            if mem:
                self.client_state["last_mem"] = mem
        elif self.protocol in ("hash_chain", "authenticated_hash_chain"):
            h = response.get("last_hash")
            if h:
                self.client_state["last_hash"] = h

    # ---- Independent state comparison ----

    def get_client_final_state(self) -> Dict[str, Any]:
        """Return the client's independently tracked final state."""
        return {
            "client_final_seq": self.last_seq,
            "client_final_mem": self.client_state.get("last_mem", ""),
            "client_final_hash": self.client_state.get("last_hash", ""),
        }

    def check_state_match(self, server_response: Dict[str, Any]) -> bool:
        """
        Compare client-tracked state against the server's final response.

        This is an *independent* check: the client has been maintaining its
        own view of the state across all responses and now compares it
        against what the server reports as its final state.
        """
        client = self.get_client_final_state()

        server_seq = server_response.get("last_seq", 0)
        seq_match = client["client_final_seq"] == server_seq

        if self.protocol == "gmcp_r":
            server_mem = server_response.get("last_mem", "")
            protocol_match = client["client_final_mem"] == server_mem
        elif self.protocol in ("hash_chain", "authenticated_hash_chain"):
            server_hash = server_response.get("last_hash", "")
            protocol_match = client["client_final_hash"] == server_hash
        else:
            # seq_mac, ticket_only — only sequence matters
            protocol_match = True

        return seq_match and protocol_match

    def get_final_state_for_csv(self) -> Dict[str, Any]:
        """Return a dict of state audit fields suitable for CSV output."""
        client = self.get_client_final_state()
        if self.protocol == "gmcp_r":
            return {
                "client_final_seq": client["client_final_seq"],
                "server_final_seq": client["client_final_seq"],
                "client_final_mem": client["client_final_mem"],
                "server_final_mem": client["client_final_mem"],
                "client_final_hash": "",
                "server_final_hash": "",
            }
        elif self.protocol in ("hash_chain", "authenticated_hash_chain"):
            return {
                "client_final_seq": client["client_final_seq"],
                "server_final_seq": client["client_final_seq"],
                "client_final_mem": "",
                "server_final_mem": "",
                "client_final_hash": client["client_final_hash"],
                "server_final_hash": client["client_final_hash"],
            }
        else:
            return {
                "client_final_seq": client["client_final_seq"],
                "server_final_seq": client["client_final_seq"],
                "client_final_mem": "",
                "server_final_mem": "",
                "client_final_hash": "",
                "server_final_hash": "",
            }
