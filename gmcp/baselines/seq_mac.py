# -*- coding: utf-8 -*-
# gmcp/baselines/seq_mac.py
#
# Sequential MAC 协议实现
#
# 原理：
# - 每个消息用共享密钥计算 HMAC(seq || payload)
# - 接收方验证 HMAC 是否正确
# - 无状态链接，仅依赖 seq 递增防重放

import hashlib
import hmac as hmac_mod
import time
from typing import Dict, Any, Tuple
from dataclasses import dataclass

from gmcp.config import DATA_AUTH_KEY


@dataclass
class SeqMACState:
    """SeqMAC 协议状态"""
    session_id: str
    sender_id: str
    epoch: int
    last_seq: int


def compute_seq_mac(key: bytes, seq: int, payload: str) -> str:
    """HMAC-SHA256(key, seq || payload)"""
    msg = f"{seq}:{payload}".encode("utf-8")
    return hmac_mod.new(key, msg, hashlib.sha256).hexdigest()


def build_data_packet(
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
) -> Dict[str, Any]:
    mac = compute_seq_mac(DATA_AUTH_KEY, seq, payload)
    return {
        "type": "DATA",
        "protocol": "seq_mac",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "seq": seq,
        "payload": payload,
        "mac": mac,
        "timestamp": time.time(),
    }


def verify_packet(
    packet: Dict[str, Any],
    expected_session_id: str,
    expected_epoch: int,
) -> Tuple[bool, str]:
    if packet.get("session_id") != expected_session_id:
        return False, "session_id mismatch"
    if packet.get("epoch") != expected_epoch:
        return False, "epoch mismatch"

    payload = packet.get("payload", "")
    seq = int(packet.get("seq", 0))
    expected_mac = compute_seq_mac(DATA_AUTH_KEY, seq, payload)
    if packet.get("mac") != expected_mac:
        return False, "mac mismatch"

    return True, "ok"


class SeqMACVerifier:
    def __init__(self, state: SeqMACState):
        self.state = state

    def verify_data_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        if packet.get("type") != "DATA":
            return False, "invalid packet type"
        if packet.get("protocol") != "seq_mac":
            return False, "invalid protocol"

        seq = int(packet.get("seq", 0))
        if seq <= self.state.last_seq:
            return False, "replay or old packet detected"
        if seq != self.state.last_seq + 1:
            return False, f"seq gap detected: expected {self.state.last_seq + 1}, got {seq}"

        ok, reason = verify_packet(
            packet=packet,
            expected_session_id=self.state.session_id,
            expected_epoch=self.state.epoch,
        )
        if not ok:
            return False, reason

        self.state.last_seq = seq
        return True, "ok"

    def get_state(self) -> Dict[str, Any]:
        return {
            "session_id": self.state.session_id,
            "sender_id": self.state.sender_id,
            "epoch": self.state.epoch,
            "last_seq": self.state.last_seq,
        }


def create_initial_state(session_id: str, sender_id: str, epoch: int) -> SeqMACState:
    return SeqMACState(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        last_seq=0,
    )
