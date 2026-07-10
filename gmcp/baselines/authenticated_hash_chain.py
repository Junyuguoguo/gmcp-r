# -*- coding: utf-8 -*-
# gmcp/baselines/authenticated_hash_chain.py
#
# Authenticated Hash Chain 协议实现
#
# 与普通 Hash Chain 的区别：
# - 每个数据包附带 HMAC-SHA256 认证标签（与 GMCP-R 相同认证能力）
# - 去掉 MemoryTicket 和 Checkpoint（恢复时仍需重放完整链）
# - 目的：证明认证能力来自 HMAC，而非 MemoryTicket/Checkpoint

import hashlib
import hmac as hmac_mod
import time
from typing import Dict, Any, Tuple
from dataclasses import dataclass

from gmcp.config import DATA_AUTH_KEY
from gmcp.baselines.hash_chain import (
    hash_func,
    compute_chain_hash,
)


@dataclass
class AuthHashChainState:
    """Authenticated Hash Chain 协议状态"""
    session_id: str
    sender_id: str
    epoch: int
    last_seq: int
    last_hash: str
    hash_chain: list  # List of (seq, hash, payload_hash)


def build_data_packet(
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    prev_hash: str,
    payload: str,
) -> Dict[str, Any]:
    """
    构建带 HMAC 的数据包。

    字段与普通 Hash Chain 相同，额外加入 auth_tag：
    auth_tag = HMAC(DATA_AUTH_KEY, canonical(所有其他字段))
    """
    payload_hash = hash_func(payload)
    chain_hash = compute_chain_hash(prev_hash, payload)

    packet = {
        "type": "DATA",
        "protocol": "authenticated_hash_chain",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "seq": seq,
        "payload": payload,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "chain_hash": chain_hash,
        "timestamp": time.time(),
    }

    # 计算 HMAC（覆盖除 auth_tag 外的全部字段）
    from gmcp.crypto_utils import with_hmac
    packet = with_hmac(DATA_AUTH_KEY, packet, tag_field="auth_tag")
    return packet


def verify_packet(
    packet: Dict[str, Any],
    expected_session_id: str,
    expected_sender_id: str,
    expected_epoch: int,
    last_hash: str,
) -> Tuple[bool, str]:
    """
    验证数据包：
    1. HMAC 认证
    2. session/sender/epoch
    3. payload_hash
    4. chain_hash
    5. prev_hash 连续性
    """
    from gmcp.crypto_utils import verify_tagged_hmac

    # 1. HMAC 验证（必须先做）
    if not verify_tagged_hmac(DATA_AUTH_KEY, packet, tag_field="auth_tag"):
        return False, "auth_tag mismatch"

    # 2. session_id
    if packet.get("session_id") != expected_session_id:
        return False, "session_id mismatch"

    # 3. sender_id
    if packet.get("sender_id") != expected_sender_id:
        return False, "sender_id mismatch"

    # 4. epoch
    if packet.get("epoch") != expected_epoch:
        return False, "epoch mismatch"

    # 5. payload_hash
    payload = packet.get("payload", "")
    expected_payload_hash = hash_func(payload)
    if packet.get("payload_hash") != expected_payload_hash:
        return False, "payload_hash mismatch"

    # 6. chain_hash
    prev_hash = packet.get("prev_hash", "")
    expected_chain_hash = compute_chain_hash(prev_hash, payload)
    if packet.get("chain_hash") != expected_chain_hash:
        return False, "chain_hash mismatch"

    # 7. prev_hash 连续性
    if prev_hash != last_hash:
        return False, "prev_hash mismatch, chain broken"

    return True, "ok"


class AuthHashChainVerifier:
    """Authenticated Hash Chain 协议验证器"""

    def __init__(self, state: AuthHashChainState):
        self.state = state

    def verify_data_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        if packet.get("type") != "DATA":
            return False, "invalid packet type"
        if packet.get("protocol") != "authenticated_hash_chain":
            return False, "invalid protocol"

        seq = int(packet.get("seq", 0))
        if seq <= self.state.last_seq:
            return False, "replay or old packet detected"
        if seq != self.state.last_seq + 1:
            return False, f"seq gap detected: expected {self.state.last_seq + 1}, got {seq}"

        ok, reason = verify_packet(
            packet=packet,
            expected_session_id=self.state.session_id,
            expected_sender_id=self.state.sender_id,
            expected_epoch=self.state.epoch,
            last_hash=self.state.last_hash,
        )
        if not ok:
            return False, reason

        # 原子更新状态
        self.state.last_seq = seq
        self.state.last_hash = packet.get("chain_hash", "")
        self.state.hash_chain.append({
            "seq": seq,
            "hash": packet.get("chain_hash", ""),
            "payload_hash": packet.get("payload_hash", ""),
        })
        return True, "ok"

    def get_state(self) -> Dict[str, Any]:
        return {
            "session_id": self.state.session_id,
            "sender_id": self.state.sender_id,
            "epoch": self.state.epoch,
            "last_seq": self.state.last_seq,
            "last_hash": self.state.last_hash,
            "chain_length": len(self.state.hash_chain),
        }


def create_initial_state(session_id: str, sender_id: str, epoch: int) -> AuthHashChainState:
    initial_hash = hash_func(f"init:{session_id}:{epoch}")
    return AuthHashChainState(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        last_seq=0,
        last_hash=initial_hash,
        hash_chain=[],
    )
