# -*- coding: utf-8 -*-
# gmcp/baselines/ticket_only.py
#
# Ticket-Only 协议实现
#
# 原理：
# - 客户端首次连接时获取一个服务端签名的 ticket
# - 后续消息只需携带 ticket + seq，无需每条消息计算密码学证明
# - 信任模型：ticket 一旦签发即信任，类似 session cookie
# - 安全性最弱：ticket 泄露则可任意伪造消息

import hashlib
import hmac as hmac_mod
import time
import json
from typing import Dict, Any, Tuple
from dataclasses import dataclass

from gmcp.config import DATA_AUTH_KEY


@dataclass
class TicketOnlyState:
    """Ticket-Only 协议状态"""
    session_id: str
    sender_id: str
    epoch: int
    last_seq: int
    ticket: str  # 服务端签发的 ticket（HMAC）


def _sign_ticket(key: bytes, session_id: str, epoch: int) -> str:
    """签发 ticket = HMAC(key, session_id || epoch)"""
    msg = f"{session_id}:{epoch}".encode("utf-8")
    return hmac_mod.new(key, msg, hashlib.sha256).hexdigest()


def _verify_ticket(key: bytes, session_id: str, epoch: int, ticket: str) -> bool:
    expected = _sign_ticket(key, session_id, epoch)
    return hmac_mod.compare_digest(expected, ticket)


def issue_ticket(session_id: str, epoch: int) -> str:
    """服务端签发 ticket"""
    return _sign_ticket(DATA_AUTH_KEY, session_id, epoch)


def build_data_packet(
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
    ticket: str,
) -> Dict[str, Any]:
    return {
        "type": "DATA",
        "protocol": "ticket_only",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "seq": seq,
        "payload": payload,
        "ticket": ticket,
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

    ticket = packet.get("ticket", "")
    if not _verify_ticket(DATA_AUTH_KEY, expected_session_id, expected_epoch, ticket):
        return False, "invalid ticket"

    return True, "ok"


class TicketOnlyVerifier:
    def __init__(self, state: TicketOnlyState):
        self.state = state

    def verify_data_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        if packet.get("type") != "DATA":
            return False, "invalid packet type"
        if packet.get("protocol") != "ticket_only":
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


def create_initial_state(session_id: str, sender_id: str, epoch: int) -> TicketOnlyState:
    ticket = issue_ticket(session_id, epoch)
    return TicketOnlyState(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        last_seq=0,
        ticket=ticket,
    )


def build_session_ticket(session_id: str, epoch: int) -> str:
    """构建 session ticket（与 issue_ticket 相同，对外接口）"""
    return _sign_ticket(DATA_AUTH_KEY, session_id, epoch)


def verify_session_ticket(
    session_ticket: str,
    session_id: str,
    epoch: int,
) -> bool:
    """验证 session ticket 的合法性"""
    return _verify_ticket(DATA_AUTH_KEY, session_id, epoch, session_ticket)


def build_recovery_request(
    session_id: str,
    sender_id: str,
    epoch: int,
    last_seq: int,
    session_ticket: str,
    reason: str,
) -> Dict[str, Any]:
    """
    构建恢复请求

    Ticket-Only 协议的恢复仅依赖 session ticket，
    不携带记忆连续性信息
    """
    return {
        "type": "RECOVERY_REQUEST",
        "protocol": "ticket_only",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "last_seq": last_seq,
        "session_ticket": session_ticket,
        "reason": reason,
        "timestamp": time.time(),
    }


def build_recovery_response(
    session_id: str,
    epoch: int,
    last_seq: int,
    session_ticket: str,
) -> Dict[str, Any]:
    """
    构建恢复响应

    仅返回 session ticket 和基本状态，不包含记忆连续性信息。
    客户端可以恢复会话，但无法验证记忆是否被篡改。
    """
    return {
        "type": "RECOVERY_RESPONSE",
        "protocol": "ticket_only",
        "session_id": session_id,
        "epoch": epoch,
        "last_seq": last_seq,
        "session_ticket": session_ticket,
        "timestamp": time.time(),
    }


def calculate_recovery_overhead(session_ticket: str) -> int:
    """计算恢复开销（字节数），Ticket-Only 的恢复开销极小"""
    return len(session_ticket.encode("utf-8"))


# =========================
# 测试
# =========================

def demo_ticket_only():
    """演示 Ticket-Only 协议"""
    print("=" * 60)
    print("Ticket-Only Protocol Demo")
    print("=" * 60)

    session_id = "demo-session"
    sender_id = "client-001"
    epoch = 1

    state = create_initial_state(session_id, sender_id, epoch)
    verifier = TicketOnlyVerifier(state)
    ticket = state.ticket

    print(f"\nInitial state: {verifier.get_state()}")

    # 发送10个消息
    print("\n--- Sending 10 messages ---")
    for seq in range(1, 11):
        payload = f"message-{seq}"

        packet = build_data_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
            ticket=ticket,
        )

        ok, reason = verifier.verify_data_packet(packet)

        if ok:
            print(f"  seq={seq}: ✅ OK")
        else:
            print(f"  seq={seq}: ❌ FAILED - {reason}")

    print(f"\nFinal state: {verifier.get_state()}")

    # 测试恢复
    print("\n--- Testing Recovery ---")
    recovery_overhead = calculate_recovery_overhead(ticket)
    print(f"Recovery overhead: {recovery_overhead} bytes (session ticket only)")

    recovery_req = build_recovery_request(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        last_seq=state.last_seq,
        session_ticket=ticket,
        reason="network reconnect",
    )
    print(f"Recovery request keys: {list(recovery_req.keys())}")

    recovery_resp = build_recovery_response(
        session_id=session_id,
        epoch=epoch,
        last_seq=state.last_seq,
        session_ticket=ticket,
    )
    print(f"Recovery response keys: {list(recovery_resp.keys())}")

    # 验证 session ticket
    ticket_valid = verify_session_ticket(ticket, session_id, epoch)
    print(f"\nSession ticket valid: {'✅ Yes' if ticket_valid else '❌ No'}")

    # 测试篡改检测（payload 篡改）
    print("\n--- Testing Tamper Detection ---")
    tampered_packet = build_data_packet(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        seq=11,
        payload="original-message",
        ticket=ticket,
    )
    tampered_packet["payload"] = "tampered-message"

    # 注意：Ticket-Only 不验证 payload 完整性，只验证 ticket
    ok, reason = verifier.verify_data_packet(tampered_packet)
    print(f"Tampered payload: {'✅ Detected' if not ok else '⚠️  NOT detected (expected for ticket_only)'}")
    if ok:
        print("  Ticket-Only only verifies ticket, not payload integrity")

    # 测试伪造 ticket
    print("\n--- Testing Forged Ticket ---")
    forged_packet = build_data_packet(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        seq=state.last_seq + 1,
        payload="forged-message",
        ticket="forged-ticket-value",
    )
    ok, reason = verifier.verify_data_packet(forged_packet)
    print(f"Forged ticket: {'✅ Detected' if not ok else '❌ Missed'} - {reason}")

    # 测试 prev_mem 篡改无法检测（Ticket-Only 的弱点）
    print("\n--- prev_mem Tamper (Ticket-Only weakness) ---")
    print("⚠️  Ticket-Only protocol CANNOT detect prev_mem tampering")
    print("    because it has no memory chain binding.")
    print("    An attacker could modify prev_mem without detection.")


if __name__ == "__main__":
    demo_ticket_only()
