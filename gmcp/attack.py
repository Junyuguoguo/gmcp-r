# gmcp/attack.py
#
# Baseline攻击模型 —— 两类攻击者模型
#
# Category 1: 网络攻击者 (Network Attacker, 不知道密钥)
#   - modify_unsigned:      修改payload，不更新HMAC/chain_hash
#   - metadata_tamper:      修改seq/session/prev_mem等元数据，不更新HMAC
#   - exact_replay:         保存第1条完整合法报文，原封不动重发
#
# Category 2: 恶意持钥客户端 (Malicious Key-Holding Client, 知道DATA密钥)
#   - forged_prev_mem_valid_mac:   用合法HMAC构造与历史不连续的消息
#   - sequence_gap_valid_mac:      跳过序列号
#   - cross_session_valid_mac:     跨会话
#   - cross_epoch_valid_mac:       跨epoch

from typing import Dict, Any, Optional

# ---- 攻击类别常量 ----

CATEGORY_NETWORK_ATTACKER = "network_attacker"
CATEGORY_MALICIOUS_CLIENT = "malicious_client"

# 网络攻击者攻击类型（不知道密钥，无法伪造有效MAC）
NETWORK_ATTACK_TYPES = ("modify_unsigned", "metadata_tamper", "exact_replay")

# 恶意持钥客户端攻击类型（知道DATA密钥，可计算有效MAC）
MALICIOUS_CLIENT_ATTACK_TYPES = (
    "forged_prev_mem_valid_mac",
    "sequence_gap_valid_mac",
    "cross_session_valid_mac",
    "cross_epoch_valid_mac",
)

# 所有攻击类型
ALL_ATTACK_TYPES = ("none",) + NETWORK_ATTACK_TYPES + MALICIOUS_CLIENT_ATTACK_TYPES


def attack_category(attack_type: str) -> str:
    """返回攻击类型所属的类别。"""
    if attack_type in NETWORK_ATTACK_TYPES:
        return CATEGORY_NETWORK_ATTACKER
    if attack_type in MALICIOUS_CLIENT_ATTACK_TYPES:
        return CATEGORY_MALICIOUS_CLIENT
    return "none"


def attack_applicable_to_protocol(attack_type: str, protocol: str) -> bool:
    """
    判断某个攻击对某个协议是否有意义。
    例如 forged_prev_mem_valid_mac 对 seq_mac/ticket_only 不适用（它们没有prev_mem链）。
    """
    if attack_type == "forged_prev_mem_valid_mac":
        return protocol in ("gmcp_r", "hash_chain", "authenticated_hash_chain")
    return True


# =====================================================================
#  Category 1: 网络攻击者（不知道密钥，不重算MAC）
# =====================================================================

def apply_modify_unsigned(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改payload但不重新计算MAC/chain_hash。
    模拟网络中间人篡改payload。
    """
    packet = dict(packet)
    packet["payload"] = "attacked-payload-unsigned"
    return packet


def apply_metadata_tamper(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    修改元数据字段（prev_mem/prev_hash等）但不重新计算MAC。
    模拟网络中间人篡改协议状态字段。
    """
    packet = dict(packet)
    if "prev_mem" in packet:
        packet["prev_mem"] = "tampered-memory"
    elif "prev_hash" in packet:
        packet["prev_hash"] = "tampered-hash"
    # 也篡改seq以增加攻击烈度
    packet["seq"] = packet.get("seq", 0) + 100
    return packet


def apply_exact_replay(
    saved_packet: Dict[str, Any],
) -> Dict[str, Any]:
    """
    原封不动重放保存的第1条合法报文。
    返回完整报文的副本。
    """
    return dict(saved_packet)


# =====================================================================
#  Category 2: 恶意持钥客户端（知道密钥，可重算有效MAC）
# =====================================================================

def build_forged_prev_mem_packet(
    protocol: str,
    build_fn,
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
    **build_kwargs,
) -> Optional[Dict[str, Any]]:
    """
    用合法HMAC构造与历史不连续的消息（伪造prev_mem/prev_hash）。
    对gmcp_r: prev_mem设为假值，HMAC正确覆盖。
    对hash_chain/authenticated_hash_chain: prev_hash设为假值，chain_hash/HMAC正确覆盖。
    对seq_mac/ticket_only: 不适用（返回None）。
    """
    if protocol == "gmcp_r":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_mem="forged-memory-valid-mac",
            payload=payload,
        )
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash="forged-hash-valid-mac",
            payload=payload,
        )
    # seq_mac / ticket_only 没有prev_mem链，此攻击不适用
    return None


def build_sequence_gap_packet(
    protocol: str,
    build_fn,
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
    state: Any,
    gap: int = 5,
) -> Dict[str, Any]:
    """
    跳过序列号，用有效MAC构造报文。
    例如正常应发seq=10，实际发seq=15。
    """
    fake_seq = seq + gap
    if protocol == "gmcp_r":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=fake_seq,
            prev_mem=state.last_mem,
            payload=payload,
        )
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=fake_seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
    elif protocol == "seq_mac":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=fake_seq,
            payload=payload,
        )
    elif protocol == "ticket_only":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=fake_seq,
            payload=payload,
            ticket=state.ticket,
        )
    raise ValueError(f"Unknown protocol: {protocol}")


def build_cross_session_packet(
    protocol: str,
    build_fn,
    sender_id: str,
    epoch: int,
    seq: int,
    payload: str,
    state: Any,
    fake_session: str = "attacker-cross-session",
) -> Dict[str, Any]:
    """
    用合法MAC构造跨会话报文（session_id与注册会话不匹配）。
    """
    if protocol == "gmcp_r":
        return build_fn(
            session_id=fake_session,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_mem=state.last_mem,
            payload=payload,
        )
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        return build_fn(
            session_id=fake_session,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
    elif protocol == "seq_mac":
        return build_fn(
            session_id=fake_session,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
        )
    elif protocol == "ticket_only":
        return build_fn(
            session_id=fake_session,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            payload=payload,
            ticket=state.ticket,
        )
    raise ValueError(f"Unknown protocol: {protocol}")


def build_cross_epoch_packet(
    protocol: str,
    build_fn,
    session_id: str,
    sender_id: str,
    seq: int,
    payload: str,
    state: Any,
    fake_epoch: int = 999,
) -> Dict[str, Any]:
    """
    用合法MAC构造跨epoch报文（epoch与当前会话不匹配）。
    """
    if protocol == "gmcp_r":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=fake_epoch,
            seq=seq,
            prev_mem=state.last_mem,
            payload=payload,
        )
    elif protocol in ("hash_chain", "authenticated_hash_chain"):
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=fake_epoch,
            seq=seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
    elif protocol == "seq_mac":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=fake_epoch,
            seq=seq,
            payload=payload,
        )
    elif protocol == "ticket_only":
        return build_fn(
            session_id=session_id,
            sender_id=sender_id,
            epoch=fake_epoch,
            seq=seq,
            payload=payload,
            ticket=state.ticket,
        )
    raise ValueError(f"Unknown protocol: {protocol}")


# =====================================================================
#  Legacy 兼容（保留旧接口供旧代码调用）
# =====================================================================

def drop_packet(seq: int, drop_seq: int) -> bool:
    """返回 True 表示这个包要被丢弃。"""
    return seq == drop_seq


def modify_payload(packet: Dict[str, Any], target_seq: int) -> Dict[str, Any]:
    """Legacy: 修改 payload，但不重新计算 auth_tag。"""
    if packet.get("seq") == target_seq:
        packet = dict(packet)
        packet["payload"] = "attacked-payload"
    return packet


def modify_prev_mem(packet: Dict[str, Any], target_seq: int) -> Dict[str, Any]:
    """Legacy: 修改 prev_mem。"""
    if packet.get("seq") == target_seq:
        packet = dict(packet)
        packet["prev_mem"] = "fake-memory"
    return packet


def replay_packet(saved_packet: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy: 重放旧包。"""
    return dict(saved_packet)
