# gmcp/packet.py

import time
from typing import Dict, Any

from gmcp.config import DATA_AUTH_KEY
from gmcp.crypto_utils import hash_text, hmac_sha256_hex


def build_data_packet(
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    prev_mem: str,
    payload: str,
    protocol: str = "gmcp",
) -> Dict[str, Any]:
    """
    构造 DATA 报文。
    """
    payload_hash = hash_text(payload)

    packet = {
        "type": "DATA",
        "protocol": protocol,
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "seq": seq,
        "prev_mem": prev_mem,
        "payload": payload,
        "payload_hash": payload_hash,
        "timestamp": time.time(),
    }

    auth_tag = hmac_sha256_hex(DATA_AUTH_KEY, packet)
    packet["auth_tag"] = auth_tag
    return packet


def packet_without_auth(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    验证 HMAC 时要去掉 auth_tag 字段。
    """
    data = dict(packet)
    data.pop("auth_tag", None)
    return data