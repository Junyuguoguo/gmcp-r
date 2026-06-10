# gmcp/recovery.py

import time
from typing import Dict, Any

from gmcp.config import SHARED_KEY
from gmcp.crypto_utils import hmac_sha256_hex, verify_hmac


def build_snack(
    session_id: str,
    epoch: int,
    missing_from: int,
    missing_to: int,
    current_seq: int,
    current_mem: str,
) -> Dict[str, Any]:

    msg = {
        "type": "SNACK",
        "session_id": session_id,
        "epoch": epoch,
        "missing_from": missing_from,
        "missing_to": missing_to,
        "current_seq": current_seq,
        "current_mem": current_mem,
        "timestamp": time.time(),
    }

    msg["auth_tag"] = hmac_sha256_hex(SHARED_KEY, msg)
    return msg


def build_ir_refresh(
    session_id: str,
    epoch: int,
    base_seq: int,
    base_mem: str,
) -> Dict[str, Any]:

    msg = {
        "type": "IR_REFRESH",
        "session_id": session_id,
        "epoch": epoch,
        "base_seq": base_seq,
        "base_mem": base_mem,
        "timestamp": time.time(),
    }

    msg["auth_tag"] = hmac_sha256_hex(SHARED_KEY, msg)
    return msg


def verify_recovery_message(msg: Dict[str, Any]) -> bool:
    tag = msg.get("auth_tag")
    if not tag:
        return False

    data = dict(msg)
    data.pop("auth_tag", None)

    return verify_hmac(SHARED_KEY, data, tag)