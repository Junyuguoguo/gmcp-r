# gmcp/checkpoint.py

import time
from typing import Dict, Any

from gmcp.config import SHARED_KEY
from gmcp.crypto_utils import hmac_sha256_hex, verify_hmac



def build_checkpoint(
    session_id: str,
    epoch: int,
    seq: int,
    memory: str,
) -> Dict[str, Any]:
    checkpoint = {
        "type": "CHECKPOINT",
        "session_id": session_id,
        "epoch": epoch,
        "seq": seq,
        "memory": memory,
        "timestamp": time.time(),
    }

    signature = hmac_sha256_hex(SHARED_KEY, checkpoint)
    checkpoint["signature"] = signature
    return checkpoint


def verify_checkpoint(checkpoint: Dict[str, Any]) -> bool:
    signature = checkpoint.get("signature")
    if not signature:
        return False

    data = dict(checkpoint)
    data.pop("signature", None)

    return verify_hmac(SHARED_KEY, data, signature)