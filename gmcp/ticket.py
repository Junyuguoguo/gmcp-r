# gmcp/ticket.py

import time
from typing import Dict, Any, Set, Tuple

from gmcp.config import SHARED_KEY
from gmcp.crypto_utils import hmac_sha256_hex, verify_hmac, random_nonce


USED_TICKET_NONCES: Set[str] = set()


def build_memory_ticket(
    session_id: str,
    client_id: str,
    epoch: int,
    last_seq: int,
    last_mem: str,
    checkpoint_seq: int,
    checkpoint_mem: str,
    ttl_seconds: int = 3600,
) -> Dict[str, Any]:

    ticket = {
        "type": "MEMORY_TICKET",
        "session_id": session_id,
        "client_id": client_id,
        "epoch": epoch,
        "last_seq": last_seq,
        "last_mem": last_mem,
        "checkpoint_seq": checkpoint_seq,
        "checkpoint_mem": checkpoint_mem,
        "expire_time": time.time() + ttl_seconds,
        "ticket_nonce": random_nonce(),
        "key_version": 1,
    }

    server_auth_tag = hmac_sha256_hex(SHARED_KEY, ticket)
    ticket["server_auth_tag"] = server_auth_tag
    return ticket


def verify_memory_ticket(ticket: Dict[str, Any]) -> Tuple[bool, str]:
    tag = ticket.get("server_auth_tag")
    if not tag:
        return False, "missing server_auth_tag"

    data = dict(ticket)
    data.pop("server_auth_tag", None)

    if not verify_hmac(SHARED_KEY, data, tag):
        return False, "invalid ticket auth tag"

    if time.time() > ticket.get("expire_time", 0):
        return False, "ticket expired"

    nonce = ticket.get("ticket_nonce")
    if nonce in USED_TICKET_NONCES:
        return False, "ticket replay detected"

    USED_TICKET_NONCES.add(nonce)

    return True, "ok"