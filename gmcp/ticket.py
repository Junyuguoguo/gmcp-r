# gmcp/ticket.py

import time
import threading
from typing import Any, Dict, Optional, Set, Tuple

from gmcp.config import TICKET_AUTH_KEY
from gmcp.crypto_utils import hmac_sha256_hex, verify_hmac, random_nonce


class TicketNonceStore:
    """Atomic nonce store for ticket replay prevention.

    All operations are guarded by a threading.Lock() so that concurrent
    recovery requests cannot both consume the same nonce.
    """

    def __init__(self):
        self._used: Set[str] = set()
        self._lock = threading.Lock()

    def is_unused(self, nonce: Any) -> bool:
        with self._lock:
            return bool(nonce) and nonce not in self._used

    def consume(self, nonce: Any) -> bool:
        with self._lock:
            if not nonce or nonce in self._used:
                return False
            self._used.add(nonce)
            return True

    def clear(self) -> None:
        with self._lock:
            self._used.clear()


# Default global store – existing module-level helpers delegate to this.
_default_store = TicketNonceStore()

# Legacy aliases kept for backward compatibility; prefer TicketNonceStore.
USED_TICKET_NONCES: Set[str] = _default_store._used
NONCE_LOCK = _default_store._lock

REQUIRED_MEMORY_TICKET_FIELDS = {
    "type",
    "session_id",
    "client_id",
    "epoch",
    "last_seq",
    "last_mem",
    "checkpoint_seq",
    "checkpoint_mem",
    "expire_time",
    "ticket_nonce",
    "key_version",
    "server_auth_tag",
}


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

    server_auth_tag = hmac_sha256_hex(TICKET_AUTH_KEY, ticket)
    ticket["server_auth_tag"] = server_auth_tag
    return ticket


def _verify_memory_ticket_signature_and_fields(ticket: Dict[str, Any]) -> Tuple[bool, str]:
    missing = sorted(REQUIRED_MEMORY_TICKET_FIELDS - set(ticket.keys()))
    if missing:
        return False, "missing ticket fields: " + ",".join(missing)

    if ticket.get("type") != "MEMORY_TICKET":
        return False, "invalid ticket type"

    tag = ticket.get("server_auth_tag")
    if not tag:
        return False, "missing server_auth_tag"

    data = dict(ticket)
    data.pop("server_auth_tag", None)

    if not verify_hmac(TICKET_AUTH_KEY, data, tag):
        return False, "invalid ticket auth tag"

    if time.time() > ticket.get("expire_time", 0):
        return False, "ticket expired"

    try:
        last_seq = int(ticket.get("last_seq"))
        checkpoint_seq = int(ticket.get("checkpoint_seq"))
    except (TypeError, ValueError):
        return False, "invalid ticket sequence fields"

    if checkpoint_seq > last_seq:
        return False, "checkpoint_seq exceeds last_seq"

    if not str(ticket.get("last_mem", "")):
        return False, "missing last_mem binding"

    if not str(ticket.get("checkpoint_mem", "")):
        return False, "missing checkpoint_mem binding"

    return True, "ok"


def verify_memory_ticket(
    ticket: Dict[str, Any],
    expected_session_id: Optional[str] = None,
    expected_client_id: Optional[str] = None,
    expected_epoch: Optional[int] = None,
    min_last_seq: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Verify a MemoryTicket and consume its nonce on success.

    Optional context binds the ticket to the recovery request that is using it.
    min_last_seq rejects stale tickets whose last_seq would roll the peer back.
    """

    ok, reason = _verify_memory_ticket_signature_and_fields(ticket)
    if not ok:
        return ok, reason

    if expected_session_id is not None and ticket.get("session_id") != expected_session_id:
        return False, "session_id mismatch"

    if expected_client_id is not None and ticket.get("client_id") != expected_client_id:
        return False, "client_id mismatch"

    if expected_epoch is not None and int(ticket.get("epoch")) != int(expected_epoch):
        return False, "epoch mismatch"

    if min_last_seq is not None and int(ticket.get("last_seq")) < int(min_last_seq):
        return False, "rollback detected: ticket last_seq is older than required"

    nonce = ticket.get("ticket_nonce")
    if not _default_store.consume(nonce):
        return False, "ticket replay detected"

    return True, "ok"


def validate_memory_ticket(
    ticket: Dict[str, Any],
    expected_session_id: Optional[str] = None,
    expected_client_id: Optional[str] = None,
    expected_epoch: Optional[int] = None,
    min_last_seq: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Validate a MemoryTicket WITHOUT consuming its nonce.

    Use this for multi-step verification where nonce should only be consumed
    after ALL checks (including checkpoint verification) pass.
    """

    ok, reason = _verify_memory_ticket_signature_and_fields(ticket)
    if not ok:
        return ok, reason

    if expected_session_id is not None and ticket.get("session_id") != expected_session_id:
        return False, "session_id mismatch"

    if expected_client_id is not None and ticket.get("client_id") != expected_client_id:
        return False, "client_id mismatch"

    if expected_epoch is not None and int(ticket.get("epoch")) != int(expected_epoch):
        return False, "epoch mismatch"

    if min_last_seq is not None and int(ticket.get("last_seq")) < int(min_last_seq):
        return False, "rollback detected: ticket last_seq is older than required"

    nonce = ticket.get("ticket_nonce")
    if not _default_store.is_unused(nonce):
        return False, "ticket replay detected"

    # Don't consume nonce yet - caller must call consume_ticket_nonce() after all checks pass
    return True, "ok"


def consume_ticket_nonce(ticket: Dict[str, Any]) -> bool:
    """
    Atomically consume a ticket's nonce after all validation checks pass.

    Returns True if nonce was consumed, False if already consumed (replay).
    """
    nonce = ticket.get("ticket_nonce")
    return _default_store.consume(nonce)


def verify_memory_ticket_for_recovery(
    ticket: Dict[str, Any],
    expected_session_id: str,
    expected_client_id: str,
    expected_epoch: int,
    min_last_seq: int,
) -> Tuple[bool, str]:
    """
    Strict recovery-time MemoryTicket verification.

    This checks the server signature, expiry, nonce replay, context binding, and
    rollback resistance before a recovery response is allowed to update memory.
    """
    return verify_memory_ticket(
        ticket=ticket,
        expected_session_id=expected_session_id,
        expected_client_id=expected_client_id,
        expected_epoch=expected_epoch,
        min_last_seq=min_last_seq,
    )
