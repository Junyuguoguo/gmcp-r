# -*- coding: utf-8 -*-
# gmcp/recovery_protocol.py
#
# Authenticated recovery request/response helpers.
# Uses DATA_AUTH_KEY for request/response authentication.

import hashlib
import hmac
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from gmcp.config import DATA_AUTH_KEY
from gmcp.crypto_utils import canonical_json


def build_recovery_request(
    session_id: str,
    client_id: str,
    epoch: int,
    client_last_seq: int,
    client_last_mem: str,
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an authenticated recovery request with a random nonce."""
    recovery_nonce = secrets.token_hex(16)
    request: Dict[str, Any] = {
        "type": "RECOVERY_REQUEST",
        "session_id": session_id,
        "client_id": client_id,
        "epoch": epoch,
        "client_last_seq": client_last_seq,
        "client_last_mem": client_last_mem,
        "reason": reason,
        "recovery_nonce": recovery_nonce,
        "timestamp": time.time(),
    }
    if extra:
        request.update(extra)
    request["auth_tag"] = _sign(DATA_AUTH_KEY, request)
    return request


def verify_recovery_request(
    request: Dict[str, Any],
) -> Tuple[bool, str]:
    """Verify an authenticated recovery request."""
    tag = request.get("auth_tag")
    if not tag:
        return False, "missing auth_tag"
    data = dict(request)
    data.pop("auth_tag", None)
    if not _verify(DATA_AUTH_KEY, data, tag):
        return False, "invalid auth_tag"
    if not request.get("recovery_nonce"):
        return False, "missing recovery_nonce"
    return True, "ok"


def build_recovery_response(
    ok: bool,
    reason: str,
    session_id: str,
    epoch: int,
    recovery_nonce: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an authenticated recovery response."""
    response: Dict[str, Any] = {
        "type": "RECOVERY_RESPONSE",
        "ok": ok,
        "reason": reason,
        "session_id": session_id,
        "epoch": epoch,
        "recovery_nonce": recovery_nonce,
        "timestamp": time.time(),
    }
    if extra:
        response.update(extra)
    response["recovery_auth_tag"] = _sign(DATA_AUTH_KEY, response)
    return response


def verify_recovery_response(
    response: Dict[str, Any],
    expected_session_id: str,
    expected_epoch: int,
    expected_recovery_nonce: str,
) -> Tuple[bool, str]:
    """Verify an authenticated recovery response."""
    tag = response.get("recovery_auth_tag")
    if not tag:
        return False, "missing recovery_auth_tag"

    data = dict(response)
    data.pop("recovery_auth_tag", None)
    if not _verify(DATA_AUTH_KEY, data, tag):
        return False, "invalid recovery_auth_tag"

    if response.get("session_id") != expected_session_id:
        return False, "session_id mismatch"

    if int(response.get("epoch", 0)) != int(expected_epoch):
        return False, "epoch mismatch"

    if response.get("recovery_nonce") != expected_recovery_nonce:
        return False, "recovery_nonce mismatch"

    return True, "ok"


# ── Internal helpers ──────────────────────────────────────────────────

def _sign(key: bytes, message: Dict[str, Any]) -> str:
    data = dict(message)
    # Remove any existing tag field before signing
    for tag_field in ("auth_tag", "recovery_auth_tag"):
        data.pop(tag_field, None)
    return hmac.new(
        key, canonical_json(data).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _verify(key: bytes, message: Dict[str, Any], tag: str) -> bool:
    data = dict(message)
    for tag_field in ("auth_tag", "recovery_auth_tag"):
        data.pop(tag_field, None)
    expected = hmac.new(
        key, canonical_json(data).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, tag)
