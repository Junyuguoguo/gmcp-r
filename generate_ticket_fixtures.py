#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# generate_ticket_fixtures.py
#
# Server-side helper that writes named, server-signed ticket fixtures
# to a temporary JSON file.  The client experiment runner reads that
# file as opaque test input and never imports/recomputes TICKET_AUTH_KEY.
#
# Only enabled for local experiment mode.

import json
import os
import sys
import time
import tempfile

# Only import server-side keys here
from gmcp.config import TICKET_AUTH_KEY, DATA_AUTH_KEY
from gmcp.ticket import build_memory_ticket
from gmcp.crypto_utils import hmac_sha256_hex


FIXTURE_FILE = os.getenv(
    "GMCP_TICKET_FIXTURES",
    os.path.join(tempfile.gettempdir(), "gmcp_ticket_fixtures.json"),
)


def _recompute_ticket_auth_tag(ticket: dict) -> dict:
    """Recompute server_auth_tag after modifying ticket fields."""
    data = dict(ticket)
    data.pop("server_auth_tag", None)
    ticket["server_auth_tag"] = hmac_sha256_hex(TICKET_AUTH_KEY, data)
    return ticket


def generate_fixtures(
    session_id: str = "fixture-session",
    client_id: str = "client-001",
    epoch: int = 1,
    last_seq: int = 100,
    checkpoint_interval: int = 50,
) -> dict:
    """Generate a dictionary of named ticket fixtures for testing."""
    last_mem = f"mem-{last_seq}"
    checkpoint_seq = (last_seq // checkpoint_interval) * checkpoint_interval
    checkpoint_mem = f"mem-{checkpoint_seq}"

    valid_ticket = build_memory_ticket(
        session_id=session_id,
        client_id=client_id,
        epoch=epoch,
        last_seq=last_seq,
        last_mem=last_mem,
        checkpoint_seq=checkpoint_seq,
        checkpoint_mem=checkpoint_mem,
    )

    # Expired ticket: valid signature but expire_time in the past
    expired = dict(valid_ticket)
    expired["expire_time"] = time.time() - 3600
    expired = _recompute_ticket_auth_tag(expired)

    # Tampered ticket: modified field without re-signing
    tampered = dict(valid_ticket)
    tampered["last_seq"] = 999999
    # No signature recompute – intentionally invalid HMAC

    # Rollback ticket: valid signature but old last_seq
    rollback = dict(valid_ticket)
    rollback["last_seq"] = 1
    rollback["checkpoint_seq"] = 0
    rollback = _recompute_ticket_auth_tag(rollback)

    # Wrong session ticket: valid signature but different session_id
    wrong_session = dict(valid_ticket)
    wrong_session["session_id"] = "wrong-session-id"
    wrong_session = _recompute_ticket_auth_tag(wrong_session)

    fixtures = {
        "valid_ticket": valid_ticket,
        "expired_ticket": expired,
        "tampered_ticket": tampered,
        "rollback_ticket": rollback,
        "wrong_session_ticket": wrong_session,
    }

    return fixtures


def save_fixtures(fixtures: dict, path: str = FIXTURE_FILE) -> str:
    """Save fixtures to a JSON file and return the path."""
    path = path or FIXTURE_FILE
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixtures, f, ensure_ascii=False, indent=2)
    print(f"[FIXTURES] Saved {len(fixtures)} ticket fixtures to {path}")
    return path


def main():
    fixtures = generate_fixtures()
    path = save_fixtures(fixtures)
    print(f"[FIXTURES] Fixture file: {path}")
    return path


if __name__ == "__main__":
    main()
