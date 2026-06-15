# -*- coding: utf-8 -*-
# run_ticket_security_experiment.py

import csv
import os
from typing import Any, Dict, Iterable, List

from gmcp.ticket import (
    USED_TICKET_NONCES,
    build_memory_ticket,
    verify_memory_ticket_for_recovery,
)


OUTPUT_DIR = "results/ticket_security"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "ticket_security_results.csv")

ATTACK_TYPES = [
    "valid_ticket",
    "expired_ticket",
    "replayed_ticket",
    "tampered_ticket",
    "wrong_session_ticket",
    "rollback_ticket",
]
REPEATS = [1, 2, 3]

EXPECTED_SESSION_ID = "ticket-security-session"
EXPECTED_CLIENT_ID = "ticket-security-client"
EXPECTED_EPOCH = 1
CURRENT_LAST_SEQ = 100


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def iter_parameter_grid() -> Iterable[Dict[str, Any]]:
    for attack_type in ATTACK_TYPES:
        for repeat_id in REPEATS:
            yield {"attack_type": attack_type, "repeat_id": repeat_id}


def _base_ticket(last_seq: int = CURRENT_LAST_SEQ, ttl_seconds: int = 3600) -> Dict[str, Any]:
    return build_memory_ticket(
        session_id=EXPECTED_SESSION_ID,
        client_id=EXPECTED_CLIENT_ID,
        epoch=EXPECTED_EPOCH,
        last_seq=last_seq,
        last_mem=f"memory-{last_seq}",
        checkpoint_seq=max(0, last_seq - 10),
        checkpoint_mem=f"memory-{max(0, last_seq - 10)}",
        ttl_seconds=ttl_seconds,
    )


def run_one_ticket_security_experiment(attack_type: str, repeat_id: int) -> Dict[str, Any]:
    USED_TICKET_NONCES.clear()

    ticket = _base_ticket()
    expected_session_id = EXPECTED_SESSION_ID
    min_last_seq = CURRENT_LAST_SEQ

    if attack_type == "expired_ticket":
        ticket = _base_ticket(ttl_seconds=-1)

    elif attack_type == "replayed_ticket":
        ticket = _base_ticket()
        verify_memory_ticket_for_recovery(
            ticket,
            expected_session_id=expected_session_id,
            expected_client_id=EXPECTED_CLIENT_ID,
            expected_epoch=EXPECTED_EPOCH,
            min_last_seq=min_last_seq,
        )

    elif attack_type == "tampered_ticket":
        ticket = _base_ticket()
        ticket["last_mem"] = "tampered-memory"

    elif attack_type == "wrong_session_ticket":
        ticket = build_memory_ticket(
            session_id="wrong-session",
            client_id=EXPECTED_CLIENT_ID,
            epoch=EXPECTED_EPOCH,
            last_seq=CURRENT_LAST_SEQ,
            last_mem="memory-100",
            checkpoint_seq=90,
            checkpoint_mem="memory-90",
        )

    elif attack_type == "rollback_ticket":
        ticket = _base_ticket(last_seq=CURRENT_LAST_SEQ - 40)

    ticket_verified, reason = verify_memory_ticket_for_recovery(
        ticket,
        expected_session_id=expected_session_id,
        expected_client_id=EXPECTED_CLIENT_ID,
        expected_epoch=EXPECTED_EPOCH,
        min_last_seq=min_last_seq,
    )

    recovery_allowed = attack_type == "valid_ticket" and ticket_verified
    attack_detected = attack_type != "valid_ticket" and not ticket_verified
    ticket_valid = attack_type == "valid_ticket"

    return {
        "attack_type": attack_type,
        "repeat_id": repeat_id,
        "ticket_valid": ticket_valid,
        "ticket_verified": ticket_verified,
        "attack_detected": attack_detected,
        "detection_reason": reason,
        "recovery_allowed": recovery_allowed,
        "ticket_nonce": ticket.get("ticket_nonce", ""),
        "ticket_expired": reason == "ticket expired",
        "ticket_replay_detected": "replay" in reason,
    }


def save_rows(rows: List[Dict[str, Any]]) -> None:
    ensure_output_dir()
    fieldnames = list(rows[0].keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = [run_one_ticket_security_experiment(**params) for params in iter_parameter_grid()]
    save_rows(rows)
    print("[TICKET_SECURITY] results saved to", OUTPUT_CSV)
    print("[TICKET_SECURITY] total rows:", len(rows))


if __name__ == "__main__":
    main()
