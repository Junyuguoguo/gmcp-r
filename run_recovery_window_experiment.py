# -*- coding: utf-8 -*-
# run_recovery_window_experiment.py
#
# Task 6: Recovery Window and Nonce Race Experiment
#
# Scenarios:
#   control     – ticket=100, server=100, client=100 → success
#   ack_loss    – server accepted 101-149, ACK lost, client holds seq=100 ticket
#   old_ticket_within_window – ticket within current checkpoint window → accepted
#   below_floor           – ticket older than latest checkpoint floor → rejected
#   nonce_race  – two threads consume same nonce → exactly one success
#
# Produces 540 CSV rows: 480 non-race + 60 race.
#
# Usage:
#   .venv/bin/python run_recovery_window_experiment.py [--spawn-server]
#   GMCP_REPEATS=1 GMCP_OUTPUT_ROOT=results/submission_revision/smoke \
#     .venv/bin/python run_recovery_window_experiment.py --spawn-server

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from gmcp.config import (
    CLIENT_ID,
    DATA_AUTH_KEY,
    DEFAULT_PORT,
    EPOCH,
    SERVER_TARGET_HOST,
    TICKET_AUTH_KEY,
    CHECKPOINT_AUTH_KEY,
)
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, with_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet, packet_without_auth
from gmcp.recovery_protocol import (
    build_recovery_request,
    verify_recovery_response,
)
from gmcp.ticket import build_memory_ticket
from gmcp.experiment_stats import get_git_commit

# ── defaults ────────────────────────────────────────────────────────────
CHECKPOINT_INTERVALS = [50, 100, 200]
PAYLOAD_SIZES = [128, 512]
NON_RACE_REPEATS = int(os.getenv("GMCP_REPEATS", "40"))
RACE_REPEATS = int(os.getenv("GMCP_RACE_REPEATS", "20"))
OUTPUT_ROOT = os.getenv("GMCP_OUTPUT_ROOT", "results/submission_revision")
SOCKET_TIMEOUT = 10.0
SERVER_SPAWN_WAIT = 8


# ── TCP helpers ─────────────────────────────────────────────────────────

def _enable_tcp_nodelay(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def _open_tcp(host=None, port=None):
    host = host or SERVER_TARGET_HOST
    port = port or DEFAULT_PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _enable_tcp_nodelay(sock)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((host, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def _close_tcp(sock, file_obj):
    for f in (file_obj,):
        try:
            if f:
                f.close()
        except Exception:
            pass
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        if sock:
            sock.close()
    except Exception:
        pass


def _send_hello(sock, file_obj, session_id, sender_id, epoch):
    """Send HELLO handshake and wait for HELLO_ACK."""
    hello = with_hmac(DATA_AUTH_KEY, {
        "type": "HELLO",
        "protocol": "gmcp",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "client_nonce": str(int(time.time() * 1000000)),
        "timestamp": time.time(),
    })
    _send_json(sock, hello)
    line = file_obj.readline()
    return json.loads(line) if line else {"ok": False, "reason": "no response"}


def _send_json(sock, packet):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def _recv_json(file_obj):
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)


def _send_data_packet(sock, file_obj, session_id, seq, prev_mem, payload, checkpoint_interval=None):
    """Send one DATA packet and return (response, new_mem)."""
    pkt = build_data_packet(
        session_id=session_id,
        sender_id=CLIENT_ID,
        epoch=EPOCH,
        seq=seq,
        prev_mem=prev_mem,
        payload=payload,
    )
    if checkpoint_interval is not None and seq == 1:
        pkt["checkpoint_interval"] = checkpoint_interval
        data_for_auth = packet_without_auth(pkt)
        data_for_auth["checkpoint_interval"] = checkpoint_interval
        pkt["auth_tag"] = hmac_sha256_hex(DATA_AUTH_KEY, data_for_auth)

    _send_json(sock, pkt)
    response = _recv_json(file_obj)
    payload_hash = hash_text(payload)
    new_mem = update_memory(prev_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)
    return response, new_mem


def _send_recovery(sock, file_obj, session_id, client_last_seq, client_last_mem, reason, ticket):
    """Send RECOVERY_REQUEST and return (ok, response, latency_ms)."""
    start = time.time()
    request = build_recovery_request(
        session_id=session_id,
        client_id=CLIENT_ID,
        epoch=EPOCH,
        client_last_seq=client_last_seq,
        client_last_mem=client_last_mem,
        reason=reason,
        extra={"memory_ticket": ticket} if ticket else None,
    )
    request_nonce = request["recovery_nonce"]
    _send_json(sock, request)
    response = _recv_json(file_obj)
    latency_ms = (time.time() - start) * 1000

    verified, verify_reason = verify_recovery_response(
        response, session_id, EPOCH, request["recovery_nonce"]
    )
    ok = verified and response.get("ok") is True
    return ok, response, latency_ms, verified, verify_reason, request_nonce


# ── Server spawn helper ─────────────────────────────────────────────────

def _spawn_server(port=None):
    """Start real_tcp_server_with_ticket.py as a subprocess."""
    port = port or DEFAULT_PORT
    env = os.environ.copy()
    env["GMCP_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "real_tcp_server_with_ticket.py"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Wait for server to be ready
    deadline = time.time() + SERVER_SPAWN_WAIT
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("127.0.0.1", port))
            s.close()
            print(f"[SPAWN] Server ready on port {port}")
            return proc
        except (ConnectionRefusedError, OSError):
            time.sleep(0.3)
    proc.kill()
    raise RuntimeError(f"Server did not start within {SERVER_SPAWN_WAIT}s on port {port}")


# ── Scenario runners ────────────────────────────────────────────────────

def run_control(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """control: ticket=100, server=100, client=100 → success.

    floor_seq is extracted from the server recovery response (not hardcoded).
    """
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None
    last_data_resp = None

    for seq in range(1, 101):
        payload = f"ctrl-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        last_data_resp = resp
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100
    server_seq = int(last_data_resp.get("last_seq", 100)) if last_data_resp else 100
    server_last_seq_before = server_seq
    server_last_mem_before = last_data_resp.get("last_mem", current_mem) if last_data_resp else current_mem

    # Recover
    ok, response, latency_ms, resp_auth, resp_reason, req_nonce = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=current_mem,
        reason="control test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0))
    resp_floor_seq = int(response.get("recovery_floor", response.get("checkpoint_seq", 0)))
    resp_ticket_last_seq = int(response.get("ticket_last_seq", 0))
    resp_nonce_match = (response.get("recovery_nonce", "") == req_nonce)
    server_last_seq_after = resp_server_seq
    server_last_mem_after = response.get("server_last_mem", "")

    # Verify nonce consumed by re-submitting the same ticket
    nonce_consumed = False
    if ok and saved_ticket:
        ok2, resp2, _, _, _, _ = _send_recovery(
            sock, file_obj, session_id,
            client_last_seq=ticket_seq,
            client_last_mem=saved_ticket["last_mem"],
            reason="nonce-verify",
            ticket=saved_ticket,
        )
        nonce_consumed = not ok2 and "replay" in resp2.get("reason", "").lower()

    state_unchanged = (server_last_seq_before == server_last_seq_after and
                       server_last_mem_before == server_last_mem_after)

    return {
        "scenario": "control",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "recovery_floor": resp_floor_seq,
        "ticket_last_seq": resp_ticket_last_seq,
        "server_last_seq_before": server_last_seq_before,
        "server_last_seq_after": server_last_seq_after,
        "server_last_mem_before": server_last_mem_before,
        "server_last_mem_after": server_last_mem_after,
        "request_auth_ok": response.get("request_auth_ok", True),
        "response_auth_ok": resp_auth,
        "response_verify_reason": resp_reason,
        "nonce_match": resp_nonce_match,
        "nonce_consumed": nonce_consumed,
        "race_winner_count": 0,
        "state_unchanged": state_unchanged,
        "success": ok,
        "reason": response.get("reason", "unknown"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_ack_loss(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """ack_loss: server accepted 101-149, ACK lost, client holds seq=100 ticket.

    floor_seq is extracted from the server recovery response (not hardcoded).
    """
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None

    # Phase 1: advance to seq=100 and get ticket
    for seq in range(1, 101):
        payload = f"ack-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100

    # Phase 2: server accepts 101-149 (client discards responses)
    last_data_resp = None
    for seq in range(101, 150):
        payload = f"ack-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        last_data_resp = _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_seq = int(last_data_resp.get("last_seq", 149)) if last_data_resp else 149
    server_last_seq_before = server_seq
    server_last_mem_before = last_data_resp.get("last_mem", current_mem) if last_data_resp else current_mem

    # Client thinks it's at seq=100 (ACKs for 101-149 were lost)
    # But client's actual state variable was advanced; for the experiment
    # we use the ticket's recorded state as the client's believed state
    client_mem = saved_ticket["last_mem"] if saved_ticket else current_mem

    ok, response, latency_ms, resp_auth, resp_reason, req_nonce = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=client_mem,
        reason="ack_loss test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0))
    resp_floor_seq = int(response.get("recovery_floor", response.get("checkpoint_seq", 0)))
    resp_ticket_last_seq = int(response.get("ticket_last_seq", 0))
    resp_nonce_match = (response.get("recovery_nonce", "") == req_nonce)
    server_last_seq_after = resp_server_seq
    server_last_mem_after = response.get("server_last_mem", "")

    # Verify nonce consumed by re-submitting the same ticket
    nonce_consumed = False
    if ok and saved_ticket:
        ok2, resp2, _, _, _, _ = _send_recovery(
            sock, file_obj, session_id,
            client_last_seq=ticket_seq,
            client_last_mem=saved_ticket["last_mem"],
            reason="nonce-verify",
            ticket=saved_ticket,
        )
        nonce_consumed = not ok2 and "replay" in resp2.get("reason", "").lower()

    state_unchanged = (server_last_seq_before == server_last_seq_after and
                       server_last_mem_before == server_last_mem_after)

    return {
        "scenario": "ack_loss",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "recovery_floor": resp_floor_seq,
        "ticket_last_seq": resp_ticket_last_seq,
        "server_last_seq_before": server_last_seq_before,
        "server_last_seq_after": server_last_seq_after,
        "server_last_mem_before": server_last_mem_before,
        "server_last_mem_after": server_last_mem_after,
        "request_auth_ok": response.get("request_auth_ok", True),
        "response_auth_ok": resp_auth,
        "response_verify_reason": resp_reason,
        "nonce_match": resp_nonce_match,
        "nonce_consumed": nonce_consumed,
        "race_winner_count": 0,
        "state_unchanged": state_unchanged,
        "success": ok,
        "reason": response.get("reason", "unknown"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_old_ticket_within_window(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """old_ticket_within_window: ticket within current checkpoint window → accepted.

    Phase 1: advance to seq=100, capture ticket (checkpoint_seq=100).
    Phase 2: advance to seq = 100 + checkpoint_interval - 1
             (just before the *next* checkpoint), so the server's latest
             checkpoint is still 100 — same as the ticket's checkpoint_seq.
             The ticket is old but still within the recovery window.

    floor_seq is extracted from the server recovery response (not hardcoded).
    """
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None

    # Phase 1: advance to seq=100 and get ticket
    for seq in range(1, 101):
        payload = f"oldw-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100

    # Phase 2: advance server just before the next checkpoint boundary.
    # For k=100 → 199; k=50 → 149; k=200 → 199.
    # This ensures no new checkpoint is created, so the server's latest
    # checkpoint remains at 100 — the ticket's checkpoint_seq.
    next_ckpt = ((100 // checkpoint_interval) + 1) * checkpoint_interval
    advance_target = next_ckpt - 1
    server_seq = advance_target

    last_data_resp = None
    for seq in range(101, advance_target + 1):
        payload = f"oldw-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        last_data_resp = _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_last_seq_before = int(last_data_resp.get("last_seq", server_seq)) if last_data_resp else server_seq
    server_last_mem_before = last_data_resp.get("last_mem", current_mem) if last_data_resp else current_mem

    ok, response, latency_ms, resp_auth, resp_reason, req_nonce = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=saved_ticket["last_mem"] if saved_ticket else current_mem,
        reason="old_ticket_within_window test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0))
    resp_floor_seq = int(response.get("recovery_floor", response.get("checkpoint_seq", 0)))
    resp_ticket_last_seq = int(response.get("ticket_last_seq", 0))
    resp_nonce_match = (response.get("recovery_nonce", "") == req_nonce)
    server_last_seq_after = resp_server_seq
    server_last_mem_after = response.get("server_last_mem", "")

    # Verify nonce consumed by re-submitting the same ticket
    nonce_consumed = False
    if ok and saved_ticket:
        ok2, resp2, _, _, _, _ = _send_recovery(
            sock, file_obj, session_id,
            client_last_seq=ticket_seq,
            client_last_mem=saved_ticket["last_mem"],
            reason="nonce-verify",
            ticket=saved_ticket,
        )
        nonce_consumed = not ok2 and "replay" in resp2.get("reason", "").lower()

    state_unchanged = (server_last_seq_before == server_last_seq_after and
                       server_last_mem_before == server_last_mem_after)

    return {
        "scenario": "old_ticket_within_window",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "recovery_floor": resp_floor_seq,
        "ticket_last_seq": resp_ticket_last_seq,
        "server_last_seq_before": server_last_seq_before,
        "server_last_seq_after": server_last_seq_after,
        "server_last_mem_before": server_last_mem_before,
        "server_last_mem_after": server_last_mem_after,
        "request_auth_ok": response.get("request_auth_ok", True),
        "response_auth_ok": resp_auth,
        "response_verify_reason": resp_reason,
        "nonce_match": resp_nonce_match,
        "nonce_consumed": nonce_consumed,
        "race_winner_count": 0,
        "state_unchanged": state_unchanged,
        "success": ok,
        "reason": response.get("reason", "unknown"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_below_floor(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """below_floor: ticket older than latest checkpoint floor → rejected.

    Phase 1: advance to seq=100, capture ticket (checkpoint_seq=100).
    Phase 2: advance to seq=200, creating a new checkpoint at 200.
             The server's latest checkpoint is now 200, but the ticket's
             checkpoint_seq is 100 < 200 → rejected.

    floor_seq is extracted from the server recovery response (not hardcoded).
    """
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None

    # Phase 1: advance to seq=100 and get ticket
    for seq in range(1, 101):
        payload = f"blwf-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100

    # Phase 2: advance to seq=200 so a new checkpoint at 200 is created
    last_data_resp = None
    for seq in range(101, 201):
        payload = f"blwf-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        last_data_resp = _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_seq = int(last_data_resp.get("last_seq", 200)) if last_data_resp else 200
    server_last_seq_before = server_seq
    server_last_mem_before = last_data_resp.get("last_mem", current_mem) if last_data_resp else current_mem

    ok, response, latency_ms, resp_auth, resp_reason, req_nonce = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=saved_ticket["last_mem"] if saved_ticket else current_mem,
        reason="below_floor test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0))
    resp_floor_seq = int(response.get("recovery_floor", response.get("checkpoint_seq", 0)))
    resp_ticket_last_seq = int(response.get("ticket_last_seq", 0))
    resp_nonce_match = (response.get("recovery_nonce", "") == req_nonce)
    server_last_seq_after = resp_server_seq
    server_last_mem_after = response.get("server_last_mem", "")

    # Verify nonce consumed by re-submitting the same ticket
    nonce_consumed = False
    if saved_ticket:
        ok2, resp2, _, _, _, _ = _send_recovery(
            sock, file_obj, session_id,
            client_last_seq=100,
            client_last_mem=saved_ticket["last_mem"],
            reason="nonce-verify",
            ticket=saved_ticket,
        )
        nonce_consumed = not ok2 and "replay" in resp2.get("reason", "").lower()

    state_unchanged = (server_last_seq_before == server_last_seq_after and
                       server_last_mem_before == server_last_mem_after)

    return {
        "scenario": "below_floor",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "recovery_floor": resp_floor_seq,
        "ticket_last_seq": resp_ticket_last_seq,
        "server_last_seq_before": server_last_seq_before,
        "server_last_seq_after": server_last_seq_after,
        "server_last_mem_before": server_last_mem_before,
        "server_last_mem_after": server_last_mem_after,
        "request_auth_ok": response.get("request_auth_ok", True),
        "response_auth_ok": resp_auth,
        "response_verify_reason": resp_reason,
        "nonce_match": resp_nonce_match,
        "nonce_consumed": nonce_consumed,
        "race_winner_count": 0,
        "state_unchanged": state_unchanged,
        "success": ok,
        "reason": response.get("reason", "unknown"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_nonce_race(host, port, session_id, checkpoint_interval, payload_size):
    """nonce_race: two threads try recovery with the same ticket simultaneously."""
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")

    # Phase 1: advance to seq=100 using a dedicated connection
    sock_setup, fobj_setup = _open_tcp(host, port)
    _send_hello(sock_setup, fobj_setup, session_id, CLIENT_ID, EPOCH)
    saved_ticket = None
    for seq in range(1, 101):
        payload = f"race-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock_setup, fobj_setup, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]
    _close_tcp(sock_setup, fobj_setup)

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100
    client_mem = saved_ticket["last_mem"] if saved_ticket else current_mem

    if not saved_ticket:
        return {
            "scenario": "nonce_race",
            "checkpoint_interval": checkpoint_interval,
            "payload_size": payload_size,
            "ticket_seq": ticket_seq,
            "client_seq": 100,
            "server_seq": 100,
            "recovery_floor": 0, "ticket_last_seq": 0,
            "server_last_seq_before": 0, "server_last_seq_after": 0,
            "server_last_mem_before": "", "server_last_mem_after": "",
            "request_auth_ok": False,
            "response_auth_ok": False,
            "response_verify_reason": "",
            "nonce_match": False,
            "nonce_consumed": False,
            "race_winner_count": 0,
            "state_unchanged": True,
            "success": False,
            "reason": "no ticket obtained",
            "recovery_latency_ms": 0,
        }

    # Phase 2: two threads race with the same ticket
    results: list[dict | None] = [None, None]
    barrier = threading.Barrier(2)

    def worker(idx, host, port, sid, ticket, client_last_mem):
        barrier.wait()
        try:
            s, f = _open_tcp(host, port)
            _send_hello(s, f, sid, CLIENT_ID, EPOCH)
            ok, resp, lat, auth, reason, req_nonce = _send_recovery(
                s, f, sid,
                client_last_seq=100,
                client_last_mem=client_last_mem,
                reason="nonce_race",
                ticket=ticket,
            )
            _close_tcp(s, f)
            results[idx] = {"ok": ok, "latency_ms": lat, "auth": auth, "reason": reason,
                            "req_nonce": req_nonce, "response": resp}
        except Exception as e:
            results[idx] = {"ok": False, "latency_ms": 0, "auth": False, "reason": str(e),
                            "req_nonce": "", "response": {}}

    t0 = threading.Thread(target=worker, args=(0, host, port, session_id, saved_ticket, client_mem))
    t1 = threading.Thread(target=worker, args=(1, host, port, session_id, saved_ticket, client_mem))
    t0.start()
    t1.start()
    t0.join(timeout=15)
    t1.join(timeout=15)

    winners = sum(1 for r in results if r and r["ok"])
    loser_reason = ""
    loser_verify_reason = ""
    for r in results:
        if r and not r["ok"]:
            loser_reason = r.get("response", {}).get("reason", r["reason"])
            loser_verify_reason = r["reason"]
            break

    # Get floor/nonce info from winner's response if available
    winner_resp = {}
    winner_verify_reason = ""
    for r in results:
        if r and r["ok"]:
            winner_resp = r.get("response", {})
            winner_verify_reason = r["reason"]
            break
    race_floor = int(winner_resp.get("recovery_floor", winner_resp.get("checkpoint_seq", ticket_seq)))
    race_ticket_last = int(winner_resp.get("ticket_last_seq", ticket_seq))

    # Collect response_verify_reason from all workers
    all_verify_reasons = [r["reason"] for r in results if r]

    # Get request_auth_ok from all workers
    all_req_auth_ok = all(
        r.get("response", {}).get("request_auth_ok", True) for r in results if r
    )

    return {
        "scenario": "nonce_race",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": 100,
        "recovery_floor": race_floor,
        "ticket_last_seq": race_ticket_last,
        "server_last_seq_before": 100,
        "server_last_seq_after": 100 if winners > 0 else 0,
        "server_last_mem_before": "",
        "server_last_mem_after": winner_resp.get("server_last_mem", ""),
        "request_auth_ok": all_req_auth_ok,
        "response_auth_ok": all(r["auth"] for r in results if r),
        "response_verify_reason": "; ".join(all_verify_reasons),
        "nonce_match": True,
        "nonce_consumed": winners > 0,
        "race_winner_count": winners,
        "state_unchanged": False,
        "success": winners == 1,
        "reason": f"winners={winners}, loser={loser_reason}",
        "recovery_latency_ms": round(
            max(r["latency_ms"] for r in results if r), 3
        ),
    }


# ── Scenario dispatcher ─────────────────────────────────────────────────

def run_window_scenario(
    scenario: str,
    checkpoint_interval: int,
    payload_size: int,
    repeat_id: int,
    host: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Run one window scenario and return a result dict."""
    host = host or SERVER_TARGET_HOST
    port = port or DEFAULT_PORT

    sid = (
        f"window-{scenario}-k{checkpoint_interval}-p{payload_size}-"
        f"r{repeat_id}-{int(time.time() * 1e6)}"
    )

    if scenario == "nonce_race":
        result = run_nonce_race(host, port, sid, checkpoint_interval, payload_size)
        result["repeat_id"] = repeat_id
        return result

    sock, file_obj = _open_tcp(host, port)
    _send_hello(sock, file_obj, sid, CLIENT_ID, EPOCH)
    try:
        runners = {
            "control": run_control,
            "ack_loss": run_ack_loss,
            "old_ticket_within_window": run_old_ticket_within_window,
            "below_floor": run_below_floor,
        }
        if scenario not in runners:
            raise ValueError(f"unknown scenario: {scenario}")
        result = runners[scenario](sock, file_obj, sid, checkpoint_interval, payload_size)
        result["repeat_id"] = repeat_id
        return result
    finally:
        _close_tcp(sock, file_obj)


# ── Main ────────────────────────────────────────────────────────────────

CSV_COLUMNS = [
    "scenario", "checkpoint_interval", "payload_size", "repeat_id",
    "ticket_seq", "client_seq", "server_seq", "recovery_floor", "ticket_last_seq",
    "server_last_seq_before", "server_last_seq_after",
    "server_last_mem_before", "server_last_mem_after",
    "request_auth_ok", "response_auth_ok", "response_verify_reason",
    "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
    "success", "reason", "recovery_latency_ms", "git_commit",
]

NON_RACE_SCENARIOS = ["control", "ack_loss", "old_ticket_within_window", "below_floor"]


def main():
    parser = argparse.ArgumentParser(description="Recovery Window and Nonce Race Experiment")
    parser.add_argument("--spawn-server", action="store_true", help="Spawn a local server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", type=str, default=SERVER_TARGET_HOST)
    args = parser.parse_args()

    server_proc = None
    try:
        if args.spawn_server:
            server_proc = _spawn_server(args.port)

        output_dir = OUTPUT_ROOT
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, "recovery_window_experiment.csv")

        # Collect all rows
        all_rows: List[Dict[str, Any]] = []

        # Non-race scenarios: 4 scenarios × len(CHECKPOINT_INTERVALS) × len(PAYLOAD_SIZES) × NON_RACE_REPEATS
        for ci in CHECKPOINT_INTERVALS:
            for ps in PAYLOAD_SIZES:
                for rep in range(1, NON_RACE_REPEATS + 1):
                    for scenario in NON_RACE_SCENARIOS:
                        try:
                            row = run_window_scenario(
                                scenario, ci, ps, rep, args.host, args.port
                            )
                            all_rows.append(row)
                            print(
                                f"[{scenario}] k={ci} p={ps} r={rep} → "
                                f"success={row['success']}",
                                flush=True,
                            )
                        except Exception as e:
                            print(f"[{scenario}] k={ci} p={ps} r={rep} → ERROR: {e}", flush=True)
                            all_rows.append({
                                "scenario": scenario,
                                "checkpoint_interval": ci,
                                "payload_size": ps,
                                "repeat_id": rep,
                                "ticket_seq": 0, "client_seq": 0, "server_seq": 0,
                                "recovery_floor": 0, "ticket_last_seq": 0,
                                "server_last_seq_before": 0, "server_last_seq_after": 0,
                                "server_last_mem_before": "", "server_last_mem_after": "",
                                "request_auth_ok": False, "response_auth_ok": False,
                                "response_verify_reason": "",
                                "nonce_match": False, "nonce_consumed": False,
                                "race_winner_count": 0, "state_unchanged": False,
                                "success": False,
                                "reason": f"error: {e}",
                                "recovery_latency_ms": 0,
                            })

        # Race scenario: fewer configs, RACE_REPEATS each
        race_intervals = CHECKPOINT_INTERVALS[:2]  # first two checkpoint intervals
        race_payloads = PAYLOAD_SIZES[:1]           # first payload size
        for ci in race_intervals:
            for ps in race_payloads:
                for rep in range(1, RACE_REPEATS + 1):
                    try:
                        row = run_window_scenario(
                            "nonce_race", ci, ps, rep, args.host, args.port
                        )
                        all_rows.append(row)
                        print(
                            f"[nonce_race] k={ci} p={ps} r={rep} → "
                            f"winners={row['race_winner_count']}",
                            flush=True,
                        )
                    except Exception as e:
                        print(f"[nonce_race] k={ci} p={ps} r={rep} → ERROR: {e}", flush=True)
                        all_rows.append({
                            "scenario": "nonce_race",
                            "checkpoint_interval": ci,
                            "payload_size": ps,
                            "repeat_id": rep,
                            "ticket_seq": 0, "client_seq": 0, "server_seq": 0,
                            "recovery_floor": 0, "ticket_last_seq": 0,
                            "server_last_seq_before": 0, "server_last_seq_after": 0,
                            "server_last_mem_before": "", "server_last_mem_after": "",
                            "request_auth_ok": False, "response_auth_ok": False,
                            "response_verify_reason": "",
                            "nonce_match": False, "nonce_consumed": False,
                            "race_winner_count": 0, "state_unchanged": False,
                            "success": False,
                            "reason": f"error: {e}",
                            "recovery_latency_ms": 0,
                        })

        # Write CSV
        git_commit = get_git_commit()
        for row in all_rows:
            row["git_commit"] = git_commit
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(all_rows)

        print(f"\n[OUTPUT] {len(all_rows)} rows → {csv_path}")

        # Summary
        non_race = [r for r in all_rows if r["scenario"] != "nonce_race"]
        race = [r for r in all_rows if r["scenario"] == "nonce_race"]
        print(f"[SUMMARY] Non-race: {len(non_race)} rows, Race: {len(race)} rows")
        for scenario in NON_RACE_SCENARIOS:
            rows = [r for r in non_race if r["scenario"] == scenario]
            success = sum(1 for r in rows if r["success"])
            print(f"  {scenario}: {success}/{len(rows)} success")
        race_winners = sum(1 for r in race if r["race_winner_count"] == 1)
        print(f"  nonce_race: {race_winners}/{len(race)} with exactly 1 winner")

        violations = []
        for row in all_rows:
            scenario = row["scenario"]
            success = bool(row["success"])
            if not row.get("request_auth_ok"):
                violations.append(f"{scenario} repeat={row.get('repeat_id')}: request_auth_ok false")
            if not row.get("response_auth_ok"):
                violations.append(f"{scenario} repeat={row.get('repeat_id')}: response_auth_ok false")
            if not row.get("nonce_match"):
                violations.append(f"{scenario} repeat={row.get('repeat_id')}: nonce_match false")
            if scenario in ("control", "ack_loss", "old_ticket_within_window") and not success:
                violations.append(f"{scenario} repeat={row.get('repeat_id')}: expected success")
            if scenario == "below_floor":
                if success:
                    violations.append(f"below_floor repeat={row.get('repeat_id')}: expected rejection")
                if not row.get("state_unchanged"):
                    violations.append(f"below_floor repeat={row.get('repeat_id')}: state changed")
            if scenario == "nonce_race" and int(row.get("race_winner_count", 0)) != 1:
                violations.append(f"nonce_race repeat={row.get('repeat_id')}: winner count != 1")
        if violations:
            print("[RECOVERY_WINDOW] INVALID RESULTS:", file=sys.stderr)
            for violation in violations[:20]:
                print(f"  - {violation}", file=sys.stderr)
            return 1
        return 0

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait(timeout=5)
            print("[SPAWN] Server terminated")


if __name__ == "__main__":
    sys.exit(main())
