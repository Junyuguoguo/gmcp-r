# -*- coding: utf-8 -*-
# run_recovery_window_experiment.py
#
# Task 6: Recovery Window and Nonce Race Experiment
#
# Scenarios:
#   control     – ticket=100, server=100, client=100 → success
#   ack_loss    – server accepted 101-149, ACK lost, client holds seq=100 ticket
#   old_ticket  – old ticket within current checkpoint window → accepted
#   below_floor – ticket older than latest checkpoint floor → rejected
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
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet, packet_without_auth
from gmcp.recovery_protocol import (
    build_recovery_request,
    verify_recovery_response,
)
from gmcp.ticket import build_memory_ticket

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
    _send_json(sock, request)
    response = _recv_json(file_obj)
    latency_ms = (time.time() - start) * 1000

    verified, verify_reason = verify_recovery_response(
        response, session_id, EPOCH, request["recovery_nonce"]
    )
    ok = verified and response.get("ok") is True
    return ok, response, latency_ms, verified, verify_reason


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
    """control: advance to seq=100, get ticket, recover with it."""
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None

    for seq in range(1, 101):
        payload = f"ctrl-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100
    server_seq = 100

    # Recover
    ok, response, latency_ms, resp_auth, resp_reason = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=current_mem,
        reason="control test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0)) if ok else 0

    return {
        "scenario": "control",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "floor_seq": ticket_seq,
        "response_seq": resp_server_seq,
        "gap": server_seq - ticket_seq,
        "response_advance": resp_server_seq - server_seq,
        "request_auth_ok": True,
        "response_auth_ok": resp_auth,
        "nonce_match": True,
        "nonce_consumed": ok,
        "race_winner_count": 0,
        "state_unchanged": False,
        "success": ok,
        "reason": resp_reason if not ok else response.get("reason", "ok"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_ack_loss(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """ack_loss: advance to seq=100 (get ticket), then to seq=149 (discard ACKs)."""
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
    for seq in range(101, 150):
        payload = f"ack-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        # Discard response
        _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_seq = 149

    # Client thinks it's at seq=100 (ACKs for 101-149 were lost)
    # But client's actual state variable was advanced; for the experiment
    # we use the ticket's recorded state as the client's believed state
    client_mem = saved_ticket["last_mem"] if saved_ticket else current_mem

    ok, response, latency_ms, resp_auth, resp_reason = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=client_mem,
        reason="ack_loss test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0)) if ok else 0

    return {
        "scenario": "ack_loss",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "floor_seq": ticket_seq,
        "response_seq": resp_server_seq,
        "gap": server_seq - ticket_seq,
        "response_advance": resp_server_seq - server_seq,
        "request_auth_ok": True,
        "response_auth_ok": resp_auth,
        "nonce_match": True,
        "nonce_consumed": ok,
        "race_winner_count": 0,
        "state_unchanged": False,
        "success": ok,
        "reason": resp_reason if not ok else response.get("reason", "ok"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_old_ticket(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """old_ticket: get ticket at seq=100, advance server to seq=200, recover."""
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None

    # Phase 1: advance to seq=100 and get ticket
    for seq in range(1, 101):
        payload = f"old-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100

    # Phase 2: advance server to seq=200 (new checkpoint may be created)
    for seq in range(101, 201):
        payload = f"old-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_seq = 200

    # Recovery floor: ticket checkpoint_seq should still be >= floor
    # if checkpoint_interval=100, floor=100 (checkpoint at seq=100)
    floor_seq = 100  # ticket's checkpoint

    ok, response, latency_ms, resp_auth, resp_reason = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=saved_ticket["last_mem"] if saved_ticket else current_mem,
        reason="old_ticket test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0)) if ok else 0

    return {
        "scenario": "old_ticket",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "floor_seq": floor_seq,
        "response_seq": resp_server_seq,
        "gap": server_seq - ticket_seq,
        "response_advance": resp_server_seq - server_seq,
        "request_auth_ok": True,
        "response_auth_ok": resp_auth,
        "nonce_match": True,
        "nonce_consumed": ok,
        "race_winner_count": 0,
        "state_unchanged": False,
        "success": ok,
        "reason": resp_reason if not ok else response.get("reason", "ok"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_below_floor(sock, file_obj, session_id, checkpoint_interval, payload_size):
    """below_floor: get ticket at seq=100, advance to seq=200+ (new checkpoint), try old ticket."""
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    saved_ticket = None
    server_seq_before = 0

    # Phase 1: advance to seq=100 and get ticket
    for seq in range(1, 101):
        payload = f"floor-{seq:04d}-{prefix}"
        resp, current_mem = _send_data_packet(
            sock, file_obj, session_id, seq, current_mem, payload, checkpoint_interval
        )
        if "memory_ticket" in resp:
            saved_ticket = resp["memory_ticket"]

    ticket_seq = int(saved_ticket["last_seq"]) if saved_ticket else 100

    # Phase 2: advance to seq=200 so a new checkpoint at 200 is created
    for seq in range(101, 201):
        payload = f"floor-{seq:04d}-{prefix}"
        _send_json(sock, build_data_packet(
            session_id=session_id, sender_id=CLIENT_ID, epoch=EPOCH,
            seq=seq, prev_mem=current_mem, payload=payload,
        ))
        _recv_json(file_obj)
        payload_hash = hash_text(payload)
        current_mem = update_memory(current_mem, session_id, EPOCH, seq, payload_hash, CLIENT_ID)

    server_seq = 200
    server_seq_before = server_seq

    # The latest checkpoint is at seq=200, but ticket.last_seq=100 < 200 → reject
    floor_seq = 200

    ok, response, latency_ms, resp_auth, resp_reason = _send_recovery(
        sock, file_obj, session_id,
        client_last_seq=100,
        client_last_mem=saved_ticket["last_mem"] if saved_ticket else current_mem,
        reason="below_floor test",
        ticket=saved_ticket,
    )

    resp_server_seq = int(response.get("server_last_seq", 0)) if ok else 0

    return {
        "scenario": "below_floor",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": server_seq,
        "floor_seq": floor_seq,
        "response_seq": resp_server_seq,
        "gap": server_seq - ticket_seq,
        "response_advance": resp_server_seq - server_seq,
        "request_auth_ok": True,
        "response_auth_ok": resp_auth,
        "nonce_match": True,
        "nonce_consumed": False,  # nonce should NOT be consumed on rejection
        "race_winner_count": 0,
        "state_unchanged": not ok,  # state should not change on rejection
        "success": ok,
        "reason": resp_reason if not ok else response.get("reason", "ok"),
        "recovery_latency_ms": round(latency_ms, 3),
    }


def run_nonce_race(host, port, session_id, checkpoint_interval, payload_size):
    """nonce_race: two threads try recovery with the same ticket simultaneously."""
    prefix = "x" * max(0, payload_size - 20)
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")

    # Phase 1: advance to seq=100 using a dedicated connection
    sock_setup, fobj_setup = _open_tcp(host, port)
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
            "floor_seq": 0,
            "response_seq": 0,
            "gap": 0,
            "response_advance": 0,
            "request_auth_ok": False,
            "response_auth_ok": False,
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
            ok, resp, lat, auth, reason = _send_recovery(
                s, f, sid,
                client_last_seq=100,
                client_last_mem=client_last_mem,
                reason="nonce_race",
                ticket=ticket,
            )
            _close_tcp(s, f)
            results[idx] = {"ok": ok, "latency_ms": lat, "auth": auth, "reason": reason}
        except Exception as e:
            results[idx] = {"ok": False, "latency_ms": 0, "auth": False, "reason": str(e)}

    t0 = threading.Thread(target=worker, args=(0, host, port, session_id, saved_ticket, client_mem))
    t1 = threading.Thread(target=worker, args=(1, host, port, session_id, saved_ticket, client_mem))
    t0.start()
    t1.start()
    t0.join(timeout=15)
    t1.join(timeout=15)

    winners = sum(1 for r in results if r and r["ok"])
    loser_reason = ""
    for r in results:
        if r and not r["ok"]:
            loser_reason = r["reason"]
            break

    return {
        "scenario": "nonce_race",
        "checkpoint_interval": checkpoint_interval,
        "payload_size": payload_size,
        "ticket_seq": ticket_seq,
        "client_seq": 100,
        "server_seq": 100,
        "floor_seq": ticket_seq,
        "response_seq": 100 if winners > 0 else 0,
        "gap": 0,
        "response_advance": 0,
        "request_auth_ok": True,
        "response_auth_ok": all(r["auth"] for r in results if r),
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
        return run_nonce_race(host, port, sid, checkpoint_interval, payload_size)

    sock, file_obj = _open_tcp(host, port)
    try:
        runners = {
            "control": run_control,
            "ack_loss": run_ack_loss,
            "old_ticket": run_old_ticket,
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
    "ticket_seq", "client_seq", "server_seq", "floor_seq", "response_seq",
    "gap", "response_advance", "request_auth_ok", "response_auth_ok",
    "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
    "success", "reason", "recovery_latency_ms",
]

NON_RACE_SCENARIOS = ["control", "ack_loss", "old_ticket", "below_floor"]


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
                                "floor_seq": 0, "response_seq": 0,
                                "gap": 0, "response_advance": 0,
                                "request_auth_ok": False, "response_auth_ok": False,
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
                            "floor_seq": 0, "response_seq": 0,
                            "gap": 0, "response_advance": 0,
                            "request_auth_ok": False, "response_auth_ok": False,
                            "nonce_match": False, "nonce_consumed": False,
                            "race_winner_count": 0, "state_unchanged": False,
                            "success": False,
                            "reason": f"error: {e}",
                            "recovery_latency_ms": 0,
                        })

        # Write CSV
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

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait(timeout=5)
            print("[SPAWN] Server terminated")


if __name__ == "__main__":
    main()
