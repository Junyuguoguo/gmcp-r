# -*- coding: utf-8 -*-
# real_tcp_server.py

import json
import socket
import threading
import time
from typing import Dict, Any

from gmcp.config import (
    SERVER_BIND_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    SHARED_KEY,
)
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.crypto_utils import verify_hmac


state_lock = threading.Lock()


def make_state(session_id: str) -> GMCPState:
    mem_seed = "demo-seed"
    m0 = initial_memory(session_id, CLIENT_ID, EPOCH, mem_seed)

    return GMCPState(
        session_id=session_id,
        sender_id=CLIENT_ID,
        epoch=EPOCH,
        last_seq=0,
        last_mem=m0,
    )


def send_json_line(conn, response: Dict[str, Any]):
    raw = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
    conn.sendall(raw)


def verify_recovery_request(packet: Dict[str, Any]) -> bool:
    tag = packet.get("auth_tag")
    if not tag:
        return False

    data = dict(packet)
    data.pop("auth_tag", None)

    return verify_hmac(SHARED_KEY, data, tag)


def handle_recovery_request(packet, states, verifiers, stats):
    recv_time = time.time()
    session_id = packet.get("session_id", "unknown-session")

    if not verify_recovery_request(packet):
        return {
            "ok": False,
            "type": "RECOVERY_RESPONSE",
            "reason": "invalid recovery request auth_tag",
            "server_time": recv_time,
        }

    with state_lock:
        if session_id not in states:
            states[session_id] = make_state(session_id)
            verifiers[session_id] = GMCPVerifier(states[session_id])
            stats[session_id] = {
                "total": 0,
                "accepted": 0,
                "rejected": 0,
            }

        state = states[session_id]

        response = {
            "ok": True,
            "type": "RECOVERY_RESPONSE",
            "reason": "ok",
            "recovery_mode": "memory_ticket_checkpoint",
            "session_id": session_id,
            "server_last_seq": state.last_seq,
            "server_last_mem": state.last_mem,
            "checkpoint_seq": state.last_seq,
            "checkpoint_mem": state.last_mem,
            "server_time": recv_time,
        }

    return response


def handle_client(conn, addr, states, verifiers, stats):
    print(f"[REAL_TCP_SERVER] connected from {addr}", flush=True)

    file_obj = None

    try:
        conn.settimeout(30)
        file_obj = conn.makefile("r", encoding="utf-8", newline="\n")

        while True:
            try:
                line = file_obj.readline()
            except socket.timeout:
                print(f"[REAL_TCP_SERVER] connection timeout from {addr}", flush=True)
                break

            if not line:
                break

            recv_time = time.time()

            try:
                packet: Dict[str, Any] = json.loads(line)
            except Exception:
                send_json_line(conn, {
                    "ok": False,
                    "reason": "invalid json",
                    "server_time": recv_time,
                })
                continue

            packet_type = packet.get("type")

            if packet_type == "PING":
                send_json_line(conn, {
                    "ok": True,
                    "reason": "pong",
                    "server_time": recv_time,
                })
                continue

            if packet_type == "RECOVERY_REQUEST":
                response = handle_recovery_request(packet, states, verifiers, stats)
                send_json_line(conn, response)
                continue

            session_id = packet.get("session_id", "unknown-session")

            with state_lock:
                if session_id not in states:
                    states[session_id] = make_state(session_id)
                    verifiers[session_id] = GMCPVerifier(states[session_id])
                    stats[session_id] = {
                        "total": 0,
                        "accepted": 0,
                        "rejected": 0,
                    }
                    print(f"[REAL_TCP_SERVER] new session: {session_id}", flush=True)

                state = states[session_id]
                verifier = verifiers[session_id]

                ok, reason = verifier.verify_data_packet(packet)

                stats[session_id]["total"] += 1

                if ok:
                    stats[session_id]["accepted"] += 1

                    if state.last_seq % 100 == 0:
                        print(
                            f"[REAL_TCP_SERVER] session={session_id}, "
                            f"accepted={stats[session_id]['accepted']}, "
                            f"last_seq={state.last_seq}",
                            flush=True,
                        )
                else:
                    stats[session_id]["rejected"] += 1
                    print(
                        f"[REAL_TCP_SERVER] reject session={session_id}, "
                        f"seq={packet.get('seq')}, reason={reason}",
                        flush=True,
                    )

                response = {
                    "ok": ok,
                    "reason": reason,
                    "session_id": session_id,
                    "last_seq": state.last_seq,
                    "last_mem": state.last_mem,
                    "server_time": recv_time,
                    "accepted": stats[session_id]["accepted"],
                    "rejected": stats[session_id]["rejected"],
                }

            send_json_line(conn, response)

    except Exception as e:
        print(f"[REAL_TCP_SERVER] error from {addr}: {e}", flush=True)

    finally:
        try:
            if file_obj:
                file_obj.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

        print(f"[REAL_TCP_SERVER] disconnected from {addr}", flush=True)


def main():
    states: Dict[str, GMCPState] = {}
    verifiers: Dict[str, GMCPVerifier] = {}
    stats: Dict[str, Dict[str, int]] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_BIND_HOST, DEFAULT_PORT))
    sock.listen(100)

    print(f"[REAL_TCP_SERVER] Listening on {SERVER_BIND_HOST}:{DEFAULT_PORT}", flush=True)

    while True:
        conn, addr = sock.accept()

        t = threading.Thread(
            target=handle_client,
            args=(conn, addr, states, verifiers, stats),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()