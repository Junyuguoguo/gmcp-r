# -*- coding: utf-8 -*-
# real_server.py

import json
import socket
import time
from typing import Dict, Any

from gmcp.config import (
    SERVER_BIND_HOST,
    DEFAULT_PORT,
    BUFFER_SIZE,
    CLIENT_ID,
    EPOCH,
)
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier


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


def main():
    states: Dict[str, GMCPState] = {}
    verifiers: Dict[str, GMCPVerifier] = {}
    stats: Dict[str, Dict[str, int]] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_BIND_HOST, DEFAULT_PORT))

    print(f"[REAL_SERVER] Listening on {SERVER_BIND_HOST}:{DEFAULT_PORT}")
    print("[REAL_SERVER] Waiting for DATA packets...")

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        recv_time = time.time()

        try:
            packet: Dict[str, Any] = json.loads(data.decode("utf-8"))
        except Exception:
            response = {
                "ok": False,
                "reason": "invalid json",
                "server_time": recv_time,
            }
            sock.sendto(json.dumps(response).encode("utf-8"), addr)
            continue

        if packet.get("type") == "PING":
            response = {
                "ok": True,
                "reason": "pong",
                "server_time": recv_time,
            }
            sock.sendto(json.dumps(response).encode("utf-8"), addr)
            continue

        session_id = packet.get("session_id", "unknown-session")

        if session_id not in states:
            states[session_id] = make_state(session_id)
            verifiers[session_id] = GMCPVerifier(states[session_id])
            stats[session_id] = {
                "total": 0,
                "accepted": 0,
                "rejected": 0,
            }
            print(f"[REAL_SERVER] new session: {session_id}")

        state = states[session_id]
        verifier = verifiers[session_id]

        ok, reason = verifier.verify_data_packet(packet)

        stats[session_id]["total"] += 1

        if ok:
            stats[session_id]["accepted"] += 1
            if state.last_seq % 100 == 0:
                print(
                    f"[REAL_SERVER] session={session_id}, "
                    f"accepted={stats[session_id]['accepted']}, "
                    f"last_seq={state.last_seq}"
                )
        else:
            stats[session_id]["rejected"] += 1
            print(
                f"[REAL_SERVER] reject session={session_id}, "
                f"seq={packet.get('seq')}, reason={reason}"
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

        sock.sendto(json.dumps(response).encode("utf-8"), addr)


if __name__ == "__main__":
    main()