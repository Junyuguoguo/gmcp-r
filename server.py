# server.py

import json
import socket

from gmcp.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    BUFFER_SIZE,
    SESSION_ID,
    CLIENT_ID,
    EPOCH,
    CHECKPOINT_INTERVAL,
)
from gmcp.checkpoint import build_checkpoint
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier


def main():
    mem_seed = "demo-seed"
    m0 = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, mem_seed)

    state = GMCPState(
        session_id=SESSION_ID,
        sender_id=CLIENT_ID,
        epoch=EPOCH,
        last_seq=0,
        last_mem=m0,
    )

    verifier = GMCPVerifier(state)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DEFAULT_HOST, DEFAULT_PORT))

    print(f"[SERVER] Listening on {DEFAULT_HOST}:{DEFAULT_PORT}")
    print(f"[SERVER] Initial memory: {m0}")

    total = 0
    accepted = 0
    rejected = 0

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)

        try:
            packet = json.loads(data.decode("utf-8"))
        except Exception:
            print("[SERVER] Invalid JSON packet")
            rejected += 1
            continue

        ok, reason = verifier.verify_data_packet(packet)
        total += 1

        if ok:
            accepted += 1

            if state.last_seq % CHECKPOINT_INTERVAL == 0:
                cp = build_checkpoint(
                    session_id=state.session_id,
                    epoch=state.epoch,
                    seq=state.last_seq,
                    memory=state.last_mem,
                )
                print(f"[SERVER] checkpoint generated: seq={cp['seq']}")

            if accepted % 100 == 0:
                print(f"[SERVER] accepted={accepted}, last_seq={state.last_seq}")
        else:
            rejected += 1
            print(f"[SERVER] reject packet seq={packet.get('seq')}, reason={reason}")

        response = {
            "ok": ok,
            "reason": reason,
            "last_seq": state.last_seq,
            "last_mem": state.last_mem,
        }

        sock.sendto(json.dumps(response).encode("utf-8"), addr)


if __name__ == "__main__":
    main()