# -*- coding: utf-8 -*-
# real_tcp_server.py
#
# Multi-protocol TCP server with HELLO handshake and connection binding.
# Supports: gmcp, hash_chain, authenticated_hash_chain, seq_mac, ticket_only
#
# Changes (formal-runner-resilience):
#   - Added HELLO handshake with auth_tag verification
#   - Added server env info in HELLO_ACK (git_commit, python_version, os, hostname, cpu)
#   - Added ticket issue for ticket_only protocol
#   - Added connection-level binding (protocol, session_id, sender_id, epoch)
#   - Added multi-protocol state factories

import json
import socket
import threading
import time
from typing import Dict, Any, Optional

from gmcp.config import (
    SERVER_BIND_HOST,
    DEFAULT_PORT,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.crypto_utils import verify_hmac
from gmcp.experiment_transport import get_server_env_info
from gmcp.ticket import build_memory_ticket

# Multi-protocol imports
from gmcp.baselines.hash_chain import (
    HashChainState,
    HashChainVerifier,
    create_initial_state as hc_init_state,
)
from gmcp.baselines.seq_mac import (
    SeqMACState,
    SeqMACVerifier,
    create_initial_state as sm_init_state,
)
from gmcp.baselines.ticket_only import (
    TicketOnlyState,
    TicketOnlyVerifier,
    create_initial_state as to_init_state,
    issue_ticket,
)
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState,
    AuthHashChainVerifier,
    create_initial_state as ahc_init_state,
)

state_lock = threading.Lock()

SUPPORTED_PROTOCOLS = ("gmcp", "hash_chain", "seq_mac", "ticket_only", "authenticated_hash_chain")


def make_gmcp_state(session_id: str) -> GMCPState:
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


def enable_tcp_nodelay(conn) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def verify_recovery_request(packet: Dict[str, Any]) -> bool:
    tag = packet.get("auth_tag")
    if not tag:
        return False

    data = dict(packet)
    data.pop("auth_tag", None)

    return verify_hmac(DATA_AUTH_KEY, data, tag)


def handle_recovery_request(packet, states, verifiers, stats):
    recv_time = time.time()
    session_id = packet.get("session_id", "unknown-session")
    protocol = packet.get("protocol", "gmcp")

    if not verify_recovery_request(packet):
        return {
            "ok": False,
            "type": "RECOVERY_RESPONSE",
            "reason": "invalid recovery request auth_tag",
            "server_time": recv_time,
        }

    with state_lock:
        if session_id not in states:
            _create_session(session_id, protocol, states, verifiers, stats)

        state = states[session_id]

        if protocol == "gmcp":
            memory_ticket = build_memory_ticket(
                session_id=session_id,
                client_id=packet.get("client_id", CLIENT_ID),
                epoch=EPOCH,
                last_seq=state.last_seq,
                last_mem=state.last_mem,
                checkpoint_seq=state.last_seq,
                checkpoint_mem=state.last_mem,
            )
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
                "memory_ticket": memory_ticket,
                "server_time": recv_time,
            }
        elif protocol in ("hash_chain", "authenticated_hash_chain"):
            response = {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "recovery_mode": "full_chain_replay",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "last_hash": state.last_hash,
                "server_time": recv_time,
            }
        elif protocol == "seq_mac":
            response = {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "recovery_mode": "stateless_resync",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "server_time": recv_time,
            }
        elif protocol == "ticket_only":
            response = {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "recovery_mode": "reissue_ticket",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "ticket": state.ticket,
                "server_time": recv_time,
            }
        else:
            response = {
                "ok": False,
                "type": "RECOVERY_RESPONSE",
                "reason": f"unsupported protocol: {protocol}",
                "server_time": recv_time,
            }

    return response


def _create_session(session_id: str, protocol: str, states, verifiers, stats):
    """Create initial state and verifier for a given protocol session."""
    if protocol == "gmcp":
        state = make_gmcp_state(session_id)
        verifier = GMCPVerifier(state)
    elif protocol == "hash_chain":
        state = hc_init_state(session_id, CLIENT_ID, EPOCH)
        verifier = HashChainVerifier(state)
    elif protocol == "authenticated_hash_chain":
        state = ahc_init_state(session_id, CLIENT_ID, EPOCH)
        verifier = AuthHashChainVerifier(state)
    elif protocol == "seq_mac":
        state = sm_init_state(session_id, CLIENT_ID, EPOCH)
        verifier = SeqMACVerifier(state)
    elif protocol == "ticket_only":
        state = to_init_state(session_id, CLIENT_ID, EPOCH)
        verifier = TicketOnlyVerifier(state)
    else:
        raise ValueError(f"unsupported protocol: {protocol}")

    states[session_id] = state
    verifiers[session_id] = verifier
    stats[session_id] = {
        "total": 0,
        "accepted": 0,
        "rejected": 0,
    }


def handle_client(conn, addr, states, verifiers, stats):
    enable_tcp_nodelay(conn)
    print(f"[REAL_TCP_SERVER] connected from {addr}", flush=True)

    # Connection-level binding
    bound_protocol = None
    bound_session_id = None
    bound_sender_id = None
    bound_epoch = None
    hello_done = False

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

            # PING
            if packet_type == "PING":
                send_json_line(conn, {
                    "ok": True,
                    "reason": "pong",
                    "server_time": recv_time,
                })
                continue

            # HELLO handshake
            if packet_type == "HELLO":
                hello_protocol = packet.get("protocol", "gmcp")
                hello_session_id = packet.get("session_id", "unknown-session")
                hello_sender_id = packet.get("sender_id", "unknown-sender")
                hello_epoch = packet.get("epoch", 0)

                # Verify auth_tag on HELLO
                hello_tag = packet.get("auth_tag", "")
                hello_data = dict(packet)
                hello_data.pop("auth_tag", None)
                if not verify_hmac(DATA_AUTH_KEY, hello_data, hello_tag):
                    send_json_line(conn, {
                        "ok": False,
                        "type": "HELLO_ACK",
                        "reason": "HELLO auth_tag invalid",
                        "server_time": recv_time,
                    })
                    continue

                # Validate protocol
                if hello_protocol not in SUPPORTED_PROTOCOLS:
                    send_json_line(conn, {
                        "ok": False,
                        "type": "HELLO_ACK",
                        "reason": f"unsupported protocol: {hello_protocol}",
                        "server_time": recv_time,
                    })
                    continue

                # Bind connection
                bound_protocol = hello_protocol
                bound_session_id = hello_session_id
                bound_sender_id = hello_sender_id
                bound_epoch = hello_epoch
                hello_done = True

                # Create session state
                with state_lock:
                    if hello_session_id not in states:
                        _create_session(hello_session_id, hello_protocol, states, verifiers, stats)
                        print(f"[REAL_TCP_SERVER] new session: {hello_session_id} (protocol={hello_protocol})", flush=True)

                # Build HELLO_ACK
                hello_ack = {
                    "ok": True,
                    "type": "HELLO_ACK",
                    "reason": "ok",
                    "protocol": bound_protocol,
                    "session_id": bound_session_id,
                    "server_time": recv_time,
                }

                # Include server env info
                hello_ack.update(get_server_env_info())

                # For ticket_only, issue and include ticket
                if bound_protocol == "ticket_only":
                    ticket = issue_ticket(bound_session_id, bound_epoch)
                    hello_ack["ticket"] = ticket

                send_json_line(conn, hello_ack)
                continue

            # RECOVERY_REQUEST
            if packet_type == "RECOVERY_REQUEST":
                if not hello_done:
                    send_json_line(conn, {
                        "ok": False,
                        "type": "RECOVERY_RESPONSE",
                        "reason": "connection not bound: HELLO required",
                        "server_time": recv_time,
                    })
                    continue

                rec_session_id = packet.get("session_id", "unknown-session")
                rec_protocol = packet.get("protocol", "gmcp")

                # Connection binding check
                if rec_protocol != bound_protocol:
                    send_json_line(conn, {
                        "ok": False,
                        "type": "RECOVERY_RESPONSE",
                        "reason": f"connection protocol mismatch: bound={bound_protocol}, got={rec_protocol}",
                        "server_time": recv_time,
                    })
                    continue
                if rec_session_id != bound_session_id:
                    send_json_line(conn, {
                        "ok": False,
                        "type": "RECOVERY_RESPONSE",
                        "reason": f"connection session mismatch: bound={bound_session_id}, got={rec_session_id}",
                        "server_time": recv_time,
                    })
                    continue

                response = handle_recovery_request(packet, states, verifiers, stats)
                send_json_line(conn, response)
                continue

            # DATA packet — require HELLO first
            if not hello_done:
                send_json_line(conn, {
                    "ok": False,
                    "reason": "connection not bound: HELLO required",
                    "server_time": recv_time,
                })
                continue

            protocol = packet.get("protocol", "gmcp")
            session_id = packet.get("session_id", "unknown-session")
            sender_id = packet.get("sender_id", "unknown-sender")
            epoch = packet.get("epoch", 0)

            # Connection binding checks
            if protocol != bound_protocol:
                send_json_line(conn, {
                    "ok": False,
                    "reason": f"connection protocol mismatch: bound={bound_protocol}, got={protocol}",
                    "server_time": recv_time,
                })
                continue
            if session_id != bound_session_id:
                send_json_line(conn, {
                    "ok": False,
                    "reason": f"connection session mismatch: bound={bound_session_id}, got={session_id}",
                    "server_time": recv_time,
                })
                continue
            if sender_id != bound_sender_id:
                send_json_line(conn, {
                    "ok": False,
                    "reason": f"connection sender mismatch: bound={bound_sender_id}, got={sender_id}",
                    "server_time": recv_time,
                })
                continue
            if epoch != bound_epoch:
                send_json_line(conn, {
                    "ok": False,
                    "reason": f"connection epoch mismatch: bound={bound_epoch}, got={epoch}",
                    "server_time": recv_time,
                })
                continue

            with state_lock:
                if session_id not in states:
                    _create_session(session_id, protocol, states, verifiers, stats)
                    print(f"[REAL_TCP_SERVER] new session: {session_id}", flush=True)

                state = states[session_id]
                verifier = verifiers[session_id]

                ok, reason = verifier.verify_data_packet(packet)

                stats[session_id]["total"] += 1

                if ok:
                    stats[session_id]["accepted"] += 1

                    if stats[session_id]["accepted"] % 500 == 0:
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

                # Build response with protocol-appropriate state
                response: Dict[str, Any] = {
                    "ok": ok,
                    "reason": reason,
                    "session_id": session_id,
                    "server_time": recv_time,
                    "accepted": stats[session_id]["accepted"],
                    "rejected": stats[session_id]["rejected"],
                }

                # Include protocol-appropriate state fields
                if protocol == "gmcp":
                    response["last_seq"] = state.last_seq
                    response["last_mem"] = state.last_mem
                elif protocol in ("hash_chain", "authenticated_hash_chain"):
                    response["last_seq"] = state.last_seq
                    response["last_hash"] = state.last_hash
                elif protocol in ("seq_mac", "ticket_only"):
                    response["last_seq"] = state.last_seq

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
    states: Dict[str, Any] = {}
    verifiers: Dict[str, Any] = {}
    stats: Dict[str, Dict[str, int]] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_BIND_HOST, DEFAULT_PORT))
    sock.listen(100)

    print(f"[REAL_TCP_SERVER] Listening on {SERVER_BIND_HOST}:{DEFAULT_PORT}", flush=True)

    while True:
        conn, addr = sock.accept()
        enable_tcp_nodelay(conn)

        t = threading.Thread(
            target=handle_client,
            args=(conn, addr, states, verifiers, stats),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
