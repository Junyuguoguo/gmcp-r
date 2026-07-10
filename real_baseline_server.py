# -*- coding: utf-8 -*-
# real_baseline_server.py
#
# Baseline 对比实验服务器
# 支持多种协议：gmcp_r, hash_chain, seq_mac, ticket_only, authenticated_hash_chain
# 根据数据包中的 protocol 字段选择对应的验证器
# 监听端口 9001
#
# 攻击检测模型（两类攻击者）：
#   1. 网络攻击者 (network_attacker) —— 不知道密钥
#      检测手段：HMAC/MAC/chain_hash验证失败
#      攻击类型：modify_unsigned, metadata_tamper, exact_replay
#
#   2. 恶意持钥客户端 (malicious_client) —— 知道DATA密钥
#      检测手段：协议级约束（session_id/epoch/seq连续性/prev_mem链）
#      攻击类型：forged_prev_mem_valid_mac, sequence_gap_valid_mac,
#                cross_session_valid_mac, cross_epoch_valid_mac

import json
import socket
import threading
import time
from typing import Dict, Any

from gmcp.config import (
    SERVER_BIND_HOST,
    CLIENT_ID,
    EPOCH,
    DATA_AUTH_KEY,
)
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.crypto_utils import verify_hmac
from gmcp.ticket import build_memory_ticket

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
)
from gmcp.baselines.authenticated_hash_chain import (
    AuthHashChainState,
    AuthHashChainVerifier,
    create_initial_state as ahc_init_state,
)
from gmcp.session_registry import SessionContext, SessionRegistry
from gmcp.config import LOCK_STRATEGY

# 导入攻击模型常量（用于日志和文档）
from gmcp.attack import (
    ALL_ATTACK_TYPES,
    NETWORK_ATTACK_TYPES,
    MALICIOUS_CLIENT_ATTACK_TYPES,
)

BASELINE_PORT = 9001

# =========================
# Protocol registry
# =========================

SUPPORTED_PROTOCOLS = ("gmcp_r", "hash_chain", "seq_mac", "ticket_only", "authenticated_hash_chain")


def _make_gmcp_state(session_id: str):
    mem_seed = "demo-seed"
    m0 = initial_memory(session_id, CLIENT_ID, EPOCH, mem_seed)
    state = GMCPState(
        session_id=session_id,
        sender_id=CLIENT_ID,
        epoch=EPOCH,
        last_seq=0,
        last_mem=m0,
    )
    return state, GMCPVerifier(state)


def _make_hash_chain_state(session_id: str):
    state = hc_init_state(session_id, CLIENT_ID, EPOCH)
    return state, HashChainVerifier(state)


def _make_seq_mac_state(session_id: str):
    state = sm_init_state(session_id, CLIENT_ID, EPOCH)
    return state, SeqMACVerifier(state)


def _make_ticket_only_state(session_id: str):
    state = to_init_state(session_id, CLIENT_ID, EPOCH)
    return state, TicketOnlyVerifier(state)


def _make_auth_hash_chain_state(session_id: str):
    state = ahc_init_state(session_id, CLIENT_ID, EPOCH)
    return state, AuthHashChainVerifier(state)


STATE_FACTORIES = {
    "gmcp_r": _make_gmcp_state,
    "hash_chain": _make_hash_chain_state,
    "seq_mac": _make_seq_mac_state,
    "ticket_only": _make_ticket_only_state,
    "authenticated_hash_chain": _make_auth_hash_chain_state,
}


# Registry keyed by "{protocol}:{session_id}"
def _baseline_factory(registry_key: str, checkpoint_interval: int) -> SessionContext:
    """Create a SessionContext for a composite key like 'protocol:session_id'."""
    protocol, _, session_id = registry_key.partition(":")
    if protocol not in STATE_FACTORIES:
        raise ValueError(f"unsupported protocol: {protocol}")
    state, verifier = STATE_FACTORIES[protocol](session_id)
    return SessionContext(
        session_id=registry_key,
        state=state,
        verifier=verifier,
    )


# =========================
# Helper functions
# =========================

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


# =========================
# Recovery handler
# =========================

def handle_recovery_request(packet, registry: SessionRegistry):
    recv_time = time.time()
    session_id = packet.get("session_id", "unknown-session")

    if not verify_recovery_request(packet):
        return {
            "ok": False,
            "type": "RECOVERY_RESPONSE",
            "reason": "invalid recovery request auth_tag",
            "server_time": recv_time,
        }

    protocol = packet.get("protocol", "gmcp_r")
    registry_key = f"{protocol}:{session_id}"

    if protocol not in STATE_FACTORIES:
        return {
            "ok": False,
            "type": "RECOVERY_RESPONSE",
            "reason": f"unsupported protocol: {protocol}",
            "server_time": recv_time,
        }

    ctx = registry.get_or_create(registry_key, checkpoint_interval=100)
    with ctx.lock:
        state = ctx.state

        # Build recovery response depending on protocol
        if protocol == "gmcp_r":
            memory_ticket = build_memory_ticket(
                session_id=session_id,
                client_id=packet.get("client_id", CLIENT_ID),
                epoch=EPOCH,
                last_seq=state.last_seq,
                last_mem=state.last_mem,
                checkpoint_seq=state.last_seq,
                checkpoint_mem=state.last_mem,
            )
            return {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "protocol": protocol,
                "recovery_mode": "memory_ticket_checkpoint",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "memory_ticket": memory_ticket,
                "server_time": recv_time,
            }
        elif protocol == "hash_chain":
            return {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "protocol": protocol,
                "recovery_mode": "full_chain_replay",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "last_hash": state.last_hash,
                "hash_chain": state.hash_chain,
                "server_time": recv_time,
            }
        elif protocol == "authenticated_hash_chain":
            return {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "protocol": protocol,
                "recovery_mode": "full_chain_replay",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "last_hash": state.last_hash,
                "hash_chain": state.hash_chain,
                "server_time": recv_time,
            }
        elif protocol == "seq_mac":
            return {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "protocol": protocol,
                "recovery_mode": "stateless_resync",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "server_time": recv_time,
            }
        elif protocol == "ticket_only":
            return {
                "ok": True,
                "type": "RECOVERY_RESPONSE",
                "reason": "ok",
                "protocol": protocol,
                "recovery_mode": "reissue_ticket",
                "session_id": session_id,
                "server_last_seq": state.last_seq,
                "ticket": state.ticket,
                "server_time": recv_time,
            }

    return {
        "ok": False,
        "type": "RECOVERY_RESPONSE",
        "reason": "unknown protocol",
        "server_time": recv_time,
    }


# =========================
# Client handler
# =========================

def _classify_rejection_reason(reason: str) -> str:
    """
    根据拒绝原因推断攻击类别（用于日志）。
    - HMAC/MAC/chain_hash失败 → 网络攻击者检测
    - session_id/epoch/seq/prev_mem约束失败 → 恶意客户端检测
    """
    if not reason:
        return "unknown"
    r = reason.lower()
    if "auth_tag" in r or "mac mismatch" in r or "chain_hash" in r or "payload_hash" in r:
        return "network_attacker_detected"
    if "session_id" in r or "epoch" in r or "seq" in r or "prev_mem" in r or "prev_hash" in r:
        return "malicious_client_detected"
    return "other"


def handle_client(conn, addr, registry: SessionRegistry):
    enable_tcp_nodelay(conn)
    print(f"[BASELINE_SERVER] connected from {addr}", flush=True)

    file_obj = None

    try:
        conn.settimeout(30)
        file_obj = conn.makefile("r", encoding="utf-8", newline="\n")

        while True:
            try:
                line = file_obj.readline()
            except socket.timeout:
                print(f"[BASELINE_SERVER] connection timeout from {addr}", flush=True)
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

            # RECOVERY_REQUEST
            if packet_type == "RECOVERY_REQUEST":
                response = handle_recovery_request(packet, registry)
                send_json_line(conn, response)
                continue

            # DATA packet — route by protocol
            protocol = packet.get("protocol", "gmcp_r")
            if protocol not in SUPPORTED_PROTOCOLS:
                send_json_line(conn, {
                    "ok": False,
                    "reason": f"unsupported protocol: {protocol}",
                    "server_time": recv_time,
                })
                continue

            session_id = packet.get("session_id", "unknown-session")
            registry_key = f"{protocol}:{session_id}"

            ctx = registry.get_or_create(registry_key, checkpoint_interval=100)
            with ctx.lock:
                state = ctx.state
                verifier = ctx.verifier
                stats = ctx.stats

                # 验证数据包（所有协议的验证器处理protocol字段）
                ok, reason = verifier.verify_data_packet(packet)

                stats["total"] += 1

                if ok:
                    stats["accepted"] += 1
                    if stats["accepted"] % 500 == 0:
                        print(
                            f"[BASELINE_SERVER] protocol={protocol}, session={session_id}, "
                            f"accepted={stats['accepted']}, last_seq={state.last_seq}",
                            flush=True,
                        )
                else:
                    stats["rejected"] += 1
                    # 分类拒绝原因（区分网络攻击者 vs 恶意客户端）
                    attack_class = _classify_rejection_reason(reason)
                    print(
                        f"[BASELINE_SERVER] reject protocol={protocol}, session={session_id}, "
                        f"seq={packet.get('seq')}, reason={reason}, "
                        f"attack_class={attack_class}",
                        flush=True,
                    )

                response = {
                    "ok": ok,
                    "reason": reason,
                    "protocol": protocol,
                    "session_id": session_id,
                    "last_seq": state.last_seq,
                    "server_time": recv_time,
                    "accepted": stats["accepted"],
                    "rejected": stats["rejected"],
                }

                # Attach protocol-specific state info
                if protocol == "gmcp_r":
                    response["last_mem"] = state.last_mem
                elif protocol in ("hash_chain", "authenticated_hash_chain"):
                    response["last_hash"] = state.last_hash

            send_json_line(conn, response)

    except Exception as e:
        print(f"[BASELINE_SERVER] error from {addr}: {e}", flush=True)

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
        print(f"[BASELINE_SERVER] disconnected from {addr}", flush=True)


# =========================
# Main
# =========================

def main():
    registry = SessionRegistry(factory=_baseline_factory, lock_strategy=LOCK_STRATEGY)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_BIND_HOST, BASELINE_PORT))
    sock.listen(100)

    print(f"[BASELINE_SERVER] Listening on {SERVER_BIND_HOST}:{BASELINE_PORT}")
    print(f"[BASELINE_SERVER] Supported protocols: {', '.join(SUPPORTED_PROTOCOLS)}")
    print(f"[BASELINE_SERVER] Lock strategy: {LOCK_STRATEGY}")
    print(f"[BASELINE_SERVER] Attack model:")
    print(f"  Network attacker attacks: {', '.join(NETWORK_ATTACK_TYPES)}")
    print(f"  Malicious client attacks: {', '.join(MALICIOUS_CLIENT_ATTACK_TYPES)}")
    print(flush=True)

    while True:
        conn, addr = sock.accept()
        enable_tcp_nodelay(conn)

        t = threading.Thread(
            target=handle_client,
            args=(conn, addr, registry),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
