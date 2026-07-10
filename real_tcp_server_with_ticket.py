# -*- coding: utf-8 -*-
# real_tcp_server_with_ticket.py
# 
# 增强版服务器：定期签发MemoryTicket，支持真实恢复流程测试
# 集成CheckpointManager，实现真正的checkpoint恢复

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
    CHECKPOINT_INTERVAL,
)
from gmcp.memory import initial_memory
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.ticket import build_memory_ticket
from gmcp.checkpoint_manager import CheckpointManager
from gmcp.recovery_protocol import (
    build_recovery_response,
    verify_recovery_request,
)
from gmcp.session_registry import SessionContext, SessionRegistry
from gmcp.config import LOCK_STRATEGY
# 每隔多少条消息签发一次MemoryTicket
TICKET_INTERVAL = 100


def _session_factory(session_id: str, checkpoint_interval: int) -> SessionContext:
    """Create a full SessionContext for a new session."""
    mem_seed = "demo-seed"
    m0 = initial_memory(session_id, CLIENT_ID, EPOCH, mem_seed)
    state = GMCPState(
        session_id=session_id,
        sender_id=CLIENT_ID,
        epoch=EPOCH,
        last_seq=0,
        last_mem=m0,
    )
    verifier = GMCPVerifier(state)
    checkpoint_mgr = CheckpointManager(
        session_id=session_id,
        epoch=EPOCH,
        checkpoint_interval=checkpoint_interval,
    )
    return SessionContext(
        session_id=session_id,
        state=state,
        verifier=verifier,
        checkpoint_manager=checkpoint_mgr,
    )


def send_json_line(conn, response: Dict[str, Any]):
    raw = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
    conn.sendall(raw)


def enable_tcp_nodelay(conn) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def _reject(session_id: str, recovery_nonce: str, reason: str, recv_time: float,
            extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build an authenticated failure recovery response."""
    response = build_recovery_response(
        ok=False,
        reason=reason,
        session_id=session_id,
        epoch=EPOCH,
        recovery_nonce=recovery_nonce,
    )
    if extra:
        response.update(extra)
        # Re-sign with the extra fields included
        response["recovery_auth_tag"] = _sign_response(response)
    return response

def _sign_response(response: Dict[str, Any]) -> str:
    """Re-sign a recovery response after adding extra fields."""
    from gmcp.crypto_utils import canonical_json
    import hmac as _hmac
    import hashlib as _hashlib
    data = dict(response)
    data.pop("recovery_auth_tag", None)
    return _hmac.new(
        DATA_AUTH_KEY, canonical_json(data).encode("utf-8"), _hashlib.sha256
    ).hexdigest()


def handle_recovery_request(packet, registry: SessionRegistry):
    recv_time = time.time()
    session_id = packet.get("session_id", "unknown-session")
    recovery_nonce = packet.get("recovery_nonce", "")

    ok_req, reason_req = verify_recovery_request(packet)
    if not ok_req:
        return _reject(session_id, recovery_nonce, "invalid recovery request auth_tag",
                        recv_time, extra={
                            "request_auth_ok": False,
                            "server_last_seq": 0, "server_last_mem": "",
                            "recovery_floor": 0, "ticket_last_seq": 0,
                        })
    client_ckpt_interval = int(packet.get("checkpoint_interval", CHECKPOINT_INTERVAL))
    # Validate range — fall back to default if out of bounds
    if client_ckpt_interval < 10 or client_ckpt_interval > 1000:
        client_ckpt_interval = CHECKPOINT_INTERVAL

    ctx = registry.get_or_create(session_id, client_ckpt_interval)
    with ctx.lock:
        state = ctx.state
        checkpoint_mgr = ctx.checkpoint_manager
        
        # 验证客户端带回来的MemoryTicket（必需）
        client_ticket = packet.get("memory_ticket")
        ticket_valid = False
        ticket_reason = "no ticket provided"
        
        if not isinstance(client_ticket, dict):
            # 缺少票据，拒绝请求
            print(f"[SERVER] 恢复请求缺少MemoryTicket", flush=True)
            return _reject(session_id, recovery_nonce, "missing memory_ticket", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": 0, "ticket_last_seq": 0})
        
        from gmcp.ticket import validate_memory_ticket, consume_ticket_nonce
        # 获取最近的Checkpoint，使用其seq作为recovery_floor
        latest_checkpoint = checkpoint_mgr.get_latest_checkpoint()
        if latest_checkpoint:
            recovery_floor = latest_checkpoint.seq
        else:
            # 如果没有Checkpoint，使用0（允许任何票据）
            recovery_floor = 0

        ticket_last_seq = int(client_ticket.get("last_seq", 0))
        
        # 第一步：验证票据（不消费nonce）
        ticket_valid, ticket_reason = validate_memory_ticket(
            ticket=client_ticket,
            expected_session_id=session_id,
            expected_client_id=packet.get("client_id", CLIENT_ID),
            expected_epoch=EPOCH,
            min_last_seq=recovery_floor,  # 使用recovery_floor
        )
        
        if not ticket_valid:
            print(f"[SERVER] MemoryTicket验证失败: {ticket_reason}", flush=True)
            return _reject(session_id, recovery_nonce, f"memory_ticket invalid: {ticket_reason}", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        print(f"[SERVER] MemoryTicket验证成功", flush=True)
        
        # 验证票据中的Checkpoint与服务器记录一致
        ticket_checkpoint_seq = int(client_ticket.get("checkpoint_seq", 0))
        ticket_checkpoint_mem = client_ticket.get("checkpoint_mem", "")
        
        # 根据ticket.checkpoint_seq查找服务器保存的Checkpoint
        stored_checkpoint = checkpoint_mgr.get_checkpoint_for_seq(ticket_checkpoint_seq)
        if not stored_checkpoint:
            # 找不到Checkpoint，拒绝恢复
            print(f"[SERVER] 未找到Checkpoint seq={ticket_checkpoint_seq}，拒绝恢复", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint not found", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        # 验证Checkpoint认证标签
        checkpoint_ok, checkpoint_reason = checkpoint_mgr.verify_checkpoint(stored_checkpoint)
        if not checkpoint_ok:
            print(f"[SERVER] Checkpoint认证标签验证失败: {checkpoint_reason}", flush=True)
            return _reject(session_id, recovery_nonce, f"checkpoint authentication failed: {checkpoint_reason}", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        # 比较Checkpoint的session_id、epoch、seq和memory
        if stored_checkpoint.session_id != session_id:
            print(f"[SERVER] Checkpoint session_id不匹配", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint session_id mismatch", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        if stored_checkpoint.epoch != EPOCH:
            print(f"[SERVER] Checkpoint epoch不匹配", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint epoch mismatch", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        if stored_checkpoint.seq != ticket_checkpoint_seq:
            print(f"[SERVER] Checkpoint seq不匹配: stored={stored_checkpoint.seq}, ticket={ticket_checkpoint_seq}", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint seq mismatch", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        if stored_checkpoint.memory != ticket_checkpoint_mem:
            print(f"[SERVER] Checkpoint memory不匹配: stored={stored_checkpoint.memory[:16]}..., ticket={ticket_checkpoint_mem[:16]}...", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint memory mismatch", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        # 验证ticket.checkpoint_seq <= ticket.last_seq <= server.last_seq
        if ticket_checkpoint_seq > ticket_last_seq or ticket_last_seq > state.last_seq:
            print(f"[SERVER] Checkpoint序列不一致: ckpt_seq={ticket_checkpoint_seq}, ticket_last={ticket_last_seq}, server_last={state.last_seq}", flush=True)
            return _reject(session_id, recovery_nonce, "checkpoint sequence inconsistency", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        
        print(f"[SERVER] Checkpoint验证成功: seq={ticket_checkpoint_seq}", flush=True)
        
        # 所有检查通过，现在消费nonce
        if not consume_ticket_nonce(client_ticket):
            print(f"[SERVER] nonce消费失败（可能已被使用）", flush=True)
            return _reject(session_id, recovery_nonce, "ticket replay detected during nonce consumption", recv_time,
                            extra={"request_auth_ok": True,
                                   "server_last_seq": state.last_seq, "server_last_mem": state.last_mem,
                                   "recovery_floor": recovery_floor, "ticket_last_seq": ticket_last_seq})
        print(f"[SERVER] nonce已消费", flush=True)
        
        # 获取最近的Checkpoint
        latest_checkpoint = checkpoint_mgr.get_latest_checkpoint()
        if latest_checkpoint:
            checkpoint_seq = latest_checkpoint.seq
            checkpoint_mem = latest_checkpoint.memory
        else:
            # 如果没有Checkpoint，使用当前状态
            checkpoint_seq = state.last_seq
            checkpoint_mem = state.last_mem
        
        # 生成新的MemoryTicket
        memory_ticket = build_memory_ticket(
            session_id=session_id,
            client_id=packet.get("client_id", CLIENT_ID),
            epoch=EPOCH,
            last_seq=state.last_seq,
            last_mem=state.last_mem,
            checkpoint_seq=checkpoint_seq,
            checkpoint_mem=checkpoint_mem,
        )

        response = build_recovery_response(
            ok=True,
            reason="ok",
            session_id=session_id,
            epoch=EPOCH,
            recovery_nonce=recovery_nonce,
            extra={
                "request_auth_ok": True,
                "recovery_mode": "memory_ticket_checkpoint",
                "server_last_seq": state.last_seq,
                "server_last_mem": state.last_mem,
                "checkpoint_seq": checkpoint_seq,
                "recovery_floor": checkpoint_seq,
                "checkpoint_mem": checkpoint_mem,
                "memory_ticket": memory_ticket,
                "ticket_verified": ticket_valid,
                "ticket_reason": ticket_reason,
                "ticket_last_seq": ticket_last_seq,
            },
        )

    return response


def handle_client(conn, addr, registry: SessionRegistry):
    enable_tcp_nodelay(conn)
    print(f"[REAL_TCP_SERVER] connected from {addr}", flush=True)

    # --- Connection-level binding for cross-session attack detection ---
    bound_session_id = None
    bound_sender_id = None
    bound_epoch = None
    bound_protocol = None
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

            # 每条消息开始时初始化memory_ticket
            memory_ticket = None

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

            # HELLO handshake
            if packet_type == "HELLO":
                from gmcp.crypto_utils import verify_tagged_hmac
                hello_protocol = packet.get("protocol", "gmcp")
                hello_session_id = packet.get("session_id", "unknown-session")
                hello_sender_id = packet.get("sender_id", "unknown-sender")
                hello_epoch = packet.get("epoch", 0)

                # Verify auth_tag on HELLO
                if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
                    send_json_line(conn, {
                        "ok": False,
                        "type": "HELLO_ACK",
                        "reason": "HELLO auth_tag invalid",
                        "server_time": recv_time,
                    })
                    continue

                # Bind connection
                bound_protocol = hello_protocol
                bound_session_id = hello_session_id
                bound_sender_id = hello_sender_id
                bound_epoch = hello_epoch
                hello_done = True

                send_json_line(conn, {
                    "ok": True,
                    "type": "HELLO_ACK",
                    "reason": "ok",
                    "protocol": bound_protocol,
                    "session_id": bound_session_id,
                    "server_time": recv_time,
                })
                continue

            if packet_type == "RECOVERY_REQUEST":
                rec_session_id = packet.get("session_id", "unknown-session")
                rec_sender_id = packet.get("sender_id", packet.get("client_id", "unknown-sender"))
                rec_epoch = packet.get("epoch", 0)
                rec_protocol = packet.get("protocol", "gmcp")
                rec_nonce = packet.get("recovery_nonce", "")
                # Strict mode: require HELLO first
                if not hello_done:
                    send_json_line(conn, build_recovery_response(
                        False, "connection not bound: HELLO required",
                        rec_session_id, rec_epoch, rec_nonce,
                    ))
                    continue

                # --- Connection-level binding check for RECOVERY_REQUEST ---
                if rec_protocol != bound_protocol:
                    send_json_line(conn, build_recovery_response(
                        False, f"connection protocol mismatch: bound={bound_protocol}, got={rec_protocol}",
                        rec_session_id, rec_epoch, rec_nonce,
                    ))
                    continue
                if rec_session_id != bound_session_id:
                    send_json_line(conn, build_recovery_response(
                        False, f"connection session mismatch: bound={bound_session_id}, got={rec_session_id}",
                        rec_session_id, rec_epoch, rec_nonce,
                    ))
                    continue
                if rec_sender_id != bound_sender_id:
                    send_json_line(conn, build_recovery_response(
                        False, f"connection sender mismatch: bound={bound_sender_id}, got={rec_sender_id}",
                        rec_session_id, rec_epoch, rec_nonce,
                    ))
                    continue
                if rec_epoch != bound_epoch:
                    send_json_line(conn, build_recovery_response(
                        False, f"connection epoch mismatch: bound={bound_epoch}, got={rec_epoch}",
                        rec_session_id, rec_epoch, rec_nonce,
                    ))
                    continue
                response = handle_recovery_request(packet, registry)
                send_json_line(conn, response)
                continue

            session_id = packet.get("session_id", "unknown-session")
            sender_id = packet.get("sender_id", "unknown-sender")
            epoch = packet.get("epoch", 0)

            # Strict mode: require HELLO first
            if not hello_done:
                send_json_line(conn, {
                    "ok": False,
                    "reason": "connection not bound: HELLO required",
                    "server_time": recv_time,
                })
                continue

            # --- Connection-level binding check ---
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

            client_ckpt_interval = int(packet.get("checkpoint_interval", CHECKPOINT_INTERVAL))
            if client_ckpt_interval < 10 or client_ckpt_interval > 1000:
                client_ckpt_interval = CHECKPOINT_INTERVAL

            ctx = registry.get_or_create(session_id, client_ckpt_interval)
            with ctx.lock:
                state = ctx.state
                verifier = ctx.verifier
                checkpoint_mgr = ctx.checkpoint_manager
                stats = ctx.stats

                ok, reason = verifier.verify_data_packet(packet)

                stats["total"] += 1

                if ok:
                    stats["accepted"] += 1

                    # 检查是否需要创建checkpoint
                    if checkpoint_mgr.should_checkpoint(state.last_seq):
                        checkpoint = checkpoint_mgr.create_checkpoint(
                            seq=state.last_seq,
                            memory=state.last_mem,
                        )
                        print(
                            f"[REAL_TCP_SERVER] checkpoint created at seq={state.last_seq}",
                            flush=True,
                        )
                        
                        # 创建Checkpoint时同步签发MemoryTicket
                        memory_ticket = build_memory_ticket(
                            session_id=session_id,
                            client_id=CLIENT_ID,
                            epoch=EPOCH,
                            last_seq=state.last_seq,
                            last_mem=state.last_mem,
                            checkpoint_seq=checkpoint.seq,
                            checkpoint_mem=checkpoint.memory,
                        )
                        print(
                            f"[REAL_TCP_SERVER] issued MemoryTicket at checkpoint seq={state.last_seq}",
                            flush=True,
                        )

                    if state.last_seq % 500 == 0:
                        print(
                            f"[REAL_TCP_SERVER] session={session_id}, "
                            f"accepted={stats['accepted']}, "
                            f"last_seq={state.last_seq}",
                            flush=True,
                        )
                else:
                    stats["rejected"] += 1
                    print(
                        f"[REAL_TCP_SERVER] reject session={session_id}, "
                        f"seq={packet.get('seq')}, reason={reason}",
                        flush=True,
                    )

                # 定期签发MemoryTicket（仅当Checkpoint未签发时）
                if memory_ticket is None and ok and state.last_seq % TICKET_INTERVAL == 0 and state.last_seq > 0:
                    # 获取最近的checkpoint
                    latest_checkpoint = checkpoint_mgr.get_latest_checkpoint()
                    if latest_checkpoint:
                        checkpoint_seq = latest_checkpoint.seq
                        checkpoint_mem = latest_checkpoint.memory
                    else:
                        # 没有Checkpoint时，创建一个再签发票据
                        checkpoint = checkpoint_mgr.create_checkpoint(
                            seq=state.last_seq,
                            memory=state.last_mem,
                        )
                        checkpoint_seq = checkpoint.seq
                        checkpoint_mem = checkpoint.memory
                    
                    memory_ticket = build_memory_ticket(
                        session_id=session_id,
                        client_id=CLIENT_ID,
                        epoch=EPOCH,
                        last_seq=state.last_seq,
                        last_mem=state.last_mem,
                        checkpoint_seq=checkpoint_seq,
                        checkpoint_mem=checkpoint_mem,
                    )
                    print(
                        f"[REAL_TCP_SERVER] issued MemoryTicket at seq={state.last_seq}, "
                        f"checkpoint_seq={checkpoint_seq}",
                        flush=True,
                    )

                response = {
                    "ok": ok,
                    "reason": reason,
                    "session_id": session_id,
                    "last_seq": state.last_seq,
                    "last_mem": state.last_mem,
                    "server_time": recv_time,
                    "accepted": stats["accepted"],
                    "rejected": stats["rejected"],
                }

                # 如果有ticket，添加到响应中
                if memory_ticket:
                    response["memory_ticket"] = memory_ticket

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
    registry = SessionRegistry(factory=_session_factory, lock_strategy=LOCK_STRATEGY)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_BIND_HOST, DEFAULT_PORT))
    sock.listen(100)

    print(f"[REAL_TCP_SERVER] Listening on {SERVER_BIND_HOST}:{DEFAULT_PORT}", flush=True)
    print(f"[REAL_TCP_SERVER] MemoryTicket will be issued every {TICKET_INTERVAL} messages", flush=True)

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
