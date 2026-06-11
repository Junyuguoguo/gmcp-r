# -*- coding: utf-8 -*-
# client.py

import argparse
import json
import os
import socket
import time

from gmcp.config import (
    SERVER_TARGET_HOST,
    DEFAULT_PORT,
    SESSION_ID,
    CLIENT_ID,
    EPOCH,
    DEFAULT_MESSAGE_COUNT,
)
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.crypto_utils import hash_text, hmac_sha256_hex
from gmcp.attack import drop_packet, modify_payload, modify_prev_mem


def make_payload(seq: int, payload_size: int) -> str:
    prefix = f"message-{seq}-"
    remain = max(0, payload_size - len(prefix))
    return prefix + ("x" * remain)


def modify_prev_mem_with_valid_hmac(packet):
    """
    修改 prev_mem，并重新计算 auth_tag。
    这样可以专门测试 prev_mem mismatch，
    而不是只触发 auth_tag verification failed。
    """
    attacked = dict(packet)
    attacked["prev_mem"] = "fake-memory"

    attacked.pop("auth_tag", None)
    attacked["auth_tag"] = hmac_sha256_hex(
        key=b"gmcp-demo-shared-key",
        data=attacked,
    )
    return attacked


def parse_args():
    parser = argparse.ArgumentParser(description="GMCP-R client")

    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_MESSAGE_COUNT,
        help="message count",
    )

    parser.add_argument(
        "--payload-size",
        type=int,
        default=128,
        help="payload size in bytes",
    )

    parser.add_argument(
        "--attack",
        type=str,
        default="none",
        choices=["none", "drop", "modify", "prev_mem"],
        help="attack type",
    )

    parser.add_argument(
        "--attack-seq",
        type=int,
        default=100,
        help="attack target seq",
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=0.001,
        help="sleep time between packets",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # 默认 session_id 还是 session-001
    # 做真实网络多轮实验时，可以通过环境变量 GMCP_SESSION_ID 指定不同 session
    session_id = os.getenv("GMCP_SESSION_ID", SESSION_ID)

    mem_seed = "demo-seed"
    current_mem = initial_memory(session_id, CLIENT_ID, EPOCH, mem_seed)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    target = (SERVER_TARGET_HOST, DEFAULT_PORT)

    print("[CLIENT] Start sending messages")
    print(f"[CLIENT] target={SERVER_TARGET_HOST}:{DEFAULT_PORT}")
    print(f"[CLIENT] session_id={session_id}")
    print(f"[CLIENT] count={args.count}, payload_size={args.payload_size}, attack={args.attack}")

    accepted = 0
    rejected = 0
    timeout = 0

    start_time = time.time()

    for seq in range(1, args.count + 1):
        payload = make_payload(seq, args.payload_size)

        packet = build_data_packet(
            session_id=session_id,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_mem=current_mem,
            payload=payload,
        )

        # 删除攻击：丢弃某一条消息
        if args.attack == "drop" and drop_packet(seq, drop_seq=args.attack_seq):
            print(f"[CLIENT] attack: drop seq={seq}")
            continue

        # 篡改攻击：修改 payload，但不重新计算 auth_tag
        if args.attack == "modify" and seq == args.attack_seq:
            print(f"[CLIENT] attack: modify payload seq={seq}")
            packet = modify_payload(packet, target_seq=args.attack_seq)

        # 记忆断裂攻击：修改 prev_mem，并重新计算 auth_tag
        if args.attack == "prev_mem" and seq == args.attack_seq:
            print(f"[CLIENT] attack: modify prev_mem seq={seq}")
            packet = modify_prev_mem_with_valid_hmac(packet)

        raw = json.dumps(packet, ensure_ascii=False).encode("utf-8")
        sock.sendto(raw, target)

        try:
            data, _ = sock.recvfrom(65535)
            response = json.loads(data.decode("utf-8"))
        except socket.timeout:
            timeout += 1
            print(f"[CLIENT] timeout at seq={seq}")
            break

        if not response.get("ok"):
            rejected += 1
            print(f"[CLIENT] server rejected seq={seq}, reason={response.get('reason')}")
            break

        accepted += 1

        payload_hash = hash_text(payload)
        current_mem = update_memory(
            prev_mem=current_mem,
            session_id=session_id,
            epoch=EPOCH,
            seq=seq,
            payload_hash=payload_hash,
            sender_id=CLIENT_ID,
        )

        if seq % 100 == 0:
            print(f"[CLIENT] sent seq={seq}")

        time.sleep(args.sleep)

    elapsed = time.time() - start_time
    throughput = accepted / elapsed if elapsed > 0 else 0

    print("[CLIENT] Finished")
    print(f"[CLIENT] accepted={accepted}, rejected={rejected}, timeout={timeout}")
    print(f"[CLIENT] elapsed={elapsed:.4f}s, throughput={throughput:.2f} msg/s")


if __name__ == "__main__":
    main()