# client.py

import json
import socket
import time

from gmcp.config import DEFAULT_HOST, DEFAULT_PORT, SESSION_ID, CLIENT_ID, EPOCH, DEFAULT_MESSAGE_COUNT
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.crypto_utils import hash_text
from gmcp.attack import drop_packet, modify_payload, modify_prev_mem


def main():
    mem_seed = "demo-seed"
    current_mem = initial_memory(SESSION_ID, CLIENT_ID, EPOCH, mem_seed)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    print("[CLIENT] Start sending messages")

    for seq in range(1, DEFAULT_MESSAGE_COUNT + 1):
        payload = f"message-{seq}"

        packet = build_data_packet(
            session_id=SESSION_ID,
            sender_id=CLIENT_ID,
            epoch=EPOCH,
            seq=seq,
            prev_mem=current_mem,
            payload=payload,
        )
        # 删除攻击：丢弃第 100 条消息
        # if drop_packet(seq, drop_seq=100):
        #     print(f"[CLIENT] attack: drop seq={seq}")
        #     continue

        # # 篡改攻击：修改第 200 条消息
        # packet = modify_payload(packet, target_seq=200)
        #
        # # 记忆断裂攻击：修改第 300 条消息 prev_mem
        # packet = modify_prev_mem(packet, target_seq=300)

        raw = json.dumps(packet, ensure_ascii=False).encode("utf-8")
        sock.sendto(raw, (DEFAULT_HOST, DEFAULT_PORT))

        try:
            data, _ = sock.recvfrom(65535)
            response = json.loads(data.decode("utf-8"))
        except socket.timeout:
            print(f"[CLIENT] timeout at seq={seq}")
            break

        if not response.get("ok"):
            print(f"[CLIENT] server rejected seq={seq}, reason={response.get('reason')}")
            break

        payload_hash = hash_text(payload)
        current_mem = update_memory(
            prev_mem=current_mem,
            session_id=SESSION_ID,
            epoch=EPOCH,
            seq=seq,
            payload_hash=payload_hash,
            sender_id=CLIENT_ID,
        )

        if seq % 100 == 0:
            print(f"[CLIENT] sent seq={seq}")

        time.sleep(0.001)

    print("[CLIENT] Finished")


if __name__ == "__main__":
    main()