# -*- coding: utf-8 -*-
# run_hash_chain_adaptive_attack.py
#
# 自适应攻击脚本：
# - 对普通 Hash Chain：篡改 payload 并重算公共哈希 → 应被接受（基线弱点）
# - 对 Authenticated Hash Chain：同样篡改但不重算 HMAC → 应被拒绝
# - 输出 CSV：hash_chain_adaptive_attack.csv

import csv
import os
import sys
import time
import socket
import json
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gmcp.config import SERVER_TARGET_HOST, CLIENT_ID, EPOCH
from gmcp.baselines.hash_chain import (
    create_initial_state as hc_init,
    build_data_packet as hc_build,
    hash_func as hc_hash_func,
    compute_chain_hash,
)
from gmcp.baselines.authenticated_hash_chain import (
    create_initial_state as ahc_init,
    build_data_packet as ahc_build,
)

BASELINE_PORT = 9001
SOCKET_TIMEOUT = 10.0


def ensure_output_dir():
    os.makedirs("results/submission_revision", exist_ok=True)


def open_tcp(port=BASELINE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((SERVER_TARGET_HOST, port))
    file_obj = sock.makefile("r", encoding="utf-8", newline="\n")
    return sock, file_obj


def close_tcp(sock, file_obj):
    try:
        if file_obj:
            file_obj.close()
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


def send_json_line(sock, packet):
    raw = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    sock.sendall(raw)


def recv_json_line(file_obj):
    line = file_obj.readline()
    if not line:
        raise ConnectionError("server closed")
    return json.loads(line)


def run_adaptive_attack(protocol: str, session_id: str) -> Dict[str, Any]:
    """
    对指定协议执行自适应攻击：
    1. 正常发送 3 条消息建立链
    2. 第 4 条：篡改 payload 并重算公共哈希（hash_chain / payload_hash / chain_hash）
    3. 对 auth_hash_chain：不重算 auth_tag
    4. 记录服务端是否接受
    """
    if protocol == "hash_chain":
        state = hc_init(session_id, CLIENT_ID, EPOCH)
        build_fn = hc_build
    elif protocol == "authenticated_hash_chain":
        state = ahc_init(session_id, CLIENT_ID, EPOCH)
        build_fn = ahc_build
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    sock, file_obj = open_tcp()

    accepted_packets = 0
    attack_accepted = False
    attack_result = ""

    try:
        # 正常发送 3 条
        for seq in range(1, 4):
            pkt = build_fn(session_id, CLIENT_ID, EPOCH, seq, state.last_hash, f"normal-{seq}")
            send_json_line(sock, pkt)
            resp = recv_json_line(file_obj)
            if resp.get("ok"):
                state.last_seq = seq
                state.last_hash = pkt.get("chain_hash", state.last_hash)
                accepted_packets += 1

        # 第 4 条：构造正常包，然后篡改 payload 并重算公共哈希
        attack_seq = 4
        tampered_payload = "TAMPERED-DATA"

        if protocol == "hash_chain":
            # 构造正常包
            pkt = hc_build(session_id, CLIENT_ID, EPOCH, attack_seq, state.last_hash, "original-msg")
        else:
            pkt = ahc_build(session_id, CLIENT_ID, EPOCH, attack_seq, state.last_hash, "original-msg")

        # 篡改 payload 和重算公共哈希
        pkt["payload"] = tampered_payload
        pkt["payload_hash"] = hc_hash_func(tampered_payload)
        pkt["chain_hash"] = compute_chain_hash(pkt["prev_hash"], tampered_payload)
        # 不重算 auth_tag（如果是 authenticated_hash_chain）

        # 标记攻击属性
        attack_property = "history_pointer"
        attack_applicable = True  # hash_chain 有 prev_hash

        send_json_line(sock, pkt)
        resp = recv_json_line(file_obj)

        if resp.get("ok"):
            attack_accepted = True
            attack_result = "accepted (attack succeeded)"
        else:
            attack_result = f"rejected: {resp.get('reason', 'unknown')}"

        return {
            "protocol": protocol,
            "session_id": session_id,
            "attack_type": "adaptive_payload_modify",
            "attack_property": attack_property,
            "attack_applicable": attack_applicable,
            "payload_modified": True,
            "public_hashes_recomputed": True,
            "auth_tag_recomputed": False,
            "attack_accepted": attack_accepted,
            "attack_result": attack_result,
            "accepted_before_attack": accepted_packets,
        }

    finally:
        close_tcp(sock, file_obj)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Hash Chain Adaptive Attack")
    parser.add_argument("--spawn-server", action="store_true",
                        help="Spawn baseline server before running")
    args = parser.parse_args()

    ensure_output_dir()

    output_path = "results/submission_revision/hash_chain_adaptive_attack.csv"
    fieldnames = [
        "protocol", "session_id", "attack_type", "attack_property",
        "attack_applicable", "payload_modified", "public_hashes_recomputed",
        "auth_tag_recomputed", "attack_accepted", "attack_result",
        "accepted_before_attack",
    ]

    server_proc = None
    if args.spawn_server:
        import subprocess
        server_proc = subprocess.Popen(
            [sys.executable, "real_baseline_server.py"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        time.sleep(2)  # 等待服务器启动
        print("[INFO] Baseline server spawned")

    results = []
    try:
        for protocol in ["hash_chain", "authenticated_hash_chain"]:
            ts = int(time.time() * 1000000)
            session_id = f"adaptive-attack-{protocol}-{ts}"
            print(f"\n--- Adaptive attack on {protocol} ---")
            result = run_adaptive_attack(protocol, session_id)
            results.append(result)
            status = "✅ BLOCKED" if not result["attack_accepted"] else "❌ ACCEPTED"
            print(f"  {status}: {result['attack_result']}")

        # 写入 CSV
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)

        print(f"\n[COMPLETE] Results saved to {output_path}")

        # 验证预期结果
        hc_result = next(r for r in results if r["protocol"] == "hash_chain")
        ahc_result = next(r for r in results if r["protocol"] == "authenticated_hash_chain")

        print("\n" + "=" * 60)
        print("VERIFICATION:")
        print(f"  Plain Hash Chain attack accepted: {hc_result['attack_accepted']} (expected: True)")
        print(f"  Auth Hash Chain attack accepted:  {ahc_result['attack_accepted']} (expected: False)")

        if hc_result["attack_accepted"] and not ahc_result["attack_accepted"]:
            print("\n✅ ALL EXPECTATIONS MET: Authenticated Hash Chain blocks adaptive attack")
            return 0
        else:
            print("\n❌ UNEXPECTED RESULTS")
            return 1

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait(timeout=5)
            print("[INFO] Baseline server terminated")


if __name__ == "__main__":
    sys.exit(main())
