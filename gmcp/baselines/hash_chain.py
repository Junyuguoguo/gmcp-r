# -*- coding: utf-8 -*-
# gmcp/baselines/hash_chain.py
#
# Hash Chain 协议实现
# 
# 原理：
# - 每个消息包含前一个消息的哈希值，形成哈希链
# - 发送方：h_i = H(h_{i-1} || payload_i)
# - 接收方：验证 h_i = H(h_{i-1} || payload_i)
# - 恢复时需要重放完整历史链

import hashlib
import time
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass


@dataclass
class HashChainState:
    """Hash Chain 协议状态"""
    session_id: str
    sender_id: str
    epoch: int
    last_seq: int
    last_hash: str
    # 历史链（用于恢复）
    hash_chain: list  # List of (seq, hash, payload_hash)


def hash_func(data: str) -> str:
    """计算SHA-256哈希"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_chain_hash(prev_hash: str, payload: str) -> str:
    """
    计算链哈希
    h_i = H(h_{i-1} || payload_i)
    """
    data = f"{prev_hash}:{payload}"
    return hash_func(data)


def build_data_packet(
    session_id: str,
    sender_id: str,
    epoch: int,
    seq: int,
    prev_hash: str,
    payload: str,
) -> Dict[str, Any]:
    """
    构建数据包
    
    包含：
    - type: "DATA"
    - session_id, sender_id, epoch, seq
    - payload: 实际数据
    - payload_hash: payload的哈希
    - chain_hash: 链哈希 = H(prev_hash || payload)
    - timestamp: 时间戳
    """
    payload_hash = hash_func(payload)
    chain_hash = compute_chain_hash(prev_hash, payload)
    
    packet = {
        "type": "DATA",
        "protocol": "hash_chain",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "seq": seq,
        "payload": payload,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "chain_hash": chain_hash,
        "timestamp": time.time(),
    }
    
    return packet


def verify_packet(
    packet: Dict[str, Any],
    expected_session_id: str,
    expected_epoch: int,
    last_hash: str,
) -> Tuple[bool, str]:
    """
    验证数据包
    
    验证步骤：
    1. 检查session_id和epoch
    2. 验证payload_hash
    3. 验证chain_hash = H(prev_hash || payload)
    4. 验证prev_hash == last_hash
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 检查session_id
    if packet.get("session_id") != expected_session_id:
        return False, "session_id mismatch"
    
    # 2. 检查epoch
    if packet.get("epoch") != expected_epoch:
        return False, "epoch mismatch"
    
    # 3. 验证payload_hash
    payload = packet.get("payload", "")
    expected_payload_hash = hash_func(payload)
    if packet.get("payload_hash") != expected_payload_hash:
        return False, "payload_hash mismatch"
    
    # 4. 验证chain_hash
    prev_hash = packet.get("prev_hash", "")
    expected_chain_hash = compute_chain_hash(prev_hash, payload)
    if packet.get("chain_hash") != expected_chain_hash:
        return False, "chain_hash mismatch"
    
    # 5. 验证prev_hash连续性
    if prev_hash != last_hash:
        return False, "prev_hash mismatch, chain broken"
    
    return True, "ok"


class HashChainVerifier:
    """
    Hash Chain 协议验证器
    
    用于服务端验证数据包
    """
    
    def __init__(self, state: HashChainState):
        self.state = state
    
    def verify_data_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        """
        验证数据包并更新状态
        
        返回：
        - bool: 是否验证通过
        - str: 验证失败原因
        """
        # 验证包类型
        if packet.get("type") != "DATA":
            return False, "invalid packet type"
        
        if packet.get("protocol") != "hash_chain":
            return False, "invalid protocol"
        
        # 验证seq递增
        seq = int(packet.get("seq", 0))
        if seq <= self.state.last_seq:
            return False, "replay or old packet detected"
        
        if seq != self.state.last_seq + 1:
            return False, f"seq gap detected: expected {self.state.last_seq + 1}, got {seq}"
        
        # 验证包内容
        ok, reason = verify_packet(
            packet=packet,
            expected_session_id=self.state.session_id,
            expected_epoch=self.state.epoch,
            last_hash=self.state.last_hash,
        )
        
        if not ok:
            return False, reason
        
        # 更新状态
        self.state.last_seq = seq
        self.state.last_hash = packet.get("chain_hash", "")
        
        # 保存到历史链（用于恢复）
        self.state.hash_chain.append({
            "seq": seq,
            "hash": packet.get("chain_hash", ""),
            "payload_hash": packet.get("payload_hash", ""),
        })
        
        return True, "ok"
    
    def get_state(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            "session_id": self.state.session_id,
            "sender_id": self.state.sender_id,
            "epoch": self.state.epoch,
            "last_seq": self.state.last_seq,
            "last_hash": self.state.last_hash,
            "chain_length": len(self.state.hash_chain),
        }


def create_initial_state(session_id: str, sender_id: str, epoch: int) -> HashChainState:
    """创建初始状态"""
    # 初始哈希
    initial_hash = hash_func(f"init:{session_id}:{epoch}")
    
    return HashChainState(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        last_seq=0,
        last_hash=initial_hash,
        hash_chain=[],
    )


def build_recovery_request(
    session_id: str,
    sender_id: str,
    epoch: int,
    last_seq: int,
    last_hash: str,
    reason: str,
) -> Dict[str, Any]:
    """
    构建恢复请求
    
    Hash Chain协议的恢复需要重放完整历史链
    """
    request = {
        "type": "RECOVERY_REQUEST",
        "protocol": "hash_chain",
        "session_id": session_id,
        "sender_id": sender_id,
        "epoch": epoch,
        "last_seq": last_seq,
        "last_hash": last_hash,
        "reason": reason,
        "timestamp": time.time(),
    }
    
    return request


def build_recovery_response(
    session_id: str,
    epoch: int,
    last_seq: int,
    last_hash: str,
    hash_chain: list,
) -> Dict[str, Any]:
    """
    构建恢复响应
    
    返回完整历史链供客户端重放验证
    """
    response = {
        "type": "RECOVERY_RESPONSE",
        "protocol": "hash_chain",
        "session_id": session_id,
        "epoch": epoch,
        "last_seq": last_seq,
        "last_hash": last_hash,
        "hash_chain": hash_chain,  # 完整历史链
        "timestamp": time.time(),
    }
    
    return response


def recover_from_chain(
    hash_chain: list,
    start_seq: int,
    end_seq: int,
) -> Tuple[bool, str, str]:
    """
    从历史链恢复状态
    
    返回：
    - bool: 是否恢复成功
    - str: 恢复失败原因
    - str: 恢复后的last_hash
    """
    if not hash_chain:
        return False, "empty hash chain", ""
    
    # 找到起始位置
    start_idx = None
    for i, entry in enumerate(hash_chain):
        if entry["seq"] == start_seq:
            start_idx = i
            break
    
    if start_idx is None:
        return False, f"seq {start_seq} not found in chain", ""
    
    # 验证链的连续性
    current_hash = hash_chain[start_idx]["hash"]
    for i in range(start_idx + 1, len(hash_chain)):
        entry = hash_chain[i]
        if entry["seq"] > end_seq:
            break
        
        # 验证链连续性
        expected_hash = compute_chain_hash(current_hash, entry.get("payload", ""))
        if entry["hash"] != expected_hash:
            return False, f"chain broken at seq {entry['seq']}", ""
        
        current_hash = entry["hash"]
    
    return True, "ok", current_hash


def calculate_recovery_overhead(hash_chain: list, target_seq: int) -> int:
    """
    计算恢复开销（字节数）
    
    Hash Chain需要重放完整历史链
    """
    import json
    
    total_bytes = 0
    for entry in hash_chain:
        if entry["seq"] <= target_seq:
            total_bytes += len(json.dumps(entry).encode('utf-8'))
    
    return total_bytes


# =========================
# 测试
# =========================

def demo_hash_chain():
    """演示Hash Chain协议"""
    print("=" * 60)
    print("Hash Chain Protocol Demo")
    print("=" * 60)
    
    # 创建初始状态
    session_id = "demo-session"
    sender_id = "client-001"
    epoch = 1
    
    state = create_initial_state(session_id, sender_id, epoch)
    verifier = HashChainVerifier(state)
    
    print(f"\nInitial state: {verifier.get_state()}")
    
    # 发送10个消息
    print("\n--- Sending 10 messages ---")
    for seq in range(1, 11):
        payload = f"message-{seq}"
        
        # 构建数据包
        packet = build_data_packet(
            session_id=session_id,
            sender_id=sender_id,
            epoch=epoch,
            seq=seq,
            prev_hash=state.last_hash,
            payload=payload,
        )
        
        # 验证数据包
        ok, reason = verifier.verify_data_packet(packet)
        
        if ok:
            print(f"  seq={seq}: ✅ OK (hash={packet['chain_hash'][:16]}...)")
        else:
            print(f"  seq={seq}: ❌ FAILED - {reason}")
    
    print(f"\nFinal state: {verifier.get_state()}")
    
    # 测试恢复
    print("\n--- Testing Recovery ---")
    recovery_overhead = calculate_recovery_overhead(state.hash_chain, 10)
    print(f"Recovery overhead for 10 messages: {recovery_overhead} bytes")
    
    # 测试篡改检测
    print("\n--- Testing Tamper Detection ---")
    tampered_packet = build_data_packet(
        session_id=session_id,
        sender_id=sender_id,
        epoch=epoch,
        seq=11,
        prev_hash=state.last_hash,
        payload="tampered-message",
    )
    tampered_packet["payload"] = "modified-message"  # 篡改payload
    
    ok, reason = verifier.verify_data_packet(tampered_packet)
    print(f"Tampered packet: {'✅ Detected' if not ok else '❌ Missed'} - {reason}")


if __name__ == "__main__":
    demo_hash_chain()
