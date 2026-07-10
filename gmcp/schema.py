# -*- coding: utf-8 -*-
# gmcp/schema.py
#
# 数据包字段验证模块
# 验证 DATA、RECOVERY_REQUEST、SNACK、IR_REFRESH、MEMORY_TICKET 等数据包的字段

import time
from typing import Dict, Any, Tuple, List, Set

from gmcp.config import TIMESTAMP_WINDOW_SECONDS


# =========================
# 字段定义
# =========================

# DATA 包必需字段
DATA_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "sender_id",
    "epoch",
    "seq",
    "payload",
    "payload_hash",
    "prev_mem",
    "auth_tag",
}

# DATA 包可选字段
DATA_OPTIONAL_FIELDS = {
    "timestamp",
}

# RECOVERY_REQUEST 包必需字段
RECOVERY_REQUEST_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "client_id",
    "epoch",
    "client_last_seq",
    "client_last_mem",
    "reason",
    "timestamp",
    "auth_tag",
}

# RECOVERY_REQUEST 包可选字段
RECOVERY_REQUEST_OPTIONAL_FIELDS = {
    "memory_ticket",
}

# SNACK 包必需字段（选择性确认）
SNACK_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "epoch",
    "missing_seqs",
    "timestamp",
    "auth_tag",
}

# IR_REFRESH 包必需字段（即时刷新）
IR_REFRESH_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "epoch",
    "last_seq",
    "last_mem",
    "timestamp",
    "auth_tag",
}

# MEMORY_TICKET 包必需字段
MEMORY_TICKET_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "client_id",
    "epoch",
    "last_seq",
    "last_mem",
    "checkpoint_seq",
    "checkpoint_mem",
    "expire_time",
    "ticket_nonce",
    "key_version",
    "server_auth_tag",
}

# CHECKPOINT 包必需字段
CHECKPOINT_REQUIRED_FIELDS = {
    "type",
    "session_id",
    "epoch",
    "seq",
    "memory",
    "timestamp",
    "signature",
}


# =========================
# 类型验证规则
# =========================

# 字段类型验证规则
FIELD_TYPE_RULES = {
    # DATA 包
    "type": str,
    "session_id": str,
    "sender_id": str,
    "epoch": int,
    "seq": int,
    "payload": str,
    "payload_hash": str,
    "prev_mem": str,
    "auth_tag": str,
    "timestamp": (int, float),
    
    # RECOVERY_REQUEST 包
    "client_id": str,
    "client_last_seq": int,
    "client_last_mem": str,
    "reason": str,
    
    # SNACK 包
    "missing_seqs": list,
    
    # IR_REFRESH 包
    "last_seq": int,
    "last_mem": str,
    
    # MEMORY_TICKET 包
    "checkpoint_seq": int,
    "checkpoint_mem": str,
    "expire_time": (int, float),
    "ticket_nonce": str,
    "key_version": int,
    "server_auth_tag": str,
    
    # CHECKPOINT 包
    "memory": str,
    "signature": str,
}


# =========================
# 验证函数
# =========================

def validate_field_type(value: Any, expected_type: type) -> bool:
    """验证字段类型"""
    if isinstance(expected_type, tuple):
        return isinstance(value, expected_type)
    return isinstance(value, expected_type)


def validate_required_fields(packet: Dict[str, Any], required_fields: Set[str]) -> Tuple[bool, str]:
    """验证必需字段是否存在"""
    missing_fields = required_fields - set(packet.keys())
    if missing_fields:
        return False, f"missing required fields: {', '.join(sorted(missing_fields))}"
    return True, "ok"


def validate_field_types(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """验证字段类型"""
    for field_name, expected_type in FIELD_TYPE_RULES.items():
        if field_name in packet:
            value = packet[field_name]
            if not validate_field_type(value, expected_type):
                return False, f"invalid type for field '{field_name}': expected {expected_type}, got {type(value)}"
    return True, "ok"


def validate_timestamp(timestamp: float) -> Tuple[bool, str]:
    """验证时间戳是否在合理范围内"""
    current_time = time.time()
    time_diff = abs(current_time - timestamp)
    
    if time_diff > TIMESTAMP_WINDOW_SECONDS:
        return False, f"timestamp out of window: {time_diff:.1f}s > {TIMESTAMP_WINDOW_SECONDS}s"
    
    return True, "ok"


def validate_seq(seq: int) -> Tuple[bool, str]:
    """验证序列号是否合法"""
    if not isinstance(seq, int):
        return False, "seq must be an integer"
    
    if seq < 0:
        return False, "seq must be non-negative"
    
    return True, "ok"


def validate_epoch(epoch: int) -> Tuple[bool, str]:
    """验证epoch是否合法"""
    if not isinstance(epoch, int):
        return False, "epoch must be an integer"
    
    if epoch < 0:
        return False, "epoch must be non-negative"
    
    return True, "ok"


# =========================
# 数据包验证函数
# =========================

def validate_data_packet(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 DATA 包
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(packet, DATA_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(packet)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if packet.get("type") != "DATA":
        return False, "invalid packet type, expected 'DATA'"
    
    # 4. 验证 seq
    seq = safe_get_int(packet, "seq")
    ok, reason = validate_seq(seq)
    if not ok:
        return False, f"invalid seq: {reason}"
    
    # 5. 验证 epoch
    epoch = safe_get_int(packet, "epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 6. 验证 timestamp（如果存在）
    timestamp = packet.get("timestamp")
    if timestamp is not None:
        ok, reason = validate_timestamp(timestamp)
        if not ok:
            return False, f"invalid timestamp: {reason}"
    
    return True, "ok"


def validate_recovery_request(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 RECOVERY_REQUEST 包
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(packet, RECOVERY_REQUEST_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(packet)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if packet.get("type") != "RECOVERY_REQUEST":
        return False, "invalid packet type, expected 'RECOVERY_REQUEST'"
    
    # 4. 验证 client_last_seq
    client_last_seq = safe_get_int(packet, "client_last_seq")
    ok, reason = validate_seq(client_last_seq)
    if not ok:
        return False, f"invalid client_last_seq: {reason}"
    
    # 5. 验证 epoch
    epoch = safe_get_int(packet, "epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 6. 验证 timestamp
    timestamp = packet.get("timestamp")
    if timestamp is not None:
        ok, reason = validate_timestamp(timestamp)
        if not ok:
            return False, f"invalid timestamp: {reason}"
    
    return True, "ok"


def validate_snack(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 SNACK 包
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(packet, SNACK_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(packet)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if packet.get("type") != "SNACK":
        return False, "invalid packet type, expected 'SNACK'"
    
    # 4. 验证 missing_seqs
    missing_seqs = packet.get("missing_seqs")
    if not isinstance(missing_seqs, list):
        return False, "missing_seqs must be a list"
    
    for seq in missing_seqs:
        if not isinstance(seq, int) or seq < 0:
            return False, f"invalid seq in missing_seqs: {seq}"
    
    # 5. 验证 epoch
    epoch = safe_get_int(packet, "epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 6. 验证 timestamp
    timestamp = packet.get("timestamp")
    if timestamp is not None:
        ok, reason = validate_timestamp(timestamp)
        if not ok:
            return False, f"invalid timestamp: {reason}"
    
    return True, "ok"


def validate_ir_refresh(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 IR_REFRESH 包
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(packet, IR_REFRESH_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(packet)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if packet.get("type") != "IR_REFRESH":
        return False, "invalid packet type, expected 'IR_REFRESH'"
    
    # 4. 验证 last_seq
    last_seq = safe_get_int(packet, "last_seq")
    ok, reason = validate_seq(last_seq)
    if not ok:
        return False, f"invalid last_seq: {reason}"
    
    # 5. 验证 epoch
    epoch = safe_get_int(packet, "epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 6. 验证 timestamp
    timestamp = packet.get("timestamp")
    if timestamp is not None:
        ok, reason = validate_timestamp(timestamp)
        if not ok:
            return False, f"invalid timestamp: {reason}"
    
    return True, "ok"


def validate_memory_ticket(ticket: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 MEMORY_TICKET
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(ticket, MEMORY_TICKET_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(ticket)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if ticket.get("type") != "MEMORY_TICKET":
        return False, "invalid ticket type, expected 'MEMORY_TICKET'"
    
    # 4. 验证 last_seq
    last_seq = safe_get_int(ticket, "last_seq")
    ok, reason = validate_seq(last_seq)
    if not ok:
        return False, f"invalid last_seq: {reason}"
    
    # 5. 验证 checkpoint_seq
    checkpoint_seq = safe_get_int(ticket, "checkpoint_seq")
    ok, reason = validate_seq(checkpoint_seq)
    if not ok:
        return False, f"invalid checkpoint_seq: {reason}"
    
    # 6. 验证 checkpoint_seq <= last_seq
    if checkpoint_seq > last_seq:
        return False, "checkpoint_seq exceeds last_seq"
    
    # 7. 验证 epoch
    epoch = safe_get_int(ticket, "epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 8. 验证 expire_time
    expire_time = safe_get_float(ticket, "expire_time")
    if expire_time == 0.0 and "expire_time" not in ticket:
        return False, "expire_time is required"
    
    return True, "ok"


def validate_checkpoint(checkpoint: Dict[str, Any]) -> Tuple[bool, str]:
    """
    验证 CHECKPOINT
    
    返回：
    - bool: 是否验证通过
    - str: 验证失败原因
    """
    # 1. 验证必需字段
    ok, reason = validate_required_fields(checkpoint, CHECKPOINT_REQUIRED_FIELDS)
    if not ok:
        return False, reason
    
    # 2. 验证字段类型
    ok, reason = validate_field_types(checkpoint)
    if not ok:
        return False, reason
    
    # 3. 验证 type 字段
    if checkpoint.get("type") != "CHECKPOINT":
        return False, "invalid checkpoint type, expected 'CHECKPOINT'"
    
    # 4. 验证 seq
    seq = checkpoint.get("seq")
    ok, reason = validate_seq(seq)
    if not ok:
        return False, f"invalid seq: {reason}"
    
    # 5. 验证 epoch
    epoch = checkpoint.get("epoch")
    ok, reason = validate_epoch(epoch)
    if not ok:
        return False, f"invalid epoch: {reason}"
    
    # 6. 验证 timestamp
    timestamp = checkpoint.get("timestamp")
    if timestamp is not None:
        ok, reason = validate_timestamp(timestamp)
        if not ok:
            return False, f"invalid timestamp: {reason}"
    
    return True, "ok"


# =========================
# 通用验证函数
# =========================

def validate_packet(packet: Dict[str, Any]) -> Tuple[bool, str]:
    """
    通用数据包验证函数
    
    根据 packet type 自动选择验证函数
    """
    packet_type = packet.get("type")
    
    if packet_type == "DATA":
        return validate_data_packet(packet)
    elif packet_type == "RECOVERY_REQUEST":
        return validate_recovery_request(packet)
    elif packet_type == "SNACK":
        return validate_snack(packet)
    elif packet_type == "IR_REFRESH":
        return validate_ir_refresh(packet)
    elif packet_type == "MEMORY_TICKET":
        return validate_memory_ticket(packet)
    elif packet_type == "CHECKPOINT":
        return validate_checkpoint(packet)
    elif packet_type == "PING":
        # PING 包只需要 type 字段
        return True, "ok"
    else:
        return False, f"unknown packet type: {packet_type}"


def safe_get_int(packet: Dict[str, Any], key: str, default: int = 0) -> int:
    """
    安全地获取整数字段
    
    捕获异常，防止恶意包导致崩溃
    """
    try:
        value = packet.get(key, default)
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_get_float(packet: Dict[str, Any], key: str, default: float = 0.0) -> float:
    """
    安全地获取浮点数字段
    
    捕获异常，防止恶意包导致崩溃
    """
    try:
        value = packet.get(key, default)
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_get_str(packet: Dict[str, Any], key: str, default: str = "") -> str:
    """
    安全地获取字符串字段
    
    捕获异常，防止恶意包导致崩溃
    """
    try:
        value = packet.get(key, default)
        if value is None:
            return default
        return str(value)
    except (TypeError, ValueError):
        return default


# =========================
# 测试
# =========================

def demo_validation():
    """演示验证功能"""
    print("=" * 60)
    print("Schema Validation Demo")
    print("=" * 60)
    
    # 测试 DATA 包
    valid_data_packet = {
        "type": "DATA",
        "session_id": "session-001",
        "sender_id": "client-001",
        "epoch": 1,
        "seq": 1,
        "payload": "hello",
        "payload_hash": "abc123",
        "prev_mem": "mem000",
        "auth_tag": "tag123",
        "timestamp": time.time(),
    }
    
    print("\n1. Valid DATA packet:")
    ok, reason = validate_data_packet(valid_data_packet)
    print(f"   Result: {'✅ PASS' if ok else '❌ FAIL'} - {reason}")
    
    # 测试缺少字段的 DATA 包
    invalid_data_packet = {
        "type": "DATA",
        "session_id": "session-001",
        # 缺少其他字段
    }
    
    print("\n2. Invalid DATA packet (missing fields):")
    ok, reason = validate_data_packet(invalid_data_packet)
    print(f"   Result: {'✅ PASS' if ok else '❌ FAIL'} - {reason}")
    
    # 测试 RECOVERY_REQUEST 包
    valid_recovery_request = {
        "type": "RECOVERY_REQUEST",
        "session_id": "session-001",
        "client_id": "client-001",
        "epoch": 1,
        "client_last_seq": 100,
        "client_last_mem": "mem100",
        "reason": "disconnect",
        "timestamp": time.time(),
        "auth_tag": "tag123",
    }
    
    print("\n3. Valid RECOVERY_REQUEST packet:")
    ok, reason = validate_recovery_request(valid_recovery_request)
    print(f"   Result: {'✅ PASS' if ok else '❌ FAIL'} - {reason}")
    
    # 测试安全获取字段
    print("\n4. Safe field extraction:")
    packet = {"seq": "100", "epoch": "1", "invalid": "abc"}
    print(f"   seq: {safe_get_int(packet, 'seq')}")
    print(f"   epoch: {safe_get_int(packet, 'epoch')}")
    print(f"   invalid (default 0): {safe_get_int(packet, 'invalid')}")
    print(f"   missing (default -1): {safe_get_int(packet, 'missing', -1)}")


if __name__ == "__main__":
    demo_validation()
