# gmcp/attack.py

from typing import Dict, Any


def drop_packet(seq: int, drop_seq: int) -> bool:
    """
    返回 True 表示这个包要被丢弃。
    """
    return seq == drop_seq


def modify_payload(packet: Dict[str, Any], target_seq: int) -> Dict[str, Any]:
    """
    修改 payload，但不重新计算 auth_tag，用于模拟篡改攻击。
    """
    if packet.get("seq") == target_seq:
        packet = dict(packet)
        packet["payload"] = "attacked-payload"
    return packet


def modify_prev_mem(packet: Dict[str, Any], target_seq: int) -> Dict[str, Any]:
    """
    修改 prev_mem，用于模拟历史状态断裂。
    """
    if packet.get("seq") == target_seq:
        packet = dict(packet)
        packet["prev_mem"] = "fake-memory"
    return packet


def replay_packet(saved_packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    重放旧包。
    """
    return dict(saved_packet)