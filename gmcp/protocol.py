# gmcp/protocol.py

from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any

from gmcp.config import SHARED_KEY
from gmcp.crypto_utils import verify_hmac, hash_text
from gmcp.memory import update_memory
from gmcp.packet import packet_without_auth


@dataclass
class GMCPState:
    session_id: str
    sender_id: str
    epoch: int
    last_seq: int
    last_mem: str


class GMCPVerifier:
    """
    服务端验证器。
    负责验证 DATA 包是否合法，并更新服务端记忆状态。
    """

    def __init__(self, state: GMCPState):
        self.state = state

    def verify_data_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        """
        返回:
            bool: 是否验证通过
            str: 原因
        """

        if packet.get("type") != "DATA":
            return False, "invalid packet type"

        recv_auth_tag = packet.get("auth_tag")
        if not recv_auth_tag:
            return False, "missing auth_tag"

        data_for_auth = packet_without_auth(packet)
        if not verify_hmac(SHARED_KEY, data_for_auth, recv_auth_tag):
            return False, "auth_tag verification failed"

        if packet.get("session_id") != self.state.session_id:
            return False, "session_id mismatch"

        if packet.get("epoch") != self.state.epoch:
            return False, "epoch mismatch"

        seq = int(packet.get("seq"))

        if seq <= self.state.last_seq:
            return False, "replay or old packet detected"

        if seq != self.state.last_seq + 1:
            return False, f"seq gap detected: expected {self.state.last_seq + 1}, got {seq}"

        payload = packet.get("payload")
        payload_hash = packet.get("payload_hash")

        if hash_text(payload) != payload_hash:
            return False, "payload_hash mismatch"

        prev_mem = packet.get("prev_mem")
        if prev_mem != self.state.last_mem:
            return False, "prev_mem mismatch, history is not continuous"

        new_mem = update_memory(
            prev_mem=self.state.last_mem,
            session_id=self.state.session_id,
            epoch=self.state.epoch,
            seq=seq,
            payload_hash=payload_hash,
            sender_id=packet.get("sender_id"),
        )

        self.state.last_seq = seq
        self.state.last_mem = new_mem

        return True, "ok"