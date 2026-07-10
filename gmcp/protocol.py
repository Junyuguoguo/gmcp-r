# gmcp/protocol.py

from dataclasses import dataclass
from typing import Tuple, Dict, Any

from gmcp.config import DATA_AUTH_KEY
from gmcp.crypto_utils import hash_text, verify_tagged_hmac
from gmcp.memory import update_memory


DATA_REQUIRED_FIELDS = {
    "type",
    "protocol",
    "session_id",
    "sender_id",
    "epoch",
    "seq",
    "prev_mem",
    "payload",
    "payload_hash",
    "timestamp",
    "auth_tag",
}
DATA_OPTIONAL_FIELDS = {"checkpoint_interval"}


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

        packet_fields = set(packet)
        missing_fields = DATA_REQUIRED_FIELDS - packet_fields
        if missing_fields:
            return False, f"missing DATA fields: {', '.join(sorted(missing_fields))}"

        unknown_fields = packet_fields - DATA_REQUIRED_FIELDS - DATA_OPTIONAL_FIELDS
        if unknown_fields:
            return False, f"unknown DATA fields: {', '.join(sorted(unknown_fields))}"

        if packet["type"] != "DATA":
            return False, "invalid packet type"

        if packet["protocol"] != "gmcp":
            return False, "protocol mismatch"

        if not verify_tagged_hmac(DATA_AUTH_KEY, packet):
            return False, "auth_tag verification failed"

        if packet["session_id"] != self.state.session_id:
            return False, "session_id mismatch"

        if packet["sender_id"] != self.state.sender_id:
            return False, "sender_id mismatch"

        if packet["epoch"] != self.state.epoch:
            return False, "epoch mismatch"

        seq = packet["seq"]
        if type(seq) is not int:
            return False, "seq must be an integer"

        if seq <= self.state.last_seq:
            return False, "replay or old packet detected"

        if seq != self.state.last_seq + 1:
            return False, f"seq gap detected: expected {self.state.last_seq + 1}, got {seq}"

        payload = packet["payload"]
        payload_hash = packet["payload_hash"]

        if hash_text(payload) != payload_hash:
            return False, "payload_hash mismatch"

        prev_mem = packet["prev_mem"]
        if prev_mem != self.state.last_mem:
            return False, "prev_mem mismatch, history is not continuous"

        new_mem = update_memory(
            prev_mem=self.state.last_mem,
            session_id=self.state.session_id,
            epoch=self.state.epoch,
            seq=seq,
            payload_hash=payload_hash,
            sender_id=packet["sender_id"],
        )

        self.state.last_seq = seq
        self.state.last_mem = new_mem

        return True, "ok"
