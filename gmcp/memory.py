# gmcp/memory.py

from gmcp.crypto_utils import hash_text


def initial_memory(session_id: str, sender_id: str, epoch: int, mem_seed: str) -> str:
    """
    生成初始记忆 M0。
    """
    text = f"GMCP_INIT|{session_id}|{sender_id}|{epoch}|{mem_seed}"
    return hash_text(text)


def update_memory(
    prev_mem: str,
    session_id: str,
    epoch: int,
    seq: int,
    payload_hash: str,
    sender_id: str,
) -> str:
    """
    M_i = H(M_{i-1} || session_id || epoch || seq_i || payload_hash_i || sender_id)
    """
    text = f"{prev_mem}|{session_id}|{epoch}|{seq}|{payload_hash}|{sender_id}"
    return hash_text(text)