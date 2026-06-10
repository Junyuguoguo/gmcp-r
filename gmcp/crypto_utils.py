# gmcp/crypto_utils.py

import hashlib
import hmac
import json
import secrets
from typing import Any, Dict


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_dumps(data: Dict[str, Any]) -> str:
    """
    用固定格式序列化 JSON，保证 HMAC 和哈希计算稳定。
    sort_keys=True 很重要，否则字段顺序变化会导致认证失败。
    """
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def hash_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def random_nonce(size: int = 16) -> str:
    return secrets.token_hex(size)


def hmac_sha256_hex(key: bytes, data: Dict[str, Any]) -> str:
    raw = json_dumps(data).encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, data: Dict[str, Any], tag: str) -> bool:
    expected = hmac_sha256_hex(key, data)
    return hmac.compare_digest(expected, tag)