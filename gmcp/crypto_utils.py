# gmcp/crypto_utils.py

import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Mapping


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(data),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def json_dumps(data: Dict[str, Any]) -> str:
    """
    用固定格式序列化 JSON，保证 HMAC 和哈希计算稳定。
    sort_keys=True 很重要，否则字段顺序变化会导致认证失败。
    """
    return canonical_json(data)


def hash_text(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def random_nonce(size: int = 16) -> str:
    return secrets.token_hex(size)


def with_hmac(
    key: bytes, message: Mapping[str, Any], tag_field: str = "auth_tag"
) -> Dict[str, Any]:
    result = dict(message)
    result.pop(tag_field, None)
    result[tag_field] = hmac.new(
        key, canonical_json(result).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return result


def verify_tagged_hmac(
    key: bytes, message: Mapping[str, Any], tag_field: str = "auth_tag"
) -> bool:
    received = message.get(tag_field)
    if not isinstance(received, str) or not received:
        return False
    unsigned = dict(message)
    unsigned.pop(tag_field, None)
    expected = hmac.new(
        key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, received)


def hmac_sha256_hex(key: bytes, data: Dict[str, Any]) -> str:
    return with_hmac(key, data)["auth_tag"]


def verify_hmac(key: bytes, data: Dict[str, Any], tag: str) -> bool:
    return verify_tagged_hmac(key, {**data, "auth_tag": tag})
