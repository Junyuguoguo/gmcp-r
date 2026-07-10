# -*- coding: utf-8 -*-
# tests/test_authenticated_hash_chain.py
#
# Task 5 验证：Authenticated Hash Chain 公平 baseline
# - 普通 Hash Chain 接受 payload 篡改（只要重算公共哈希）
# - Authenticated Hash Chain 拒绝无有效 HMAC 的篡改
# - Seq+MAC / Ticket Only 的 history-pointer 适应性攻击返回 N/A

import unittest

from gmcp.baselines.hash_chain import (
    create_initial_state as hc_init,
    build_data_packet as hc_build,
    HashChainVerifier,
)
from gmcp.baselines.authenticated_hash_chain import (
    create_initial_state as ahc_init,
    build_data_packet as ahc_build,
    AuthHashChainVerifier,
)


class TestPlainHashChainAcceptsAdaptiveAttack(unittest.TestCase):
    """普通 Hash Chain：payload 被篡改、公共哈希被重算后应被接受。"""

    def test_modify_payload_and_recompute_hashes(self):
        state = hc_init("s", "c", 1)
        verifier = HashChainVerifier(state)

        # 正常发一条
        pkt = hc_build("s", "c", 1, 1, state.last_hash, "original")
        ok, _ = verifier.verify_data_packet(pkt)
        self.assertTrue(ok)

        # 构造 seq=2 的正常包，然后篡改 payload 并重算所有公共哈希
        tampered = hc_build("s", "c", 1, 2, state.last_hash, "original")
        tampered["payload"] = "tampered-data"
        tampered["payload_hash"] = __import__("gmcp.baselines.hash_chain", fromlist=["hash_func"]).hash_func("tampered-data")
        from gmcp.baselines.hash_chain import compute_chain_hash
        tampered["chain_hash"] = compute_chain_hash(tampered["prev_hash"], "tampered-data")

        ok, reason = verifier.verify_data_packet(tampered)
        self.assertTrue(ok, f"Plain hash chain should accept recomputed tampered packet, got: {reason}")


class TestAuthenticatedHashChainRejectsAdaptiveAttack(unittest.TestCase):
    """Authenticated Hash Chain：无有效 HMAC 的篡改必须被拒绝。"""

    def test_modify_payload_without_new_hmac_is_rejected(self):
        state = ahc_init("s", "c", 1)
        verifier = AuthHashChainVerifier(state)

        # 正常发一条
        pkt = ahc_build("s", "c", 1, 1, state.last_hash, "original")
        ok, _ = verifier.verify_data_packet(pkt)
        self.assertTrue(ok)

        # 构造 seq=2 的正常包，然后篡改 payload 和重算公共哈希，但不重算 auth_tag
        tampered = ahc_build("s", "c", 1, 2, state.last_hash, "original")
        tampered["payload"] = "tampered-data"
        from gmcp.baselines.hash_chain import hash_func, compute_chain_hash
        tampered["payload_hash"] = hash_func("tampered-data")
        tampered["chain_hash"] = compute_chain_hash(tampered["prev_hash"], "tampered-data")
        # auth_tag 保持原值 → HMAC 校验失败

        ok, reason = verifier.verify_data_packet(tampered)
        self.assertFalse(ok, "Authenticated hash chain should reject payload mutation without valid HMAC")
        self.assertIn("auth_tag", reason)

    def test_replay_old_packet_is_rejected(self):
        state = ahc_init("s", "c", 1)
        verifier = AuthHashChainVerifier(state)

        pkt1 = ahc_build("s", "c", 1, 1, state.last_hash, "msg1")
        ok, _ = verifier.verify_data_packet(pkt1)
        self.assertTrue(ok)

        # 重放 pkt1
        ok, reason = verifier.verify_data_packet(pkt1)
        self.assertFalse(ok)
        self.assertIn("replay", reason)


class TestHistoryPointerAttackApplicability(unittest.TestCase):
    """Seq+MAC / Ticket Only 的 history-pointer 适应性攻击不适用（N/A）。"""

    def test_seq_mac_no_history_pointer(self):
        """Seq+MAC 没有 prev_mem / prev_hash 字段，history-pointer 攻击不适用。"""
        from gmcp.baselines.seq_mac import build_data_packet, SeqMACVerifier, create_initial_state
        state = create_initial_state("s", "c", 1)
        pkt = build_data_packet("s", "c", 1, 1, "hello")
        # 尝试 history_pointer 攻击：不存在 prev_mem 或 prev_hash
        self.assertNotIn("prev_mem", pkt)
        self.assertNotIn("prev_hash", pkt)
        # 攻击不适用
        attack_applicable = "prev_mem" in pkt or "prev_hash" in pkt
        self.assertFalse(attack_applicable)

    def test_ticket_only_no_history_pointer(self):
        """Ticket Only 没有 prev_mem / prev_hash 字段，history-pointer 攻击不适用。"""
        from gmcp.baselines.ticket_only import build_data_packet, create_initial_state
        state = create_initial_state("s", "c", 1)
        pkt = build_data_packet("s", "c", 1, 1, "hello", state.ticket)
        self.assertNotIn("prev_mem", pkt)
        self.assertNotIn("prev_hash", pkt)
        attack_applicable = "prev_mem" in pkt or "prev_hash" in pkt
        self.assertFalse(attack_applicable)

    def test_auth_hash_chain_has_prev_hash(self):
        """Authenticated Hash Chain 有 prev_hash 字段，history-pointer 攻击适用。"""
        state = ahc_init("s", "c", 1)
        pkt = ahc_build("s", "c", 1, 1, state.last_hash, "hello")
        self.assertIn("prev_hash", pkt)
        attack_applicable = "prev_hash" in pkt
        self.assertTrue(attack_applicable)


if __name__ == "__main__":
    unittest.main()
