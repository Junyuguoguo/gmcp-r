# -*- coding: utf-8 -*-
# tests/test_recovery_security.py
#
# Tests for: per-session locking, atomic nonces, checkpoint signatures,
# recovery request/response authentication.

import threading
import time
import unittest

from gmcp.session_registry import SessionContext, SessionRegistry
from gmcp.ticket import TicketNonceStore
from gmcp.checkpoint_manager import sign_checkpoint_fields, verify_checkpoint_fields
from gmcp.checkpoint import build_checkpoint, verify_checkpoint
from gmcp.config import DATA_AUTH_KEY, CHECKPOINT_AUTH_KEY
from gmcp.memory import initial_memory
from gmcp.recovery_protocol import (
    build_recovery_request,
    build_recovery_response,
    verify_recovery_response,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(session_id: str, checkpoint_interval: int) -> SessionContext:
    """Minimal factory for testing — no real protocol state needed."""
    return SessionContext(
        session_id=session_id,
        state=None,
        verifier=None,
        checkpoint_manager=None,
        stats={"total": 0, "accepted": 0, "rejected": 0},
    )


# ---------------------------------------------------------------------------
# Task 2 tests: recovery request/response
# ---------------------------------------------------------------------------

class RecoveryResponseTests(unittest.TestCase):
    def make_pair(self):
        request = build_recovery_request(
            "s", "client-001", 1, 100, "m100", "disconnect", {"opaque": "ticket"}
        )
        response = build_recovery_response(
            True, "ok", "s", 1, request["recovery_nonce"],
            {"server_last_seq": 149, "server_last_mem": "m149",
             "checkpoint_seq": 100, "checkpoint_mem": "m100",
             "memory_ticket": {"opaque": "replacement"}},
        )
        return request, response

    def test_tamper_missing_tag_and_old_nonce_are_rejected(self):
        request, response = self.make_pair()
        self.assertEqual(verify_recovery_response(response, "s", 1, request["recovery_nonce"]), (True, "ok"))
        response["server_last_seq"] = 100
        self.assertFalse(verify_recovery_response(response, "s", 1, request["recovery_nonce"])[0])
        request, response = self.make_pair()
        response.pop("recovery_auth_tag")
        self.assertFalse(verify_recovery_response(response, "s", 1, request["recovery_nonce"])[0])
        _, response = self.make_pair()
        self.assertEqual(verify_recovery_response(response, "s", 1, "old"), (False, "recovery_nonce mismatch"))


# ---------------------------------------------------------------------------
# Task 3 tests: atomic nonces
# ---------------------------------------------------------------------------

class TicketNonceStoreTests(unittest.TestCase):
    def test_basic_consume_and_replay(self):
        store = TicketNonceStore()
        self.assertTrue(store.is_unused("nonce-1"))
        self.assertTrue(store.consume("nonce-1"))
        self.assertFalse(store.is_unused("nonce-1"))
        self.assertFalse(store.consume("nonce-1"))

    def test_empty_nonce_rejected(self):
        store = TicketNonceStore()
        self.assertFalse(store.is_unused(""))
        self.assertFalse(store.consume(""))
        self.assertFalse(store.consume(None))

    def test_clear_resets_nonces(self):
        store = TicketNonceStore()
        store.consume("n1")
        self.assertFalse(store.is_unused("n1"))
        store.clear()
        self.assertTrue(store.is_unused("n1"))

    def test_atomicity_under_contention(self):
        """Two threads race to consume the same nonce; exactly one must succeed."""
        store = TicketNonceStore()
        barrier = threading.Barrier(2, timeout=5)
        results = []

        def worker():
            barrier.wait()
            results.append(store.consume("race-nonce"))

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        self.assertEqual(sorted(results), [False, True])


# ---------------------------------------------------------------------------
# Task 3 tests: unified checkpoint signatures
# ---------------------------------------------------------------------------

class CheckpointSignatureTests(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self):
        fields = sign_checkpoint_fields("s", 1, 100, "mem100")
        self.assertIn("signature", fields)
        ok, reason = verify_checkpoint_fields(fields)
        self.assertTrue(ok, reason)

    def test_mutation_detected(self):
        fields = sign_checkpoint_fields("s", 1, 100, "mem100")
        fields["memory"] = "tampered"
        ok, reason = verify_checkpoint_fields(fields)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_checkpoint_uses_checkpoint_key_not_data_key(self):
        """Changing DATA_AUTH_KEY must not affect checkpoint verification."""
        fields = sign_checkpoint_fields("s", 1, 100, "mem100")
        ok, _ = verify_checkpoint_fields(fields)
        self.assertTrue(ok)
        # Verify with explicit wrong key fails
        import hmac, hashlib
        data = dict(fields)
        data.pop("signature", None)
        from gmcp.crypto_utils import canonical_json
        wrong_tag = hmac.new(b"wrong-key", canonical_json(data).encode(), hashlib.sha256).hexdigest()
        self.assertNotEqual(fields["signature"], wrong_tag)

    def test_compatibility_wrapper_delegates_to_checkpoint_key(self):
        """Legacy build_checkpoint should use CHECKPOINT_AUTH_KEY, not DATA_AUTH_KEY."""
        cp = build_checkpoint("s", 1, 50, "mem50")
        self.assertTrue(verify_checkpoint(cp))
        # Mutating should fail
        cp["memory"] = "bad"
        self.assertFalse(verify_checkpoint(cp))


# ---------------------------------------------------------------------------
# Task 4 tests: per-session locking
# ---------------------------------------------------------------------------

class SessionRegistryTests(unittest.TestCase):
    """Task 4: Per-session locking overlap and strategy tests."""

    # --- per_session_lock strategy ---

    def test_per_session_lock_two_sessions_independent(self):
        """Hold session A's lock; session B's lock must still be acquirable within 1 s."""
        registry = SessionRegistry(factory=_make_ctx, lock_strategy="per_session_lock")
        ctx_a = registry.get_or_create("session-A", checkpoint_interval=100)
        ctx_b = registry.get_or_create("session-B", checkpoint_interval=100)

        # Locks must be different objects
        self.assertIsNot(ctx_a.lock, ctx_b.lock)

        # Hold A's lock, then try to acquire B's lock in a background thread
        ctx_a.lock.acquire()
        try:
            acquired = []
            def try_b():
                got = ctx_b.lock.acquire(timeout=2)
                if got:
                    ctx_b.lock.release()
                acquired.append(got)

            t = threading.Thread(target=try_b)
            t.start()
            t.join(timeout=3)
            self.assertTrue(acquired, "Thread did not finish in time")
            self.assertTrue(acquired[0], "Session B's lock should be independently acquirable")
        finally:
            ctx_a.lock.release()

    def test_per_session_lock_same_session_returns_same_context(self):
        registry = SessionRegistry(factory=_make_ctx, lock_strategy="per_session_lock")
        ctx1 = registry.get_or_create("s1", checkpoint_interval=50)
        ctx2 = registry.get_or_create("s1", checkpoint_interval=50)
        self.assertIs(ctx1, ctx2)

    # --- global_lock strategy ---

    def test_global_lock_all_sessions_share_one_lock(self):
        registry = SessionRegistry(factory=_make_ctx, lock_strategy="global_lock")
        ctx_a = registry.get_or_create("session-A", checkpoint_interval=100)
        ctx_b = registry.get_or_create("session-B", checkpoint_interval=100)

        # Both contexts must reference the same lock object
        self.assertIs(ctx_a.lock, ctx_b.lock)

    def test_global_lock_blocks_cross_session(self):
        """In global mode, holding A's lock blocks acquisition of B's lock."""
        registry = SessionRegistry(factory=_make_ctx, lock_strategy="global_lock")
        ctx_a = registry.get_or_create("session-A", checkpoint_interval=100)
        ctx_b = registry.get_or_create("session-B", checkpoint_interval=100)

        ctx_a.lock.acquire()
        try:
            acquired = []
            def try_b():
                got = ctx_b.lock.acquire(timeout=0.3)
                if got:
                    ctx_b.lock.release()
                acquired.append(got)

            t = threading.Thread(target=try_b)
            t.start()
            t.join(timeout=1)
            self.assertTrue(acquired, "Thread did not finish in time")
            self.assertFalse(acquired[0], "B's lock should be blocked when A holds the global lock")
        finally:
            ctx_a.lock.release()

    # --- validation ---

    def test_invalid_lock_strategy_raises(self):
        with self.assertRaises(ValueError):
            SessionRegistry(factory=_make_ctx, lock_strategy="bogus")

    def test_checkpoint_interval_out_of_range_raises(self):
        registry = SessionRegistry(factory=_make_ctx)
        with self.assertRaises(ValueError):
            registry.get_or_create("s1", checkpoint_interval=5)
        with self.assertRaises(ValueError):
            registry.get_or_create("s1", checkpoint_interval=2000)

    def test_checkpoint_interval_boundary_values(self):
        registry = SessionRegistry(factory=_make_ctx)
        ctx10 = registry.get_or_create("s10", checkpoint_interval=10)
        self.assertIsNotNone(ctx10)
        ctx1000 = registry.get_or_create("s1000", checkpoint_interval=1000)
        self.assertIsNotNone(ctx1000)

    # --- SessionContext defaults ---

    def test_session_context_defaults(self):
        ctx = SessionContext(session_id="x", state=None, verifier=None)
        self.assertEqual(ctx.stats, {"total": 0, "accepted": 0, "rejected": 0})
        self.assertIsInstance(ctx.lock, type(threading.Lock()))

    # --- stats are isolated per context ---

    def test_stats_isolation_between_sessions(self):
        registry = SessionRegistry(factory=_make_ctx)
        ctx_a = registry.get_or_create("a", checkpoint_interval=100)
        ctx_b = registry.get_or_create("b", checkpoint_interval=100)
        ctx_a.stats["total"] = 42
        self.assertEqual(ctx_b.stats["total"], 0)

    # --- concurrent get_or_create is safe ---

    def test_concurrent_get_or_create(self):
        registry = SessionRegistry(factory=_make_ctx)
        barrier = threading.Barrier(10)
        results = []

        def worker(i):
            barrier.wait()
            ctx = registry.get_or_create(f"session-{i % 3}", checkpoint_interval=100)
            results.append(ctx)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # Only 3 unique sessions should exist
        unique_ids = {ctx.session_id for ctx in results}
        self.assertEqual(len(unique_ids), 3)
        # All references for the same session_id should be identical
        for sid in unique_ids:
            matching = [ctx for ctx in results if ctx.session_id == sid]
            self.assertTrue(all(ctx is matching[0] for ctx in matching))


if __name__ == "__main__":
    unittest.main()
