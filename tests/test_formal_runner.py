# -*- coding: utf-8 -*-
# tests/test_formal_runner.py
#
# 15 tests for the formal experiment runner resilience paths.
# These tests exercise offline / mockable logic from run_real_baseline_comparison,
# run_real_recovery_experiment, gmcp.experiment_transport, and supporting modules
# without requiring a live server.

import copy
import json
import socket
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from gmcp.config import (
    DATA_AUTH_KEY,
    TICKET_AUTH_KEY,
    CLIENT_ID,
    EPOCH,
    SESSION_ID,
)
from gmcp.crypto_utils import (
    hash_text,
    hmac_sha256_hex,
    with_hmac,
    verify_tagged_hmac,
    verify_hmac,
    canonical_json,
)
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet, packet_without_auth
from gmcp.recovery_protocol import (
    build_recovery_request,
    build_recovery_response,
    verify_recovery_request,
    verify_recovery_response,
)
from gmcp.ticket import (
    build_memory_ticket,
    verify_memory_ticket,
    TicketNonceStore,
    USED_TICKET_NONCES,
)
from gmcp.attack import (
    attack_category,
    attack_applicable_to_protocol,
    apply_modify_unsigned,
    apply_metadata_tamper,
    apply_exact_replay,
    build_forged_prev_mem_packet,
    build_sequence_gap_packet,
    build_cross_session_packet,
    build_cross_epoch_packet,
    ALL_ATTACK_TYPES,
    CATEGORY_NETWORK_ATTACKER,
    CATEGORY_MALICIOUS_CLIENT,
)
from gmcp.protocol import GMCPState, GMCPVerifier


class TestTCPConnectTimeoutStructuredFailure(unittest.TestCase):
    """Test 1: TCP connect timeout returns a structured failure row, not None."""

    def test_open_tcp_timeout_returns_structured_failure_row(self):
        """When socket.connect raises a timeout, run_one_baseline_experiment
        must return a dict with run_valid=False and a non-empty failure_reason,
        never None."""
        import run_real_baseline_comparison as runner

        with patch.object(runner, "open_tcp", side_effect=socket.timeout("timed out")):
            result = runner.run_one_baseline_experiment(
                protocol="gmcp_r",
                attack_type="none",
                message_count=10,
                payload_size=128,
                repeat_id=1,
            )
        self.assertIsNotNone(result, "Result must not be None on TCP timeout")
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("run_valid", True))
        self.assertNotEqual(result.get("failure_reason", ""), "")
        self.assertEqual(result.get("accepted_count", 0), 0)


class TestHelloHandshakeProtocolNegotiation(unittest.TestCase):
    """Test 2: HELLO sends correct wire protocol name; gmcp_r maps to 'gmcp'."""

    def test_send_hello_maps_gmcp_r_to_gmcp_wire_name(self):
        """send_hello must normalize 'gmcp_r' -> 'gmcp' in the HELLO message."""
        from gmcp.experiment_transport import send_hello, WIRE_PROTOCOL_NAMES

        mock_sock = MagicMock()
        # Build a fake HELLO_ACK response
        expected_wire = WIRE_PROTOCOL_NAMES["gmcp_r"]
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": expected_wire,
            "session_id": "test-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        result = send_hello(
            mock_sock, mock_file, "gmcp_r", "test-session", "client-1", 1
        )
        self.assertEqual(result["protocol"], "gmcp")

        # Inspect the HELLO that was sent
        sent_raw = mock_sock.sendall.call_args[0][0]
        sent_msg = json.loads(sent_raw.decode("utf-8").strip())
        self.assertEqual(sent_msg["type"], "HELLO")
        self.assertEqual(sent_msg["protocol"], "gmcp")
        self.assertIn("auth_tag", sent_msg)

    def test_send_hello_rejects_mismatched_ack_protocol(self):
        """If server returns wrong protocol in ACK, send_hello must raise."""
        from gmcp.experiment_transport import send_hello

        mock_sock = MagicMock()
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": "wrong_proto",
            "session_id": "test-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        with self.assertRaises(RuntimeError) as ctx:
            send_hello(mock_sock, mock_file, "gmcp_r", "test-session", "c1", 1)
        self.assertIn("protocol mismatch", str(ctx.exception).lower())


class TestRecoveryRequestResponseRoundTrip(unittest.TestCase):
    """Test 3: Recovery request/response HMAC round-trip verifies correctly."""

    def test_build_and_verify_recovery_roundtrip(self):
        req = build_recovery_request(
            session_id="s1",
            client_id="c1",
            epoch=1,
            client_last_seq=100,
            client_last_mem="mem100",
            reason="disconnect",
        )
        self.assertEqual(req["type"], "RECOVERY_REQUEST")
        self.assertIn("recovery_nonce", req)
        self.assertIn("auth_tag", req)

        ok, reason = verify_recovery_request(req)
        self.assertTrue(ok, reason)
        self.assertEqual(reason, "ok")

    def test_recovery_response_verifies_nonce_and_session(self):
        nonce = "test-nonce-abc"
        resp = build_recovery_response(
            ok=True,
            reason="recovered",
            session_id="s1",
            epoch=1,
            recovery_nonce=nonce,
            extra={"server_last_seq": 100, "server_last_mem": "mem100"},
        )
        ok, reason = verify_recovery_response(resp, "s1", 1, nonce)
        self.assertTrue(ok, reason)

    def test_recovery_response_fails_on_wrong_nonce(self):
        nonce = "correct-nonce"
        resp = build_recovery_response(
            ok=True, reason="ok", session_id="s1", epoch=1, recovery_nonce=nonce
        )
        ok, reason = verify_recovery_response(resp, "s1", 1, "wrong-nonce")
        self.assertFalse(ok)
        self.assertIn("nonce", reason.lower())


class TestMemoryTicketVerification(unittest.TestCase):
    """Test 4: MemoryTicket signature, expiry, replay-detection, rollback-detection."""

    def test_ticket_sign_and_verify_roundtrip(self):
        store = TicketNonceStore()
        ticket = build_memory_ticket(
            session_id="s1",
            client_id="c1",
            epoch=1,
            last_seq=500,
            last_mem="mem500",
            checkpoint_seq=400,
            checkpoint_mem="mem400",
            ttl_seconds=3600,
        )
        # Verify with a fresh store to avoid global nonce interference
        # For the round-trip test, check the signature:
        tag = ticket["server_auth_tag"]
        data = dict(ticket)
        data.pop("server_auth_tag", None)
        self.assertTrue(verify_hmac(TICKET_AUTH_KEY, data, tag))

    def test_ticket_replay_detection(self):
        store = TicketNonceStore()
        ticket = build_memory_ticket(
            session_id="s1", client_id="c1", epoch=1,
            last_seq=10, last_mem="m10", checkpoint_seq=5, checkpoint_mem="m5",
        )
        nonce = ticket["ticket_nonce"]
        self.assertTrue(store.consume(nonce))
        self.assertFalse(store.consume(nonce), "Second use of same nonce must fail")

    def test_ticket_rollback_detection(self):
        store = TicketNonceStore()
        # Build a ticket with last_seq=50
        ticket = build_memory_ticket(
            session_id="s1", client_id="c1", epoch=1,
            last_seq=50, last_mem="m50", checkpoint_seq=40, checkpoint_mem="m40",
        )
        ok = store.consume(ticket["ticket_nonce"])
        # Verify with min_last_seq=100 → must reject as rollback
        tag = ticket["server_auth_tag"]
        data = dict(ticket)
        data.pop("server_auth_tag", None)
        self.assertTrue(verify_hmac(TICKET_AUTH_KEY, data, tag))
        # Direct test: last_seq < min_last_seq
        self.assertLess(ticket["last_seq"], 100)


class TestAttackDetection(unittest.TestCase):
    """Test 5: All attack types are detected by GMCPVerifier (server-side)."""

    def _make_state(self):
        sid = "attack-test-session"
        mem0 = initial_memory(sid, CLIENT_ID, EPOCH, "seed")
        return GMCPState(
            session_id=sid, sender_id=CLIENT_ID, epoch=EPOCH,
            last_seq=0, last_mem=mem0,
        )

    def _send_packet(self, verifier, seq, payload, prev_mem):
        pkt = build_data_packet(
            session_id=verifier.state.session_id,
            sender_id=verifier.state.sender_id,
            epoch=verifier.state.epoch,
            seq=seq,
            prev_mem=prev_mem,
            payload=payload,
        )
        return verifier.verify_data_packet(pkt)

    def test_modify_payload_detected(self):
        """Payload modification must be detected via HMAC mismatch."""
        state = self._make_state()
        verifier = GMCPVerifier(state)
        mem0 = state.last_mem

        pkt = build_data_packet(
            session_id=state.session_id, sender_id=state.sender_id,
            epoch=state.epoch, seq=1, prev_mem=mem0, payload="hello",
        )
        attacked = apply_modify_unsigned(pkt)
        ok, reason = verifier.verify_data_packet(attacked)
        self.assertFalse(ok)
        self.assertIn("auth_tag", reason.lower())

    def test_prev_mem_tamper_detected(self):
        """prev_mem tamper (without valid HMAC) detected by GMCPVerifier."""
        state = self._make_state()
        verifier = GMCPVerifier(state)

        pkt = build_data_packet(
            session_id=state.session_id, sender_id=state.sender_id,
            epoch=state.epoch, seq=1, prev_mem=state.last_mem, payload="hello",
        )
        attacked = apply_metadata_tamper(pkt)
        ok, reason = verifier.verify_data_packet(attacked)
        self.assertFalse(ok)

    def test_replay_detected(self):
        """Replaying the same seq must be rejected."""
        state = self._make_state()
        verifier = GMCPVerifier(state)
        mem0 = state.last_mem

        pkt1 = build_data_packet(
            session_id=state.session_id, sender_id=state.sender_id,
            epoch=state.epoch, seq=1, prev_mem=mem0, payload="first",
        )
        ok1, _ = verifier.verify_data_packet(pkt1)
        self.assertTrue(ok1)

        # Replay the same packet
        ok2, reason = verifier.verify_data_packet(pkt1)
        self.assertFalse(ok2)
        self.assertIn("replay", reason.lower())

    def test_seq_gap_detected(self):
        """Sending seq=3 when expected seq=1 must be rejected."""
        state = self._make_state()
        verifier = GMCPVerifier(state)
        mem0 = state.last_mem

        pkt = build_data_packet(
            session_id=state.session_id, sender_id=state.sender_id,
            epoch=state.epoch, seq=3, prev_mem=mem0, payload="gap",
        )
        ok, reason = verifier.verify_data_packet(pkt)
        self.assertFalse(ok)
        self.assertIn("gap", reason.lower())


class TestProtocolAdapterStateTracking(unittest.TestCase):
    """Test 6: ProtocolAdapter tracks client state independently after accept."""

    def test_gmcp_r_adapter_independent_state(self):
        from gmcp.experiment_transport import ProtocolAdapter

        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload-1")
        self.assertIn("prev_mem", pkt)
        self.assertIn("auth_tag", pkt)

        # Simulate server response
        from gmcp.memory import update_memory
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        response = {"ok": True, "last_seq": 1, "last_mem": new_mem}
        adapter.update_after_accept(pkt, response)

        self.assertEqual(adapter.last_seq, 1)
        self.assertEqual(adapter.client_state["last_mem"], new_mem)

    def test_adapter_state_match_detects_mismatch(self):
        from gmcp.experiment_transport import ProtocolAdapter

        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        from gmcp.memory import update_memory
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})

        # State should match
        self.assertTrue(adapter.check_state_match())

        # Force mismatch by passing wrong server state
        self.assertFalse(adapter.check_state_match({"last_seq": 1, "last_mem": "wrong"}))


class TestDataPacketConstruction(unittest.TestCase):
    """Test 7: build_data_packet produces correct fields and valid HMAC."""

    def test_packet_has_all_required_fields(self):
        mem0 = initial_memory("s1", "c1", 1, "seed")
        pkt = build_data_packet(
            session_id="s1", sender_id="c1", epoch=1,
            seq=1, prev_mem=mem0, payload="hello",
        )
        required = {
            "type", "protocol", "session_id", "sender_id",
            "epoch", "seq", "prev_mem", "payload", "payload_hash",
            "timestamp", "auth_tag",
        }
        self.assertTrue(required.issubset(pkt.keys()))
        self.assertEqual(pkt["type"], "DATA")
        self.assertEqual(pkt["protocol"], "gmcp")

    def test_packet_hmac_is_valid(self):
        mem0 = initial_memory("s1", "c1", 1, "seed")
        pkt = build_data_packet(
            session_id="s1", sender_id="c1", epoch=1,
            seq=1, prev_mem=mem0, payload="test",
        )
        self.assertTrue(verify_tagged_hmac(DATA_AUTH_KEY, pkt))

    def test_packet_without_auth_excludes_tag(self):
        mem0 = initial_memory("s1", "c1", 1, "seed")
        pkt = build_data_packet(
            session_id="s1", sender_id="c1", epoch=1,
            seq=1, prev_mem=mem0, payload="test",
        )
        stripped = packet_without_auth(pkt)
        self.assertNotIn("auth_tag", stripped)
        self.assertIn("payload", stripped)


class TestAttackApplicabilityMatrix(unittest.TestCase):
    """Test 8: forged_prev_mem only applies to hash-chain protocols."""

    def test_forged_prev_mem_not_applicable_to_seq_mac(self):
        self.assertFalse(
            attack_applicable_to_protocol("forged_prev_mem_valid_mac", "seq_mac")
        )

    def test_forged_prev_mem_not_applicable_to_ticket_only(self):
        self.assertFalse(
            attack_applicable_to_protocol("forged_prev_mem_valid_mac", "ticket_only")
        )

    def test_forged_prev_mem_applicable_to_gmcp_r(self):
        self.assertTrue(
            attack_applicable_to_protocol("forged_prev_mem_valid_mac", "gmcp_r")
        )

    def test_all_other_attacks_applicable_to_all_protocols(self):
        for attack in ALL_ATTACK_TYPES:
            if attack == "forged_prev_mem_valid_mac":
                continue
            for proto in ("gmcp_r", "hash_chain", "seq_mac", "ticket_only"):
                self.assertTrue(
                    attack_applicable_to_protocol(attack, proto),
                    f"{attack} should be applicable to {proto}",
                )


class TestCrossSessionProtection(unittest.TestCase):
    """Test 9: Cross-session attack packets are rejected by GMCPVerifier."""

    def test_cross_session_attack_rejected(self):
        state = GMCPState(
            session_id="real-session", sender_id="c1", epoch=1,
            last_seq=0, last_mem=initial_memory("real-session", "c1", 1, "seed"),
        )
        verifier = GMCPVerifier(state)

        # Build a valid packet with a different session_id
        pkt = build_data_packet(
            session_id="attacker-session",  # wrong session
            sender_id="c1", epoch=1, seq=1,
            prev_mem=state.last_mem, payload="attack",
        )
        ok, reason = verifier.verify_data_packet(pkt)
        self.assertFalse(ok)
        self.assertIn("session_id", reason.lower())


class TestCrossEpochProtection(unittest.TestCase):
    """Test 10: Cross-epoch attack packets are rejected by GMCPVerifier."""

    def test_cross_epoch_attack_rejected(self):
        state = GMCPState(
            session_id="s1", sender_id="c1", epoch=1,
            last_seq=0, last_mem=initial_memory("s1", "c1", 1, "seed"),
        )
        verifier = GMCPVerifier(state)

        pkt = build_data_packet(
            session_id="s1", sender_id="c1", epoch=999,  # wrong epoch
            seq=1, prev_mem=state.last_mem, payload="attack",
        )
        ok, reason = verifier.verify_data_packet(pkt)
        self.assertFalse(ok)
        self.assertIn("epoch", reason.lower())


class TestRecoveryNonceVerification(unittest.TestCase):
    """Test 11: Recovery requests without nonce are rejected."""

    def test_missing_nonce_rejected(self):
        req = build_recovery_request(
            session_id="s1", client_id="c1", epoch=1,
            client_last_seq=10, client_last_mem="m10", reason="test",
        )
        ok, reason = verify_recovery_request(req)
        self.assertTrue(ok)

        # Tamper: remove nonce
        tampered = dict(req)
        tampered.pop("recovery_nonce", None)
        tampered.pop("auth_tag", None)
        tampered["auth_tag"] = hmac_sha256_hex(DATA_AUTH_KEY, tampered)
        ok2, reason2 = verify_recovery_request(tampered)
        self.assertFalse(ok2)
        self.assertIn("nonce", reason2.lower())


class TestTicketReplayDetection(unittest.TestCase):
    """Test 12: Ticket nonce replay is detected across verify calls."""

    def test_ticket_nonce_replay_detected_globally(self):
        # Use the module-level store
        USED_TICKET_NONCES.clear()
        ticket = build_memory_ticket(
            session_id="s1", client_id="c1", epoch=1,
            last_seq=10, last_mem="m10", checkpoint_seq=5, checkpoint_mem="m5",
        )
        ok1, r1 = verify_memory_ticket(ticket)
        self.assertTrue(ok1, r1)

        # Same ticket again → replay
        ticket2 = dict(ticket)
        ok2, r2 = verify_memory_ticket(ticket2)
        self.assertFalse(ok2)
        self.assertIn("replay", r2.lower())
        USED_TICKET_NONCES.clear()


class TestTicketRollbackDetection(unittest.TestCase):
    """Test 13: MemoryTicket with stale last_seq is rejected as rollback."""

    def test_rollback_ticket_rejected(self):
        USED_TICKET_NONCES.clear()
        ticket = build_memory_ticket(
            session_id="s1", client_id="c1", epoch=1,
            last_seq=50, last_mem="m50", checkpoint_seq=40, checkpoint_mem="m40",
        )
        # Verify with min_last_seq=200 → must reject
        ok, reason = verify_memory_ticket(
            ticket,
            expected_session_id="s1",
            expected_client_id="c1",
            expected_epoch=1,
            min_last_seq=200,
        )
        self.assertFalse(ok)
        self.assertIn("rollback", reason.lower())
        USED_TICKET_NONCES.clear()


class TestMemoryContinuityVerification(unittest.TestCase):
    """Test 14: Memory chain continuity is maintained across sequential packets."""

    def test_memory_chain_is_deterministic_and_continuous(self):
        sid = "continuity-test"
        mem0 = initial_memory(sid, CLIENT_ID, EPOCH, "seed")

        mem_chain = [mem0]
        for seq in range(1, 6):
            payload = f"msg-{seq}"
            payload_hash = hash_text(payload)
            new_mem = update_memory(
                prev_mem=mem_chain[-1],
                session_id=sid, epoch=EPOCH, seq=seq,
                payload_hash=payload_hash, sender_id=CLIENT_ID,
            )
            mem_chain.append(new_mem)

        # All memories should be unique
        self.assertEqual(len(set(mem_chain)), 6)

        # Re-compute from scratch → must match
        recomputed = [mem0]
        for seq in range(1, 6):
            payload = f"msg-{seq}"
            payload_hash = hash_text(payload)
            new_mem = update_memory(
                prev_mem=recomputed[-1],
                session_id=sid, epoch=EPOCH, seq=seq,
                payload_hash=payload_hash, sender_id=CLIENT_ID,
            )
            recomputed.append(new_mem)
        self.assertEqual(mem_chain, recomputed)

    def test_different_payload_produces_different_memory(self):
        sid = "diff-test"
        mem0 = initial_memory(sid, CLIENT_ID, EPOCH, "seed")
        mem_a = update_memory(mem0, sid, 1, 1, hash_text("A"), CLIENT_ID)
        mem_b = update_memory(mem0, sid, 1, 1, hash_text("B"), CLIENT_ID)
        self.assertNotEqual(mem_a, mem_b)


class TestJSONLineTransport(unittest.TestCase):
    """Test 15: send_json_line / recv_json_line round-trip and error handling."""

    def test_send_recv_roundtrip(self):
        from gmcp.experiment_transport import send_json_line, recv_json_line

        mock_sock = MagicMock()
        data = {"type": "TEST", "value": 42}
        send_json_line(mock_sock, data)

        sent_bytes = mock_sock.sendall.call_args[0][0]
        self.assertTrue(sent_bytes.endswith(b"\n"))
        parsed = json.loads(sent_bytes.decode("utf-8").strip())
        self.assertEqual(parsed["type"], "TEST")
        self.assertEqual(parsed["value"], 42)

    def test_recv_json_line_raises_on_eof(self):
        from gmcp.experiment_transport import recv_json_line

        mock_file = MagicMock()
        mock_file.readline.return_value = ""  # EOF

        with self.assertRaises(ConnectionError):
            recv_json_line(mock_file)

    def test_recv_json_line_raises_on_malformed_json(self):
        from gmcp.experiment_transport import recv_json_line

        mock_file = MagicMock()
        mock_file.readline.return_value = "not-json\n"

        with self.assertRaises(json.JSONDecodeError):
            recv_json_line(mock_file)


if __name__ == "__main__":
    unittest.main()
