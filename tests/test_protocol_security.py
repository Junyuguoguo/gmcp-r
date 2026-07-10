import math
import unittest

from gmcp.config import DATA_AUTH_KEY
from gmcp.crypto_utils import hmac_sha256_hex
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet, packet_without_auth
from gmcp.protocol import GMCPState, GMCPVerifier

try:
    from gmcp.crypto_utils import canonical_json, verify_tagged_hmac, with_hmac
except ImportError:
    canonical_json = None
    verify_tagged_hmac = None
    with_hmac = None


class ProtocolSecurityTests(unittest.TestCase):
    def make_verifier(self):
        mem = initial_memory("s", "client-001", 1, "demo-seed")
        state = GMCPState("s", "client-001", 1, 0, mem)
        return state, GMCPVerifier(state)

    def resign(self, packet):
        packet["auth_tag"] = hmac_sha256_hex(
            DATA_AUTH_KEY, packet_without_auth(packet)
        )
        return packet

    def test_canonical_json_is_stable_and_rejects_nan(self):
        self.assertIsNotNone(canonical_json, "canonical_json is not implemented")
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')
        with self.assertRaises(ValueError):
            canonical_json({"x": math.nan})

    def test_tagged_hmac_helpers_sign_canonical_message_without_mutation(self):
        self.assertIsNotNone(with_hmac, "with_hmac is not implemented")
        self.assertIsNotNone(
            verify_tagged_hmac, "verify_tagged_hmac is not implemented"
        )
        message = {"b": 2, "a": 1, "auth_tag": "stale"}

        tagged = with_hmac(b"test-key", message)

        self.assertEqual(message["auth_tag"], "stale")
        self.assertTrue(verify_tagged_hmac(b"test-key", tagged))
        self.assertFalse(
            verify_tagged_hmac(b"test-key", {**tagged, "a": 99})
        )
        self.assertFalse(verify_tagged_hmac(b"test-key", {"a": 1}))

    def test_wrong_sender_with_valid_hmac_is_rejected_without_mutation(self):
        state, verifier = self.make_verifier()
        before = (state.last_seq, state.last_mem)
        packet = build_data_packet(
            "s", "different-sender", 1, 1, state.last_mem, "p"
        )
        self.assertEqual(
            verifier.verify_data_packet(packet), (False, "sender_id mismatch")
        )
        self.assertEqual((state.last_seq, state.last_mem), before)

    def test_wrong_protocol_and_missing_field_are_rejected(self):
        state, verifier = self.make_verifier()
        packet = build_data_packet(
            "s", "client-001", 1, 1, state.last_mem, "p", protocol="seq_mac"
        )
        self.assertEqual(
            verifier.verify_data_packet(packet), (False, "protocol mismatch")
        )
        packet = build_data_packet("s", "client-001", 1, 1, state.last_mem, "p")
        packet.pop("payload_hash")
        self.assertIn("missing DATA fields", verifier.verify_data_packet(packet)[1])

    def test_unknown_field_is_rejected_even_with_valid_hmac(self):
        state, verifier = self.make_verifier()
        packet = build_data_packet("s", "client-001", 1, 1, state.last_mem, "p")
        packet["unexpected"] = "signed but unsupported"
        self.resign(packet)

        ok, reason = verifier.verify_data_packet(packet)

        self.assertFalse(ok)
        self.assertIn("unknown DATA fields", reason)
        self.assertEqual(state.last_seq, 0)

    def test_non_integer_seq_is_rejected_without_mutation(self):
        state, verifier = self.make_verifier()
        before = (state.last_seq, state.last_mem)
        packet = build_data_packet("s", "client-001", 1, 1, state.last_mem, "p")
        packet["seq"] = "1"
        self.resign(packet)

        self.assertEqual(
            verifier.verify_data_packet(packet), (False, "seq must be an integer")
        )
        self.assertEqual((state.last_seq, state.last_mem), before)


if __name__ == "__main__":
    unittest.main()
