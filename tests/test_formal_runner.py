# -*- coding: utf-8 -*-
# tests/test_formal_runner.py
#
# Tests that exercise run_cross_host_validation.run_one_experiment and its
# direct dependencies (gmcp.experiment_transport) without requiring a live
# external server.  Each test targets runner or transport behaviour only;
# low-level crypto / packet / attack / ticket tests live elsewhere.

import json
import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from gmcp.experiment_transport import (
    ProtocolAdapter,
    send_hello,
    send_json_line,
    recv_json_line,
    WIRE_PROTOCOL_NAMES,
)
from gmcp.memory import initial_memory, update_memory
from gmcp.crypto_utils import hash_text


# ---------------------------------------------------------------------------
# 1. TCP connect timeout → structured failure dict (never None)
# ---------------------------------------------------------------------------

class TestTCPConnectTimeoutStructuredFailure(unittest.TestCase):
    """run_one_experiment must return a structured failure row on TCP timeout."""

    def test_open_tcp_timeout_returns_structured_failure(self):
        import run_cross_host_validation as runner

        with patch.object(runner, "open_tcp", side_effect=socket.timeout("timed out")):
            result = runner.run_one_experiment(
                protocol="gmcp_r",
                message_count=10,
                payload_size=128,
                repeat_id=1,
                server_host="127.0.0.1",
                server_port=9999,
                client_host_id="test-client",
                server_host_id="test-server",
                network_path_type="loopback",
                baseline_rtt_ms=1.0,
                git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
            )
        self.assertIsNotNone(result, "Result must not be None on TCP timeout")
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("run_valid", True))
        self.assertNotEqual(result.get("failure_reason", ""), "")
        self.assertEqual(result.get("accepted_count", 0), 0)
        self.assertEqual(result.get("sent_count", 0), 0)

    def test_hello_failure_returns_structured_failure(self):
        """If HELLO handshake fails, run_one_experiment returns run_valid=False."""
        import run_cross_host_validation as runner

        mock_sock = MagicMock()
        mock_file = MagicMock()
        # open_tcp returns mock socket
        with patch.object(runner, "open_tcp", return_value=(mock_sock, mock_file)):
            # send_hello raises on HELLO rejection
            with patch("run_cross_host_validation.send_hello", side_effect=RuntimeError("HELLO rejected")):
                result = runner.run_one_experiment(
                    protocol="gmcp_r",
                    message_count=10,
                    payload_size=128,
                    repeat_id=1,
                    server_host="127.0.0.1",
                    server_port=9999,
                    client_host_id="test-client",
                    server_host_id="test-server",
                    network_path_type="loopback",
                    baseline_rtt_ms=1.0,
                    git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
                )
        self.assertFalse(result.get("run_valid", True))
        self.assertIn("HELLO", result.get("failure_reason", "").upper())


# ---------------------------------------------------------------------------
# 2. HELLO handshake: wire protocol name mapping & mismatch detection
# ---------------------------------------------------------------------------

class TestHelloHandshakeProtocolNegotiation(unittest.TestCase):
    """send_hello maps gmcp_r→gmcp on the wire and rejects mismatches."""

    def test_send_hello_maps_gmcp_r_to_gmcp_wire_name(self):
        mock_sock = MagicMock()
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

    def test_send_hello_rejects_mismatched_session_id(self):
        mock_sock = MagicMock()
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": "gmcp",
            "session_id": "wrong-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        with self.assertRaises(RuntimeError) as ctx:
            send_hello(mock_sock, mock_file, "gmcp_r", "test-session", "c1", 1)
        self.assertIn("session_id", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# 3. ProtocolAdapter: independent state tracking & mismatch detection
# ---------------------------------------------------------------------------

class TestProtocolAdapterStateTracking(unittest.TestCase):
    """ProtocolAdapter tracks client state independently after accept."""

    def test_gmcp_r_adapter_builds_valid_packet(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload-1")
        self.assertIn("prev_mem", pkt)
        self.assertIn("auth_tag", pkt)
        self.assertEqual(pkt["protocol"], "gmcp")

    def test_adapter_update_tracks_state_independently(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload-1")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        response = {"ok": True, "last_seq": 1, "last_mem": new_mem}
        adapter.update_after_accept(pkt, response)

        self.assertEqual(adapter.last_seq, 1)
        self.assertEqual(adapter.client_state["last_mem"], new_mem)

    def test_adapter_state_match_detects_match(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})
        self.assertTrue(adapter.check_state_match())

    def test_adapter_state_match_detects_mismatch(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})
        self.assertFalse(adapter.check_state_match({"last_seq": 1, "last_mem": "wrong"}))

    def test_adapter_multi_seq_state_chain(self):
        """Adapter correctly chains state across multiple packets."""
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        for seq in range(1, 6):
            payload = f"msg-{seq}"
            pkt = adapter.build_packet(seq, payload)
            new_mem = update_memory(
                adapter.client_state["last_mem"],
                "s1", 1, seq, pkt["payload_hash"], "c1",
            )
            adapter.update_after_accept(pkt, {"ok": True, "last_seq": seq, "last_mem": new_mem})

        self.assertEqual(adapter.last_seq, 5)
        self.assertTrue(adapter.check_state_match())
        # All memories should be unique across the chain
        self.assertNotEqual(adapter._initial_mem, adapter.client_state["last_mem"])


# ---------------------------------------------------------------------------
# 4. JSON line transport: round-trip, EOF, malformed
# ---------------------------------------------------------------------------

class TestJSONLineTransport(unittest.TestCase):
    """send_json_line / recv_json_line round-trip and error handling."""

    def test_send_recv_roundtrip(self):
        mock_sock = MagicMock()
        data = {"type": "TEST", "value": 42}
        send_json_line(mock_sock, data)

        sent_bytes = mock_sock.sendall.call_args[0][0]
        self.assertTrue(sent_bytes.endswith(b"\n"))
        parsed = json.loads(sent_bytes.decode("utf-8").strip())
        self.assertEqual(parsed["type"], "TEST")
        self.assertEqual(parsed["value"], 42)

    def test_recv_json_line_raises_on_eof(self):
        mock_file = MagicMock()
        mock_file.readline.return_value = ""  # EOF

        with self.assertRaises(ConnectionError):
            recv_json_line(mock_file)

    def test_recv_json_line_raises_on_malformed_json(self):
        mock_file = MagicMock()
        mock_file.readline.return_value = "not-json\n"

        with self.assertRaises(json.JSONDecodeError):
            recv_json_line(mock_file)

    def test_send_json_line_preserves_unicode(self):
        mock_sock = MagicMock()
        data = {"msg": "你好世界"}
        send_json_line(mock_sock, data)

        sent_bytes = mock_sock.sendall.call_args[0][0]
        parsed = json.loads(sent_bytes.decode("utf-8").strip())
        self.assertEqual(parsed["msg"], "你好世界")


# ---------------------------------------------------------------------------
# 5. Integration: run_one_experiment against embedded server (loopback)
# ---------------------------------------------------------------------------

class TestRunnerWithEmbeddedServer(unittest.TestCase):
    """run_one_experiment against a real EmbeddedTCPServer on loopback."""

    @classmethod
    def setUpClass(cls):
        import run_cross_host_validation as runner
        cls._runner = runner
        cls._port = 19876  # fixed port for deterministic tests
        cls._server = runner.EmbeddedTCPServer("127.0.0.1", cls._port)
        cls._server.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls._server.stop()
        time.sleep(0.1)

    def _run(self, protocol, message_count=5, payload_size=64):
        git_meta = {
            "git_commit": "a" * 40,
            "git_branch": "main",
            "git_dirty": "false",
            "client_cpu_model": "test",
        }
        return self._runner.run_one_experiment(
            protocol=protocol,
            message_count=message_count,
            payload_size=payload_size,
            repeat_id=1,
            server_host="127.0.0.1",
            server_port=self._port,
            client_host_id="test-client",
            server_host_id="test-server",
            network_path_type="loopback",
            baseline_rtt_ms=0.5,
            git_meta=git_meta,
        )

    def test_gmcp_r_integration(self):
        result = self._run("gmcp_r")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)
        self.assertEqual(result["sent_count"], 5)
        self.assertTrue(result["state_match"])
        self.assertTrue(result["sequence_match"])

    def test_seq_mac_integration(self):
        result = self._run("seq_mac")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)

    def test_hash_chain_integration(self):
        result = self._run("hash_chain")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)
        self.assertTrue(result["hash_match"])

    def test_ticket_only_integration(self):
        result = self._run("ticket_only")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)

    def test_result_has_all_csv_fields(self):
        result = self._run("gmcp_r", message_count=2, payload_size=32)
        required_keys = {
            "session_id", "protocol", "client_host_id", "server_host_id",
            "network_path_type", "accepted_count", "rejected_count",
            "run_valid", "state_match", "sequence_match",
            "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
            "client_final_seq", "server_final_seq",
            "client_final_mem", "server_final_mem",
        }
        self.assertTrue(required_keys.issubset(result.keys()), f"Missing keys: {required_keys - result.keys()}")


if __name__ == "__main__":
    unittest.main()
