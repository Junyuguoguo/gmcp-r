import unittest


class PlotCompatibilityTests(unittest.TestCase):
    def test_baseline_bool_series_is_numeric_for_old_pandas_plotting(self):
        import pandas as pd

        from plot_baseline_comparison_results import bool_series

        converted = bool_series(pd.Series(["True", "False", True, False]))
        self.assertEqual(converted.tolist(), [1, 0, 1, 0])
        self.assertNotEqual(str(converted.dtype), "bool")


class BaselineComparisonContractTests(unittest.TestCase):
    def test_protocol_matrix_fields_and_security_expectations(self):
        from run_baseline_comparison_experiment import simulate_protocol_result

        gmcp_row = simulate_protocol_result(
            protocol="gmcp_r",
            attack_type="rollback_ticket",
            message_count=5000,
            payload_size=512,
            checkpoint_interval=100,
            repeat_id=1,
        )

        required_fields = {
            "protocol",
            "attack_type",
            "message_count",
            "payload_size",
            "checkpoint_interval",
            "repeat_id",
            "memory_supported",
            "memory_recovered",
            "memory_match",
            "attack_detected",
            "normal_recovery_success",
            "secure_memory_recovery_success",
            "fast_secure_memory_recovery_success",
            "recovery_latency_ms",
            "recovery_extra_messages",
            "recovery_extra_bytes",
            "replay_count",
            "recovery_mode",
            "throughput_score",
            "detection_reason",
            "recovery_reason",
        }
        self.assertTrue(required_fields.issubset(gmcp_row))
        self.assertTrue(gmcp_row["attack_detected"])
        self.assertTrue(gmcp_row["memory_recovered"])
        self.assertTrue(gmcp_row["fast_secure_memory_recovery_success"])

        seq_prev = simulate_protocol_result("seq_mac", "prev_mem", 500, 128, 100, 1)
        ticket_prev = simulate_protocol_result("ticket_only", "prev_mem", 500, 128, 100, 1)
        hash_prev = simulate_protocol_result("hash_chain", "prev_mem", 500, 128, 100, 1)
        gmcp_prev = simulate_protocol_result("gmcp_r", "prev_mem", 500, 128, 100, 1)

        self.assertFalse(seq_prev["attack_detected"])
        self.assertFalse(ticket_prev["attack_detected"])
        self.assertTrue(hash_prev["attack_detected"])
        self.assertTrue(gmcp_prev["attack_detected"])

        hash_latency = simulate_protocol_result("hash_chain", "disconnect", 5000, 512, 100, 1)[
            "recovery_latency_ms"
        ]
        gmcp_latency = simulate_protocol_result("gmcp_r", "disconnect", 5000, 512, 100, 1)[
            "recovery_latency_ms"
        ]
        self.assertLess(gmcp_latency, hash_latency)


class MemoryTicketContractTests(unittest.TestCase):
    def test_ticket_context_expiry_replay_tamper_and_rollback_checks(self):
        from gmcp.ticket import (
            USED_TICKET_NONCES,
            build_memory_ticket,
            verify_memory_ticket_for_recovery,
        )

        USED_TICKET_NONCES.clear()
        ticket = build_memory_ticket(
            session_id="session-a",
            client_id="client-a",
            epoch=1,
            last_seq=10,
            last_mem="mem-10",
            checkpoint_seq=8,
            checkpoint_mem="mem-8",
        )

        ok, reason = verify_memory_ticket_for_recovery(
            ticket,
            expected_session_id="session-a",
            expected_client_id="client-a",
            expected_epoch=1,
            min_last_seq=10,
        )
        self.assertTrue(ok, reason)

        replay_ok, replay_reason = verify_memory_ticket_for_recovery(
            ticket,
            expected_session_id="session-a",
            expected_client_id="client-a",
            expected_epoch=1,
            min_last_seq=10,
        )
        self.assertFalse(replay_ok)
        self.assertIn("replay", replay_reason)

        USED_TICKET_NONCES.clear()
        rollback_ticket = build_memory_ticket(
            session_id="session-a",
            client_id="client-a",
            epoch=1,
            last_seq=5,
            last_mem="mem-5",
            checkpoint_seq=5,
            checkpoint_mem="mem-5",
        )
        rollback_ok, rollback_reason = verify_memory_ticket_for_recovery(
            rollback_ticket,
            expected_session_id="session-a",
            expected_client_id="client-a",
            expected_epoch=1,
            min_last_seq=10,
        )
        self.assertFalse(rollback_ok)
        self.assertIn("rollback", rollback_reason)

        USED_TICKET_NONCES.clear()
        wrong_session_ticket = build_memory_ticket(
            session_id="session-b",
            client_id="client-a",
            epoch=1,
            last_seq=10,
            last_mem="mem-10",
            checkpoint_seq=8,
            checkpoint_mem="mem-8",
        )
        wrong_ok, wrong_reason = verify_memory_ticket_for_recovery(
            wrong_session_ticket,
            expected_session_id="session-a",
            expected_client_id="client-a",
            expected_epoch=1,
            min_last_seq=10,
        )
        self.assertFalse(wrong_ok)
        self.assertIn("session_id", wrong_reason)


class WeakNetworkContractTests(unittest.TestCase):
    def test_controlled_weak_network_model_fields_and_expected_trends(self):
        from run_weak_network_experiment import simulate_weak_network_result

        gmcp_row = simulate_weak_network_result(
            protocol="gmcp_r",
            loss_rate=0.10,
            reorder_rate=0.03,
            delay_ms=200,
            message_count=1000,
            payload_size=512,
            repeat_id=1,
        )
        hash_row = simulate_weak_network_result(
            protocol="hash_chain",
            loss_rate=0.10,
            reorder_rate=0.03,
            delay_ms=200,
            message_count=1000,
            payload_size=512,
            repeat_id=1,
        )
        ticket_row = simulate_weak_network_result(
            protocol="ticket_only",
            loss_rate=0.10,
            reorder_rate=0.03,
            delay_ms=200,
            message_count=1000,
            payload_size=512,
            repeat_id=1,
        )

        required_fields = {
            "protocol",
            "loss_rate",
            "reorder_rate",
            "delay_ms",
            "message_count",
            "payload_size",
            "repeat_id",
            "delivery_success_rate",
            "recovery_success_rate",
            "memory_match_rate",
            "attack_detection_rate",
            "avg_recovery_latency_ms",
            "extra_messages",
            "extra_bytes",
            "throughput_score",
        }
        self.assertTrue(required_fields.issubset(gmcp_row))
        self.assertGreater(gmcp_row["memory_match_rate"], 0.9)
        self.assertEqual(ticket_row["memory_match_rate"], 0.0)
        self.assertLess(gmcp_row["avg_recovery_latency_ms"], hash_row["avg_recovery_latency_ms"])
        self.assertGreater(gmcp_row["recovery_success_rate"], ticket_row["recovery_success_rate"])


class RerunFailedRecoveryTests(unittest.TestCase):
    def test_detects_failed_recovery_rows_from_tcp_disconnects(self):
        from rerun_failed_real_recovery import is_failed_recovery_row

        self.assertTrue(
            is_failed_recovery_row(
                {
                    "full_recovery_success": "False",
                    "recovery_success": "False",
                    "timeout_count": "1",
                    "accepted_count": "0",
                    "detection_reason": "tcp error: server closed connection",
                }
            )
        )
        self.assertFalse(
            is_failed_recovery_row(
                {
                    "full_recovery_success": "True",
                    "recovery_success": "True",
                    "timeout_count": "0",
                    "accepted_count": "500",
                    "detection_reason": "prev_mem mismatch, history is not continuous",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
