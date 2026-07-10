import unittest
import csv
from collections import defaultdict
from pathlib import Path


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


class PaperDataConsistencyTests(unittest.TestCase):
    def test_real_recovery_summary_matches_raw_csv(self):
        raw_path = Path("results/real_recovery/real_recovery_results.csv")
        summary_path = Path("results/real_recovery/summary_real_recovery.csv")

        with raw_path.open(newline="", encoding="utf-8") as f:
            raw_rows = list(csv.DictReader(f))
        with summary_path.open(newline="", encoding="utf-8") as f:
            summary_rows = {row["attack_type"]: row for row in csv.DictReader(f)}

        grouped = defaultdict(list)
        for row in raw_rows:
            grouped[row["attack_type"]].append(row)

        self.assertEqual(set(grouped), set(summary_rows))
        for attack_type, rows in grouped.items():
            summary = summary_rows[attack_type]
            latencies = [float(row["recovery_latency_ms"]) for row in rows]
            success_rate = sum(
                str(row["full_recovery_success"]).lower() == "true" for row in rows
            ) / len(rows) * 100
            memory_rate = sum(
                str(row["memory_match_after_recovery"]).lower() == "true" for row in rows
            ) / len(rows) * 100

            self.assertEqual(int(summary["sample_count"]), len(rows))
            self.assertAlmostEqual(float(summary["recovery_success_rate"]), success_rate, places=3)
            self.assertAlmostEqual(float(summary["memory_match_rate"]), memory_rate, places=3)
            self.assertAlmostEqual(
                float(summary["latency_mean_ms"]),
                sum(latencies) / len(latencies),
                places=3,
            )

    def test_baseline_summary_and_delivery_sources_match_raw_csv(self):
        raw_path = Path("paper_data/01_real_baseline.csv")
        summary_path = Path("results/real_baseline_comparison/summary_real_baseline_comparison_v2.csv")

        with raw_path.open(newline="", encoding="utf-8") as f:
            raw_rows = list(csv.DictReader(f))
        with summary_path.open(newline="", encoding="utf-8") as f:
            summary_rows = {row["protocol"]: row for row in csv.DictReader(f)}

        grouped = defaultdict(list)
        for row in raw_rows:
            grouped[row["protocol"]].append(row)

        expected_strings = []
        for protocol, rows in grouped.items():
            normal = [row for row in rows if row["attack_type"] == "none"]
            attacks = [row for row in rows if row["attack_type"] != "none"]
            detected = [
                str(row["attack_detected_by_server"]).lower() == "true"
                for row in attacks
            ]
            throughput = sum(float(row["throughput_msg_per_sec"]) for row in normal) / len(normal)
            rtt = sum(float(row["rtt_mean_ms"]) for row in normal) / len(normal)
            detection_rate = sum(detected) / len(detected) * 100
            false_accept = sum(not value for value in detected) / len(detected) * 100

            summary = summary_rows[protocol]
            self.assertAlmostEqual(float(summary["normal_throughput"]), throughput, delta=1)
            self.assertAlmostEqual(float(summary["normal_rtt"]), rtt, places=3)
            self.assertAlmostEqual(float(summary["attack_detection_rate"]), detection_rate, places=3)
            self.assertAlmostEqual(float(summary["false_accept_rate"]), false_accept, places=3)
            expected_strings.append(f"{throughput:,.0f}")
            expected_strings.append(f"{rtt:.3f}")

        delivery_text = "\n".join(
            Path(path).read_text(encoding="utf-8")
            for path in [
                "README.md",
                "EXPERIMENT_SUMMARY.md",
                "paper/main_zh.md",
                "paper/build_mdpi_chinese_docx.py",
                "paper/tables/baseline_v2.md",
            ]
        )
        for expected in expected_strings:
            self.assertIn(expected, delivery_text)

    def test_weak_network_manuscript_uses_actual_repeat_count(self):
        manuscript = Path("paper/main_zh.md").read_text(encoding="utf-8")

        self.assertNotIn("每种配置重复50次", manuscript)
        self.assertIn("每个条件重复2次", manuscript)

    def test_delivery_sources_do_not_contain_stale_numbers_or_placeholder_refs(self):
        checked_files = [
            Path("README.md"),
            Path("EXPERIMENT_SUMMARY.md"),
            Path("paper/main.tex"),
            Path("paper/build_mdpi_chinese_docx.py"),
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in checked_files)

        stale_tokens = [
            "1,071 msg/s",
            "3,976 msg/s",
            "3,299 msg/s",
            "首个提供记忆连续性+高效恢复",
            "ANOVA p<0.001",
            "[REF-",
        ]
        for token in stale_tokens:
            self.assertNotIn(token, combined)

    def test_baseline_validation_uses_server_detection_field(self):
        from validate_experiment_results import calculate_baseline_detection_rates

        rows = [
            {
                "protocol": "gmcp_r",
                "attack_type": "drop",
                "success_rate": "0",
                "attack_detected_by_server": "False",
            },
            {
                "protocol": "gmcp_r",
                "attack_type": "modify",
                "success_rate": "100",
                "attack_detected_by_server": "True",
            },
        ]

        rates = calculate_baseline_detection_rates(rows)
        self.assertEqual(rates["gmcp_r"]["detected"], 1)
        self.assertEqual(rates["gmcp_r"]["total"], 2)


if __name__ == "__main__":
    unittest.main()
