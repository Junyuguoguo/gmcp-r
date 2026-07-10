# -*- coding: utf-8 -*-
# tests/test_submission_experiment_contracts.py
#
# Task 6: Recovery Window and Nonce Race contract tests.
# Task 7: O(k) vs O(n) Benchmark contract tests.

import csv as csv_mod
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from gmcp.config import CLIENT_ID, EPOCH
from gmcp.crypto_utils import hash_text
from gmcp.memory import initial_memory, update_memory
from gmcp.packet import build_data_packet
from gmcp.protocol import GMCPState, GMCPVerifier
from gmcp.checkpoint_manager import CheckpointManager
from gmcp.recovery_protocol import (
    build_recovery_request,
    build_recovery_response,
    verify_recovery_request,
    verify_recovery_response,
)
from gmcp.ticket import (
    TicketNonceStore,
    build_memory_ticket,
    consume_ticket_nonce,
    validate_memory_ticket,
)
from gmcp.session_registry import SessionContext, SessionRegistry


# ── Task 6 helpers ──────────────────────────────────────────────────────

def _send_data(state, verifier, checkpoint_mgr, seq, payload="test-payload"):
    """Send one DATA packet through verifier and optionally create ticket."""
    pkt = build_data_packet(
        session_id=state.session_id,
        sender_id=state.sender_id,
        epoch=state.epoch,
        seq=seq,
        prev_mem=state.last_mem,
        payload=payload,
    )
    ok, reason = verifier.verify_data_packet(pkt)
    assert ok, f"DATA seq={seq} rejected: {reason}"
    ticket = None
    if checkpoint_mgr.should_checkpoint(seq):
        ckpt = checkpoint_mgr.create_checkpoint(seq, state.last_mem)
        ticket = build_memory_ticket(
            session_id=state.session_id,
            client_id=state.sender_id,
            epoch=state.epoch,
            last_seq=state.last_seq,
            last_mem=state.last_mem,
            checkpoint_seq=ckpt.seq,
            checkpoint_mem=ckpt.memory,
        )
    return state.last_mem, ticket


def _build_server_context(session_id, checkpoint_interval=100):
    """Create an isolated server-side session context."""
    m0 = initial_memory(session_id, CLIENT_ID, EPOCH, "demo-seed")
    state = GMCPState(session_id, CLIENT_ID, EPOCH, 0, m0)
    verifier = GMCPVerifier(state)
    checkpoint_mgr = CheckpointManager(session_id, EPOCH, checkpoint_interval)
    return SessionContext(
        session_id=session_id,
        state=state,
        verifier=verifier,
        checkpoint_manager=checkpoint_mgr,
    )


# ── Task 6: Recovery Window Contract Tests ──────────────────────────────

class RecoveryWindowContractTests(unittest.TestCase):
    """One-repeat scenario invariant tests for each recovery window type."""

    def setUp(self):
        self._nonce_store = TicketNonceStore()

    def test_control_recovery(self):
        """control: ticket=100, server=100, client=100 → success."""
        sid = f"control-{int(time.time()*1e6)}"
        ctx = _build_server_context(sid, checkpoint_interval=100)

        with ctx.lock:
            for seq in range(1, 101):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)
            ckpt = ctx.checkpoint_manager.get_latest_checkpoint()
            self.assertIsNotNone(ckpt)
            self.assertEqual(ckpt.seq, 100)

            ticket = build_memory_ticket(
                session_id=sid,
                client_id=CLIENT_ID,
                epoch=EPOCH,
                last_seq=ctx.state.last_seq,
                last_mem=ctx.state.last_mem,
                checkpoint_seq=ckpt.seq,
                checkpoint_mem=ckpt.memory,
            )

        ok, reason = validate_memory_ticket(
            ticket,
            expected_session_id=sid,
            expected_client_id=CLIENT_ID,
            expected_epoch=EPOCH,
            min_last_seq=0,
        )
        self.assertTrue(ok, f"ticket validation failed: {reason}")

        ticket_last = int(ticket["last_seq"])
        server_last = ctx.state.last_seq
        self.assertEqual(ticket_last, 100)
        self.assertEqual(server_last, 100)

    def test_ack_loss_recovery(self):
        """ack_loss: server=149, client ticket=100 → gap but accepted."""
        sid = f"ack-loss-{int(time.time()*1e6)}"
        ctx = _build_server_context(sid, checkpoint_interval=100)

        with ctx.lock:
            for seq in range(1, 101):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)
            ckpt = ctx.checkpoint_manager.get_latest_checkpoint()
            ticket = build_memory_ticket(
                session_id=sid,
                client_id=CLIENT_ID,
                epoch=EPOCH,
                last_seq=ctx.state.last_seq,
                last_mem=ctx.state.last_mem,
                checkpoint_seq=ckpt.seq,
                checkpoint_mem=ckpt.memory,
            )
            for seq in range(101, 150):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)

        self.assertEqual(int(ticket["last_seq"]), 100)
        self.assertEqual(ctx.state.last_seq, 149)

        ok, reason = validate_memory_ticket(
            ticket,
            expected_session_id=sid,
            expected_client_id=CLIENT_ID,
            expected_epoch=EPOCH,
            min_last_seq=ckpt.seq,
        )
        self.assertTrue(ok, f"ack_loss ticket validation failed: {reason}")

    def test_old_ticket_within_window_recovery(self):
        """old_ticket_within_window: ticket from seq=100, server at seq=199, checkpoint=100 → accepted."""
        sid = f"old-ticket-{int(time.time()*1e6)}"
        ctx = _build_server_context(sid, checkpoint_interval=100)

        with ctx.lock:
            for seq in range(1, 101):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)
            ckpt_100 = ctx.checkpoint_manager.get_latest_checkpoint()
            ticket = build_memory_ticket(
                session_id=sid,
                client_id=CLIENT_ID,
                epoch=EPOCH,
                last_seq=ctx.state.last_seq,
                last_mem=ctx.state.last_mem,
                checkpoint_seq=ckpt_100.seq,
                checkpoint_mem=ckpt_100.memory,
            )
            # Advance just before next checkpoint (199 < 200),
            # so latest checkpoint remains at 100.
            for seq in range(101, 200):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)

        self.assertEqual(int(ticket["last_seq"]), 100)
        self.assertEqual(ctx.state.last_seq, 199)

        # Latest checkpoint is still 100 — ticket is within the window
        latest_ckpt = ctx.checkpoint_manager.get_latest_checkpoint()
        self.assertEqual(latest_ckpt.seq, 100)

        ok, reason = validate_memory_ticket(
            ticket,
            expected_session_id=sid,
            expected_client_id=CLIENT_ID,
            expected_epoch=EPOCH,
            min_last_seq=latest_ckpt.seq,
        )
        self.assertTrue(ok, f"old_ticket_within_window validation failed: {reason}")

    def test_below_floor_rejected(self):
        """below_floor: ticket seq=100, checkpoint floor=200 → rejected."""
        sid = f"below-floor-{int(time.time()*1e6)}"
        ctx = _build_server_context(sid, checkpoint_interval=100)

        with ctx.lock:
            for seq in range(1, 101):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)
            ckpt_100 = ctx.checkpoint_manager.get_latest_checkpoint()
            ticket = build_memory_ticket(
                session_id=sid,
                client_id=CLIENT_ID,
                epoch=EPOCH,
                last_seq=ctx.state.last_seq,
                last_mem=ctx.state.last_mem,
                checkpoint_seq=ckpt_100.seq,
                checkpoint_mem=ckpt_100.memory,
            )
            for seq in range(101, 201):
                _send_data(ctx.state, ctx.verifier, ctx.checkpoint_manager, seq)

        latest_ckpt = ctx.checkpoint_manager.get_latest_checkpoint()
        self.assertEqual(latest_ckpt.seq, 200)

        ok, reason = validate_memory_ticket(
            ticket,
            expected_session_id=sid,
            expected_client_id=CLIENT_ID,
            expected_epoch=EPOCH,
            min_last_seq=latest_ckpt.seq,
        )
        self.assertFalse(ok)
        self.assertIn("rollback", reason)
        self.assertEqual(ctx.state.last_seq, 200)

    def test_nonce_race(self):
        """nonce_race: two threads consume same nonce → exactly one success."""
        sid = f"nonce-race-{int(time.time()*1e6)}"
        store = TicketNonceStore()

        ticket = build_memory_ticket(
            session_id=sid,
            client_id=CLIENT_ID,
            epoch=EPOCH,
            last_seq=100,
            last_mem="mem-100",
            checkpoint_seq=100,
            checkpoint_mem="mem-100",
        )

        results: list[bool | None] = [None, None]
        barrier = threading.Barrier(2)

        def worker(idx):
            barrier.wait()
            nonce = ticket["ticket_nonce"]
            results[idx] = store.consume(nonce)

        t0 = threading.Thread(target=worker, args=(0,))
        t1 = threading.Thread(target=worker, args=(1,))
        t0.start()
        t1.start()
        t0.join(timeout=5)
        t1.join(timeout=5)

        self.assertIn(True, results)
        self.assertIn(False, results)
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)


class RecoveryWindowCSVContractTests(unittest.TestCase):
    """Verify CSV output schema and row count for run_recovery_window_experiment."""

    def test_csv_has_expected_columns(self):
        csv_path = Path("results/submission_revision/recovery_window_experiment.csv")
        if not csv_path.exists():
            self.skipTest(f"CSV not found: {csv_path}")

        with csv_path.open(newline="", encoding="utf-8") as f:
            rows = list(csv_mod.DictReader(f))

        required_columns = {
            "scenario", "checkpoint_interval", "payload_size", "repeat_id",
            "ticket_seq", "client_seq", "server_seq", "floor_seq", "response_seq",
            "gap", "response_advance", "request_auth_ok", "response_auth_ok",
            "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
            "success", "reason",
        }
        if rows:
            self.assertTrue(
                required_columns.issubset(rows[0].keys()),
                f"Missing columns: {required_columns - set(rows[0].keys())}",
            )

    def test_csv_row_count_matches_contract(self):
        csv_path = Path("results/submission_revision/recovery_window_experiment.csv")
        if not csv_path.exists():
            self.skipTest(f"CSV not found: {csv_path}")

        with csv_path.open(newline="", encoding="utf-8") as f:
            rows = list(csv_mod.DictReader(f))

        self.assertEqual(len(rows), 540, f"Expected 540 rows, got {len(rows)}")

        non_race = [r for r in rows if r["scenario"] != "nonce_race"]
        race = [r for r in rows if r["scenario"] == "nonce_race"]
        self.assertEqual(len(non_race), 480)
        self.assertEqual(len(race), 60)

    def test_scenario_invariants_from_csv(self):
        csv_path = Path("results/submission_revision/recovery_window_experiment.csv")
        if not csv_path.exists():
            self.skipTest(f"CSV not found: {csv_path}")

        with csv_path.open(newline="", encoding="utf-8") as f:
            rows = list(csv_mod.DictReader(f))

        for row in rows:
            scenario = row["scenario"]
            success = row["success"].lower() == "true"

            if scenario == "control":
                self.assertTrue(success, f"control should succeed: {row}")
                self.assertEqual(row["ticket_seq"], row["server_seq"])
            elif scenario == "ack_loss":
                self.assertTrue(success, f"ack_loss should succeed: {row}")
            elif scenario == "old_ticket_within_window":
                self.assertTrue(success, f"old_ticket_within_window should succeed: {row}")
            elif scenario == "below_floor":
                self.assertFalse(success, f"below_floor should fail: {row}")
                self.assertTrue(
                    row["state_unchanged"].lower() == "true",
                    "below_floor should not change server state",
                )
            elif scenario == "nonce_race":
                race_count = int(row.get("race_winner_count", 0))
                self.assertEqual(race_count, 1, f"nonce_race should have exactly 1 winner")


# ── Task 7: O(k) vs O(n) Benchmark Tests ────────────────────────────────


class CheckpointCostComparisonTests(unittest.TestCase):
    """Task 7: verify prepare_history, measure_gmcp_recovery, measure_authenticated_chain_recovery."""

    def _make_prepared(self, n=20, k=10, repeat_id=1):
        from run_checkpoint_cost_comparison import prepare_history
        workdir = tempfile.mkdtemp(prefix=f"test_cost_{n}_{k}_")
        self.addCleanup(lambda: __import__("shutil").rmtree(workdir, ignore_errors=True))
        return prepare_history(n, k, repeat_id, workdir)

    def test_prepare_history_creates_files_and_checkpoint(self):
        p = self._make_prepared(20, 10, 1)
        self.assertTrue(os.path.exists(p.history_path))
        self.assertTrue(os.path.exists(p.chain_path))
        self.assertEqual(p.checkpoint_seq, 10)
        self.assertEqual(p.final_seq, 20)
        self.assertIsNotNone(p.checkpoint_record)
        self.assertEqual(p.checkpoint_record["seq"], 10)

    def test_gmcp_replay_count_equals_offset(self):
        """For n=20, k=10 and offsets 1/5/9: GMCP replay count == offset."""
        from run_checkpoint_cost_comparison import measure_gmcp_recovery
        p = self._make_prepared(20, 10, 1)
        for offset in [1, 5, 9]:
            m = measure_gmcp_recovery(p, offset)
            self.assertEqual(m.replay_count, offset,
                             f"offset={offset}: expected replay_count={offset}, got {m.replay_count}")
            self.assertEqual(m.protocol, "gmcp_r")

    def test_chain_replay_count_equals_target_seq(self):
        """For n=20, k=10 and offsets 1/5/9: chain replay count == target seq."""
        from run_checkpoint_cost_comparison import measure_authenticated_chain_recovery
        p = self._make_prepared(20, 10, 1)
        for offset in [1, 5, 9]:
            target_seq = p.checkpoint_seq + offset  # 11, 15, 19
            m = measure_authenticated_chain_recovery(p, offset)
            self.assertEqual(m.replay_count, target_seq,
                             f"offset={offset}: expected replay_count={target_seq}, got {m.replay_count}")
            self.assertEqual(m.protocol, "authenticated_hash_chain")

    def test_both_protocols_reconstruct_correct_state(self):
        """Both GMCP-R and chain reconstruct matching target states."""
        from run_checkpoint_cost_comparison import (
            measure_gmcp_recovery, measure_authenticated_chain_recovery,
            prepare_history,
        )
        p = self._make_prepared(20, 10, 1)

        for offset in [1, 5, 9]:
            gmcp_m = measure_gmcp_recovery(p, offset)
            chain_m = measure_authenticated_chain_recovery(p, offset)

            # GMCP-R state match
            self.assertTrue(gmcp_m.target_state_match,
                            f"GMCP state mismatch at offset={offset}")
            # GMCP reconstructed_mem should be non-empty
            self.assertTrue(len(gmcp_m.reconstructed_mem) > 0,
                            f"GMCP reconstructed_mem empty at offset={offset}")

            # Chain reconstructed_hash should be non-empty
            self.assertTrue(len(chain_m.reconstructed_hash) > 0,
                            f"Chain reconstructed_hash empty at offset={offset}")

    def test_gmcp_reads_fewer_bytes_at_offset_1(self):
        """GMCP reads fewer bytes than chain at offset=1 (k=10)."""
        from run_checkpoint_cost_comparison import (
            measure_gmcp_recovery, measure_authenticated_chain_recovery,
        )
        p = self._make_prepared(20, 10, 1)

        gmcp_m = measure_gmcp_recovery(p, 1)
        chain_m = measure_authenticated_chain_recovery(p, 1)

        self.assertLess(gmcp_m.recovery_material_bytes, chain_m.recovery_material_bytes,
                        f"GMCP bytes ({gmcp_m.recovery_material_bytes}) should be < "
                        f"chain bytes ({chain_m.recovery_material_bytes}) at offset=1")

    def test_smoke_run_produces_expected_row_count(self):
        """Smoke run with small parameters produces correct number of rows."""
        from run_checkpoint_cost_comparison import (
            prepare_history, measure_gmcp_recovery,
            measure_authenticated_chain_recovery, measurement_to_row, CSV_COLUMNS,
        )
        import csv as csv_mod

        # n=20, k=10, offsets=[1,5,9], 2 protocols, 2 repeats = 12 rows
        n, k, repeats = 20, 10, 2
        offsets = [1, 5, 9]

        with tempfile.TemporaryDirectory(prefix="test_smoke_") as outdir:
            csv_path = os.path.join(outdir, "test.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv_mod.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()
                row_count = 0
                for repeat_id in range(1, repeats + 1):
                    with tempfile.TemporaryDirectory(prefix=f"prep_{repeat_id}_") as workdir:
                        p = prepare_history(n, k, repeat_id, workdir)
                        for offset in offsets:
                            gmcp_m = measure_gmcp_recovery(p, offset)
                            writer.writerow(measurement_to_row(gmcp_m))
                            row_count += 1
                            chain_m = measure_authenticated_chain_recovery(p, offset)
                            writer.writerow(measurement_to_row(chain_m))
                            row_count += 1

            # Verify CSV
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = list(csv_mod.DictReader(f))

            self.assertEqual(len(reader), 12)
            self.assertEqual(row_count, 12)

            # All state matches should be True
            for row in reader:
                self.assertEqual(row["target_state_match"], "True",
                                 f"State mismatch in row: {row['protocol']} offset={row['offset']}")
                self.assertGreater(int(row["replay_count"]), 0)


# ── Task 9: Manifest, Validation and Plots Contract Tests ────────────────


class ManifestTests(unittest.TestCase):
    """Test sha256_file, write_manifest, and validate_revision."""

    def test_sha256_file_is_stable(self):
        """sha256_file returns same hash for same content."""
        from gmcp.experiment_manifest import sha256_file

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"hello world\n")
            path = f.name
        self.addCleanup(os.unlink, path)

        h1 = sha256_file(path)
        h2 = sha256_file(path)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # hex digest

    def test_sha256_file_different_for_different_content(self):
        from gmcp.experiment_manifest import sha256_file

        paths = []
        for content in [b"alpha", b"beta"]:
            f = tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False)
            f.write(content)
            f.close()
            paths.append(f.name)
            self.addCleanup(os.unlink, f.name)

        self.assertNotEqual(sha256_file(paths[0]), sha256_file(paths[1]))

    def test_write_manifest_creates_json_with_hashes(self):
        """write_manifest creates manifest.json with expected fields."""
        from gmcp.experiment_manifest import write_manifest

        with tempfile.TemporaryDirectory(prefix="manifest_") as tmpdir:
            # Create a dummy CSV
            csv_path = os.path.join(tmpdir, "test.csv")
            with open(csv_path, "w", newline="") as f:
                f.write("a,b\n1,2\n")

            manifest_path = write_manifest(
                tmpdir,
                csv_files={"test": "test.csv"},
            )
            self.assertTrue(os.path.isfile(manifest_path))

            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

            self.assertIn("protocol", manifest)
            self.assertEqual(manifest["protocol"], "GMCP-R")
            self.assertIn("csv_hashes", manifest)
            self.assertIn("test", manifest["csv_hashes"])
            self.assertIn("sha256", manifest["csv_hashes"]["test"])
            self.assertIn("python_version", manifest)
            self.assertIn("git", manifest)

    def test_validate_revision_detects_changed_hashes(self):
        """validate_revision detects when CSV has changed after manifest."""
        from gmcp.experiment_manifest import write_manifest, validate_revision

        with tempfile.TemporaryDirectory(prefix="validate_") as tmpdir:
            csv_path = os.path.join(tmpdir, "recovery_window_experiment.csv")
            with open(csv_path, "w", newline="") as f:
                writer = csv_mod.DictWriter(f, fieldnames=[
                    "scenario", "checkpoint_interval", "payload_size", "repeat_id",
                    "ticket_seq", "client_seq", "server_seq", "floor_seq", "response_seq",
                    "gap", "response_advance", "request_auth_ok", "response_auth_ok",
                    "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
                    "success", "reason", "recovery_latency_ms",
                ])
                writer.writeheader()
                writer.writerow({
                    "scenario": "control", "checkpoint_interval": "100",
                    "payload_size": "128", "repeat_id": "1",
                    "ticket_seq": "100", "client_seq": "100", "server_seq": "100",
                    "floor_seq": "100", "response_seq": "100",
                    "gap": "0", "response_advance": "0",
                    "request_auth_ok": "True", "response_auth_ok": "True",
                    "nonce_match": "True", "nonce_consumed": "True",
                    "race_winner_count": "0", "state_unchanged": "False",
                    "success": "True", "reason": "ok", "recovery_latency_ms": "1.5",
                })

            write_manifest(tmpdir, csv_files={"recovery_window": csv_path})

            # Now modify the CSV
            with open(csv_path, "a", newline="") as f:
                f.write("control,100,128,2,100,100,100,100,100,0,0,True,True,True,True,0,False,True,ok,1.5\n")

            violations = validate_revision(tmpdir, expected_repeats=1)
            # Should detect hash mismatch
            hash_violations = [v for v in violations if "hash mismatch" in v]
            self.assertGreater(len(hash_violations), 0,
                               f"Expected hash mismatch violation, got: {violations}")


class ValidationContractTests(unittest.TestCase):
    """Test that validate_submission_revision catches common errors."""

    def test_detects_duplicate_composite_keys(self):
        """Validator catches duplicate (scenario, interval, payload, repeat) keys."""
        from validate_submission_revision import _validate_recovery_window

        rows = [
            {"scenario": "control", "checkpoint_interval": "100", "payload_size": "128",
             "repeat_id": "1", "success": "True", "state_unchanged": "False",
             "race_winner_count": "0"},
            {"scenario": "control", "checkpoint_interval": "100", "payload_size": "128",
             "repeat_id": "1", "success": "True", "state_unchanged": "False",
             "race_winner_count": "0"},
        ]
        violations = _validate_recovery_window(rows, expected_repeats=1)
        self.assertTrue(any("duplicate" in v.lower() for v in violations))

    def test_detects_below_floor_accepted(self):
        """Validator catches below_floor rows that are accepted."""
        from validate_submission_revision import _validate_recovery_window

        rows = [
            {"scenario": "below_floor", "checkpoint_interval": "100", "payload_size": "128",
             "repeat_id": "1", "success": "True", "state_unchanged": "False",
             "race_winner_count": "0"},
        ]
        violations = _validate_recovery_window(rows, expected_repeats=1)
        self.assertTrue(any("below_floor" in v.lower() for v in violations))

    def test_detects_wrong_race_winner_count(self):
        """Validator catches nonce_race with wrong winner count."""
        from validate_submission_revision import _validate_recovery_window

        rows = [
            {"scenario": "nonce_race", "checkpoint_interval": "100", "payload_size": "128",
             "repeat_id": "1", "success": "True", "state_unchanged": "False",
             "race_winner_count": "2"},  # Should be 1
        ]
        violations = _validate_recovery_window(rows, expected_repeats=1)
        self.assertTrue(any("winner" in v.lower() for v in violations))

    def test_detects_state_mismatch_in_checkpoint_cost(self):
        """Validator catches state mismatches in checkpoint cost CSV."""
        from validate_submission_revision import _validate_checkpoint_cost

        rows = [
            {"protocol": "gmcp_r", "n": "20", "k": "10", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "False"},
        ]
        violations = _validate_checkpoint_cost(rows, expected_repeats=1)
        self.assertTrue(any("state mismatch" in v.lower() for v in violations))

    def test_detects_missing_matrix_combos(self):
        """Validator catches missing (n, k) combinations in checkpoint cost."""
        from validate_submission_revision import _validate_checkpoint_cost

        rows = [
            {"protocol": "gmcp_r", "n": "20", "k": "10", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "True"},
            {"protocol": "gmcp_r", "n": "30", "k": "10", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "True"},
            {"protocol": "gmcp_r", "n": "30", "k": "5", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "True"},
            # n=20,k=10 and n=30,k=10 and n=30,k=5 present, but n=20,k=5 missing
        ]
        violations = _validate_checkpoint_cost(rows, expected_repeats=1)
        # Should detect missing combo (20, 5)
        self.assertTrue(any("missing" in v.lower() for v in violations),
                        f"Expected missing combo violation, got: {violations}")

    def test_detects_accepted_adaptive_attack_on_auth_chain(self):
        """Validator catches authenticated hash chain accepting tampered packet."""
        from validate_submission_revision import _validate_adaptive_attack

        rows = [
            {"protocol": "hash_chain", "attack_applicable": "True", "attack_accepted": "True"},
            {"protocol": "authenticated_hash_chain", "attack_applicable": "True",
             "attack_accepted": "True"},  # Should be False
        ]
        violations = _validate_adaptive_attack(rows)
        self.assertTrue(any("authenticated_hash_chain" in v.lower() for v in violations))

    def test_detects_na_attack_injected(self):
        """Validator catches N/A attacks being injected for seq_mac/ticket_only."""
        from validate_submission_revision import _validate_baseline

        rows = [
            {"protocol": "seq_mac", "attack_type": "prev_mem",
             "message_count": "100", "repeat_id": "1",
             "attack_injected": "True", "attack_detected_by_server": "False"},
        ]
        violations = _validate_baseline(rows)
        self.assertTrue(any("N/A" in v or "na" in v.lower() for v in violations))

    def test_detects_duplicate_checkpoint_cost_keys(self):
        """Validator catches duplicate composite keys in checkpoint cost."""
        from validate_submission_revision import _validate_checkpoint_cost

        rows = [
            {"protocol": "gmcp_r", "n": "20", "k": "10", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "True"},
            {"protocol": "gmcp_r", "n": "20", "k": "10", "offset": "1",
             "repeat_id": "1", "replay_count": "1", "recovery_material_bytes": "100",
             "target_state_match": "True"},
        ]
        violations = _validate_checkpoint_cost(rows, expected_repeats=1)
        self.assertTrue(any("duplicate" in v.lower() for v in violations))


class PlotGenerationTests(unittest.TestCase):
    """Test that plot functions handle missing data gracefully."""

    def test_plots_handle_missing_csvs(self):
        """Plot functions write placeholder PNGs when CSVs are missing."""
        from plot_submission_revision import (
            plot_baseline_capability,
            plot_adaptive_tamper,
            plot_recovery_window,
            plot_nonce_race,
            plot_recovery_time,
            plot_replay_count,
            plot_byte_cost,
            plot_concurrency_ci,
            plot_observed_rate_confidence,
        )

        with tempfile.TemporaryDirectory(prefix="plot_test_") as tmpdir:
            fake_csv = os.path.join(tmpdir, "nonexistent.csv")

            plot_fns = [
                ("baseline_capability", plot_baseline_capability),
                ("adaptive_tamper", plot_adaptive_tamper),
                ("recovery_window", plot_recovery_window),
                ("nonce_race", plot_nonce_race),
                ("recovery_time", plot_recovery_time),
                ("replay_count", plot_replay_count),
                ("byte_cost", plot_byte_cost),
                ("concurrency_ci", plot_concurrency_ci),
                ("observed_rate", plot_observed_rate_confidence),
            ]

            for name, fn in plot_fns:
                out = os.path.join(tmpdir, f"test_{name}.png")
                fn(fake_csv, out)
                self.assertTrue(os.path.isfile(out),
                                f"{name}: PNG not created at {out}")
                self.assertGreater(os.path.getsize(out), 0,
                                   f"{name}: PNG is empty at {out}")

    def test_generate_all_plots_returns_nine_figures(self):
        """generate_all_plots returns dict with 9 entries."""
        from plot_submission_revision import generate_all_plots

        with tempfile.TemporaryDirectory(prefix="plot_all_") as tmpdir:
            plots = generate_all_plots(tmpdir)
            self.assertEqual(len(plots), 9,
                             f"Expected 9 plots, got {len(plots)}: {list(plots.keys())}")
            for name, path in plots.items():
                self.assertTrue(os.path.isfile(path),
                                f"Plot '{name}' not created: {path}")


if __name__ == "__main__":
    unittest.main()
