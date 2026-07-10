# GMCP-R Submission Experiment Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修正 GMCP-R 协议实现与实验设计，生成可审计的投稿版 CSV、汇总数据、图表和运行清单。

**Architecture:** 先统一规范认证、恢复响应、票据/Checkpoint 服务端边界和 session 锁，再让 baseline、恢复窗口、O(k)/O(n) 与并发实验复用这些核心接口。所有新产物写入 `results/submission_revision/`，由独立验证器从原始 CSV 重算汇总并校验图表输入。

**Tech Stack:** Python 3.11、`unittest/threading/socket/csv/json/pathlib/statistics`、NumPy、Pandas、Matplotlib、HMAC-SHA256、SHA-256。

## Global Constraints

- 不修改论文 Markdown、DOCX 或 PDF。
- 不登录截图中已暴露密码的服务器；本地验证优先。
- `TICKET_AUTH_KEY` 与 `CHECKPOINT_AUTH_KEY` 只允许服务器侧代码访问。
- 客户端只验证 `K_D` 认证的完整 `RECOVERY_RESPONSE`，不得验证 MemoryTicket HMAC。
- HMAC 使用 UTF-8、排序键、紧凑分隔符、`ensure_ascii=False` 和 `allow_nan=False`。
- DATA HMAC 覆盖除 `auth_tag` 外的完整报文，并验证 `protocol/session_id/sender_id/epoch`。
- 主 baseline 使用 Authenticated Hash Chain；普通 Hash Chain 只作负面对照。
- Seq+MAC 与 Ticket Only 的历史指针攻击记录为 N/A，不进入检测率分母。
- 新产物写入 `results/submission_revision/`，不覆盖已有 `results/` 或 `paper_data/`。
- CI 使用独立运行均值；100% 比例同时记录分子、分母和精确二项下界。
- 工作区已有用户修改；只暂存任务明确列出的文件，禁止 `git add .`。
- 测试使用 `.venv/bin/python`；不得假定 pytest 或 SciPy 可用。
- 网络实验 runner 提供 `--spawn-server`，自行启动、探活并终止匹配版本的本地服务器，保证单任务 smoke test 可独立运行。

---

## File Map

Protocol core:

- Modify `gmcp/crypto_utils.py`: strict canonical JSON and generic HMAC helpers.
- Modify `gmcp/protocol.py`: required DATA fields and context binding.
- Create `gmcp/recovery_protocol.py`: recovery request/response authentication.
- Modify `gmcp/ticket.py`: atomic nonce store and server-only fixtures.
- Modify `gmcp/checkpoint_manager.py`: authoritative Checkpoint signing and injectable storage.
- Modify `gmcp/checkpoint.py`: deprecated compatibility wrapper.
- Create `gmcp/session_registry.py`: registry and per-session locks.
- Modify `real_tcp_server_with_ticket.py`: shared recovery/session interfaces.

Experiments:

- Create `gmcp/baselines/authenticated_hash_chain.py`.
- Modify `real_baseline_server.py` and `run_real_baseline_comparison.py`.
- Create `run_hash_chain_adaptive_attack.py`.
- Modify `run_real_recovery_experiment.py`, `run_real_ticket_recovery_experiment.py`, and `run_checkpoint_recovery_experiment.py`.
- Create `generate_ticket_fixtures.py` as a server-side-only invalid-ticket fixture generator.
- Create `run_recovery_window_experiment.py` and `run_checkpoint_cost_comparison.py`.
- Modify `run_concurrent_experiment.py` and `gmcp/experiment_stats.py`.

Artifacts/tests:

- Create `gmcp/experiment_manifest.py`, `validate_submission_revision.py`, `plot_submission_revision.py`, and `run_submission_revision.py`.
- Create focused tests under `tests/test_protocol_security.py`, `tests/test_recovery_security.py`, `tests/test_authenticated_hash_chain.py`, `tests/test_experiment_statistics.py`, and `tests/test_submission_experiment_contracts.py`.

---

### Task 1: Strict Canonical Authentication and DATA Context Binding

**Files:**
- Modify: `gmcp/crypto_utils.py:14-37`
- Modify: `gmcp/protocol.py:1-83`
- Test: `tests/test_protocol_security.py`

**Interfaces:**
- Produces `canonical_json(data: Mapping[str, Any]) -> str`.
- Produces `with_hmac(key, message, tag_field="auth_tag") -> Dict[str, Any]`.
- Produces `verify_tagged_hmac(key, message, tag_field="auth_tag") -> bool`.
- Preserves `hmac_sha256_hex()` and `verify_hmac()` signatures.

- [ ] **Step 1: Write failing tests**

```python
import math
import unittest
from gmcp.crypto_utils import canonical_json
from gmcp.memory import initial_memory
from gmcp.packet import build_data_packet
from gmcp.protocol import GMCPState, GMCPVerifier

class ProtocolSecurityTests(unittest.TestCase):
    def make_verifier(self):
        mem = initial_memory("s", "client-001", 1, "demo-seed")
        state = GMCPState("s", "client-001", 1, 0, mem)
        return state, GMCPVerifier(state)

    def test_canonical_json_is_stable_and_rejects_nan(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')
        with self.assertRaises(ValueError):
            canonical_json({"x": math.nan})

    def test_wrong_sender_with_valid_hmac_is_rejected_without_mutation(self):
        state, verifier = self.make_verifier()
        before = (state.last_seq, state.last_mem)
        packet = build_data_packet("s", "different-sender", 1, 1, state.last_mem, "p")
        self.assertEqual(verifier.verify_data_packet(packet), (False, "sender_id mismatch"))
        self.assertEqual((state.last_seq, state.last_mem), before)

    def test_wrong_protocol_and_missing_field_are_rejected(self):
        state, verifier = self.make_verifier()
        packet = build_data_packet("s", "client-001", 1, 1, state.last_mem, "p", protocol="seq_mac")
        self.assertEqual(verifier.verify_data_packet(packet), (False, "protocol mismatch"))
        packet = build_data_packet("s", "client-001", 1, 1, state.last_mem, "p")
        packet.pop("payload_hash")
        self.assertIn("missing DATA fields", verifier.verify_data_packet(packet)[1])
```

- [ ] **Step 2: Verify tests fail**

Run `.venv/bin/python -m unittest tests.test_protocol_security -v`.

Expected: `canonical_json` is missing and current verifier accepts wrong sender/protocol.

- [ ] **Step 3: Implement canonical helpers**

```python
def canonical_json(data):
    return json.dumps(dict(data), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)

def with_hmac(key, message, tag_field="auth_tag"):
    result = dict(message)
    result.pop(tag_field, None)
    result[tag_field] = hmac.new(
        key, canonical_json(result).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return result

def verify_tagged_hmac(key, message, tag_field="auth_tag"):
    received = message.get(tag_field)
    if not isinstance(received, str) or not received:
        return False
    unsigned = dict(message)
    unsigned.pop(tag_field, None)
    expected = hmac.new(
        key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, received)
```

Compatibility helpers delegate to these rules.

- [ ] **Step 4: Implement DATA validation**

Define required fields `{type, protocol, session_id, sender_id, epoch, seq, prev_mem, payload, payload_hash, timestamp, auth_tag}` and allow optional `checkpoint_interval`. Reject missing/unknown fields, then validate type, protocol, HMAC, session, sender, epoch, integer seq, payload hash, and previous memory before atomic state update.

- [ ] **Step 5: Verify and commit**

Run `.venv/bin/python -m unittest tests.test_protocol_security tests.test_experiment_contracts -v`.

Expected: PASS.

```bash
git add gmcp/crypto_utils.py gmcp/protocol.py tests/test_protocol_security.py
git commit -m "fix: bind data authentication to protocol context"
```

---

### Task 2: Authenticated Recovery Request and Response

**Files:**
- Create: `gmcp/recovery_protocol.py`
- Modify: `real_tcp_server_with_ticket.py:50-285`
- Modify: `run_real_recovery_experiment.py:116-209`
- Modify: `run_checkpoint_recovery_experiment.py:101-189`
- Test: `tests/test_recovery_security.py`

**Interfaces:**
- Produces `build_recovery_request(...) -> Dict[str, Any]` with random `recovery_nonce` and `auth_tag`.
- Produces `verify_recovery_request(...) -> Tuple[bool, str]`.
- Produces `build_recovery_response(..., extra=None) -> Dict[str, Any]` with `recovery_auth_tag`.
- Produces `verify_recovery_response(..., expected_recovery_nonce) -> Tuple[bool, str]`.

- [ ] **Step 1: Write failing response tests**

```python
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
```

- [ ] **Step 2: Verify missing-module failure**

Run `.venv/bin/python -m unittest tests.test_recovery_security -v`.

- [ ] **Step 3: Implement recovery helpers**

Use only `DATA_AUTH_KEY`. Sign every success and failure response. Verify HMAC before context/nonce. Successful responses require `server_last_seq`, `server_last_mem`, `checkpoint_seq`, `checkpoint_mem`, and `memory_ticket`.

- [ ] **Step 4: Migrate server and clients**

Every return in `handle_recovery_request` calls `build_recovery_response`. Client scripts remove `verify_memory_ticket_for_recovery`, call `verify_recovery_response`, update state only on verified success, and store replacement tickets without reading their HMAC.

Use this success gate:

```python
verified, verify_reason = verify_recovery_response(
    response, session_id, EPOCH, request["recovery_nonce"]
)
ok = verified and response.get("ok") is True
```

- [ ] **Step 5: Add static client-boundary test**

Assert the three recovery client sources contain neither `TICKET_AUTH_KEY` nor `verify_memory_ticket_for_recovery`.

- [ ] **Step 6: Verify and commit**

Run `.venv/bin/python -m unittest tests.test_recovery_security tests.test_protocol_security tests.test_experiment_contracts -v`.

```bash
git add gmcp/recovery_protocol.py real_tcp_server_with_ticket.py \
  run_real_recovery_experiment.py run_checkpoint_recovery_experiment.py \
  tests/test_recovery_security.py
git commit -m "fix: authenticate complete recovery responses"
```

---

### Task 3: Atomic Nonces and Unified Checkpoints

**Files:**
- Modify: `gmcp/ticket.py:1-213`
- Modify: `gmcp/checkpoint_manager.py:1-336`
- Modify: `gmcp/checkpoint.py:1-38`
- Create: `generate_ticket_fixtures.py`
- Modify: `run_real_ticket_recovery_experiment.py:1-519`
- Test: `tests/test_recovery_security.py`

**Interfaces:**
- Produces `TicketNonceStore.is_unused/consume/clear`.
- Produces `sign_checkpoint_fields()` and `verify_checkpoint_fields()` using `CHECKPOINT_AUTH_KEY`.

- [ ] **Step 1: Write failing tests**

Use `threading.Barrier` with two workers consuming the same nonce; expected results `[False, True]`. Build and verify a compatibility Checkpoint, mutate memory and expect failure, then prove changing `DATA_AUTH_KEY` does not affect Checkpoint verification.

- [ ] **Step 2: Verify tests fail**

Run `.venv/bin/python -m unittest tests.test_recovery_security -v`.

- [ ] **Step 3: Implement atomic store**

```python
class TicketNonceStore:
    def __init__(self):
        self._used = set()
        self._lock = threading.Lock()
    def is_unused(self, nonce):
        with self._lock:
            return bool(nonce) and nonce not in self._used
    def consume(self, nonce):
        with self._lock:
            if not nonce or nonce in self._used:
                return False
            self._used.add(nonce)
            return True
    def clear(self):
        with self._lock:
            self._used.clear()
```

Existing wrappers delegate to one default store; remove unlocked membership/add operations.

- [ ] **Step 4: Centralize Checkpoint signatures**

Put dict-level sign/verify helpers in `checkpoint_manager.py`. Add optional `storage_dir: Path` to `CheckpointManager`. Make `gmcp/checkpoint.py` a deprecated wrapper and remove its `DATA_AUTH_KEY` import.

- [ ] **Step 5: Move invalid-ticket creation server-side**

`generate_ticket_fixtures.py` is a server-side helper that writes named, server-signed fixtures to a temporary JSON file. `run_real_ticket_recovery_experiment.py` reads that file as opaque test input and never imports/recomputes `TICKET_AUTH_KEY` values. The helper and fixture file are only enabled for local experiment mode.

- [ ] **Step 6: Verify and commit**

Run `.venv/bin/python -m unittest tests.test_recovery_security tests.test_experiment_contracts -v`.

```bash
git add gmcp/ticket.py gmcp/checkpoint_manager.py gmcp/checkpoint.py \
  generate_ticket_fixtures.py \
  run_real_ticket_recovery_experiment.py tests/test_recovery_security.py
git commit -m "fix: isolate ticket and checkpoint server state"
```

---

### Task 4: Per-Session Locking

**Files:**
- Create: `gmcp/session_registry.py`
- Modify: `real_tcp_server_with_ticket.py:28-505`
- Modify: `real_baseline_server.py:42-377`
- Test: `tests/test_recovery_security.py`

**Interfaces:**
- Produces `SessionContext(state, verifier, checkpoint_manager, stats, lock)`.
- Produces `SessionRegistry.get_or_create(session_id, checkpoint_interval)`.
- Supports `lock_strategy in {global_lock, per_session_lock}`.

- [ ] **Step 1: Write failing overlap tests**

Hold session A's lock and assert session B's lock can be acquired within one second in per-session mode. In global mode assert both contexts reference the same lock.

- [ ] **Step 2: Implement registry**

Use a short registry lock only around dictionary lookup/creation. Inject a context factory and validate checkpoint interval in `[10, 1000]`.

```python
def get_or_create(self, session_id, checkpoint_interval):
    with self._registry_lock:
        context = self._contexts.get(session_id)
        if context is None:
            context = self._factory(session_id, checkpoint_interval)
            context.lock = self._global_lock if self.lock_strategy == "global_lock" else threading.Lock()
            self._contexts[session_id] = context
        return context
```

- [ ] **Step 3: Migrate both servers**

Socket I/O and JSON parsing remain outside locks. DATA/recovery state uses `context.lock`; nonce consumption only uses `TicketNonceStore.consume()`.

- [ ] **Step 4: Verify and commit**

Run recovery tests plus a two-session local smoke test; expected both sessions accept seq 1 independently.

```bash
git add gmcp/session_registry.py real_tcp_server_with_ticket.py \
  real_baseline_server.py tests/test_recovery_security.py
git commit -m "refactor: isolate server state by session"
```

---

### Task 5: Authenticated Hash Chain and Fair Baseline

**Files:**
- Create: `gmcp/baselines/authenticated_hash_chain.py`
- Modify: `real_baseline_server.py`
- Modify: `run_real_baseline_comparison.py`
- Create: `run_hash_chain_adaptive_attack.py`
- Test: `tests/test_authenticated_hash_chain.py`

**Interfaces:**
- Produces authenticated state, packet builder and verifier with protocol `authenticated_hash_chain`.
- Produces `AttackApplication(packet, attack_property, attack_applicable, attack_injected, expected_capability)`.

- [ ] **Step 1: Write failing tests**

Test that plain Hash Chain accepts payload plus recomputed public hashes, Authenticated Hash Chain rejects the same mutation without a new HMAC, and Seq+MAC history-pointer adaptation returns N/A without modifying the packet.

- [ ] **Step 2: Implement Authenticated Hash Chain**

Reuse plain-chain hash functions; add full-message HMAC. Validate type, protocol, session, sender, epoch, seq, payload hash, chain hash and previous hash before state mutation.

- [ ] **Step 3: Implement fair attack adapter**

Map `history_pointer` to `prev_mem` for GMCP-R and `prev_hash` for authenticated chain. Return `attack_applicable=False` for Seq+MAC/Ticket Only. Add CSV fields `attack_property`, `attack_applicable`, `expected_capability`, and `observed_detected`.

- [ ] **Step 4: Implement adaptive negative-control runner**

Write `hash_chain_adaptive_attack.csv` with `payload_modified`, `public_hashes_recomputed`, `auth_tag_recomputed=False`, and `accepted`. Plain chain stays outside the fair performance summary.

- [ ] **Step 5: Verify and commit**

```bash
.venv/bin/python -m unittest tests.test_authenticated_hash_chain -v
GMCP_REPEATS=1 GMCP_OUTPUT_ROOT=results/submission_revision/smoke \
  .venv/bin/python run_real_baseline_comparison.py --spawn-server
```

Expected: adaptive plain chain accepted, authenticated chain rejected, N/A excluded.

```bash
git add gmcp/baselines/authenticated_hash_chain.py real_baseline_server.py \
  run_real_baseline_comparison.py run_hash_chain_adaptive_attack.py \
  tests/test_authenticated_hash_chain.py
git commit -m "feat: add fair authenticated hash chain baseline"
```

---

### Task 6: Recovery Window and Nonce Race Experiment

**Files:**
- Create: `run_recovery_window_experiment.py`
- Modify: `real_tcp_server_with_ticket.py`
- Test: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- Produces `run_window_scenario(scenario, checkpoint_interval, payload_size, repeat_id) -> Dict[str, Any]`.
- Produces 540 full rows: 480 non-race plus 60 race.

- [ ] **Step 1: Write one-repeat scenario tests**

Assert control `100/100/100`; ACK-loss and old-ticket `100/149/149`; below-floor rejected with unchanged state and unused nonce; race has exactly one success and one authenticated replay rejection.

- [ ] **Step 2: Implement deterministic setup**

Use unique sessions. Save seq=100 ticket without inspecting it. For ACK loss, send 101-149 and discard responses. For old-ticket, advance server through another connection. For floor rejection, create a newer Checkpoint. Use `threading.Barrier(3)` for the nonce race.

- [ ] **Step 3: Emit audit columns**

Include scenario, ticket/client/server/floor/response seq values, gap, response advance, request/response auth, nonce match/consume/race counts, state-unchanged flag, success and reason.

- [ ] **Step 4: Smoke test and commit**

```bash
GMCP_REPEATS=1 GMCP_OUTPUT_ROOT=results/submission_revision/smoke \
  .venv/bin/python run_recovery_window_experiment.py --spawn-server
```

Expected: 18 rows and all scenario invariants pass.

```bash
git add run_recovery_window_experiment.py real_tcp_server_with_ticket.py \
  tests/test_submission_experiment_contracts.py
git commit -m "feat: exercise recovery windows and nonce races"
```

---

### Task 7: Persistent O(k) Versus O(n) Benchmark

**Files:**
- Create: `run_checkpoint_cost_comparison.py`
- Test: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- Produces `prepare_history(n, k, repeat_id, workdir) -> PreparedHistory`.
- Produces `measure_gmcp_recovery(prepared, offset) -> RecoveryMeasurement`.
- Produces `measure_authenticated_chain_recovery(prepared, offset) -> RecoveryMeasurement`.

- [ ] **Step 1: Write small-fixture tests**

For n=20, k=10 and offsets 1/5/9, GMCP replay count equals offset; chain replay count equals target seq; both states match; GMCP reads fewer bytes at offset 1.

- [ ] **Step 2: Implement persistent prepared history**

Write deterministic JSON Lines in `TemporaryDirectory`; return byte counts from the same reader used for recovery. Store authenticated Checkpoint at `n-k`.

- [ ] **Step 3: Implement timed recovery**

Use `perf_counter_ns()` around material read, authentication and reconstruction only. Perform one unrecorded warmup. Record replay count, recovery material bytes, logical bytes read, auth records verified, target/reconstructed state and match.

- [ ] **Step 4: Implement matrices**

Defaults: n `1000,10000,100000`; k `10,50,100,500`; offsets `1,k//2,k-1`; two protocols; 30 repeats. Full output is exactly 2160 rows. Support environment overrides for smoke runs.

- [ ] **Step 5: Verify and commit**

```bash
GMCP_SESSION_LENGTHS=1000 GMCP_CHECKPOINT_INTERVALS=10,50 GMCP_REPEATS=3 \
  GMCP_OUTPUT_ROOT=results/submission_revision/smoke \
  .venv/bin/python run_checkpoint_cost_comparison.py
```

Expected: 36 rows, all reconstruction matches, temp logs removed.

```bash
git add run_checkpoint_cost_comparison.py tests/test_submission_experiment_contracts.py
git commit -m "feat: compare checkpoint and full-chain recovery costs"
```

---

### Task 8: Run-Level Statistics and Concurrency

**Files:**
- Modify: `gmcp/experiment_stats.py:1-216`
- Modify: `gmcp/statistical_analysis.py:1-100`
- Modify: `run_concurrent_experiment.py:1-462`
- Test: `tests/test_experiment_statistics.py`

**Interfaces:**
- Produces no-SciPy `calculate_statistics(values, confidence=0.95)`.
- Produces `calculate_observed_rate(success_count, total_count)`.
- Produces concurrency rows keyed by lock strategy, client count and repeat.

- [ ] **Step 1: Write failing tests**

Load current 5-client run means and assert CI half-width rounds to 0.0896 ms. Assert exact all-success lower bounds 94.04%, 97.97%, and 99.59% for 60, 180, and 900.

- [ ] **Step 2: Remove mandatory SciPy**

Use NumPy/standard library. Implement a tested 95% Student-t critical table for df 1-30 and normal approximation above 30; reject other confidence levels.

Make SciPy optional in `gmcp/statistical_analysis.py`: CI functions delegate to `gmcp.experiment_stats`; advanced t-test/ANOVA helpers raise a clear `RuntimeError("SciPy is required for advanced statistical tests")` when SciPy is absent instead of failing at module import.

For all-success observations:

```python
lower = 0.025 ** (1.0 / total_count)
upper = 1.0
method = "clopper_pearson_exact_boundary"
```

Mirror zero success; use Wilson for intermediate rates.

- [ ] **Step 3: Add lock-strategy dimension**

Run global and per-session modes separately. Output independent run rows. Summaries group 30 `rtt_mean_ms` values; never average message-level CI fields.

- [ ] **Step 4: Verify and commit**

```bash
.venv/bin/python -m unittest tests.test_experiment_statistics -v
GMCP_REPEATS=1 GMCP_OUTPUT_ROOT=results/submission_revision/smoke \
  .venv/bin/python run_concurrent_experiment.py --spawn-server
```

Expected: 10 rows for two strategies and five client counts.

```bash
git add gmcp/experiment_stats.py gmcp/statistical_analysis.py run_concurrent_experiment.py \
  tests/test_experiment_statistics.py
git commit -m "fix: compute intervals from independent experiment runs"
```

---

### Task 9: Manifest, Validation and Plots

**Files:**
- Create: `gmcp/experiment_manifest.py`
- Create: `validate_submission_revision.py`
- Create: `plot_submission_revision.py`
- Test: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- Produces `sha256_file(path)`, `write_manifest(...)`, and `validate_revision(...)`.

- [ ] **Step 1: Write failing artifact tests**

Temporary fixtures must detect duplicate keys, missing matrix combinations, N/A denominator errors, summary mismatch and changed hashes.

- [ ] **Step 2: Implement manifest**

Record protocol version, commit/dirty flag, Python/OS/dependencies, command, seed, timing, environment, lock strategy, limitations, CSV hashes and each plot's input hash.

- [ ] **Step 3: Implement validator**

Validate configured row counts, unique composite keys, matrix coverage, recomputed summaries, all reconstruction flags, race counts and N/A exclusions. Exit nonzero with one line per violation.

- [ ] **Step 4: Implement nine figures**

Generate the design's baseline capability, adaptive tamper, recovery window, nonce race, recovery time, replay count, byte cost, concurrency/CI, and observed-rate/confidence figures. Each function receives explicit CSV and output paths.

- [ ] **Step 5: Verify and commit**

```bash
.venv/bin/python -m unittest tests.test_submission_experiment_contracts -v
.venv/bin/python validate_submission_revision.py \
  --output-root results/submission_revision/smoke --expected-repeats 1
.venv/bin/python plot_submission_revision.py \
  --output-root results/submission_revision/smoke
```

Expected: validator exits 0 and all PNGs are nonempty.

```bash
git add gmcp/experiment_manifest.py validate_submission_revision.py \
  plot_submission_revision.py tests/test_submission_experiment_contracts.py
git commit -m "feat: validate and plot submission experiment artifacts"
```

---

### Task 10: Orchestration and Full Local Evidence

**Files:**
- Create: `run_submission_revision.py`
- Modify: `tests/test_experiment_contracts.py` only for corrected semantics.
- Output: `results/submission_revision/**`

**Interfaces:**
- Produces `--mode smoke|full` orchestration and final `manifest.json`.

- [ ] **Step 1: Implement fail-fast orchestration**

Run protocol tests, baseline, adaptive chain, recovery control, recovery window, ticket rejection, checkpoint cost, concurrency, validator, plots and manifest in order. Record and stop on the first failing subprocess.

- [ ] **Step 2: Run all tests**

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: PASS. The wrong-sender probe rejects; Authenticated Hash Chain rejects adaptive tampering; plain Hash Chain still accepts it as the documented negative control.

- [ ] **Step 3: Run smoke orchestration**

Run `.venv/bin/python run_submission_revision.py --mode smoke`.

Expected: exit 0, no legacy results overwritten, all smoke invariants pass.

- [ ] **Step 4: Visually inspect smoke figures**

Check every PNG for clipped labels, empty panels, incorrect N/A values, unreadable glyphs and mismatched legends. Fix only observed defects, then rerun plot and validation commands.

- [ ] **Step 5: Run the full 30-repeat suite**

Run `.venv/bin/python run_submission_revision.py --mode full`.

Expected evidence: 540 recovery-window rows, 2160 checkpoint-cost rows, 300 concurrency rows, every below-floor rejection leaves state unchanged, every nonce race has one success, and every reconstruction matches.

- [ ] **Step 6: Validate independently**

```bash
.venv/bin/python validate_submission_revision.py \
  --output-root results/submission_revision --expected-repeats 30
```

Expected: `VALIDATION PASSED`, exit 0.

- [ ] **Step 7: Check scope and commit source only**

```bash
git status --short
git diff --check
git add run_submission_revision.py tests/test_experiment_contracts.py
git commit -m "feat: orchestrate submission experiment revision"
```

- [ ] **Step 8: Hand off exact evidence**

Report test output, run duration, raw/summary CSV paths, figure paths, manifest path, success counts with confidence bounds, CI unit and limitations. Do not claim remote validation unless separately authorized with rotated credentials.

---

## Self-Review Mapping

- Tasks 1-4 cover encoding, DATA context, recovery HMAC, ticket opacity, Checkpoint keys, nonce atomicity and per-session locks.
- Task 5 covers Authenticated Hash Chain, adaptive tamper and N/A attack semantics.
- Task 6 covers control, forward sync, recovery floor and concurrent nonce.
- Task 7 covers the full O(k)/O(n) matrix and logical byte measurement.
- Task 8 covers run-level CI and exact boundaries for observed 100% rates.
- Tasks 9-10 cover isolated artifacts, hashes, plots, validation and full local execution.
- No task modifies paper files or uses remote credentials.
