# GMCP-R Final Submission Revision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复投稿前审查提示列出的正式实验审计缺口，并让代码、CSV、validator、README、实验总结、论文、图表和 DOCX 使用同一批可复验数据。

**Architecture:** 先用单元测试和真实 socket 集成测试锁定协议、恢复窗口、checkpoint 成本和 baseline 审计语义，再修实验脚本与服务器绑定逻辑。通过 smoke 数据验证代码后提交“实验代码 commit”，从该 commit 运行正式实验生成 `paper_data/01_real_baseline.csv`、`paper_data/08_recovery_window.csv`、`paper_data/09_checkpoint_cost.csv`，最后自动更新文档、图表和 DOCX 并运行 release validator。

**Tech Stack:** Python 3.11、unittest、socket/threading、CSV/JSONL、HMAC-SHA256、pandas/matplotlib/python-docx、LibreOffice headless rendering。

## Global Constraints

- 不伪造、手工填写、复制或随机生成正式实验结果。
- `paper_data` 中的正式 CSV 必须由对应实验脚本真实运行生成。
- smoke test 数据不能覆盖 `paper_data`。
- 实验 timeout、error、缺失行、重复组合或验证失败时退出非零状态。
- 修改代码后先提交一个“实验代码 commit”，再从该 commit 运行正式实验。
- CSV 中的 `git_commit` 必须记录实际运行实验时的代码 commit。
- 正式数据文件必须重新生成：`paper_data/01_real_baseline.csv`、`paper_data/08_recovery_window.csv`、`paper_data/09_checkpoint_cost.csv`。
- release 数据行数为 `7200 + 300 + 120 + 15 + 150 + 900 + 120 + 760 + 2160 = 11725`。
- 使用 `.venv/bin/python` 运行本仓库测试和实验。
- 不把服务器密码、token、私钥写入仓库。

---

### Task 1: Recovery Window Contracts

**Files:**
- Modify: `run_recovery_window_experiment.py`
- Modify: `real_tcp_server_with_ticket.py`
- Modify: `validate_submission_revision.py`
- Modify: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- Produces release `paper_data/08_recovery_window.csv` with 760 rows.
- Validator checks unique `(scenario, checkpoint_interval, payload_size, repeat_id)`.
- `RECOVERY_REQUEST` is rejected before HELLO or on session/sender/epoch/protocol mismatch.

- [ ] **Step 1: Write failing tests**
  Add tests proving `nonce_race` carries positive unique `repeat_id`, all `below_floor` rows are checked, and recovery requests require HELLO connection binding.
- [ ] **Step 2: Run focused tests and confirm failure**
  Run `.venv/bin/python -m unittest tests.test_submission_experiment_contracts -v`.
- [ ] **Step 3: Implement fixes**
  Set `result["repeat_id"] = repeat_id` before the `nonce_race` early return; keep normal scenarios explicit. Remove validator `break` from `below_floor`; enforce all scenario invariants. Add recovery connection binding checks in `real_tcp_server_with_ticket.py`.
- [ ] **Step 4: Verify**
  Run `.venv/bin/python -m unittest tests.test_submission_experiment_contracts -v`.

### Task 2: Checkpoint Cost Exact Read Contracts

**Files:**
- Modify: `run_checkpoint_cost_comparison.py`
- Modify: `validate_submission_revision.py`
- Modify: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- `measure_gmcp_recovery()` reads exactly `offset` JSONL records after seek.
- `measure_auth_chain_recovery()` reads exactly `target_seq` records.
- CSV includes `stored_mem_ok`; success rows have `physical_bytes_read == logical_bytes_replayed`.

- [ ] **Step 1: Write failing tests**
  Add tempfile JSONL tests for offset 1 and 5, unexpected EOF, tampered auth tag, tampered payload hash, tampered prev_mem, tampered mem, and authenticated hash chain exact-read behavior.
- [ ] **Step 2: Run focused tests and confirm failure**
  Run `.venv/bin/python -m unittest tests.test_submission_experiment_contracts.CheckpointCostContractTests -v`.
- [ ] **Step 3: Implement exact bounded reads and `stored_mem_ok`**
  Replace read-until-next-record logic with `for expected_index in range(offset)` and add explicit stored-memory verification.
- [ ] **Step 4: Verify**
  Run the focused checkpoint tests.

### Task 3: Baseline Attack Packet Audit

**Files:**
- Modify: `run_real_baseline_comparison.py`
- Modify: `real_baseline_server.py`
- Modify: `validate_submission_revision.py`
- Modify: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- Baseline CSV includes attack packet audit fields: `attack_packet_seq`, `attack_packet_sent`, `attack_packet_accepted`, `attack_packet_rejected`, `attack_packet_reason`, `attack_packet_reason_class`, `post_attack_resynchronized`, `retry_sent`, `retry_accepted`, `run_valid`, `failure_reason`.
- Applicable rejected attack rows retry the clean packet at the same sequence and then continue.
- N/A historical-field attacks for `seq_mac` and `ticket_only` send normal traffic but no attack packet.

- [ ] **Step 1: Write failing tests**
  Add validator fixture tests for applicable rejected rows, false accepted rows, N/A rows, and cross-session/cross-epoch reason matching.
- [ ] **Step 2: Run focused tests and confirm failure**
  Run `.venv/bin/python -m unittest tests.test_submission_experiment_contracts.BaselineAuditContractTests -v`.
- [ ] **Step 3: Implement audit capture and resynchronization**
  Lock attack-packet audit immediately after the attack response; retry same seq on rejection; keep `sent_count == accepted + rejected + timeout + error`.
- [ ] **Step 4: Verify**
  Run the focused baseline tests.

### Task 4: Strict Validators and Release Artifact Checks

**Files:**
- Modify: `validate_submission_revision.py`
- Create: `validate_release_artifacts.py`
- Modify: `tests/test_submission_experiment_contracts.py`

**Interfaces:**
- `parse_bool(value)` handles strings without `bool("False")`.
- `validate_submission_revision.py --mode smoke|release --output-root PATH`.
- `validate_release_artifacts.py` verifies nine `paper_data` CSVs, total row count 11725, old-number scans, and Markdown table consistency.

- [ ] **Step 1: Write failing validator tests**
  Test missing files fail in release mode, baseline detection denominator filters only applicable+injected+sent rows, and old artifact numbers are rejected.
- [ ] **Step 2: Implement strict validation**
  Require CSVs and manifest in release mode; keep smoke mode for temporary outputs.
- [ ] **Step 3: Verify**
  Run `.venv/bin/python -m unittest tests.test_submission_experiment_contracts -v`.

### Task 5: Smoke, Experiment Code Commit, and Formal Runs

**Files:**
- Modify: `run_submission_revision.py` if needed.
- Generated: `results/submission_revision/smoke/*`.
- Generated then copied: `paper_data/01_real_baseline.csv`, `paper_data/08_recovery_window.csv`, `paper_data/09_checkpoint_cost.csv`.

**Interfaces:**
- Smoke commands write only to temporary output.
- Formal commands run after code commit and embed the experiment code commit hash.

- [ ] **Step 1: Run unit and socket tests**
  `.venv/bin/python -m unittest discover -s tests -v`.
- [ ] **Step 2: Run smoke baseline/recovery/checkpoint and smoke validator**
  Use repeat count 1 and temp output root.
- [ ] **Step 3: Commit experiment code**
  Stage only code/test/CI/validator files and commit.
- [ ] **Step 4: Run formal experiments**
  Run 7200-row baseline, 760-row recovery window, and 2160-row checkpoint cost from the code commit, locally or on `38.76.169.74`.

### Task 6: Documentation, Figures, DOCX, and Final Commit

**Files:**
- Modify: `README.md`
- Modify: `paper_data/README.md`
- Modify: `EXPERIMENT_SUMMARY.md`
- Modify: `paper/main_zh.md`
- Modify: `paper/build_mdpi_chinese_docx.py`
- Modify or create figure scripts.
- Generated: `paper/generated_figures/*`, `paper/GMCP-R_MDPI_Electronics_中文初稿.docx`.

**Interfaces:**
- Documentation is generated from current CSVs, not manual numeric edits.
- Paper uses 5 protocols, 8 attack conditions, two attacker models, Recovery Window 760, Checkpoint Cost 2160, total 11725.
- DOCX source scan contains none of the old unqualified strings: `3600`, `5205`, `12940`, `Ticket Only 50%`, `Seq+MAC 25%`, `三种基线协议`, `四种协议`, `none, drop, modify, replay, prev_mem`.

- [ ] **Step 1: Generate summaries and figures from CSV**
  Add or update a controlled generator; do not use global string replacement.
- [ ] **Step 2: Update paper and DOCX**
  Regenerate `paper/main_zh.md`, figures, and DOCX.
- [ ] **Step 3: Run release validation and scans**
  `GMCP_RELEASE_VALIDATION=1 .venv/bin/python -m unittest discover -s tests -v` and `.venv/bin/python validate_release_artifacts.py`.
- [ ] **Step 4: Commit final artifacts**
  Commit regenerated CSV/docs/figures/DOCX with a final submission-revision message.

## Self-Review

- Spec coverage: The tasks cover recovery window repeat/audit, checkpoint exact reads, baseline attack audit/resync, strict validators, smoke/formal run order, docs/figures/DOCX, and final report requirements.
- Placeholder scan: No task contains an unresolved placeholder; implementation details point to exact files and commands.
- Type consistency: Validator mode, CSV fields, row counts, and artifact paths use the same names as the review prompt.
