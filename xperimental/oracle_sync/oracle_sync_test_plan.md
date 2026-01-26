# Oracle Sync (ORACLE_SYNC_01) — Testing Development Plan

**Goal:** Provide Codex (coding agent) a concrete, code-grounded plan to build an automated test harness and scenario suite for the Oracle Sync plugin, focused on correctness, robustness, and regression prevention.

Target code (4 files):

- `edge_node/extensions/business/oracle_sync/oracle_sync_01.py`   
- `edge_node/extensions/business/oracle_sync/sync_mixins/ora_sync_states_mixin.py`   
- `edge_node/extensions/business/oracle_sync/sync_mixins/ora_sync_utils_mixin.py`   
- `edge_node/extensions/business/oracle_sync/sync_mixins/ora_sync_constants.py`   

Deliverable to implement: `edge_node/xperimental/oracle_sync/test_ora_sync.py` (pytest-friendly, runnable as a script as well).

---

## 1) Code-grounded system understanding (what must be tested)

### 1.1 State machine flow (high-level)
The plugin is a state machine that:
1) **On startup** begins in **S8** (request historical agreements), then transitions to **S0** once caught up.   
2) **Per epoch**, after epoch change: announce participants (**S11**), compute local tables (**S1**), exchange local tables (**S2**), compute median tables (**S3**), exchange median tables (**S4**), compute agreed median (**S5**), gather signatures (**S6**), exchange signatures (**S10**), update epoch manager (**S7**), then wait (**S0**).   

### 1.2 Message handling guarantees and constraints
- Incoming payloads are buffered **per-oracle** as deques with `MAX_RECEIVED_MESSAGES_PER_ORACLE`, and the state machine consumes at most **one message per oracle per step** (`popleft`).   
- Non-oracle senders are ignored (`_is_oracle`).   
- There are multiple message schemas enforced via `_check_received_oracle_data_for_values()` using `VALUE_STANDARDS` (type validation + optional CID decoding).   

### 1.3 Consensus & fault behavior
- Participant set is negotiated in **S11** and influences thresholds such as “half of valid oracles”.   
- When **agreement is not reached**, or when **not enough signatures** are collected, nodes move into the “request agreed tables” path (S8/S9) and may **mark epochs as faulty**.   
- “Too close to epoch change” requests should be ignored (3 minutes before end).   

### 1.4 R1FS (IPFS-like) conditional behavior
- Messages may include **CIDs instead of full data** for certain keys (`maybe_cid=True` in `VALUE_STANDARDS`). Retrieval failures must cause the message to be rejected.   
- Add-to-R1FS has multiple fallback paths (not warmed, add failure, exception).   

---

## 2) Test strategy overview

### 2.1 What “good” looks like (acceptance criteria)
Codex should aim for:

1) **Deterministic simulation tests** that exercise full state-machine cycles with multiple oracles.
2) **Robust validation tests** (type/stage/signature/CID) that ensure bad payloads are ignored, not crashing the state machine.
3) **Corner-case regression tests** for timeouts, early stopping, oracle dropouts, and partial/historical sync.
4) Tests that run locally in seconds, with **no dependency on real blockchain/IPFS/network** (fully mocked).

Recommended tooling:
- **pytest fixtures + monkeypatch** for dependency injection and time control.   
- **unittest.mock autospec** where appropriate to keep mocks honest.   
- **Hypothesis stateful testing** for randomized message ordering & adversarial sequences.   

---

## 3) Test harness architecture (what Codex should build)

### 3.1 Core idea
Build a **closed-loop simulation** that runs N OracleSync instances, routes their outbound messages to each other, and advances “time” deterministically.

**Key constraints to respect:**
- The plugin relies on `NetworkProcessorPlugin` methods (payload handlers, `add_payload_by_fields`, state machine API).
- For unit tests, we don’t need the full framework; we need **minimal shims** + **monkeypatched methods**.

### 3.2 Components to implement in `test_ora_sync.py`

#### A) `FakeClock`
- `time()` → float seconds (manual advance)
- `sleep(dt)` → advance time rather than real sleeping
- `datetime.now(tz)` support (only what `_check_too_close_to_epoch_change` needs)

#### B) `FakeEpochManager`
Provide the subset used by the plugin/mixins, including:
- `epoch_length`, `get_current_epoch()`, `get_time_epoch()`, `maybe_close_epoch()`
- `get_current_epoch_end(current_epoch)` (for “ignore requests” window)
- `get_last_sync_epoch()` and persistence stubs: `maybe_update_cached_data(force=True)`, `save_status()`
- For availability:
  - `get_current_epoch_availability(return_absolute=True, return_max=True)` (self-assessment)
  - `get_node_previous_epoch(node)` (local view of previous epoch availability)
  - `get_epoch_availability(epoch, return_additional=True)` returns: `(availability_table, signatures_table, agreement_cid, signatures_cid)`   
- `is_epoch_valid(epoch)` and (if used) methods to mark invalid/faulty epochs.

Keep internal data as simple dicts:
- `epoch_availability[epoch][node] -> int`
- `epoch_signatures[epoch] -> dict(oracle->sig)` (or per-node signatures if needed)
- `epoch_valid[epoch] -> bool`
- `last_sync_epoch`

#### C) `FakeBlockchain`
Must support:
- `get_oracles()` to return the oracle list.   
- `sign(dct, add_data=True, use_digest=True)` to attach a deterministic signature field (`EE_SIGN`).   
- `verify(dct_data, str_signature=None, sender_address=None)` returning an object with `.valid` and `.message`.   
- `maybe_add_prefix(addr)` (can be no-op)
- (Optional) helpers to “tamper” signatures for negative tests.

**Deterministic signature approach for tests:**
- signature := sha256(json_sorted(data_without_EE_SIGN) + sender)
- store sender address inside the signed object if production does that.

#### D) `FakeR1FS`
Supports:
- `is_ipfs_warmed` bool
- `add_pickle(obj)` returns CID or None
- `get_file(cid)` returns a temp file path written by the fake (pickle dump)
- Optional knobs to inject failures and timeouts.

#### E) `MessageBus` (simulation network)
- Captures outbound `oracle_data` payloads produced by each oracle and delivers them to other oracles by calling their `handle_received_payloads()`.   
- Must model:
  - broadcast vs targeted (production seems broadcast)
  - delivery delays and reordering (for adversarial tests)
  - duplicate deliveries

#### F) `OracleHarness`
Wraps a plugin instance and injects:
- `netmon` (with `epoch_manager` + node helpers used in logs/formatting)
- `bc`, `r1fs`, `time`, `sleep`, and any other module references used via `self.*`
- override `add_payload_by_fields(oracle_data=...)` to push into `MessageBus` instead of real networking

**Implementation tactic:**
- Instantiate `OracleSync01Plugin` without framework bootstrapping, or subclass it in test to bypass base init.
- Then set required attributes and call `on_init()` (but patch `on_init` loops to avoid waiting).   

---

## 4) Test inventory (unit, integration, property-based)

### 4.1 Constants tests (`ora_sync_constants.py`)
1) **Threshold sanity:**
   - `FULL_AVAILABILITY_THRESHOLD == round(SUPERVISOR_MIN_AVAIL_PRC * EPOCH_MAX_VALUE)`   
   - `POTENTIALLY_FULL_AVAILABILITY_THRESHOLD` math stays within `[0, EPOCH_MAX_VALUE]`   
2) **Timeout multipliers nonzero and stable**
   - `*_SEND_MULTIPLIER`, `REQUEST_AGREEMENT_TABLE_MULTIPLIER`, `SIGNATURES_EXCHANGE_MULTIPLIER`   
3) **VALUE_STANDARDS coherence**
   - keys exist for used message fields and `maybe_cid` matches intended fields (LOCAL_TABLE, MEDIAN_TABLE).   

### 4.2 Utils mixin tests (`ora_sync_utils_mixin.py`)
**A) R1FS helpers**
- `r1fs_add_data_to_message()`:
  - warmup false → embeds full dict
  - warmup true + add succeeds → embeds CID
  - warmup true + add returns None → embeds full dict
  - add raises exception → embeds full dict   
- `r1fs_get_data_from_message()`:
  - value is dict → returns as-is
  - value is CID → loads pickle
  - CID retrieval fails → returns None and triggers rejection upstream   

**B) Message validation**
- `_check_received_oracle_data_for_values()` matrix:
  - non-dict oracle_data → reject
  - missing fields / None fields → reject
  - wrong types vs `VALUE_STANDARDS` → reject
  - stage mismatch (single stage and list-of-stages) → reject
  - `maybe_cid` field with CID that fails retrieval → reject
  - `verify=True` invalid signature → reject   

**C) Epoch-range validation**
- `_check_received_epoch__agreed_median_table_ok()`:
  - non-contiguous `epoch_keys` → reject
  - mismatch between epoch_keys and table keys/signature keys/is_valid keys → reject   

**D) “Too close to epoch change” rule**
- Freeze time near `get_current_epoch_end()` and verify `_check_too_close_to_epoch_change()` flips at `ORACLE_SYNC_IGNORE_REQUESTS_SECONDS`   

### 4.3 States mixin tests (`ora_sync_states_mixin.py`)
Because the mixin functions are state callbacks, cover them in two layers:

#### Layer 1: “Pure-ish” unit tests (minimal environment)
Focus on compute/check functions that can run with mocked dependencies:
- `_compute_simple_median_table()` and `_compute_simple_agreed_value_table()` (if present)
- `_compute_agreed_median_table()` (driven by a prepared `dct_median_tables` and `is_participating`)   
- `_compute_requested_agreed_median_table()` (hash-frequency consensus and faulty epoch marking)   

**Key corner cases:**
- **Strict majority rule**: verify behavior when max_frequency == floor(n/2) (must fail) and when > floor(n/2) (must succeed).   
- “Faulty nodes” path: median frequency below `min_frequency` excludes nodes; ensure exclusion is deterministic and doesn’t crash.   
- Potential float threshold from `_count_half_of_valid_oracles()` (it returns `/2`): ensure comparisons behave as intended and don’t cause off-by-one.   

#### Layer 2: Integration tests (full multi-oracle simulation)
Run N oracles through:
- Participant announcement (**S11**) and threshold update based on local availability.   
- Local table exchange (**S2**) and median computation (**S3**) leading to **S5** agreement and signature exchange.   
- Epoch manager update (**S7**) and transition back to **S0** only after signature criteria holds.   

### 4.4 Plugin-level tests (`oracle_sync_01.py`)
1) **Message queue bounds**
   - Push > `MAX_RECEIVED_MESSAGES_PER_ORACLE` and verify older messages are dropped, and `get_received_messages_from_oracles()` drains one per oracle.   
2) **Startup state**
   - `on_init()` initializes state machine in **S8** and sets message buffers.   
3) **Process exception containment**
   - Force an exception in a state callback and verify `process()` sets `exception_occurred` and does not crash the test runner (it sleeps briefly).   
4) **Oracle list refresh logic**
   - Ensure `maybe_refresh_oracle_list()` is rate limited and handles empty blockchain response.   

---

## 5) Scenario suite (must-have end-to-end tests)

### Scenario A — Happy-path consensus (3 oracles, 1 epoch)
**Objective:** validate S11→S7 pipeline produces identical agreement across oracles and updates epoch manager.

**Setup:**
- 3 oracle nodes (A,B,C) with high previous availability.
- Several non-oracle nodes with availability values; each oracle’s local view should match (or have small differences if median logic expects it).

**Assertions:**
- `compiled_agreed_median_table` matches expected strict-majority values.
- Signatures are collected, exchanged, and stored.
- `epoch_manager.get_last_sync_epoch()` increments to previous epoch.

### Scenario B — One oracle cannot participate
**Objective:** ensure the “non-participating oracle” follows S8 request path and still catches up.

**Setup:**
- Oracle C has previous availability below `FULL_AVAILABILITY_THRESHOLD`.   

**Assertions:**
- C does not announce participation; A,B still reach consensus.
- C requests agreed tables and updates epoch manager after receiving responses.

### Scenario C — Disordered + duplicated messages
**Objective:** message routing noise shouldn’t break correctness.

**Setup:**
- Inject random reorder/duplication in MessageBus for S2/S4/S6/S10 phases.

**Assertions:**
- Final agreement still converges (or deterministically fails if strict majority is impossible).
- No infinite loops; timeouts or early-stopping triggers transition.

### Scenario D — Invalid signatures / tampering
**Objective:** invalid data is ignored, not poisoning consensus.

**Setup:**
- Tamper with one oracle’s signed median table entries or agreement signature.

**Assertions:**
- `_check_received_oracle_data_for_values(...verify=True...)` rejects it.   
- Consensus still succeeds if enough honest oracles remain.

### Scenario E — R1FS CID path and retrieval failures
**Objective:** verify both (CID success) and (CID failure -> message rejected) paths.

**Setup:**
- Enable `cfg_use_r1fs=True`.   
- For LOCAL_TABLE/MEDIAN_TABLE, send CID and ensure receivers fetch from FakeR1FS.
- Inject CID retrieval failure for one sender.

**Assertions:**
- Good CID messages are accepted and decoded.
- Failed retrieval causes message rejection (and may trigger timeout/fallback).

### Scenario F — Historical sync on startup (multi-epoch range)
**Objective:** node starts late and needs epochs `[last_synced+1, current_epoch-1]`.

**Setup:**
- Set `_last_epoch_synced` behind by K epochs.
- Ensure other oracles respond with `EPOCH__AGREED_MEDIAN_TABLE`, signatures, keys, and `EPOCH__IS_VALID`.   

**Assertions:**
- Receiver only accepts complete continuous ranges.
- Epoch manager gets updated for each epoch in range.
- If consensus hashes don’t reach strict majority, epochs are marked faulty.

---

## 6) Property-based / stateful testing (high value, optional but recommended)

### 6.1 Fuzz message validators
Use Hypothesis strategies to generate:
- missing keys, wrong types, None values
- epoch_keys with gaps, mismatched dict keys, mixed str/int keys
- random stages

Property: validator functions must not throw, only return True/False with logs.   

### 6.2 Rule-based state machine simulation
Model:
- actions: deliver message, drop message, advance time, flip oracle availability participation, toggle R1FS warmed state
- invariants:
  - state transitions remain within known states
  - buffers never exceed configured maxlen
  - if strict majority is possible and enough time passes, sync eventually completes

Hypothesis provides `RuleBasedStateMachine` for this.   

---

## 7) Implementation steps for Codex (ordered, concrete tasks)

### Step 0 — Create the skeleton file
- Create `edge_node/xperimental/oracle_sync/test_ora_sync.py`
- Add `pytest` entrypoint compatibility (`if __name__ == "__main__": ... pytest.main([...])`)

### Step 1 — Build fakes (clock, epoch manager, blockchain, r1fs)
- Implement each fake with explicit failure injection switches.
- Add unit tests per fake (sanity + failure modes).

### Step 2 — Build MessageBus + OracleHarness
- Override plugin outbound send path to push into MessageBus.
- Route inbound messages via `handle_received_payloads()`.

### Step 3 — Wire 3-oracle simulation and run a single sync cycle
- Deterministic time advance:
  - call `process()` in a loop
  - advance time so that send intervals/timeouts trigger
- Assert correct state progression and epoch manager update.

### Step 4 — Add the scenario suite (A–F)
- Each scenario must run in < 2–5 seconds and be deterministic.

### Step 5 — Add validator unit tests
- Directly call `_check_received_oracle_data_for_values`, `_check_received_epoch__agreed_median_table_ok`, etc., with crafted payloads.

### Step 6 — Add Hypothesis tests (optional)
- If runtime is acceptable in CI, keep them enabled with tuned settings; otherwise mark as nightly.

### Step 7 — Quality gates
- Add coverage reporting for these 4 files (target: 80%+ on mixins).
- Ensure logs do not flood: use pytest’s `caplog` or silence debug flags.

---

## 8) Suggested micro-refactors (only if tests reveal pain points)
These are not required for the test file, but will dramatically improve testability and long-term reliability:

1) Extract “compute median” and “compute agreed median” into pure functions that accept dicts and return dicts (no `self` access).
2) Normalize strict-majority thresholds to integers (`ceil(n/2)` or `n//2 + 1`) to avoid float comparisons.   
3) Add a thin abstraction for outbound messaging (e.g., `send_oracle_data(oracle_data)`) to simplify mocking.

---

## 9) Done definition (what to merge)
A PR is “done” when:
- `test_ora_sync.py` contains:
  - fakes + harness + message bus
  - ≥ 6 scenario tests (A–F)
  - validator unit tests
- Tests pass reliably with `pytest -q` and do not depend on network, real blockchain, or real IPFS.
- Clear docstring at top explains how to run locally and how to extend scenarios.

